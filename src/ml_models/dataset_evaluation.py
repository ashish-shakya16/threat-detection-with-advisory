"""Offline evaluation of the Isolation Forest detector on public IDS datasets.

Supported datasets (download them yourself; see docs/DATASET_EVALUATION.md):
    cicids2017  CIC-IDS2017 "MachineLearningCVE" or "GeneratedLabelledFlows" CSVs
    unsw-nb15   UNSW-NB15 official partition: UNSW_NB15_training-set.csv and
                UNSW_NB15_testing-set.csv

Protocol (chosen to avoid the common ways these datasets inflate results):
    1. Train and test data come from different files supplied by the caller:
       different capture days for CICIDS2017, the official partition for
       UNSW-NB15. Rows are never randomly shuffled across that boundary.
    2. Rows with NaN/inf values and exact duplicates are removed, and test
       rows identical to a training row are dropped (cross-split leakage).
    3. Identifier and shortcut columns (flow IDs, IP addresses, ports,
       timestamps) are removed so the model cannot memorise hosts.
    4. The Isolation Forest is fitted on benign training rows only.
    5. The decision threshold is chosen on a held-out validation split of the
       training data for a target false-positive rate. The test set is used
       once, for reporting only.

This evaluates detection on CICFlowMeter-style / Argus-style flow features
offline. SecureX's live monitor does not compute these features, so these
results do not measure live detection performance.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

CICIDS_IDENTIFIERS = [
    'Flow ID', 'Source IP', 'Src IP', 'Source Port', 'Src Port', 'Destination IP', 'Dst IP',
    'Timestamp', 'Destination Port', 'Dst Port',
]
UNSW_IDENTIFIERS = ['id', 'srcip', 'sport', 'dstip', 'dsport', 'stime', 'ltime']
UNSW_CATEGORICAL = ['proto', 'service', 'state']

LIMITATIONS = [
    'Offline evaluation on recorded flow features; it does not measure SecureX live monitoring, '
    'which uses process and connection telemetry rather than these flow statistics.',
    'Isolation Forest flags deviations from benign training traffic; it does not identify attack types.',
    'CIC-IDS2017 has documented labelling and flow-construction errors (Engelen, Rimmer and Joosen, '
    '"Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", IEEE SPW 2021); '
    'results on the original CSVs inherit them.',
    'Both datasets are lab captures from 2015-2017 and are not representative of every network.',
    'Results on one dataset do not imply results on another; cross-dataset testing is not performed.',
]


@dataclass
class PreparedData:
    feature_names: List[str]
    x_fit: np.ndarray            # benign rows used to fit the model
    x_val: np.ndarray
    y_val: np.ndarray
    x_test: np.ndarray
    y_test: np.ndarray
    test_categories: np.ndarray
    cleaning: Dict[str, int] = field(default_factory=dict)


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _read_csvs(paths: Sequence[str]) -> pd.DataFrame:
    frames = []
    for path in paths:
        try:
            frame = pd.read_csv(path, low_memory=False)
        except UnicodeDecodeError:
            # Some CICIDS2017 files contain non-UTF-8 label characters.
            frame = pd.read_csv(path, low_memory=False, encoding='latin-1')
        frame.columns = [str(column).strip() for column in frame.columns]
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def _clean(frame: pd.DataFrame, stats: Dict[str, int], prefix: str) -> pd.DataFrame:
    stats[f'{prefix}_rows_raw'] = len(frame)
    frame = frame.replace([np.inf, -np.inf], np.nan).dropna()
    stats[f'{prefix}_rows_after_nan_inf'] = len(frame)
    frame = frame.drop_duplicates()
    stats[f'{prefix}_rows_after_dedup'] = len(frame)
    return frame


def _sample(frame: pd.DataFrame, max_rows: Optional[int], seed: int) -> pd.DataFrame:
    if max_rows and len(frame) > max_rows:
        return frame.sample(n=max_rows, random_state=seed)
    return frame


def _standardize(dataset: str, frame: pd.DataFrame):
    """Return (features, binary labels, category labels) for one dataset."""
    if dataset == 'cicids2017':
        if 'Label' not in frame.columns:
            raise ValueError('CIC-IDS2017 file has no "Label" column')
        categories = frame['Label'].astype(str).str.strip()
        labels = (categories.str.upper() != 'BENIGN').astype(int)
        features = frame.drop(columns=[c for c in CICIDS_IDENTIFIERS + ['Label'] if c in frame.columns])
        # The original CSVs repeat "Fwd Header Length" as "Fwd Header Length.1".
        features = features.drop(columns=[c for c in features.columns if c.endswith('.1')])
    elif dataset == 'unsw-nb15':
        if 'label' not in frame.columns:
            raise ValueError('UNSW-NB15 file has no "label" column')
        labels = frame['label'].astype(int)
        categories = frame['attack_cat'].fillna('Normal').astype(str).str.strip() if 'attack_cat' in frame else \
            labels.map({0: 'Normal', 1: 'Attack'})
        categories = categories.replace('', 'Normal')
        drop = [c for c in UNSW_IDENTIFIERS + ['label', 'attack_cat'] if c in frame.columns]
        features = frame.drop(columns=drop)
    else:
        raise ValueError(f'Unknown dataset {dataset!r}; use cicids2017 or unsw-nb15')
    return features, labels.to_numpy(), categories.to_numpy()


def prepare(dataset: str, train_paths: Sequence[str], test_paths: Sequence[str],
            validation_fraction: float = 0.2, max_rows: Optional[int] = None, seed: int = 42) -> PreparedData:
    stats: Dict[str, int] = {}
    train = _clean(_read_csvs(train_paths), stats, 'train')
    test = _clean(_read_csvs(test_paths), stats, 'test')

    x_train_raw, y_train, _ = _standardize(dataset, train)
    x_test_raw, y_test, test_categories = _standardize(dataset, test)

    categorical = [c for c in UNSW_CATEGORICAL if c in x_train_raw.columns] if dataset == 'unsw-nb15' else []
    numeric = [c for c in x_train_raw.columns if c not in categorical]
    x_train_raw[numeric] = x_train_raw[numeric].apply(pd.to_numeric, errors='coerce')
    x_test_raw[numeric] = x_test_raw[numeric].apply(pd.to_numeric, errors='coerce')

    # One-hot encode using categories seen in training only.
    x_train = pd.get_dummies(x_train_raw, columns=categorical, dtype=float)
    x_test = pd.get_dummies(x_test_raw, columns=categorical, dtype=float).reindex(columns=x_train.columns, fill_value=0.0)

    keep_train = x_train.notna().all(axis=1).to_numpy()
    keep_test = x_test.notna().all(axis=1).to_numpy()
    x_train, y_train = x_train[keep_train], y_train[keep_train]
    x_test, y_test, test_categories = x_test[keep_test], y_test[keep_test], test_categories[keep_test]

    constant = [c for c in x_train.columns if x_train[c].nunique(dropna=False) <= 1]
    x_train, x_test = x_train.drop(columns=constant), x_test.drop(columns=constant)
    stats['constant_features_dropped'] = len(constant)

    # Cross-split leakage: drop test rows whose features and label also occur in training.
    train_keys = set(pd.util.hash_pandas_object(x_train.assign(_y=y_train), index=False))
    test_keys = pd.util.hash_pandas_object(x_test.assign(_y=y_test), index=False).to_numpy()
    unseen = np.array([key not in train_keys for key in test_keys], dtype=bool)
    stats['test_rows_overlapping_train_removed'] = int((~unseen).sum())
    x_test, y_test, test_categories = x_test[unseen], y_test[unseen], test_categories[unseen]

    train_frame = _sample(x_train.assign(_y=y_train), max_rows, seed)
    test_frame = _sample(x_test.assign(_y=y_test, _cat=test_categories), max_rows, seed)
    x_train, y_train = train_frame.drop(columns=['_y']), train_frame['_y'].to_numpy()
    test_categories = test_frame['_cat'].to_numpy()
    x_test, y_test = test_frame.drop(columns=['_y', '_cat']), test_frame['_y'].to_numpy()

    stratify = y_train if len(np.unique(y_train)) > 1 and min(np.bincount(y_train)) > 1 else None
    x_fit_all, x_val, y_fit_all, y_val = train_test_split(
        x_train, y_train, test_size=validation_fraction, random_state=seed, stratify=stratify,
    )
    x_fit = x_fit_all[y_fit_all == 0]
    if len(x_fit) == 0:
        raise ValueError('No benign rows in the training files; the detector needs benign traffic to learn from')
    if not (y_val == 0).any():
        raise ValueError('No benign rows in the validation split; cannot choose a threshold')
    stats.update({
        'fit_rows_benign': len(x_fit), 'validation_rows': len(x_val), 'test_rows': len(x_test),
        'test_attack_rows': int(y_test.sum()),
    })
    return PreparedData(list(x_train.columns), x_fit.to_numpy(float), x_val.to_numpy(float), y_val,
                        x_test.to_numpy(float), y_test, test_categories, stats)


def _metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> Dict[str, object]:
    predicted = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    both_classes = len(np.unique(y_true)) == 2
    return {
        'precision': float(precision_score(y_true, predicted, zero_division=0)),
        'recall': float(recall_score(y_true, predicted, zero_division=0)),
        'f1': float(f1_score(y_true, predicted, zero_division=0)),
        'false_positive_rate': float(fp / (fp + tn)) if (fp + tn) else None,
        'roc_auc': float(roc_auc_score(y_true, scores)) if both_classes else None,
        'average_precision': float(average_precision_score(y_true, scores)) if both_classes else None,
        'confusion_matrix': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        'support': {'benign': int((y_true == 0).sum()), 'attack': int((y_true == 1).sum())},
    }


def evaluate(dataset: str, train_paths: Sequence[str], test_paths: Sequence[str], target_fpr: float = 0.01,
             max_rows: Optional[int] = None, seed: int = 42, n_estimators: int = 200) -> Dict[str, object]:
    """Run the full protocol and return a report dictionary."""
    data = prepare(dataset, train_paths, test_paths, max_rows=max_rows, seed=seed)

    scaler = StandardScaler().fit(data.x_fit)
    model = IsolationForest(n_estimators=n_estimators, contamination='auto', random_state=seed, n_jobs=-1)
    model.fit(scaler.transform(data.x_fit))

    # Higher = more anomalous.
    val_scores = -model.score_samples(scaler.transform(data.x_val))
    test_scores = -model.score_samples(scaler.transform(data.x_test))
    threshold = float(np.quantile(val_scores[data.y_val == 0], 1 - target_fpr))

    test_predicted = test_scores >= threshold
    per_category = {}
    for category in sorted(set(data.test_categories)):
        mask = data.test_categories == category
        per_category[str(category)] = {
            'rows': int(mask.sum()),
            'flagged_rate': float(test_predicted[mask].mean()),
        }

    report = {
        'dataset': dataset,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'files': {
            'train': [{'name': os.path.basename(p), 'sha256': file_sha256(p)} for p in train_paths],
            'test': [{'name': os.path.basename(p), 'sha256': file_sha256(p)} for p in test_paths],
        },
        'protocol': {
            'split': 'train/test from separate caller-supplied files; validation = stratified '
                     f'{0.2:.0%} of training rows',
            'model_fit_on': 'benign training rows only',
            'threshold_selection': f'{1 - target_fpr:.1%} quantile of benign validation scores '
                                   f'(target false-positive rate {target_fpr:.1%})',
            'max_rows_per_split': max_rows,
            'seed': seed,
        },
        'cleaning': data.cleaning,
        'features': data.feature_names,
        'model': {'type': 'IsolationForest', 'n_estimators': n_estimators, 'scaler': 'StandardScaler',
                  'scikit_learn': sklearn.__version__, 'pandas': pd.__version__},
        'threshold': threshold,
        'validation_metrics': _metrics(data.y_val, val_scores, threshold),
        'test_metrics': _metrics(data.y_test, test_scores, threshold),
        'test_flagged_rate_by_category': per_category,
        'limitations': LIMITATIONS,
    }
    report['_artifacts'] = {'model': model, 'scaler': scaler}
    return report


def to_markdown(report: Dict[str, object]) -> str:
    test, val = report['test_metrics'], report['validation_metrics']

    def fmt(value):
        return 'n/a' if value is None else f'{value:.4f}'

    lines = [
        f"# Isolation Forest evaluation: {report['dataset']}",
        '',
        f"Generated {report['created_at']} by `scripts/evaluate_datasets.py`.",
        '',
        '## Data',
        '| Split | File | SHA-256 |', '|---|---|---|',
    ]
    for split in ('train', 'test'):
        for item in report['files'][split]:
            lines.append(f"| {split} | {item['name']} | `{item['sha256'][:16]}...` |")
    lines += ['', '## Cleaning', '| Step | Count |', '|---|---|']
    lines += [f'| {key} | {value} |' for key, value in report['cleaning'].items()]
    lines += ['', '## Protocol']
    lines += [f'- **{key}:** {value}' for key, value in report['protocol'].items()]
    lines += [f"- **features:** {len(report['features'])}", f"- **threshold:** {report['threshold']:.6f}", '',
              '## Results', '| Metric | Validation | Test |', '|---|---|---|']
    for key in ('precision', 'recall', 'f1', 'false_positive_rate', 'roc_auc', 'average_precision'):
        lines.append(f'| {key} | {fmt(val[key])} | {fmt(test[key])} |')
    cm = test['confusion_matrix']
    lines += ['', f"Test confusion matrix: TN={cm['tn']} FP={cm['fp']} FN={cm['fn']} TP={cm['tp']}", '',
              '## Test flagged rate by category', '| Category | Rows | Flagged |', '|---|---|---|']
    for name, item in report['test_flagged_rate_by_category'].items():
        lines.append(f"| {name} | {item['rows']} | {item['flagged_rate']:.2%} |")
    lines += ['', '## Limitations'] + [f'- {item}' for item in report['limitations']]
    return '\n'.join(lines) + '\n'


def save_report(report: Dict[str, object], out_dir: str, save_model: bool = False) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    base = os.path.join(out_dir, f"model_evaluation_{report['dataset']}_{stamp}")
    public = {key: value for key, value in report.items() if not key.startswith('_')}
    paths = {'json': base + '.json', 'markdown': base + '.md'}
    with open(paths['json'], 'w', encoding='utf-8') as handle:
        json.dump(public, handle, indent=2)
    with open(paths['markdown'], 'w', encoding='utf-8') as handle:
        handle.write(to_markdown(public))
    if save_model:
        import joblib
        paths['model'] = base + '.joblib'
        joblib.dump({**report['_artifacts'], 'features': report['features'], 'threshold': report['threshold'],
                     'dataset': report['dataset']}, paths['model'])
    return paths
