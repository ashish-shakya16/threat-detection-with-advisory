"""Evaluate the SecureX Isolation Forest detector on CIC-IDS2017 or UNSW-NB15.

Examples (see docs/DATASET_EVALUATION.md for where to get the files):

  python scripts/evaluate_datasets.py --dataset unsw-nb15 \
      --train data/datasets/UNSW_NB15_training-set.csv \
      --test  data/datasets/UNSW_NB15_testing-set.csv

  python scripts/evaluate_datasets.py --dataset cicids2017 \
      --train data/datasets/Monday-WorkingHours.pcap_ISCX.csv data/datasets/Tuesday-WorkingHours.pcap_ISCX.csv \
              data/datasets/Wednesday-workingHours.pcap_ISCX.csv \
      --test  data/datasets/Thursday-*.csv data/datasets/Friday-*.csv
"""

import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ml_models.dataset_evaluation import evaluate, save_report  # noqa: E402


def expand(patterns):
    paths = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        if not matches:
            sys.exit(f'No file matches {pattern!r}')
        paths.extend(matches)
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dataset', required=True, choices=['cicids2017', 'unsw-nb15'])
    parser.add_argument('--train', nargs='+', required=True, help='training CSV file(s) or glob patterns')
    parser.add_argument('--test', nargs='+', required=True, help='test CSV file(s) or glob patterns')
    parser.add_argument('--target-fpr', type=float, default=0.01, help='false-positive rate used to pick the threshold')
    parser.add_argument('--max-rows', type=int, default=None, help='randomly sample at most this many rows per split')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--out', default='data/reports', help='directory for the JSON and Markdown report')
    parser.add_argument('--save-model', action='store_true', help='also save the fitted model with joblib')
    args = parser.parse_args()

    train, test = expand(args.train), expand(args.test)
    overlap = set(map(os.path.abspath, train)) & set(map(os.path.abspath, test))
    if overlap:
        sys.exit(f'The same file cannot be used for training and testing: {sorted(overlap)}')

    report = evaluate(args.dataset, train, test, args.target_fpr, args.max_rows, args.seed)
    paths = save_report(report, args.out, args.save_model)
    metrics = report['test_metrics']
    print(f"Test precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
          f"f1={metrics['f1']:.4f} fpr={metrics['false_positive_rate']:.4f} roc_auc={metrics['roc_auc']}")
    for kind, path in paths.items():
        print(f'{kind}: {path}')


if __name__ == '__main__':
    main()
