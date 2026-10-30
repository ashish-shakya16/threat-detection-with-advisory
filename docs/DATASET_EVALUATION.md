# Dataset Evaluation (CIC-IDS2017 and UNSW-NB15)

`scripts/evaluate_datasets.py` measures how well SecureX's Isolation Forest
separates attack traffic from benign traffic on two public intrusion-detection
datasets. It writes a JSON and Markdown report to `data/reports/`.

The datasets are **not included** in this repository (size and licence). No
evaluation results exist until you download them and run the script.

## What this does and does not measure

It does measure offline anomaly detection on *flow features* (CICFlowMeter
features for CIC-IDS2017, Argus/Bro features for UNSW-NB15).

It does **not** measure SecureX's live monitoring. The live monitor collects
process and connection telemetry with psutil, not these flow statistics, so
these numbers must not be reported as live detection accuracy.

## 1. Get the data

| Dataset | Source | Files to use |
|---|---|---|
| CIC-IDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html (registration form) | `MachineLearningCSV.zip` → the eight `*.pcap_ISCX.csv` files |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv` (official partition) |

Put the CSVs in `data/datasets/`. That folder is git-ignored apart from `.gitkeep`.

## 2. Run

```bash
pip install -r requirements.txt

# UNSW-NB15: official train/test partition
python scripts/evaluate_datasets.py --dataset unsw-nb15 \
    --train data/datasets/UNSW_NB15_training-set.csv \
    --test  data/datasets/UNSW_NB15_testing-set.csv

# CIC-IDS2017: train on Monday-Wednesday, test on Thursday-Friday
python scripts/evaluate_datasets.py --dataset cicids2017 \
    --train "data/datasets/Monday-*.csv" "data/datasets/Tuesday-*.csv" "data/datasets/Wednesday-*.csv" \
    --test  "data/datasets/Thursday-*.csv" "data/datasets/Friday-*.csv" \
    --max-rows 500000
```

Options: `--target-fpr` (default 0.01), `--max-rows` (random sample per split, for
memory), `--seed`, `--out`, and `--save-model` (writes a `.joblib` with the model,
scaler, feature list and threshold).

## 3. Protocol

These choices address the evaluation-validity problems reported for these
datasets (random splits across correlated flows, duplicates, identifier
shortcuts, test-set threshold tuning):

1. **Separate files for train and test.** CIC-IDS2017 is split by capture day,
   so Thursday and Friday attacks (web attacks, infiltration, botnet, port scan,
   DDoS) are not seen during training. UNSW-NB15 uses its official partition.
   The script refuses to use the same file for both.
2. **Cleaning.** Rows with NaN or infinite values are dropped. Exact duplicate
   rows are dropped within each split. Test rows identical to a training row
   (features and label) are removed. The report gives every count.
3. **No identifiers or shortcuts.** Flow ID, IP addresses, ports and timestamps
   are removed. So is the duplicated `Fwd Header Length.1` column in CIC-IDS2017.
   Constant columns are dropped. UNSW-NB15 `proto`, `service` and `state` are
   one-hot encoded using categories seen in training only.
4. **Benign-only training.** The scaler and Isolation Forest are fitted on the
   benign rows of the training split (80%).
5. **Threshold from validation.** The decision threshold is the (1 − target FPR)
   quantile of anomaly scores on benign rows of a stratified 20% validation split
   of the training files. The test set is only scored once, for the report.
6. **Metrics.** Precision, recall, F1, false-positive rate, ROC-AUC, average
   precision, the confusion matrix, and the flagged rate per attack category, for
   both validation and test. Input files are identified by SHA-256.

## 4. Known limitations

- CIC-IDS2017 has documented labelling and flow-construction errors (Engelen,
  Rimmer and Joosen, "Troubleshooting an Intrusion Detection Dataset: the
  CICIDS2017 Case Study", IEEE Security and Privacy Workshops 2021). The script
  uses the original CSVs, so results inherit those errors. The corrected
  re-release from that work can be used instead if its columns match.
- Both datasets are lab captures from 2015-2017.
- Results on one dataset say nothing about the other; no cross-dataset test is run.
- `--max-rows` sampling changes the results. Report the value you used.
- Isolation Forest only flags deviations from benign traffic. It does not name attack types.
