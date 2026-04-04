# ML Pipeline

The `ml_training/` directory contains an offline training pipeline that produces the Random Forest, Isolation Forest, and XGBoost models consumed by `firewall-engine/ai_detection.py`.

---

## Dataset Formats

The pipeline supports three public intrusion-detection datasets. Download them separately and place them in a `data/` directory (not committed to the repository).

### CICIDS2017

```
data/cicids2017/
  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  ... (8 CSV files total)
```

Source: https://www.unb.ca/cic/datasets/ids-2017.html

### NSL-KDD

```
data/nsl-kdd/
  KDDTrain+.txt
  KDDTest+.txt
```

Source: https://www.unb.ca/cic/datasets/nsl.html

### UNSW-NB15

```
data/unsw-nb15/
  UNSW-NB15_1.csv
  UNSW-NB15_2.csv
  UNSW-NB15_3.csv
  UNSW-NB15_4.csv
```

Source: https://research.unsw.edu.au/projects/unsw-nb15-dataset

### Synthetic data (no download required)

For development without real datasets, the synthetic generator produces labeled flows:

```bash
python ml_training/utils/data_generator.py --rows 50000 --output data/synthetic.csv
```

---

## Training Commands

### 1. Activate the virtual environment

```bash
source .venv/bin/activate   # or: python -m venv .venv && source .venv/bin/activate
pip install -r ml_training/requirements.txt
```

### 2. Preprocess

```bash
python ml_training/preprocessing.py \
  --dataset cicids2017 \
  --input data/cicids2017/ \
  --output data/processed/cicids2017_processed.csv
```

### 3. Feature selection

```bash
python ml_training/feature_selection.py \
  --input data/processed/cicids2017_processed.csv \
  --output data/processed/cicids2017_features.csv \
  --k 20
```

### 4. Train

```bash
python ml_training/train.py \
  --input data/processed/cicids2017_features.csv \
  --output ml_training/models/ \
  --cv 5
```

This saves three files:

```
ml_training/models/
  random_forest.joblib
  isolation_forest.joblib
  xgboost_model.joblib
```

### 5. Evaluate

```bash
python ml_training/evaluation.py \
  --models ml_training/models/ \
  --test   data/processed/cicids2017_features.csv
```

Outputs accuracy, precision, recall, F1, and ROC-AUC for each model.

---

## Retraining Guide

1. Collect new labeled traffic samples (PCAP → CSV using CICFlowMeter or a similar tool).
2. Run preprocessing and feature selection on the new data.
3. Train using `--retrain` flag to continue from existing models:
   ```bash
   python ml_training/train.py \
     --input data/new_data_features.csv \
     --output ml_training/models/ \
     --retrain
   ```
4. Run evaluation to compare new models against the old ones.
5. If metrics improve, copy models to `firewall-engine/models/` and restart the engine.

> **Tip:** Store baseline evaluation metrics in `ml_training/baselines/` to track improvement over time.

---

## A/B Testing

`ml_training/evaluation.py` includes an A/B framework that compares two model directories on the same test set:

```bash
python ml_training/evaluation.py \
  --models      ml_training/models/ \
  --challenger  ml_training/models_challenger/ \
  --test        data/processed/cicids2017_features.csv \
  --ab
```

Output includes a side-by-side table and a statistical significance test (McNemar's test for classification).

---

## Feature Vector

The 20 features used for inference (after log1p normalization and z-score standardization):

| # | Feature | Description |
|---|---|---|
| 1 | `pkt_count_fwd` | Forward packet count |
| 2 | `pkt_count_bwd` | Backward packet count |
| 3 | `byte_count_fwd` | Forward byte total |
| 4 | `byte_count_bwd` | Backward byte total |
| 5 | `fwd_bwd_ratio` | Forward/backward byte ratio |
| 6 | `duration_ms` | Flow duration (ms) |
| 7 | `pkt_rate` | Packets per second |
| 8 | `byte_rate` | Bytes per second |
| 9 | `iat_mean` | Mean inter-arrival time |
| 10 | `iat_std` | Std dev inter-arrival time |
| 11 | `iat_min` | Min inter-arrival time |
| 12 | `iat_max` | Max inter-arrival time |
| 13 | `pkt_size_mean` | Mean packet size |
| 14 | `pkt_size_std` | Std dev packet size |
| 15 | `pkt_size_min` | Min packet size |
| 16 | `pkt_size_max` | Max packet size |
| 17 | `tcp_syn_count` | TCP SYN flag count |
| 18 | `tcp_fin_count` | TCP FIN flag count |
| 19 | `tcp_rst_count` | TCP RST flag count |
| 20 | `tcp_urg_count` | TCP URG flag count |
