"""
ML Training Pipeline – Data Preprocessing.

Supports three well-known network intrusion datasets:

* **CICIDS2017** – Canadian Institute for Cybersecurity IDS 2017
* **NSL-KDD**   – Improved version of the KDD Cup 1999 dataset
* **UNSW-NB15** – UNSW Network-Based dataset 2015

Workflow
--------
1. :func:`load_dataset` – detect format and load raw CSV(s) into a DataFrame.
2. :func:`clean_data` – remove NaNs, infinities, and exact duplicates.
3. :func:`encode_labels` – map attack-type strings to integer class IDs.
4. :func:`split_data` – stratified train / validation / test split.
5. :func:`fit_scaler` – fit a :class:`~sklearn.preprocessing.StandardScaler`
   on training features and transform all splits.
6. :func:`save_preprocessed` – persist every split and the scaler to disk.

All steps are also wrapped in the high-level :func:`run_preprocessing`
pipeline function.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataset column definitions
# ---------------------------------------------------------------------------

# CICIDS2017 – columns present in the CSV export.
_CICIDS_LABEL_COL = " Label"

# NSL-KDD – positional columns (no header in the original file).
_NSLKDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]
_NSLKDD_LABEL_COL = "label"

# UNSW-NB15
_UNSW_LABEL_COL = "label"
_UNSW_ATTACK_CAT_COL = "attack_cat"

# Columns to always drop (metadata / identifiers).
_DROP_COLS_CICIDS = [" Flow ID", " Source IP", " Destination IP", " Timestamp"]
_DROP_COLS_UNSW = ["id", "attack_cat"]


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def _detect_format(path: Path) -> str:
    """Heuristically detect the dataset format from column names."""
    sample = pd.read_csv(path, nrows=1)
    cols = set(sample.columns)
    if _CICIDS_LABEL_COL in cols or "Label" in cols:
        return "cicids2017"
    if "label" in cols and "difficulty" in cols:
        return "nslkdd"
    if "attack_cat" in cols:
        return "unswnb15"
    raise ValueError(f"Could not detect dataset format in {path}")


def load_dataset(path: str | Path, fmt: str | None = None) -> pd.DataFrame:
    """
    Load a network intrusion dataset into a :class:`~pandas.DataFrame`.

    Parameters
    ----------
    path:
        Path to a CSV file *or* a directory containing multiple CSV files
        (they will be concatenated).
    fmt:
        Dataset format override: ``"cicids2017"``, ``"nslkdd"``,
        or ``"unswnb15"``.  Auto-detected when *None*.

    Returns
    -------
    DataFrame with a normalised ``label`` column and numeric features.
    """
    path = Path(path)
    if path.is_dir():
        csvs = sorted(path.glob("*.csv"))
        if not csvs:
            raise FileNotFoundError(f"No CSV files found in {path}")
        logger.info("Loading %d CSV(s) from %s", len(csvs), path)
        frames = [_load_single_csv(p, fmt) for p in csvs]
        df = pd.concat(frames, ignore_index=True)
    else:
        df = _load_single_csv(path, fmt)

    logger.info("Loaded dataset: %d rows × %d columns", *df.shape)
    return df


def _load_single_csv(path: Path, fmt: str | None) -> pd.DataFrame:
    detected = fmt or _detect_format(path)
    logger.debug("Loading %s as format=%s", path.name, detected)

    if detected == "cicids2017":
        df = pd.read_csv(path, low_memory=False)
        # Normalise label column
        if _CICIDS_LABEL_COL in df.columns:
            df = df.rename(columns={_CICIDS_LABEL_COL: "label"})
        elif "Label" in df.columns:
            df = df.rename(columns={"Label": "label"})
        # Drop metadata
        df = df.drop(columns=[c for c in _DROP_COLS_CICIDS if c in df.columns])

    elif detected == "nslkdd":
        df = pd.read_csv(path, header=None, names=_NSLKDD_COLUMNS)
        df = df.drop(columns=["difficulty"], errors="ignore")
        # Encode categorical protocol/service/flag
        for col in ("protocol_type", "service", "flag"):
            if col in df.columns:
                df[col] = LabelEncoder().fit_transform(df[col].astype(str))

    elif detected == "unswnb15":
        df = pd.read_csv(path, low_memory=False)
        df = df.drop(columns=[c for c in _DROP_COLS_UNSW if c in df.columns])

    else:
        raise ValueError(f"Unknown dataset format: {detected}")

    return df


# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean raw dataset:

    * Replace ``inf`` / ``-inf`` with ``NaN``.
    * Drop rows with any ``NaN``.
    * Drop exact duplicate rows.
    * Coerce all non-label columns to ``float32``.

    Returns
    -------
    Cleaned DataFrame (new object).
    """
    original_len = len(df)
    df = df.copy()

    # Replace infinities
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop NaN rows
    df.dropna(inplace=True)
    after_nan = len(df)

    # Drop duplicates
    df.drop_duplicates(inplace=True)
    after_dup = len(df)

    logger.info(
        "Cleaning: %d → %d (dropped %d NaN rows, %d duplicates)",
        original_len, after_dup,
        original_len - after_nan,
        after_nan - after_dup,
    )

    # Coerce feature columns to float32
    label_col = "label"
    feat_cols = [c for c in df.columns if c != label_col]
    df[feat_cols] = df[feat_cols].apply(pd.to_numeric, errors="coerce").astype("float32")
    df.dropna(subset=feat_cols, inplace=True)

    return df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Label encoding
# ---------------------------------------------------------------------------

def encode_labels(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, LabelEncoder, dict[int, str]]:
    """
    Encode the ``label`` column as integers.

    Parameters
    ----------
    df:
        DataFrame with a ``label`` column containing attack-type strings.

    Returns
    -------
    (df_encoded, encoder, class_map)
        * ``df_encoded``  – DataFrame with ``label`` replaced by integer codes.
        * ``encoder``     – Fitted :class:`~sklearn.preprocessing.LabelEncoder`.
        * ``class_map``   – ``{int_code: original_string}`` mapping.
    """
    le = LabelEncoder()
    df = df.copy()
    df["label"] = le.fit_transform(df["label"].astype(str))
    class_map: dict[int, str] = {i: cls for i, cls in enumerate(le.classes_)}
    logger.info(
        "Encoded %d classes: %s",
        len(class_map),
        list(le.classes_),
    )
    return df, le, class_map


# ---------------------------------------------------------------------------
# Train / validation / test split
# ---------------------------------------------------------------------------

def split_data(
    df: pd.DataFrame,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
) -> tuple[
    pd.DataFrame, pd.DataFrame, pd.DataFrame,
    pd.Series, pd.Series, pd.Series,
]:
    """
    Stratified split into train / validation / test sets.

    Returns
    -------
    ``(X_train, X_val, X_test, y_train, y_val, y_test)``
    """
    X = df.drop(columns=["label"])
    y = df["label"]

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y,
        test_size=test_size + val_size,
        random_state=random_state,
        stratify=y,
    )
    relative_val = val_size / (test_size + val_size)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=1.0 - relative_val,
        random_state=random_state,
        stratify=y_temp,
    )

    logger.info(
        "Split: train=%d  val=%d  test=%d",
        len(X_train), len(X_val), len(X_test),
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


# ---------------------------------------------------------------------------
# Scaling
# ---------------------------------------------------------------------------

def fit_scaler(
    X_train: pd.DataFrame,
    X_val: pd.DataFrame,
    X_test: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, StandardScaler]:
    """
    Fit a :class:`~sklearn.preprocessing.StandardScaler` on *X_train* and
    transform all three splits.

    Returns
    -------
    ``(X_train_scaled, X_val_scaled, X_test_scaled, scaler)``
    """
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)
    logger.info("Scaler fitted on %d training samples", len(X_train))
    return X_train_s, X_val_s, X_test_s, scaler


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_preprocessed(
    output_dir: str | Path,
    X_train: np.ndarray,
    X_val: np.ndarray,
    X_test: np.ndarray,
    y_train: pd.Series | np.ndarray,
    y_val: pd.Series | np.ndarray,
    y_test: pd.Series | np.ndarray,
    scaler: StandardScaler,
    feature_names: list[str],
    class_map: dict[int, str],
) -> None:
    """
    Persist all preprocessed artefacts to *output_dir*.

    Written files
    -------------
    ``X_train.npy``, ``X_val.npy``, ``X_test.npy`` – feature arrays.
    ``y_train.npy``, ``y_val.npy``, ``y_test.npy`` – label arrays.
    ``scaler.joblib`` – fitted StandardScaler.
    ``feature_names.json`` – ordered list of feature column names.
    ``class_map.json`` – ``{int: class_name}`` mapping.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    np.save(out / "X_train.npy", X_train)
    np.save(out / "X_val.npy", X_val)
    np.save(out / "X_test.npy", X_test)
    np.save(out / "y_train.npy", np.asarray(y_train))
    np.save(out / "y_val.npy", np.asarray(y_val))
    np.save(out / "y_test.npy", np.asarray(y_test))
    joblib.dump(scaler, out / "scaler.joblib")

    with (out / "feature_names.json").open("w") as fh:
        json.dump(feature_names, fh, indent=2)

    # Ensure class_map keys are strings for JSON serialisation.
    str_class_map = {str(k): v for k, v in class_map.items()}
    with (out / "class_map.json").open("w") as fh:
        json.dump(str_class_map, fh, indent=2)

    logger.info("Preprocessed artefacts saved to %s", out)


# ---------------------------------------------------------------------------
# High-level pipeline
# ---------------------------------------------------------------------------

def run_preprocessing(
    dataset_path: str | Path,
    output_dir: str | Path = "ml_training/data/preprocessed",
    fmt: str | None = None,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
) -> dict[str, Any]:
    """
    Execute the full preprocessing pipeline in one call.

    Returns
    -------
    Dict with keys ``X_train``, ``X_val``, ``X_test``, ``y_train``,
    ``y_val``, ``y_test``, ``scaler``, ``feature_names``, ``class_map``,
    ``label_encoder``.
    """
    logger.info("Starting preprocessing pipeline for: %s", dataset_path)

    df = load_dataset(dataset_path, fmt=fmt)
    df = clean_data(df)
    df, le, class_map = encode_labels(df)

    X_train_df, X_val_df, X_test_df, y_train, y_val, y_test = split_data(
        df, test_size=test_size, val_size=val_size, random_state=random_state
    )
    feature_names = list(X_train_df.columns)

    X_train, X_val, X_test, scaler = fit_scaler(X_train_df, X_val_df, X_test_df)

    save_preprocessed(
        output_dir,
        X_train, X_val, X_test,
        y_train, y_val, y_test,
        scaler, feature_names, class_map,
    )

    logger.info("Preprocessing complete.")
    return {
        "X_train": X_train, "X_val": X_val, "X_test": X_test,
        "y_train": y_train, "y_val": y_val, "y_test": y_test,
        "scaler": scaler, "feature_names": feature_names,
        "class_map": class_map, "label_encoder": le,
    }
