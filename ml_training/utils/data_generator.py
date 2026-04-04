"""
Synthetic Network Traffic Data Generator.

Produces a labelled :class:`~pandas.DataFrame` that mimics the feature space
of the CICIDS2017 / UNSW-NB15 datasets.

Traffic classes
---------------
* **BENIGN**     – normal user sessions (web, SSH, DNS, …)
* **PORT_SCAN**  – Nmap-style TCP SYN scan
* **DDOS**       – volumetric flood (UDP/ICMP/SYN)
* **BOTNET**     – low-and-slow C2 beaconing
* **EXFILTRATION** – large-payload data exfiltration to rare destinations

Usage example::

    from ml_training.utils.data_generator import generate_dataset

    df = generate_dataset(n_samples=50_000, class_balance="realistic")
    df.to_csv("synthetic_traffic.csv", index=False)
"""

from __future__ import annotations

import logging
from typing import Literal

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature schema
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    # Flow-level timing
    "flow_duration",          # microseconds
    "flow_iat_mean",          # inter-arrival time mean (µs)
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    # Forward path
    "fwd_packet_len_mean",
    "fwd_packet_len_std",
    "fwd_packet_len_max",
    "fwd_packet_len_min",
    "fwd_packets_per_sec",
    "fwd_bytes_per_sec",
    "fwd_psh_flags",
    "fwd_urg_flags",
    # Backward path
    "bwd_packet_len_mean",
    "bwd_packet_len_std",
    "bwd_packet_len_max",
    "bwd_packet_len_min",
    "bwd_packets_per_sec",
    "bwd_bytes_per_sec",
    # Packet-level counts
    "total_fwd_packets",
    "total_bwd_packets",
    "total_length_fwd_packets",
    "total_length_bwd_packets",
    # TCP flags
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    # Windowing / protocol
    "init_win_bytes_fwd",
    "init_win_bytes_bwd",
    "protocol",               # 6=TCP, 17=UDP, 1=ICMP
    "dst_port",
    # Derived ratios
    "down_up_ratio",
    "avg_packet_size",
    "subflow_fwd_packets",
    "subflow_bwd_packets",
    "active_mean",
    "idle_mean",
]

CLASS_LABELS = ["BENIGN", "PORT_SCAN", "DDOS", "BOTNET", "EXFILTRATION"]
N_FEATURES = len(FEATURE_NAMES)


# ---------------------------------------------------------------------------
# Per-class distribution definitions
# ---------------------------------------------------------------------------

class _FeatureDist:
    """Holds (mean, std) for each feature for a single traffic class."""

    def __init__(self, overrides: dict[str, tuple[float, float]]) -> None:
        # Sensible defaults roughly matching BENIGN traffic.
        defaults: dict[str, tuple[float, float]] = {
            "flow_duration":           (5_000_000, 3_000_000),
            "flow_iat_mean":           (50_000, 30_000),
            "flow_iat_std":            (20_000, 10_000),
            "flow_iat_max":            (200_000, 100_000),
            "flow_iat_min":            (1_000, 500),
            "fwd_packet_len_mean":     (512, 200),
            "fwd_packet_len_std":      (100, 50),
            "fwd_packet_len_max":      (1460, 200),
            "fwd_packet_len_min":      (40, 20),
            "fwd_packets_per_sec":     (20, 10),
            "fwd_bytes_per_sec":       (10_000, 5_000),
            "fwd_psh_flags":           (3, 1),
            "fwd_urg_flags":           (0, 0.1),
            "bwd_packet_len_mean":     (400, 150),
            "bwd_packet_len_std":      (80, 40),
            "bwd_packet_len_max":      (1460, 200),
            "bwd_packet_len_min":      (40, 20),
            "bwd_packets_per_sec":     (15, 8),
            "bwd_bytes_per_sec":       (8_000, 4_000),
            "total_fwd_packets":       (30, 15),
            "total_bwd_packets":       (25, 12),
            "total_length_fwd_packets": (15_000, 7_000),
            "total_length_bwd_packets": (10_000, 5_000),
            "fin_flag_count":          (1, 0.5),
            "syn_flag_count":          (1, 0.5),
            "rst_flag_count":          (0, 0.3),
            "psh_flag_count":          (3, 1),
            "ack_flag_count":          (30, 15),
            "urg_flag_count":          (0, 0.05),
            "init_win_bytes_fwd":      (8192, 2000),
            "init_win_bytes_bwd":      (8192, 2000),
            "protocol":                (6, 0.1),
            "dst_port":                (443, 100),
            "down_up_ratio":           (1.2, 0.4),
            "avg_packet_size":         (450, 100),
            "subflow_fwd_packets":     (30, 15),
            "subflow_bwd_packets":     (25, 12),
            "active_mean":             (2_000_000, 500_000),
            "idle_mean":               (500_000, 200_000),
        }
        self.params: dict[str, tuple[float, float]] = {**defaults, **overrides}


_DISTRIBUTIONS: dict[str, _FeatureDist] = {
    "BENIGN": _FeatureDist({}),

    "PORT_SCAN": _FeatureDist({
        # Very short flows – single SYN or SYN-ACK
        "flow_duration":           (500, 200),
        "flow_iat_mean":           (200, 50),
        "fwd_packet_len_mean":     (44, 5),       # SYN packet
        "fwd_packets_per_sec":     (500, 100),
        "bwd_packet_len_mean":     (0, 10),        # No response (filtered)
        "bwd_packets_per_sec":     (0, 5),
        "total_fwd_packets":       (1, 0.2),
        "total_bwd_packets":       (0, 0.3),
        "syn_flag_count":          (1, 0.1),
        "ack_flag_count":          (0, 0.5),
        "fin_flag_count":          (0, 0.1),
        "dst_port":                (1024, 500),    # Random ports
        "down_up_ratio":           (0, 0.1),
        "protocol":                (6, 0.1),
    }),

    "DDOS": _FeatureDist({
        # High rate, small packets
        "flow_duration":           (60_000_000, 10_000_000),
        "fwd_packets_per_sec":     (10_000, 3_000),
        "fwd_bytes_per_sec":       (1_000_000, 300_000),
        "fwd_packet_len_mean":     (64, 20),
        "bwd_packet_len_mean":     (0, 10),
        "bwd_packets_per_sec":     (0, 50),
        "total_fwd_packets":       (600_000, 180_000),
        "total_bwd_packets":       (0, 100),
        "syn_flag_count":          (600_000, 180_000),
        "ack_flag_count":          (0, 100),
        "protocol":                (17, 1),        # UDP flood
        "dst_port":                (80, 5),
        "init_win_bytes_fwd":      (0, 10),
    }),

    "BOTNET": _FeatureDist({
        # Low-and-slow periodic beaconing
        "flow_duration":           (300_000_000, 50_000_000),
        "flow_iat_mean":           (60_000_000, 5_000_000),   # ~1 min between packets
        "flow_iat_std":            (500, 100),                 # Very regular
        "fwd_packets_per_sec":     (0.1, 0.05),
        "fwd_bytes_per_sec":       (50, 20),
        "fwd_packet_len_mean":     (200, 50),
        "total_fwd_packets":       (5, 2),
        "total_bwd_packets":       (3, 1),
        "dst_port":                (443, 10),
        "protocol":                (6, 0.1),
        "urg_flag_count":          (0, 0.01),
    }),

    "EXFILTRATION": _FeatureDist({
        # Large upload, unusual destination port
        "flow_duration":           (120_000_000, 20_000_000),
        "fwd_packet_len_mean":     (1400, 50),     # Near MTU
        "fwd_bytes_per_sec":       (800_000, 200_000),
        "fwd_packets_per_sec":     (600, 100),
        "bwd_packet_len_mean":     (80, 20),       # Small ACKs
        "bwd_packets_per_sec":     (600, 100),
        "total_fwd_packets":       (72_000, 24_000),
        "total_bwd_packets":       (72_000, 24_000),
        "total_length_fwd_packets": (100_800_000, 33_600_000),
        "dst_port":                (8443, 200),
        "down_up_ratio":           (0.05, 0.02),   # Very asymmetric
        "protocol":                (6, 0.1),
    }),
}


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def _sample_class(
    label: str,
    n: int,
    rng: np.random.Generator,
) -> pd.DataFrame:
    """Sample *n* synthetic rows for *label*."""
    dist = _DISTRIBUTIONS[label]
    rows: dict[str, np.ndarray] = {}
    for feat in FEATURE_NAMES:
        mean, std = dist.params[feat]
        samples = rng.normal(loc=mean, scale=max(std, 1e-9), size=n)
        # Clip to plausible non-negative range
        samples = np.clip(samples, 0, None)
        rows[feat] = samples.astype(np.float32)

    # Force protocol to nearest valid value
    proto = rows["protocol"]
    proto = np.where(proto < 3, 1, np.where(proto < 11, 6, 17)).astype(np.float32)
    rows["protocol"] = proto

    # Force dst_port to integer range [0, 65535]
    rows["dst_port"] = np.clip(rows["dst_port"].astype(np.int32), 0, 65535).astype(np.float32)

    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    df["label"] = label
    return df


_REALISTIC_RATIOS: dict[str, float] = {
    "BENIGN":       0.75,
    "PORT_SCAN":    0.08,
    "DDOS":         0.07,
    "BOTNET":       0.05,
    "EXFILTRATION": 0.05,
}

_BALANCED_RATIOS: dict[str, float] = {label: 1.0 / len(CLASS_LABELS) for label in CLASS_LABELS}


def generate_dataset(
    n_samples: int = 100_000,
    class_balance: Literal["realistic", "balanced"] | dict[str, float] = "realistic",
    random_state: int = 42,
    shuffle: bool = True,
) -> pd.DataFrame:
    """
    Generate a synthetic labelled network traffic dataset.

    Parameters
    ----------
    n_samples:
        Total number of flow records to generate.
    class_balance:
        ``"realistic"`` – skewed distribution matching real-world deployments.
        ``"balanced"``  – equal samples per class.
        ``dict``        – custom ``{label: fraction}`` mapping (must sum to ~1).
    random_state:
        NumPy random seed for reproducibility.
    shuffle:
        Whether to randomly shuffle the output DataFrame.

    Returns
    -------
    DataFrame with feature columns (from :data:`FEATURE_NAMES`) plus
    a ``label`` column containing one of the five class strings.
    """
    rng = np.random.default_rng(random_state)

    if isinstance(class_balance, dict):
        ratios = class_balance
    elif class_balance == "balanced":
        ratios = _BALANCED_RATIOS
    else:
        ratios = _REALISTIC_RATIOS

    # Normalise ratios
    total_weight = sum(ratios.values())
    ratios = {k: v / total_weight for k, v in ratios.items()}

    # Compute per-class counts (ensure they sum to n_samples)
    counts: dict[str, int] = {}
    remainder = n_samples
    labels = list(ratios.keys())
    for lbl in labels[:-1]:
        counts[lbl] = max(1, round(ratios[lbl] * n_samples))
        remainder -= counts[lbl]
    counts[labels[-1]] = max(1, remainder)

    logger.info(
        "Generating %d synthetic samples: %s",
        n_samples,
        {k: v for k, v in counts.items()},
    )

    frames: list[pd.DataFrame] = [
        _sample_class(lbl, n, rng)
        for lbl, n in counts.items()
    ]
    df = pd.concat(frames, ignore_index=True)

    if shuffle:
        df = df.sample(frac=1, random_state=random_state).reset_index(drop=True)

    logger.info(
        "Dataset generated: %d rows, label distribution:\n%s",
        len(df),
        df["label"].value_counts().to_string(),
    )
    return df


def generate_and_save(
    output_path: str,
    n_samples: int = 100_000,
    class_balance: Literal["realistic", "balanced"] | dict[str, float] = "realistic",
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Generate a synthetic dataset and save it to *output_path* as CSV.

    Returns
    -------
    The generated :class:`~pandas.DataFrame`.
    """
    df = generate_dataset(
        n_samples=n_samples,
        class_balance=class_balance,
        random_state=random_state,
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    logger.info("Saved synthetic dataset → %s", out)
    return df
