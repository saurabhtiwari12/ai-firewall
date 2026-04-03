"""
Configuration management for the AI Firewall Engine.

Loads settings from environment variables with sensible defaults.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (ValueError, TypeError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (ValueError, TypeError):
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Base directory
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent.parent  # firewall-engine/


@dataclass
class CaptureSettings:
    """Network packet capture configuration."""

    interface: str = field(default_factory=lambda: _env("CAPTURE_INTERFACE", "eth0"))
    bpf_filter: str = field(default_factory=lambda: _env("CAPTURE_BPF_FILTER", ""))
    queue_maxsize: int = field(default_factory=lambda: _env_int("CAPTURE_QUEUE_MAXSIZE", 10_000))
    mock_mode: bool = field(default_factory=lambda: _env_bool("CAPTURE_MOCK_MODE", False))
    mock_pps: int = field(default_factory=lambda: _env_int("CAPTURE_MOCK_PPS", 50))


@dataclass
class FlowSettings:
    """Flow aggregation configuration."""

    idle_timeout_sec: int = field(default_factory=lambda: _env_int("FLOW_IDLE_TIMEOUT", 30))
    active_timeout_sec: int = field(default_factory=lambda: _env_int("FLOW_ACTIVE_TIMEOUT", 300))
    max_flows: int = field(default_factory=lambda: _env_int("FLOW_MAX_FLOWS", 100_000))
    export_queue_maxsize: int = field(
        default_factory=lambda: _env_int("FLOW_EXPORT_QUEUE_MAXSIZE", 5_000)
    )


@dataclass
class ModelSettings:
    """AI model paths and parameters."""

    models_dir: Path = field(
        default_factory=lambda: Path(_env("MODELS_DIR", str(_HERE / "models")))
    )
    random_forest_path: str = field(
        default_factory=lambda: _env("MODEL_RF_PATH", "random_forest.joblib")
    )
    isolation_forest_path: str = field(
        default_factory=lambda: _env("MODEL_IF_PATH", "isolation_forest.joblib")
    )
    xgboost_path: str = field(
        default_factory=lambda: _env("MODEL_XGB_PATH", "xgboost_model.joblib")
    )
    scaler_path: str = field(
        default_factory=lambda: _env("MODEL_SCALER_PATH", "scaler.joblib")
    )
    prediction_batch_size: int = field(
        default_factory=lambda: _env_int("MODEL_BATCH_SIZE", 64)
    )
    async_workers: int = field(
        default_factory=lambda: _env_int("MODEL_ASYNC_WORKERS", 2)
    )


@dataclass
class BehavioralSettings:
    """Behavioral analysis thresholds."""

    port_scan_threshold: int = field(
        default_factory=lambda: _env_int("BA_PORT_SCAN_THRESHOLD", 20)
    )
    port_scan_window_sec: int = field(
        default_factory=lambda: _env_int("BA_PORT_SCAN_WINDOW", 60)
    )
    conn_rate_threshold: int = field(
        default_factory=lambda: _env_int("BA_CONN_RATE_THRESHOLD", 100)
    )
    conn_rate_window_sec: int = field(
        default_factory=lambda: _env_int("BA_CONN_RATE_WINDOW", 10)
    )
    exfil_bytes_threshold: int = field(
        default_factory=lambda: _env_int("BA_EXFIL_BYTES_THRESHOLD", 10_000_000)
    )
    beacon_interval_sec: float = field(
        default_factory=lambda: _env_float("BA_BEACON_INTERVAL", 60.0)
    )
    beacon_jitter_tolerance: float = field(
        default_factory=lambda: _env_float("BA_BEACON_JITTER", 0.1)
    )
    ddos_src_threshold: int = field(
        default_factory=lambda: _env_int("BA_DDOS_SRC_THRESHOLD", 50)
    )
    ddos_window_sec: int = field(
        default_factory=lambda: _env_int("BA_DDOS_WINDOW", 10)
    )
    history_window_sec: int = field(
        default_factory=lambda: _env_int("BA_HISTORY_WINDOW", 300)
    )


@dataclass
class ThreatScoringSettings:
    """Threat scoring weights and thresholds."""

    ai_weight: float = field(default_factory=lambda: _env_float("TS_AI_WEIGHT", 0.50))
    anomaly_weight: float = field(default_factory=lambda: _env_float("TS_ANOMALY_WEIGHT", 0.30))
    behavioral_weight: float = field(
        default_factory=lambda: _env_float("TS_BEHAVIORAL_WEIGHT", 0.20)
    )
    safe_threshold: float = field(default_factory=lambda: _env_float("TS_SAFE_THRESHOLD", 0.30))
    suspicious_threshold: float = field(
        default_factory=lambda: _env_float("TS_SUSPICIOUS_THRESHOLD", 0.60)
    )
    high_risk_threshold: float = field(
        default_factory=lambda: _env_float("TS_HIGH_RISK_THRESHOLD", 0.80)
    )
    history_size: int = field(default_factory=lambda: _env_int("TS_HISTORY_SIZE", 1_000))


@dataclass
class ZeroTrustSettings:
    """Zero-trust policy engine configuration."""

    default_action: str = field(
        default_factory=lambda: _env("ZT_DEFAULT_ACTION", "monitor")
    )
    blacklist_ttl_sec: int = field(
        default_factory=lambda: _env_int("ZT_BLACKLIST_TTL", 3600)
    )
    rate_limit_rps: int = field(
        default_factory=lambda: _env_int("ZT_RATE_LIMIT_RPS", 100)
    )
    rate_limit_window_sec: int = field(
        default_factory=lambda: _env_int("ZT_RATE_LIMIT_WINDOW", 1)
    )
    audit_log_path: str = field(
        default_factory=lambda: _env("ZT_AUDIT_LOG_PATH", str(_HERE / "logs" / "audit.log"))
    )
    policy_file: str = field(
        default_factory=lambda: _env(
            "ZT_POLICY_FILE", str(_HERE / "config" / "policies.json")
        )
    )


@dataclass
class EnforcementSettings:
    """Firewall enforcement configuration."""

    dry_run: bool = field(default_factory=lambda: _env_bool("FW_DRY_RUN", True))
    sinkhole_ip: str = field(
        default_factory=lambda: _env("FW_SINKHOLE_IP", "100.64.0.1")
    )
    rule_cleanup_interval_sec: int = field(
        default_factory=lambda: _env_int("FW_RULE_CLEANUP_INTERVAL", 300)
    )
    backend: str = field(
        default_factory=lambda: _env("FW_BACKEND", "auto")
    )  # auto | iptables | nftables | netsh


@dataclass
class APISettings:
    """Backend API client configuration."""

    base_url: str = field(
        default_factory=lambda: _env("API_BASE_URL", "http://localhost:8000")
    )
    api_key: str = field(default_factory=lambda: _env("API_KEY", ""))
    timeout_sec: int = field(default_factory=lambda: _env_int("API_TIMEOUT", 10))
    retry_attempts: int = field(default_factory=lambda: _env_int("API_RETRY_ATTEMPTS", 3))
    retry_backoff_sec: float = field(
        default_factory=lambda: _env_float("API_RETRY_BACKOFF", 1.0)
    )
    events_endpoint: str = field(
        default_factory=lambda: _env("API_EVENTS_ENDPOINT", "/api/events/")
    )
    alerts_endpoint: str = field(
        default_factory=lambda: _env("API_ALERTS_ENDPOINT", "/api/alerts/")
    )


@dataclass
class LoggingSettings:
    """Logging configuration."""

    level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))
    format: str = field(
        default_factory=lambda: _env(
            "LOG_FORMAT",
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    )
    log_dir: Path = field(
        default_factory=lambda: Path(_env("LOG_DIR", str(_HERE / "logs")))
    )
    file_name: str = field(
        default_factory=lambda: _env("LOG_FILE", "firewall-engine.log")
    )
    max_bytes: int = field(default_factory=lambda: _env_int("LOG_MAX_BYTES", 10_485_760))
    backup_count: int = field(default_factory=lambda: _env_int("LOG_BACKUP_COUNT", 5))


@dataclass
class Settings:
    """Top-level application settings."""

    capture: CaptureSettings = field(default_factory=CaptureSettings)
    flow: FlowSettings = field(default_factory=FlowSettings)
    model: ModelSettings = field(default_factory=ModelSettings)
    behavioral: BehavioralSettings = field(default_factory=BehavioralSettings)
    threat: ThreatScoringSettings = field(default_factory=ThreatScoringSettings)
    zero_trust: ZeroTrustSettings = field(default_factory=ZeroTrustSettings)
    enforcement: EnforcementSettings = field(default_factory=EnforcementSettings)
    api: APISettings = field(default_factory=APISettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)

    def validate(self) -> None:
        """Run basic validation of settings values."""
        weights = (
            self.threat.ai_weight
            + self.threat.anomaly_weight
            + self.threat.behavioral_weight
        )
        if abs(weights - 1.0) > 1e-6:
            raise ValueError(
                f"Threat scoring weights must sum to 1.0, got {weights:.4f}"
            )

        if self.threat.safe_threshold >= self.threat.suspicious_threshold:
            raise ValueError("safe_threshold must be < suspicious_threshold")
        if self.threat.suspicious_threshold >= self.threat.high_risk_threshold:
            raise ValueError("suspicious_threshold must be < high_risk_threshold")

    def configure_logging(self) -> None:
        """Apply logging configuration to the root logger."""
        self.logging.log_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.logging.log_dir / self.logging.file_name

        handlers: list[logging.Handler] = [logging.StreamHandler()]
        try:
            from logging.handlers import RotatingFileHandler

            handlers.append(
                RotatingFileHandler(
                    log_file,
                    maxBytes=self.logging.max_bytes,
                    backupCount=self.logging.backup_count,
                    encoding="utf-8",
                )
            )
        except OSError as exc:
            print(f"[WARNING] Could not open log file {log_file}: {exc}")

        logging.basicConfig(
            level=getattr(logging, self.logging.level.upper(), logging.INFO),
            format=self.logging.format,
            handlers=handlers,
            force=True,
        )


def load_settings() -> Settings:
    """Create and validate a Settings instance from the environment."""
    settings = Settings()
    settings.validate()
    return settings


# Module-level singleton for convenience imports.
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Return the module-level settings singleton (lazy init)."""
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings
