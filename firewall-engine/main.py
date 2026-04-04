"""
Main orchestration entry point for the AI Firewall Engine.

Pipeline
--------
  PacketCapture → FlowAggregator → FeatureEngineer
      → AIDetector + BehavioralAnalyzer
      → ThreatScorer → ZeroTrustPolicyEngine
      → FirewallEnforcer  +  BackendAPIClient

Threads
-------
  • capture-thread     – reads packets from the NIC (or mock)
  • flow-reaper        – expires idle/active flows
  • analysis-thread    – consumes exported flows, scores, and enforces
  • enforcement-cleanup – removes expired firewall rules
  • api-poster         – sends threat events to the backend REST API
  • signal handler     – SIGINT / SIGTERM → graceful shutdown
"""

from __future__ import annotations

import json
import logging
import os
import queue
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Ensure firewall-engine directory is on sys.path when run directly
# ---------------------------------------------------------------------------
_ENGINE_DIR = Path(__file__).resolve().parent
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

# ---------------------------------------------------------------------------
# Local imports (order matters – lower-level modules first)
# ---------------------------------------------------------------------------
from config.settings import get_settings, Settings
from packet_capture import PacketCapture, PacketInfo
from flow_aggregation import FlowAggregator, FlowRecord
from feature_engineering import FeatureEngineer
from ai_detection import AIDetector
from behavioral_analysis import BehavioralAnalyzer
from threat_scoring import ThreatScorer, ThreatScore, RiskLevel
from zero_trust_policy import ZeroTrustPolicyEngine, PolicyDecision, PolicyAction
from firewall_enforcement import FirewallEnforcer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Backend API client
# ---------------------------------------------------------------------------

class BackendAPIClient:
    """
    Simple REST client that POSTs threat events to the backend API.

    Retries with exponential back-off on transient errors.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        timeout_sec: int = 10,
        retry_attempts: int = 3,
        retry_backoff_sec: float = 1.0,
        events_endpoint: str = "/api/events/",
        alerts_endpoint: str = "/api/alerts/",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
        self.timeout = timeout_sec
        self.retry_attempts = retry_attempts
        self.retry_backoff = retry_backoff_sec
        self.events_url = self.base_url + events_endpoint
        self.alerts_url = self.base_url + alerts_endpoint

        self._event_queue: queue.Queue[dict] = queue.Queue(maxsize=2000)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._posted = 0
        self._errors = 0

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._post_loop, name="api-poster", daemon=True
        )
        self._thread.start()
        logger.info("BackendAPIClient started → %s", self.base_url)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("BackendAPIClient stopped (posted=%d errors=%d)", self._posted, self._errors)

    def submit_event(self, payload: dict) -> None:
        try:
            self._event_queue.put_nowait(payload)
        except queue.Full:
            logger.warning("API event queue full – dropping event for %s", payload.get("src_ip"))

    def _post_loop(self) -> None:
        while not self._stop.is_set():
            try:
                payload = self._event_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            self._post_with_retry(payload)

    def _post_with_retry(self, payload: dict) -> None:
        import requests  # local import to keep startup fast

        url = (
            self.alerts_url
            if payload.get("risk_level") in ("high_risk", "critical")
            else self.events_url
        )
        for attempt in range(1, self.retry_attempts + 1):
            try:
                resp = requests.post(
                    url,
                    data=json.dumps(payload),
                    headers=self.headers,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                self._posted += 1
                logger.debug("Posted event → %s (status=%d)", url, resp.status_code)
                return
            except Exception as exc:
                self._errors += 1
                wait = self.retry_backoff * (2 ** (attempt - 1))
                logger.warning(
                    "API post failed (attempt %d/%d): %s – retrying in %.1fs",
                    attempt,
                    self.retry_attempts,
                    exc,
                    wait,
                )
                if attempt < self.retry_attempts:
                    time.sleep(wait)


# ---------------------------------------------------------------------------
# Firewall Engine
# ---------------------------------------------------------------------------

class FirewallEngine:
    """
    Top-level orchestrator wiring together all pipeline components.

    Parameters
    ----------
    settings:
        Validated ``Settings`` instance.  If ``None``, loaded from env.
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._settings = settings or get_settings()
        cfg = self._settings

        # --- Packet capture -------------------------------------------------
        self.capture = PacketCapture(
            interface=cfg.capture.interface,
            bpf_filter=cfg.capture.bpf_filter,
            queue_maxsize=cfg.capture.queue_maxsize,
            mock_mode=cfg.capture.mock_mode,
            mock_pps=cfg.capture.mock_pps,
        )

        # --- Flow aggregation -----------------------------------------------
        self.aggregator = FlowAggregator(
            idle_timeout_sec=cfg.flow.idle_timeout_sec,
            active_timeout_sec=cfg.flow.active_timeout_sec,
            max_flows=cfg.flow.max_flows,
            export_queue_maxsize=cfg.flow.export_queue_maxsize,
        )

        # --- Feature engineering --------------------------------------------
        self.feature_eng = FeatureEngineer()
        scaler_path = cfg.model.models_dir / cfg.model.scaler_path
        if scaler_path.exists():
            self.feature_eng.load_scaler(scaler_path)

        # --- AI detection ---------------------------------------------------
        self.detector = AIDetector(
            models_dir=cfg.model.models_dir,
            rf_filename=cfg.model.random_forest_path,
            if_filename=cfg.model.isolation_forest_path,
            xgb_filename=cfg.model.xgboost_path,
            async_workers=cfg.model.async_workers,
        )

        # --- Behavioral analysis --------------------------------------------
        self.behavioral = BehavioralAnalyzer(
            port_scan_threshold=cfg.behavioral.port_scan_threshold,
            port_scan_window_sec=cfg.behavioral.port_scan_window_sec,
            conn_rate_threshold=cfg.behavioral.conn_rate_threshold,
            conn_rate_window_sec=cfg.behavioral.conn_rate_window_sec,
            exfil_bytes_threshold=cfg.behavioral.exfil_bytes_threshold,
            beacon_interval_sec=cfg.behavioral.beacon_interval_sec,
            beacon_jitter_tolerance=cfg.behavioral.beacon_jitter_tolerance,
            ddos_src_threshold=cfg.behavioral.ddos_src_threshold,
            ddos_window_sec=cfg.behavioral.ddos_window_sec,
            history_window_sec=cfg.behavioral.history_window_sec,
        )

        # --- Threat scoring -------------------------------------------------
        self.scorer = ThreatScorer(
            ai_weight=cfg.threat.ai_weight,
            anomaly_weight=cfg.threat.anomaly_weight,
            behavioral_weight=cfg.threat.behavioral_weight,
            safe_threshold=cfg.threat.safe_threshold,
            suspicious_threshold=cfg.threat.suspicious_threshold,
            high_risk_threshold=cfg.threat.high_risk_threshold,
            history_size=cfg.threat.history_size,
        )

        # --- Zero-trust policy ----------------------------------------------
        self.policy = ZeroTrustPolicyEngine(
            default_action=cfg.zero_trust.default_action,
            blacklist_ttl_sec=cfg.zero_trust.blacklist_ttl_sec,
            rate_limit_rps=cfg.zero_trust.rate_limit_rps,
            rate_limit_window_sec=cfg.zero_trust.rate_limit_window_sec,
            audit_log_path=cfg.zero_trust.audit_log_path,
            policy_file=cfg.zero_trust.policy_file if Path(cfg.zero_trust.policy_file).exists() else None,
        )

        # --- Firewall enforcement --------------------------------------------
        self.enforcer = FirewallEnforcer(
            dry_run=cfg.enforcement.dry_run,
            backend=cfg.enforcement.backend,
            sinkhole_ip=cfg.enforcement.sinkhole_ip,
            rule_cleanup_interval_sec=cfg.enforcement.rule_cleanup_interval_sec,
        )

        # --- Backend API client ---------------------------------------------
        self.api_client = BackendAPIClient(
            base_url=cfg.api.base_url,
            api_key=cfg.api.api_key,
            timeout_sec=cfg.api.timeout_sec,
            retry_attempts=cfg.api.retry_attempts,
            retry_backoff_sec=cfg.api.retry_backoff_sec,
            events_endpoint=cfg.api.events_endpoint,
            alerts_endpoint=cfg.api.alerts_endpoint,
        )

        # --- Internal state -------------------------------------------------
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._ingest_thread: Optional[threading.Thread] = None
        self._analysis_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start all pipeline components."""
        logger.info("=== AI Firewall Engine starting ===")

        # Pre-load models eagerly to avoid first-request latency
        self.detector.load_models()

        self.aggregator.start()
        self.enforcer.start()
        self.api_client.start()

        # Ingest thread: packet queue → flow aggregator
        t_ingest = threading.Thread(
            target=self._ingest_loop, name="ingest", daemon=True
        )
        t_ingest.start()
        self._threads.append(t_ingest)

        # Analysis thread: flow export queue → scoring → enforcement
        t_analysis = threading.Thread(
            target=self._analysis_loop, name="analysis", daemon=True
        )
        t_analysis.start()
        self._threads.append(t_analysis)

        # Start capture last (it starts feeding the pipeline)
        self.capture.start()

        logger.info("=== AI Firewall Engine running ===")

    def stop(self) -> None:
        """Gracefully stop all components."""
        logger.info("=== AI Firewall Engine shutting down ===")
        self._stop_event.set()

        self.capture.stop(timeout=5.0)
        self.aggregator.stop(timeout=5.0)

        for t in self._threads:
            t.join(timeout=5.0)

        self.enforcer.stop()
        self.api_client.stop()
        self.detector.shutdown()

        logger.info("=== AI Firewall Engine stopped ===")

    def run_forever(self) -> None:
        """Blocking main loop.  Returns when a stop signal is received."""
        self._register_signal_handlers()
        self.start()
        try:
            while not self._stop_event.is_set():
                self._log_stats()
                self._stop_event.wait(timeout=30.0)
        finally:
            self.stop()

    # ------------------------------------------------------------------
    # Internal pipeline loops
    # ------------------------------------------------------------------

    def _ingest_loop(self) -> None:
        """Pull packets from the capture queue and feed the flow aggregator."""
        logger.debug("Ingest loop started")
        while not self._stop_event.is_set():
            pkt = self.capture.get_packet(block=True, timeout=0.5)
            if pkt is None:
                continue
            try:
                self.aggregator.add_packet(pkt)
            except Exception as exc:
                logger.exception("Error ingesting packet: %s", exc)
        logger.debug("Ingest loop exited")

    def _analysis_loop(self) -> None:
        """
        Consume exported flows, run the full analysis pipeline, and enforce.
        """
        logger.debug("Analysis loop started")
        while not self._stop_event.is_set():
            try:
                flow: FlowRecord = self.aggregator.export_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                self._process_flow(flow)
            except Exception as exc:
                logger.exception("Error processing flow %s→%s: %s",
                                 flow.src_ip, flow.dst_ip, exc)
        logger.debug("Analysis loop exited")

    def _process_flow(self, flow: FlowRecord) -> None:
        """Full analysis pipeline for a single exported flow."""
        # 1. Feature extraction
        features = self.feature_eng.process(flow)

        # 2. AI detection (async – we still wait on the result here,
        #    but the Future allows batching in future optimisations)
        ai_future = self.detector.predict_async(features)

        # 3. Behavioral analysis (CPU-light, run on this thread)
        behavioral_result = self.behavioral.analyze(flow)

        # 4. Retrieve AI result (blocking – typically <1 ms)
        ai_result = ai_future.result(timeout=5.0)

        # 5. Composite threat score
        threat = self.scorer.score(
            ai_result=ai_result,
            behavioral_result=behavioral_result,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
        )

        # 6. Zero-trust policy decision
        decision = self.policy.evaluate(threat)

        # 7. Firewall enforcement
        self.enforcer.enforce(decision)

        # 8. Post to backend API (non-blocking)
        self._submit_event(threat, decision, flow)

    def _submit_event(
        self,
        threat: ThreatScore,
        decision: PolicyDecision,
        flow: FlowRecord,
    ) -> None:
        """Build the event payload and submit to the API queue."""
        payload = {
            **threat.to_dict(),
            "policy_action": decision.action.value,
            "policy_reason": decision.reason,
            "flow_duration": flow.duration,
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
        }
        self.api_client.submit_event(payload)

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _register_signal_handlers(self) -> None:
        def _handler(signum: int, _frame: object) -> None:
            logger.info("Received signal %d – initiating shutdown", signum)
            self._stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                pass  # Signal handling not supported on this thread

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def _log_stats(self) -> None:
        cap = self.capture.get_stats()
        agg = self.aggregator.get_stats()
        sco = self.scorer.get_statistics()
        logger.info(
            "Stats | capture: pps=%.1f drops=%d | flows: active=%d exported=%d | "
            "scoring: total=%d safe=%d suspicious=%d high_risk=%d critical=%d",
            cap.pps(),
            cap.packets_dropped,
            agg.active_flows,
            agg.total_flows_exported,
            sco["total_scored"],
            sco["by_risk"].get("safe", 0),
            sco["by_risk"].get("suspicious", 0),
            sco["by_risk"].get("high_risk", 0),
            sco["by_risk"].get("critical", 0),
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point; called when running ``python main.py``."""
    # Bootstrap configuration and logging before any other imports
    settings = get_settings()
    settings.configure_logging()

    logger.info("AI Firewall Engine starting up (PID=%d)", os.getpid())
    logger.info("Dry-run mode: %s", settings.enforcement.dry_run)
    logger.info("Capture interface: %s", settings.capture.interface)
    logger.info("Backend API: %s", settings.api.base_url)

    engine = FirewallEngine(settings=settings)
    engine.run_forever()


if __name__ == "__main__":
    main()
