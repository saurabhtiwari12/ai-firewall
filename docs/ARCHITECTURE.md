# Architecture

## Component Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          Network Traffic                                 │
│                    (raw packets on capture interface)                    │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │     packet_capture.py        │
                    │  Scapy / AsyncSniffer        │
                    │  IPv4 · IPv6 · BPF filter    │
                    └──────────────┬───────────────┘
                                   │  raw packet dict
                    ┌──────────────▼──────────────┐
                    │    flow_aggregation.py       │
                    │  5-tuple session tracker     │
                    │  IAT · flags · byte ratios   │
                    │  idle / active timeouts      │
                    └──────────────┬───────────────┘
                                   │  flow record (dict)
                    ┌──────────────▼──────────────┐
                    │  feature_engineering.py      │
                    │  20-dim log1p + z-score      │
                    │  normalization               │
                    └──────────────┬───────────────┘
                                   │  feature vector
          ┌────────────────────────▼──────────────────────────┐
          │                  ai_detection.py                  │
          │   Random Forest  +  Isolation Forest  +  XGBoost │
          │   ThreadPoolExecutor async inference              │
          │   mock fallback when models absent                │
          └────────────────────────┬──────────────────────────┘
                                   │  (ml_score, anomaly_score)
                    ┌──────────────▼──────────────┐
                    │  behavioral_analysis.py      │
                    │  Port scan · Rate burst      │
                    │  Data exfil · Beaconing      │
                    │  DDoS per source IP          │
                    └──────────────┬───────────────┘
                                   │  behavioral flags
                    ┌──────────────▼──────────────┐
                    │    threat_scoring.py         │
                    │  AI 50% / Anomaly 30%        │
                    │  Behavioral 20%              │
                    │  → Safe/Suspicious/          │
                    │    High Risk / Critical      │
                    └──────────────┬───────────────┘
                                   │  threat score + level
                    ┌──────────────▼──────────────┐
                    │  zero_trust_policy.py        │
                    │  Priority rule engine        │
                    │  Whitelist / Blacklist + TTL │
                    │  Token-bucket rate limiting  │
                    └──────────────┬───────────────┘
                                   │  BLOCK / ALLOW / RATE_LIMIT
     ┌─────────────────────────────┴──────────────────────────────┐
     │                                                            │
     ▼                                                            ▼
┌────────────────────┐                              ┌────────────────────────┐
│ firewall_          │                              │  Backend API           │
│ enforcement.py     │                              │  (Node.js / Express)   │
│                    │                              │                        │
│ iptables / nftables│                              │  JWT · RBAC · MongoDB  │
│ netsh (Windows)    │                              │  Socket.io real-time   │
│ dry-run mode       │  POST /api/events ──────────►│  REST + WebSocket      │
└────────────────────┘                              └───────────┬────────────┘
                                                                │
                                                   ┌────────────▼────────────┐
                                                   │  Frontend Dashboard     │
                                                   │  (React 18)             │
                                                   │                         │
                                                   │  Attack Map (Leaflet)   │
                                                   │  Charts (Chart.js)      │
                                                   │  Events Table           │
                                                   └─────────────────────────┘

┌─────────────────────────────┐    ┌───────────────────────────────┐
│  ML Training Pipeline       │    │  Threat Intelligence          │
│  (offline / periodic)       │    │  (background daemon)          │
│                             │    │                               │
│  CICIDS2017 · NSL-KDD       │    │  AbuseIPDB · Spamhaus ZEN     │
│  UNSW-NB15 loaders          │    │  Emerging Threats             │
│  GridSearchCV tuning        │    │  File-based JSON cache + TTL  │
│  joblib serialization       │    │  Scheduled updater            │
└─────────────────────────────┘    └───────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  Monitoring                                                │
│  Prometheus (scrapes /api/system/metrics)  ──►  Grafana   │
└────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Capture** — `packet_capture.py` sniffs packets on the configured interface using a BPF filter. In development (`MOCK_CAPTURE=true`) it generates synthetic packets.
2. **Aggregation** — `flow_aggregation.py` groups packets into bidirectional flows identified by `(src_ip, dst_ip, src_port, dst_port, protocol)`. Flows expire after `FW_FLOW_IDLE_TIMEOUT` seconds of inactivity or `FW_FLOW_ACTIVE_TIMEOUT` seconds total.
3. **Feature engineering** — Each completed flow produces a 20-dimensional feature vector (packet counts, byte stats, inter-arrival times, TCP flags, fwd/bwd ratios) normalized with log1p and z-score.
4. **AI detection** — The ensemble inference runs in a `ThreadPoolExecutor` (non-blocking). When pre-trained models are absent a deterministic mock returns fixed scores for development.
5. **Behavioral analysis** — Maintains a per-source-IP sliding window to detect scanning, bursting, exfiltration, beaconing (CV > 0.2), and flood patterns.
6. **Threat scoring** — Weighted composite `(0.5 × ml + 0.3 × anomaly + 0.2 × behavioral)` yields a 0–1 score mapped to a threat level.
7. **Policy decision** — `zero_trust_policy.py` checks static rules, whitelist/blacklist, and rate-limit tokens. Returns `ALLOW`, `BLOCK`, or `RATE_LIMIT`.
8. **Enforcement** — `firewall_enforcement.py` translates decisions into OS firewall commands. `FW_DRY_RUN=true` (default) logs commands without executing them.
9. **Event ingestion** — Blocked/suspicious flows are `POST`-ed to `/api/events`, stored in MongoDB, and broadcast via Socket.io.

## Tech Stack

| Layer | Technology |
|---|---|
| Packet capture | Python 3.11 · Scapy 2.x |
| ML inference | scikit-learn · XGBoost · joblib |
| Threat intelligence | AbuseIPDB API · Spamhaus DNS BL · Emerging Threats |
| Backend API | Node.js 20 · Express 4 · Mongoose 8 · Socket.io 4 |
| Database | MongoDB 7 |
| Cache / Rate limit | Redis 7 |
| Frontend | React 18 · Chart.js 4 · Leaflet 1.x |
| Container runtime | Docker 24 · Docker Compose v2 |
| Orchestration | Kubernetes 1.29 |
| Cloud infra | AWS EKS · VPC (Terraform 1.x) |
| Monitoring | Prometheus · Grafana |
| CI/CD | GitHub Actions |
