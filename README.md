# AI Firewall

[![CI](https://github.com/saurabhtiwari12/ai-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/saurabhtiwari12/ai-firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Node 20+](https://img.shields.io/badge/node-20%2B-green.svg)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

An enterprise-grade, AI-driven next-generation firewall with zero-trust architecture. It captures network packets in real time, extracts flow features, runs an ML ensemble (Random Forest + Isolation Forest + XGBoost) to score threats, and enforces block/allow decisions via iptables/nftables — all exposed through a React SOC dashboard.

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Components](#components)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [Contributing](#contributing)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Network Traffic                              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ raw packets
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Firewall Engine  (Python)                         │
│                                                                      │
│  packet_capture ──► flow_aggregation ──► feature_engineering        │
│                                                  │                   │
│                            ┌─────────────────────┘                  │
│                            ▼                                         │
│                      ai_detection  ◄── ML models (pkl/joblib)       │
│                            │                                         │
│                    behavioral_analysis                               │
│                            │                                         │
│                      threat_scoring                                  │
│                            │                                         │
│               zero_trust_policy ──► firewall_enforcement            │
│                            │         (iptables / nftables / netsh)  │
└────────────────────────────┼─────────────────────────────────────────┘
                             │ HTTP POST /api/events
                             ▼
┌────────────────────────────────────────────────────────────────────┐
│                   Backend API  (Node.js / Express)                 │
│                                                                    │
│  JWT Auth ─── RBAC ─── REST routes ─── Socket.io push             │
│                              │                                     │
│                           MongoDB                                  │
└──────────────────────────────┬─────────────────────────────────────┘
                               │ WebSocket / REST
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│              Frontend SOC Dashboard  (React 18)                    │
│                                                                    │
│  Dashboard ── Events ── Alerts ── Analytics ── Attack Map         │
└────────────────────────────────────────────────────────────────────┘

Monitoring: Prometheus ──► Grafana
```

---

## Features

| Category | Capability |
|---|---|
| **Packet Capture** | Scapy-based IPv4/IPv6 live capture; mock fallback for dev |
| **Flow Analysis** | 5-tuple session tracking, IAT, flags, fwd/bwd byte ratio |
| **AI Detection** | Random Forest + Isolation Forest + XGBoost ensemble |
| **Behavioral Analysis** | Port scan, DDoS, data exfiltration, beaconing detection |
| **Threat Scoring** | Weighted composite → Safe / Suspicious / High Risk / Critical |
| **Zero-Trust Policy** | Priority rule engine, whitelist/blacklist with TTL, token-bucket rate limiting |
| **Enforcement** | Auto-detects iptables / nftables / netsh; dry-run mode default |
| **Threat Intelligence** | AbuseIPDB, Spamhaus ZEN, Emerging Threats feeds with TTL cache |
| **REST API** | JWT auth, RBAC (viewer/analyst/admin), rate limiting, audit log |
| **Real-time Push** | Socket.io events to dashboard on ingest/resolve |
| **SOC Dashboard** | Dark-theme React UI: map, charts, events table, CSV export |
| **ML Pipeline** | CICIDS2017/NSL-KDD/UNSW-NB15 loaders, GridSearchCV, A/B eval |

---

## Quick Start

**Prerequisites:** Docker 24+ and Docker Compose v2.

```bash
# 1. Clone and configure
git clone https://github.com/saurabhtiwari12/ai-firewall.git
cd ai-firewall
cp .env.example .env          # edit JWT_SECRET and API keys

# 2. Start all services
docker compose up -d

# 3. Open the dashboard
open http://localhost:3000
```

> The stack starts 7 containers: firewall engine, backend API, React frontend (nginx),
> MongoDB, Redis, Prometheus, and Grafana (http://localhost:3003).

For manual installation without Docker see [docs/INSTALLATION.md](docs/INSTALLATION.md).

---

## Components

### `firewall-engine/` — Python threat detection engine
Real-time packet capture → flow aggregation → ML inference → policy enforcement.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

### `backend-api/` — Node.js REST API
Express + MongoDB + Socket.io. Handles auth, event storage, analytics, and alert management.
Full endpoint reference in [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md).

### `frontend-dashboard/` — React SOC dashboard
Dark cybersecurity theme. World attack map (Leaflet), traffic charts (Chart.js), real-time events table.

### `ml_training/` — ML training pipeline
Offline training with CICIDS2017/NSL-KDD/UNSW-NB15 datasets, feature selection, and A/B evaluation.
See [docs/ML_PIPELINE.md](docs/ML_PIPELINE.md).

### `threat_intelligence/` — Feed manager
Pulls AbuseIPDB, Spamhaus, and Emerging Threats; caches results with TTL.

### `kubernetes/` — K8s manifests
Deployments, StatefulSet (MongoDB), Services, and TLS Ingress.
See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

### `terraform/aws/` — AWS infrastructure
VPC (public/private subnets + NAT), EKS cluster, IAM roles.

---

## Environment Variables

Copy `.env.example` to `.env` and set the values below.

| Variable | Default | Description |
|---|---|---|
| `MONGO_URI` | `mongodb://localhost:27017/ai-firewall` | MongoDB connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `JWT_SECRET` | — | **Required.** ≥ 32 char random string |
| `JWT_REFRESH_SECRET` | — | **Required.** ≥ 32 char random string |
| `JWT_EXPIRES_IN` | `15m` | Access token lifetime |
| `JWT_REFRESH_EXPIRES_IN` | `7d` | Refresh token lifetime |
| `PORT` | `3001` | Backend API port |
| `NODE_ENV` | `development` | `development` / `production` |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB API key |
| `FW_DRY_RUN` | `true` | Set `false` to enable live enforcement |
| `FW_INTERFACE` | `eth0` | Network interface to capture |
| `FW_CAPTURE_FILTER` | `tcp or udp` | BPF filter string |
| `ML_CONFIDENCE_THRESHOLD` | `0.7` | Minimum ML confidence to act on |
| `PROMETHEUS_PORT` | `9090` | Prometheus scrape port |
| `GRAFANA_PORT` | `3003` | Grafana dashboard port |

---

## API Reference

All endpoints (except `/api/system/health`) require `Authorization: Bearer <token>`.

### Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | — | Create user account |
| POST | `/api/auth/login` | — | Get access + refresh tokens |
| POST | `/api/auth/refresh` | — | Rotate refresh token |
| GET | `/api/auth/me` | ✓ | Current user profile |

### Events

| Method | Path | Min Role | Description |
|---|---|---|---|
| GET | `/api/events` | viewer | List events (paginated) |
| POST | `/api/events` | analyst | Ingest new event |
| GET | `/api/events/:id` | viewer | Get single event |
| PUT | `/api/events/:id/resolve` | analyst | Resolve event |
| DELETE | `/api/events/:id` | admin | Delete event |
| GET | `/api/events/stats/summary` | viewer | Event statistics |

### Alerts

| Method | Path | Min Role | Description |
|---|---|---|---|
| GET | `/api/alerts` | viewer | List alerts |
| POST | `/api/alerts` | analyst | Create alert |
| PUT | `/api/alerts/:id` | analyst | Update alert status |
| DELETE | `/api/alerts/:id` | admin | Delete alert |

### Analytics

| Method | Path | Description |
|---|---|---|
| GET | `/api/analytics/traffic` | Traffic time series |
| GET | `/api/analytics/threats` | Threat distribution |
| GET | `/api/analytics/top-attackers` | Top source IPs |
| GET | `/api/analytics/attack-types` | Attack type breakdown |
| GET | `/api/analytics/hourly` | Hourly breakdown |

### System

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/system/health` | — | Health check |
| GET | `/api/system/status` | ✓ | Runtime status |
| GET | `/api/system/metrics` | admin | Prometheus metrics |

Full curl examples in [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md).

---

## Deployment

| Method | Guide |
|---|---|
| Docker Compose (local) | [docs/DEPLOYMENT.md#docker-compose](docs/DEPLOYMENT.md#docker-compose) |
| Kubernetes | [docs/DEPLOYMENT.md#kubernetes](docs/DEPLOYMENT.md#kubernetes) |
| AWS (Terraform + EKS) | [docs/DEPLOYMENT.md#aws-terraform](docs/DEPLOYMENT.md#aws-terraform) |

---

## Contributing

1. Fork the repository and create a feature branch (`git checkout -b feature/my-feature`)
2. Commit your changes following [Conventional Commits](https://www.conventionalcommits.org/)
3. Run `scripts/setup.sh` to ensure your environment is configured
4. Push and open a Pull Request against `main`
5. CI runs lint, unit tests, Docker builds, and a Trivy security scan automatically

Please read [docs/SECURITY.md](docs/SECURITY.md) before submitting security-related changes.

---

## License

This project is licensed under the MIT License.
