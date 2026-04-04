# Installation

## Prerequisites

| Tool | Minimum version | Install |
|---|---|---|
| Python | 3.11 | https://www.python.org/ |
| Node.js | 20 LTS | https://nodejs.org/ |
| Docker | 24 | https://docs.docker.com/engine/install/ |
| Docker Compose | v2 (plugin) | bundled with Docker Desktop |
| MongoDB | 7 (optional, for manual install) | https://www.mongodb.com/docs/manual/installation/ |
| Redis | 7 (optional, for manual install) | https://redis.io/docs/getting-started/ |

---

## Option A — Docker Compose (Recommended)

Docker Compose starts all 7 services automatically. No manual MongoDB or Redis installation required.

```bash
git clone https://github.com/saurabhtiwari12/ai-firewall.git
cd ai-firewall

# Copy environment template and fill in secrets
cp .env.example .env
# Edit .env: set JWT_SECRET, JWT_REFRESH_SECRET (each must be ≥ 32 characters)

# Start the full stack (detached)
docker compose up -d

# Verify all containers are running
docker compose ps

# Open the SOC dashboard
open http://localhost:3000
```

Services and their ports:

| Service | Port |
|---|---|
| Frontend dashboard | 3000 |
| Backend API | 3001 |
| MongoDB | 27017 |
| Redis | 6379 |
| Prometheus | 9090 |
| Grafana | 3003 |

---

## Option B — Automated Setup Script

The `scripts/setup.sh` script checks prerequisites, creates `.env`, builds the Python virtual environment, and installs Node dependencies in one step.

```bash
git clone https://github.com/saurabhtiwari12/ai-firewall.git
cd ai-firewall
chmod +x scripts/setup.sh
./scripts/setup.sh
```

After the script completes, edit `.env` then run `docker compose up -d`.

---

## Option C — Manual Installation

### 1. Clone the repository

```bash
git clone https://github.com/saurabhtiwari12/ai-firewall.git
cd ai-firewall
cp .env.example .env
```

### 2. Python components (firewall engine, ML pipeline, threat intel)

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r firewall-engine/requirements.txt
pip install -r ml_training/requirements.txt
pip install -r threat_intelligence/requirements.txt
pip install -r tests/requirements.txt
```

### 3. Backend API

```bash
cd backend-api
npm ci
cd ..
```

### 4. Frontend dashboard

```bash
cd frontend-dashboard
npm ci
npm run build       # production build → build/
cd ..
```

### 5. Start MongoDB and Redis

Using your local MongoDB and Redis instances, update `MONGO_URI` and `REDIS_URL` in `.env`, then:

```bash
mongod --dbpath /data/db &
redis-server &
```

### 6. Start the backend API

```bash
cd backend-api
npm start
```

### 7. Start the firewall engine

```bash
source .venv/bin/activate
cd firewall-engine
python main.py
```

### 8. Start the frontend dev server (optional)

```bash
cd frontend-dashboard
npm start
# Opens http://localhost:3000
```

---

## Environment Variables

See the [README](../README.md#environment-variables) for a full variable reference. At minimum, set:

```env
JWT_SECRET=<random-string-min-32-chars>
JWT_REFRESH_SECRET=<different-random-string-min-32-chars>
```

You can generate secure secrets with:

```bash
openssl rand -base64 48
```

---

## Running Tests

```bash
# Python unit tests
source .venv/bin/activate
pytest tests/ -v

# Backend API tests
cd backend-api && npm test
```
