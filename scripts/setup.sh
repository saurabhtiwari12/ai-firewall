#!/usr/bin/env bash
# setup.sh — bootstrap the AI Firewall development environment
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
info()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[setup]${NC} $*"; }
error() { echo -e "${RED}[setup] ERROR:${NC} $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── 1. Prerequisites ────────────────────────────────────────────────────────

info "Checking prerequisites…"

# Python 3.11+
if command -v python3 &>/dev/null; then
  PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
  PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
  if [[ "$PY_MAJOR" -lt 3 || ("$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 11) ]]; then
    error "Python 3.11+ required (found $PY_VER). See https://www.python.org/"
  fi
  info "  Python $PY_VER ✓"
else
  error "python3 not found. Install Python 3.11+ from https://www.python.org/"
fi

# Node 20+
if command -v node &>/dev/null; then
  NODE_VER=$(node -e "process.stdout.write(process.versions.node)")
  NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
  if [[ "$NODE_MAJOR" -lt 20 ]]; then
    error "Node.js 20+ required (found $NODE_VER). See https://nodejs.org/"
  fi
  info "  Node.js $NODE_VER ✓"
else
  error "node not found. Install Node.js 20+ from https://nodejs.org/"
fi

# Docker
if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version | awk '{print $3}' | tr -d ',')
  info "  Docker $DOCKER_VER ✓"
else
  warn "docker not found — Docker Compose deployment will not be available."
fi

# ── 2. Environment file ─────────────────────────────────────────────────────

if [[ ! -f .env ]]; then
  info "Creating .env from .env.example…"
  cp .env.example .env
  warn "  Edit .env and set JWT_SECRET, JWT_REFRESH_SECRET, and any API keys before starting."
else
  info ".env already exists — skipping copy."
fi

# ── 3. Python virtual environment ───────────────────────────────────────────

if [[ ! -d .venv ]]; then
  info "Creating Python virtual environment (.venv)…"
  python3 -m venv .venv
fi
info "Activating .venv and installing Python dependencies…"
# shellcheck source=/dev/null
source .venv/bin/activate

pip install --quiet --upgrade pip
pip install --quiet -r firewall-engine/requirements.txt
pip install --quiet -r ml_training/requirements.txt
pip install --quiet -r threat_intelligence/requirements.txt
pip install --quiet -r tests/requirements.txt

info "  Python dependencies installed ✓"

# ── 4. Node.js dependencies ─────────────────────────────────────────────────

info "Installing backend-api Node dependencies…"
(cd backend-api && npm ci --silent)
info "  backend-api ✓"

info "Installing frontend-dashboard Node dependencies…"
(cd frontend-dashboard && npm ci --silent)
info "  frontend-dashboard ✓"

# ── 5. Model directory ──────────────────────────────────────────────────────

mkdir -p ml_training/models
mkdir -p firewall-engine/logs

# ── Done ────────────────────────────────────────────────────────────────────

echo ""
info "Setup complete!"
echo ""
echo "  Next steps:"
echo "    1. Edit .env (set JWT_SECRET, JWT_REFRESH_SECRET)"
echo "    2. docker compose up -d      # start all services"
echo "    3. open http://localhost:3000 # SOC dashboard"
echo ""
