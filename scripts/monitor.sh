#!/usr/bin/env bash
# monitor.sh — check container health and tail recent logs
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
fail() { echo -e "${RED}  ✗${NC} $*"; }
info() { echo -e "${CYAN}[monitor]${NC} $*"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

API_BASE="${API_BASE:-http://localhost:3001}"
LOG_LINES="${LOG_LINES:-50}"

# ── 1. Docker Compose container status ──────────────────────────────────────

info "Container status:"
echo ""
if command -v docker &>/dev/null && docker compose ps &>/dev/null 2>&1; then
  docker compose ps
else
  fail "docker compose not available or no containers running."
fi

echo ""

# ── 2. Health endpoint ───────────────────────────────────────────────────────

info "Checking API health at $API_BASE/api/system/health …"
if command -v curl &>/dev/null; then
  HEALTH_RESPONSE=$(curl -sf --max-time 5 "$API_BASE/api/system/health" 2>/dev/null || echo "")
  if [[ -n "$HEALTH_RESPONSE" ]]; then
    STATUS=$(echo "$HEALTH_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unknown")
    DB=$(echo "$HEALTH_RESPONSE"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('database','unknown'))" 2>/dev/null || echo "unknown")
    UPTIME=$(echo "$HEALTH_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('uptime_s','?'))" 2>/dev/null || echo "?")
    if [[ "$STATUS" == "ok" ]]; then
      ok "API status: $STATUS | database: $DB | uptime: ${UPTIME}s"
    else
      fail "API status: $STATUS | database: $DB | uptime: ${UPTIME}s"
    fi
  else
    fail "Could not reach $API_BASE/api/system/health"
  fi
else
  fail "curl not found — skipping health check."
fi

echo ""

# ── 3. Recent logs ───────────────────────────────────────────────────────────

SERVICES=("firewall-engine" "backend-api" "frontend" "mongodb")

for svc in "${SERVICES[@]}"; do
  info "Last $LOG_LINES lines — $svc:"
  docker compose logs --no-color --tail "$LOG_LINES" "$svc" 2>/dev/null || \
    echo "  (no logs available for $svc)"
  echo ""
done
