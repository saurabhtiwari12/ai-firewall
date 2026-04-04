#!/usr/bin/env bash
# maintenance.sh — routine database cleanup, log rotation, and model backup
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[maintenance]${NC} $*"; }
warn()  { echo -e "${YELLOW}[maintenance]${NC} $*"; }
error() { echo -e "${RED}[maintenance] ERROR:${NC} $*" >&2; exit 1; }
step()  { echo -e "${CYAN}[maintenance] ──${NC} $*"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MONGO_URI="${MONGO_URI:-mongodb://localhost:27017/ai-firewall}"
EVENT_RETENTION_DAYS="${EVENT_RETENTION_DAYS:-90}"
BACKUP_DIR="${BACKUP_DIR:-/tmp/ai-firewall-backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# ── 1. Prune old MongoDB events ──────────────────────────────────────────────

step "Removing events older than $EVENT_RETENTION_DAYS days from MongoDB…"
if command -v mongosh &>/dev/null; then
  CUTOFF_DATE=$(date -d "-${EVENT_RETENTION_DAYS} days" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                date -v "-${EVENT_RETENTION_DAYS}d" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                python3 -c "from datetime import datetime, timedelta; print((datetime.utcnow()-timedelta(days=$EVENT_RETENTION_DAYS)).strftime('%Y-%m-%dT%H:%M:%SZ'))")
  RESULT=$(mongosh "$MONGO_URI" --quiet --eval \
    "db.events.deleteMany({ timestamp: { \$lt: new Date('$CUTOFF_DATE') } }).deletedCount")
  info "  Deleted $RESULT events older than $CUTOFF_DATE ✓"
else
  warn "mongosh not found — skipping event pruning. Install MongoDB Shell to enable."
fi

# ── 2. Log rotation ──────────────────────────────────────────────────────────

step "Rotating application logs…"
LOG_DIRS=(
  "firewall-engine/logs"
  "backend-api/logs"
)

for log_dir in "${LOG_DIRS[@]}"; do
  if [[ -d "$log_dir" ]]; then
    # Archive logs older than 7 days
    find "$log_dir" -name "*.log" -mtime +7 | while read -r logfile; do
      gzip -f "$logfile" && info "  Compressed $logfile ✓"
    done
    # Delete compressed logs older than 30 days
    find "$log_dir" -name "*.log.gz" -mtime +30 -delete && \
      info "  Cleaned old compressed logs in $log_dir ✓"
  else
    warn "  $log_dir not found — skipping."
  fi
done

# ── 3. Back up ML models ─────────────────────────────────────────────────────

step "Backing up ML models to $BACKUP_DIR …"
MODEL_DIR="ml_training/models"

if [[ -d "$MODEL_DIR" ]]; then
  MODELS=$(find "$MODEL_DIR" -name "*.pkl" -o -name "*.joblib" 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$MODELS" -gt 0 ]]; then
    ARCHIVE="$BACKUP_DIR/models_$TIMESTAMP.tar.gz"
    tar -czf "$ARCHIVE" -C "$MODEL_DIR" .
    info "  $MODELS model file(s) archived to $ARCHIVE ✓"
    # Keep only the last 10 backups
    ls -t "$BACKUP_DIR"/models_*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm --
    info "  Pruned old model backups (keeping last 10) ✓"
  else
    warn "  No trained model files found in $MODEL_DIR — skipping backup."
  fi
else
  warn "  $MODEL_DIR not found — skipping model backup."
fi

# ── 4. Summary ───────────────────────────────────────────────────────────────

echo ""
info "Maintenance complete ($TIMESTAMP)."
info "Backups stored in: $BACKUP_DIR"
