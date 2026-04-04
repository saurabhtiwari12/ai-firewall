#!/usr/bin/env bash
# deploy.sh — build, push, and deploy AI Firewall Docker images
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()  { echo -e "${YELLOW}[deploy]${NC} $*"; }
error() { echo -e "${RED}[deploy] ERROR:${NC} $*" >&2; exit 1; }
step()  { echo -e "${CYAN}[deploy] ──${NC} $*"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── Configuration ────────────────────────────────────────────────────────────

REGISTRY="${REGISTRY:-ghcr.io/saurabhtiwari12/ai-firewall}"
TAG="${TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo latest)}"
PUSH="${PUSH:-false}"
APPLY_K8S="${APPLY_K8S:-false}"

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --registry REGISTRY   Container registry prefix (default: $REGISTRY)"
  echo "  --tag TAG             Image tag (default: git short SHA)"
  echo "  --push                Push images to registry after build"
  echo "  --apply-k8s           Apply Kubernetes manifests after push"
  echo "  -h, --help            Show this help"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --registry) REGISTRY="$2"; shift 2 ;;
    --tag)      TAG="$2"; shift 2 ;;
    --push)     PUSH=true; shift ;;
    --apply-k8s) APPLY_K8S=true; shift ;;
    -h|--help)  usage ;;
    *) error "Unknown option: $1" ;;
  esac
done

info "Registry : $REGISTRY"
info "Tag      : $TAG"
info "Push     : $PUSH"
info "K8s apply: $APPLY_K8S"
echo ""

# ── Build ────────────────────────────────────────────────────────────────────

IMAGES=(
  "engine:Dockerfile.firewall"
  "backend:Dockerfile.backend"
  "frontend:Dockerfile.frontend"
)

for entry in "${IMAGES[@]}"; do
  name="${entry%%:*}"
  dockerfile="${entry##*:}"
  full_tag="$REGISTRY/$name:$TAG"
  latest_tag="$REGISTRY/$name:latest"

  step "Building $full_tag …"
  docker build \
    --file "$dockerfile" \
    --tag "$full_tag" \
    --tag "$latest_tag" \
    --label "org.opencontainers.image.revision=$TAG" \
    --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    .
  info "  Built $full_tag ✓"
done

# ── Push ─────────────────────────────────────────────────────────────────────

if [[ "$PUSH" == "true" ]]; then
  echo ""
  step "Pushing images to $REGISTRY …"
  for entry in "${IMAGES[@]}"; do
    name="${entry%%:*}"
    full_tag="$REGISTRY/$name:$TAG"
    latest_tag="$REGISTRY/$name:latest"
    docker push "$full_tag"
    docker push "$latest_tag"
    info "  Pushed $full_tag ✓"
  done
else
  warn "Skipping push (pass --push to enable)."
fi

# ── Kubernetes ───────────────────────────────────────────────────────────────

if [[ "$APPLY_K8S" == "true" ]]; then
  echo ""
  if ! command -v kubectl &>/dev/null; then
    error "kubectl not found — cannot apply Kubernetes manifests."
  fi
  step "Applying Kubernetes manifests (kubernetes/)…"
  # Substitute the image tag in manifests before applying
  for manifest in kubernetes/*.yaml; do
    sed "s|:latest|:$TAG|g" "$manifest" | kubectl apply -f -
  done
  info "  Kubernetes manifests applied ✓"
  kubectl rollout status deployment/ai-firewall-backend --timeout=120s || true
  kubectl rollout status deployment/ai-firewall-engine  --timeout=120s || true
  kubectl rollout status deployment/ai-firewall-frontend --timeout=120s || true
else
  warn "Skipping Kubernetes apply (pass --apply-k8s to enable)."
fi

echo ""
info "Deploy complete!"
