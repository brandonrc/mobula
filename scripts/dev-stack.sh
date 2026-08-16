#!/usr/bin/env bash
#
# dev-stack.sh — bring up a full local Mobula stack for playing around and
# stress-testing: a kind cluster with the KubeRay operator, the control-plane
# API server, and (optionally) the dashboard.
#
#   ./scripts/dev-stack.sh up       # kind + KubeRay operator + namespace (idempotent)
#   ./scripts/dev-stack.sh serve    # run `mobula serve` against that cluster (foreground)
#   ./scripts/dev-stack.sh ui       # run the mobula-ui dev server (foreground)
#   ./scripts/dev-stack.sh smoke    # start serve, exercise the API, tear it down
#   ./scripts/dev-stack.sh smoke --full   # ...and provision a real RayCluster (slow: image pull)
#   ./scripts/dev-stack.sh status   # what's running in the cluster
#   ./scripts/dev-stack.sh down     # delete the kind cluster and dev state
#
# Typical first run: `up`, then `serve` in one terminal and `ui` in another.
# Everything is overridable via env vars (see the defaults below).
set -euo pipefail

# --- config (override via env) ----------------------------------------------
CLUSTER_NAME="${MOBULA_DEV_CLUSTER:-mobula-dev}"        # kind cluster name
NAMESPACE="${MOBULA_DEV_NAMESPACE:-mobula-dev}"         # namespace RayClusters live in
KUBERAY_VERSION="${MOBULA_KUBERAY_VERSION:-1.4.0}"      # matches kuberay-e2e.yml
BIND="${MOBULA_BIND:-127.0.0.1:8484}"                  # must match mobula-ui's vite proxy
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB="${MOBULA_DEV_DB:-$ROOT/.dev/mobula.db}"            # sqlite desired-state store
UI_DIR="${MOBULA_UI_DIR:-$ROOT/../mobula-ui}"          # sibling checkout of mobula-ui
RESYNC_SECS="${MOBULA_RESYNC_SECS:-10}"                # snappier than prod's 30s
KUBECTX="kind-${CLUSTER_NAME}"
BASE_URL="http://${BIND}"

log()  { printf '\033[1;36m▶ %s\033[0m\n' "$*" >&2; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

# --- subcommands ------------------------------------------------------------

cmd_up() {
  need kind; need kubectl; need helm
  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "kind cluster '$CLUSTER_NAME' already exists"
  else
    log "creating kind cluster '$CLUSTER_NAME'"
    kind create cluster --name "$CLUSTER_NAME"
  fi
  kubectl config use-context "$KUBECTX" >/dev/null

  log "installing KubeRay operator $KUBERAY_VERSION (cluster-scoped)"
  helm repo add kuberay https://ray-project.github.io/kuberay-helm/ >/dev/null 2>&1 || true
  helm repo update kuberay >/dev/null
  helm upgrade --install kuberay-operator kuberay/kuberay-operator \
    --version "$KUBERAY_VERSION" --wait --timeout 5m

  log "ensuring namespace '$NAMESPACE'"
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  kubectl wait --for=condition=Available deploy/kuberay-operator --timeout=180s
  log "up. next: '$0 serve' (terminal 1) and '$0 ui' (terminal 2)"
}

cmd_serve() {
  need cargo; need kubectl
  kubectl config use-context "$KUBECTX" >/dev/null 2>&1 \
    || die "kind context '$KUBECTX' not found — run '$0 up' first"
  mkdir -p "$(dirname "$DB")"
  log "serving on $BASE_URL (ns=$NAMESPACE db=$DB resync=${RESYNC_SECS}s)"
  log "unauthenticated dev mode — do NOT expose this port"
  exec cargo run --quiet -p mobula-cli -- serve \
    --bind "$BIND" \
    --dev-allow-unauthenticated \
    --kuberay-namespace "$NAMESPACE" \
    --db "$DB" \
    --reconcile-interval-secs "$RESYNC_SECS"
}

cmd_ui() {
  need npm
  [ -d "$UI_DIR" ] || die "mobula-ui not found at $UI_DIR (set MOBULA_UI_DIR)"
  log "starting mobula-ui dev server (proxies /api → $BASE_URL)"
  cd "$UI_DIR"
  [ -d node_modules ] || npm install
  exec npm run dev
}

cmd_status() {
  need kubectl
  kubectl config use-context "$KUBECTX" >/dev/null 2>&1 || die "no kind context '$KUBECTX'"
  echo "== operator =="; kubectl get deploy kuberay-operator 2>/dev/null || true
  echo "== rayclusters ($NAMESPACE) =="; kubectl get rayclusters -n "$NAMESPACE" -o wide 2>/dev/null || true
  echo "== rayservices ($NAMESPACE) =="; kubectl get rayservices -n "$NAMESPACE" -o wide 2>/dev/null || true
  echo "== pods ($NAMESPACE) =="; kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null || true
  echo "== control plane =="
  if curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1; then
    echo "healthz: ok  version: $(curl -fsS "$BASE_URL/api/v1/version" 2>/dev/null)"
  else
    echo "healthz: unreachable (is '$0 serve' running?)"
  fi
}

cmd_down() {
  need kind
  log "deleting kind cluster '$CLUSTER_NAME' and dev state"
  kind delete cluster --name "$CLUSTER_NAME" || true
  rm -rf "$ROOT/.dev"
}

# smoke: start serve in the background, hit the API, and (with --full) drive a
# real cluster all the way to running and back. Proves the wiring end-to-end.
cmd_smoke() {
  need cargo; need curl; need kubectl
  local full=0; [ "${1:-}" = "--full" ] && full=1
  kubectl config use-context "$KUBECTX" >/dev/null 2>&1 \
    || die "kind context '$KUBECTX' not found — run '$0 up' first"

  log "building mobula-cli"
  cargo build --quiet -p mobula-cli
  local bin="$ROOT/target/debug/mobula"
  mkdir -p "$ROOT/.dev"
  local dbfile="$ROOT/.dev/smoke.db"; rm -f "$dbfile"

  log "starting serve in the background"
  "$bin" serve --bind "$BIND" --dev-allow-unauthenticated \
    --kuberay-namespace "$NAMESPACE" --db "$dbfile" \
    --reconcile-interval-secs 5 >"$ROOT/.dev/smoke-serve.log" 2>&1 &
  local serve_pid=$!
  # shellcheck disable=SC2064
  trap "kill $serve_pid 2>/dev/null || true" EXIT

  log "waiting for /healthz"
  for _ in $(seq 1 60); do
    curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1 && break
    kill -0 "$serve_pid" 2>/dev/null || die "serve exited early — see .dev/smoke-serve.log"
    sleep 1
  done
  curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1 || die "serve never became healthy"

  log "GET /api/v1/version"; curl -fsS "$BASE_URL/api/v1/version"; echo
  log "GET /api/v1/clusters"; curl -fsS "$BASE_URL/api/v1/clusters"; echo

  if [ "$full" -eq 1 ]; then
    log "POST /api/v1/clusters (real RayCluster — this pulls the Ray image, be patient)"
    curl -fsS -X POST "$BASE_URL/api/v1/clusters" \
      -H 'content-type: application/json' -d '{
        "id":"smoke",
        "spec":{"name":"smoke","project":"dev","ray_version":"2.57.0",
          "image":"rayproject/ray:2.57.0","head_cpu":"1","head_memory":"2560Mi",
          "worker_groups":[],"ttl_seconds":null}
      }' >/dev/null && echo "created."

    log "polling until observed_state=running (up to 10m)"
    local state=""
    for _ in $(seq 1 120); do
      state=$(curl -fsS "$BASE_URL/api/v1/clusters/smoke" 2>/dev/null \
        | sed -n 's/.*"observed_state":"\([^"]*\)".*/\1/p')
      printf '\r  observed_state=%s   ' "${state:-<none>}" >&2
      [ "$state" = "running" ] && { echo; break; }
      sleep 5
    done
    [ "$state" = "running" ] || { kubectl describe rayclusters -n "$NAMESPACE" || true; die "cluster never reached running"; }

    log "DELETE /api/v1/clusters/smoke"
    curl -fsS -X DELETE "$BASE_URL/api/v1/clusters/smoke" >/dev/null && echo "delete accepted."
    log "waiting for teardown"
    for _ in $(seq 1 60); do
      kubectl get raycluster -n "$NAMESPACE" smoke >/dev/null 2>&1 || { echo "  gone."; break; }
      sleep 5
    done
  fi

  log "smoke passed ✅"
}

# --- dispatch ---------------------------------------------------------------
sub="${1:-help}"; shift || true
case "$sub" in
  up)     cmd_up "$@" ;;
  serve)  cmd_serve "$@" ;;
  ui)     cmd_ui "$@" ;;
  smoke)  cmd_smoke "$@" ;;
  status) cmd_status "$@" ;;
  down)   cmd_down "$@" ;;
  help|-h|--help)
    cat >&2 <<'USAGE'
dev-stack.sh — a full local Mobula stack for playing around / stress-testing.

  up               kind cluster + KubeRay operator + namespace (idempotent)
  serve            run `mobula serve` against that cluster (foreground)
  ui               run the mobula-ui dev server (foreground)
  smoke            start serve, exercise the API, tear it down
  smoke --full     ...and provision a real RayCluster (slow: pulls the Ray image)
  status           what's running in the cluster + control-plane health
  down             delete the kind cluster and dev state

First run: `up`, then `serve` (terminal 1) and `ui` (terminal 2), open the UI.
Override via env: MOBULA_DEV_CLUSTER, MOBULA_DEV_NAMESPACE, MOBULA_KUBERAY_VERSION,
MOBULA_BIND, MOBULA_DEV_DB, MOBULA_UI_DIR, MOBULA_RESYNC_SECS.
USAGE
    ;;
  *) die "unknown subcommand '$sub' (try '$0 help')" ;;
esac
