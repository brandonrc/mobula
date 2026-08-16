#!/usr/bin/env bash
#
# Bring up the local demo stack (control plane + dashboard) with Docker.
#
#   ./deploy/up.sh              # build + start, streaming logs
#   ./deploy/up.sh -d           # detached
#   ./deploy/up.sh auth         # authenticated variant: local Keycloak +
#                               # OIDC-enforced control plane (detached)
#   ./deploy/up.sh down         # tear down
#
# Generates the OpenAPI spec from the Rust source and the typed TS client
# (vendored into mobula-ui) first, so the UI image builds with no GitHub
# Packages / npm auth. Real KubeRay provisioning is the dev-stack (kind)
# path, not this — see scripts/dev-stack.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # mobula repo root
UI="${MOBULA_UI_DIR:-$ROOT/../mobula-ui}"
COMPOSE="$ROOT/deploy/docker-compose.yml"
GEN_VERSION="${MOBULA_OPENAPI_GEN:-v7.12.0}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
need docker; need cargo

# `down` / passthrough for compose subcommands that don't need a rebuild.
if [ "${1:-}" = "down" ]; then
  exec docker compose -f "$COMPOSE" down "${@:2}"
fi

# `auth`: the authenticated variant — local Keycloak (realm `mobula`, test
# users admin/operator/developer/viewer, passwords = usernames) plus the
# control plane with real OIDC enforcement. Stops the plain demo first
# (both want host port 8484). No spec/client regen: only the mobula
# service's config changes, so the existing images are reused.
#   ./deploy/up.sh auth        # start the authenticated stack (detached)
#   ./deploy/up.sh auth down   # tear down; add -v to re-import the realm next time
if [ "${1:-}" = "auth" ]; then
  shift
  if [ "${1:-}" = "down" ]; then
    shift
    exec docker compose -f "$COMPOSE" -f "$ROOT/deploy/docker-compose.auth.yml" --profile auth down "$@"
  fi
  docker compose -f "$COMPOSE" down >/dev/null
  echo "▶ starting the authenticated stack (Keycloak on :8090, API on :8484, UI on :8088)"
  exec docker compose -f "$COMPOSE" -f "$ROOT/deploy/docker-compose.auth.yml" --profile auth up -d "$@"
fi

[ -d "$UI" ] || { echo "mobula-ui not found at $UI (set MOBULA_UI_DIR)" >&2; exit 1; }

echo "▶ generating openapi.json from the Rust source"
( cd "$ROOT" && cargo test -q -p mobula-api export_openapi >/dev/null )
[ -f "$ROOT/openapi.json" ] || { echo "openapi.json was not produced" >&2; exit 1; }

echo "▶ generating the typed client into mobula-ui/vendor/mobula-client"
rm -rf "$UI/vendor/mobula-client"
mkdir -p "$UI/vendor"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$ROOT/openapi.json:/spec/openapi.json:ro" \
  -v "$UI/vendor:/out" \
  "openapitools/openapi-generator-cli:${GEN_VERSION}" generate --skip-validate-spec \
  -i /spec/openapi.json -g typescript-fetch \
  --additional-properties=npmName=@brandonrc/mobula-client,supportsES6=true,withInterfaces=true \
  -o /out/mobula-client >/dev/null

echo "▶ docker compose up --build"
echo "   dashboard → http://localhost:8088     API → http://localhost:8484"
exec docker compose -f "$COMPOSE" up --build "$@"
