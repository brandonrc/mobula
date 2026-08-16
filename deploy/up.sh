#!/usr/bin/env bash
#
# Bring up the local demo stack (control plane + dashboard) with Docker.
#
#   ./deploy/up.sh              # build + start, streaming logs
#   ./deploy/up.sh -d           # detached
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
