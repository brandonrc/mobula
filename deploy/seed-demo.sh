#!/usr/bin/env bash
# Seed the demo stack with a plausible org: pools + allocations, clusters
# across projects, services, and a terminated cluster. Idempotent-ish (409s
# on re-run are fine). Requires the local-auth stack (`up.sh local`).
set -euo pipefail

API="${MOBULA_API:-http://localhost:8484}"
TOKEN=$(curl -sf -X POST "$API/api/v1/auth/login" -H 'content-type: application/json' \
  -d '{"username":"admin","password":"admin"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
AUTH="Authorization: Bearer $TOKEN"
CT='content-type: application/json'

post() { # path, body
  curl -s -o /dev/null -w "%{http_code} $1\n" -X POST -H "$AUTH" -H "$CT" -d "$2" "$API$1"
}
put() {
  curl -s -o /dev/null -w "%{http_code} $1\n" -X PUT -H "$AUTH" -H "$CT" -d "$2" "$API$1"
}

echo "== pools"
post /api/v1/pools '{"spec":{"name":"gpu-pool","cohort":"main","fair_sharing_weight":1.0,"elastic":true,"flavors":[
  {"name":"a100","resources":{"cpu":"64","memory":"256Gi","nvidia.com/gpu":"8"},"node_labels":{"node.kubernetes.io/instance-type":"a100-40gb"},"taints":[]},
  {"name":"mig-slice","resources":{"cpu":"16","memory":"64Gi","nvidia.com/mig-1g.10gb":"14"},"node_labels":{"nvidia.com/mig.strategy":"mixed"},"taints":[]}]}}'
post /api/v1/pools '{"spec":{"name":"cpu-pool","cohort":"main","fair_sharing_weight":1.0,"elastic":false,"flavors":[
  {"name":"standard","resources":{"cpu":"128","memory":"512Gi"},"node_labels":{},"taints":[]}]}}'

echo "== allocations"
put /api/v1/pools/gpu-pool/allocations/ml-team '{"namespace":"default","nominal":{"nvidia.com/gpu":"6"},"borrowing_limit":{"nvidia.com/gpu":"8"},"lending_limit":{}}'
put /api/v1/pools/gpu-pool/allocations/genai '{"namespace":"default","nominal":{"nvidia.com/gpu":"2"},"borrowing_limit":{"nvidia.com/gpu":"6"},"lending_limit":{}}'
put /api/v1/pools/cpu-pool/allocations/research '{"namespace":"default","nominal":{"cpu":"64"},"borrowing_limit":{},"lending_limit":{}}'
put /api/v1/pools/cpu-pool/allocations/dev '{"namespace":"default","nominal":{"cpu":"16"},"borrowing_limit":{},"lending_limit":{}}'

echo "== clusters"
cluster() { # id, project, head_cpu, head_mem, workers-json
  post /api/v1/clusters "{\"id\":\"$1\",\"spec\":{\"name\":\"$1\",\"project\":\"$2\",\"ray_version\":\"2.57.0\",\"image\":\"rayproject/ray:2.57.0\",\"head_cpu\":\"$3\",\"head_memory\":\"$4\",\"worker_groups\":$5,\"ttl_seconds\":null}}"
}
cluster vision-train ml-team 2 8Gi '[{"name":"gpu-a100","cpu":"8","memory":"32Gi","gpu":"1","min_replicas":2,"max_replicas":8,"replicas":2}]'
cluster llm-finetune genai 2 8Gi '[{"name":"gpu","cpu":"8","memory":"32Gi","gpu":"1","min_replicas":1,"max_replicas":4,"replicas":1}]'
cluster batch-inference ml-team 1 4Gi '[{"name":"gpu-spot","cpu":"4","memory":"16Gi","gpu":"1","min_replicas":0,"max_replicas":2,"replicas":0}]'
cluster data-pipeline research 2 8Gi '[{"name":"cpu","cpu":"4","memory":"8Gi","min_replicas":4,"max_replicas":16,"replicas":4}]'
cluster dev-sandbox dev 1 4Gi '[{"name":"cpu","cpu":"2","memory":"4Gi","min_replicas":1,"max_replicas":2,"replicas":1}]'
cluster old-experiment research 1 2Gi '[{"name":"cpu","cpu":"1","memory":"2Gi","min_replicas":0,"max_replicas":1,"replicas":0}]'

echo "== services"
svc() { # name, project, strategy
  post /api/v1/services "{\"name\":\"$1\",\"spec\":{\"name\":\"$1\",\"project\":\"$2\",\"ray_version\":\"2.57.0\",\"image\":\"rayproject/ray:2.57.0\",\"serve_config_v2\":\"applications:\\n  - name: $1\\n    import_path: app:entry\\n\",\"head_cpu\":\"1\",\"head_memory\":\"2Gi\",\"worker_replicas\":2,\"worker_cpu\":\"1\",\"worker_memory\":\"2Gi\",\"upgrade\":\"$3\"}}"
}
svc fraud-scorer ml-team canary
svc chat-llm genai in_place

echo "== terminate one cluster (history variety)"
curl -s -o /dev/null -w "%{http_code} DELETE old-experiment\n" -X DELETE -H "$AUTH" "$API/api/v1/clusters/old-experiment"

echo "== audit noise: a few denials + auth failures"
curl -s -o /dev/null -w "%{http_code} unauth GET\n" "$API/api/v1/clusters"
curl -s -o /dev/null -w "%{http_code} bad-password login\n" -X POST -H "$CT" -d '{"username":"admin","password":"wrong"}' "$API/api/v1/auth/login"

echo "done. UI: http://localhost:8088 (admin/admin)"
