#!/usr/bin/env bash
#
# kc-token-exchange.sh — enable RFC 8693 token exchange for the checkmaite api
# service so it can submit Ray jobs through Mobula on a user's behalf and have
# the run attribute to the human, not the shared service account.
# (#102 / checkmaite-frontend#25.)
#
# This configures Keycloak's *Standard Token Exchange* (v2, GA since Keycloak
# 26.2 — grace runs 26.7.1). It is idempotent: safe to re-run, and safe to run
# after a realm import that already declares the client (it only reconciles the
# token-exchange switch and the mobula-audience mapper).
#
# The declarative source of truth is mobula-realm.json (the checkmaite-svc
# client with "standard.token.exchange.enabled": "true"). Use THIS script when
# the realm is configured on a live instance rather than re-imported, or to
# turn exchange on for a client that predates the import.
#
# Usage:
#   KC_URL=https://keycloak.grace.example \
#   KC_ADMIN=admin KC_ADMIN_PASSWORD=... \
#   REALM=mobula CLIENT_ID=checkmaite-svc AUDIENCE=mobula \
#     ./kc-token-exchange.sh
#
# Requires kcadm.sh on PATH (ships in the Keycloak image at
# /opt/keycloak/bin/kcadm.sh).

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8090}"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:?set KC_ADMIN_PASSWORD}"
REALM="${REALM:-mobula}"
CLIENT_ID="${CLIENT_ID:-checkmaite-svc}"
# The audience the exchanged token must carry so Mobula's gateway accepts it.
AUDIENCE="${AUDIENCE:-mobula}"
KCADM="${KCADM:-kcadm.sh}"

echo "==> Logging in to ${KC_URL} (realm master) as ${KC_ADMIN}"
"$KCADM" config credentials \
  --server "$KC_URL" \
  --realm master \
  --user "$KC_ADMIN" \
  --password "$KC_ADMIN_PASSWORD"

echo "==> Looking up client '${CLIENT_ID}' in realm '${REALM}'"
CID="$("$KCADM" get clients -r "$REALM" -q "clientId=${CLIENT_ID}" --fields id --format csv --noquotes | head -n1 || true)"

if [[ -z "${CID}" ]]; then
  echo "    client not found; creating a confidential service-account client"
  CID="$("$KCADM" create clients -r "$REALM" -i \
    -s "clientId=${CLIENT_ID}" \
    -s 'publicClient=false' \
    -s 'serviceAccountsEnabled=true' \
    -s 'standardFlowEnabled=false' \
    -s 'directAccessGrantsEnabled=false' \
    -s 'attributes.\"standard.token.exchange.enabled\"=true')"
  echo "    created client id=${CID}"
else
  echo "    found client id=${CID}; enabling standard token exchange"
  "$KCADM" update "clients/${CID}" -r "$REALM" \
    -s 'attributes."standard.token.exchange.enabled"=true'
fi

echo "==> Ensuring an audience mapper adds aud='${AUDIENCE}' to exchanged tokens"
HAVE_MAPPER="$("$KCADM" get "clients/${CID}/protocol-mappers/models" -r "$REALM" \
  --fields name --format csv --noquotes 2>/dev/null | grep -Fx "aud-${AUDIENCE}" || true)"
if [[ -z "${HAVE_MAPPER}" ]]; then
  "$KCADM" create "clients/${CID}/protocol-mappers/models" -r "$REALM" \
    -s "name=aud-${AUDIENCE}" \
    -s 'protocol=openid-connect' \
    -s 'protocolMapper=oidc-audience-mapper' \
    -s "config.\"included.client.audience\"=${AUDIENCE}" \
    -s 'config."access.token.claim"=true' \
    -s 'config."id.token.claim"=false'
  echo "    added aud-${AUDIENCE} mapper"
else
  echo "    aud-${AUDIENCE} mapper already present"
fi

cat <<EOF

==> Done. '${CLIENT_ID}' can now exchange a user's token for a
    '${AUDIENCE}'-audience token whose subject is the user:

  curl -s "${KC_URL}/realms/${REALM}/protocol/openid-connect/token" \\
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \\
    -d client_id=${CLIENT_ID} -d client_secret=\$CLIENT_SECRET \\
    -d subject_token=\$USER_TOKEN \\
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \\
    -d requested_token_type=urn:ietf:params:oauth:token-type:access_token \\
    -d audience=${AUDIENCE}

    (This is exactly what mobula-auth's exchange_token() / 'mobula exchange' do.)
EOF
