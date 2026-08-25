# Per-user job attribution via token exchange (#102)

## The problem

A service that submits jobs through Mobula's gateway on behalf of humans — the
checkmaite api is the motivating case — authenticates with its own
service-account credentials. Every job it submits is therefore attributed to
that one service account (`checkmaite-svc`), not to the person who actually
asked for the run. Worse, the pre-fix path trusted a client-supplied
`X-Auth-Request-User` header to name the human, which is trivially spoofable
(checkmaite-frontend#25).

Mobula already attributes a gateway job to the **subject (`sub`) of the bearer
token** the submission carries (see `crates/mobula-api/src/job_history.rs`,
`record_submission`, from #115/#89). So the fix is not in how Mobula records
jobs — it is in getting a token whose subject is the *user* into the hands of
the service, without the service being able to fabricate one.

## The fix: OAuth 2.0 Token Exchange (RFC 8693)

A trusted service that already holds a **user's** gateway-verified token (the
access/id token from the gateway session cookie) exchanges:

- its **own** client credentials (`client_id` + `client_secret`), proving it is
  a trusted service, **plus**
- the **user's** token as the `subject_token`,

for a **new, short-lived token whose `sub` is the user** and whose `aud` is
`mobula`. The service submits *that* token through the gateway. Mobula validates
it like any other OIDC bearer (issuer, audience, expiry, JWKS signature) and
records the job's `submitter`/`created_by` as the real human.

Keycloak performs the exchange; **Mobula mints nothing**. The service cannot
forge a user identity: it can only exchange a token the user already presented,
and only if Keycloak has granted it token-exchange permission.

```
user ──(logs in, gateway verifies)──▶ user's token (aud=mobula, sub=alice)
                                         │
checkmaite-svc holds it, calls Keycloak token endpoint:
   grant_type = urn:ietf:params:oauth:grant-type:token-exchange
   client_id/secret = checkmaite-svc            (proves the trusted service)
   subject_token = user's token                 (identity source)
   requested_token_type = ...:access_token
   audience = mobula
                                         │
                                         ▼
              exchanged token (aud=mobula, sub=alice, short-lived)
                                         │
   checkmaite-svc submits Ray job through Mobula's gateway with it
                                         ▼
        Mobula validates + records submitter = alice   ✅ (not checkmaite-svc)
```

## Implementation (shape (a): direct Keycloak exchange)

We picked the shape where **Mobula exposes no new endpoint** — a trusted client
does the RFC 8693 exchange directly against Keycloak and submits the result to
the existing gateway, which validates it as usual. This keeps Mobula's trust
boundary unchanged (it only ever *validates* tokens) and puts the exchange where
the credentials already live.

Mobula ships a reusable helper so the checkmaite backend and the CLI don't each
reimplement the flow:

- **`mobula_auth::flows::exchange_token(client, token_endpoint, &TokenExchange)`**
  (`crates/mobula-auth/src/flows.rs`) — posts the RFC 8693 form and returns the
  `TokenResponse`. `TokenExchange::new(client_id, client_secret, subject_token)`
  defaults the subject-token type to an access token; set `.audience` to
  `"mobula"` before exchanging. Secrets are redacted from `Debug`.
- **`mobula exchange`** (CLI) — `mobula exchange --issuer <url> --client-id
  checkmaite-svc --client-secret … --subject-token-stdin --audience mobula`
  prints the exchanged token. Handy for testing against grace and for scripts.

Attribution is proven end-to-end by
`crates/mobula-api/tests/job_history.rs::exchanged_user_token_attributes_job_to_the_user_not_the_service`:
a token shaped like the exchange's output (`sub = alice-human`, `aud = mobula`)
submitted through the gateway records `submitter = alice-human`, while the
service's own token records `checkmaite-svc`. The exchange call itself is
covered by `mobula-auth`'s `token_exchange_swaps_subject_and_targets_audience`
against a mock Keycloak token endpoint.

## Keycloak configuration (for the coordinator to apply on grace)

Grace runs Keycloak 26.7.1, which supports **Standard Token Exchange (v2)**,
enabled per-client with the `standard.token.exchange.enabled` attribute.

Two equivalent ways to apply it — both are committed here:

1. **Realm import** — `deploy/keycloak/mobula-realm.json` now declares a
   `checkmaite-svc` confidential client with
   `"standard.token.exchange.enabled": "true"`, an `aud-mobula` audience mapper,
   and `serviceAccountsEnabled`. A realm re-import picks it up.
2. **Live instance** — `deploy/keycloak/kc-token-exchange.sh` reconciles the
   same state on a running Keycloak via `kcadm.sh` (idempotent). Run it with
   `KC_URL`/`KC_ADMIN`/`KC_ADMIN_PASSWORD` set.

The realm secret in the committed JSON (`checkmaite-svc-secret`) is a **local
demo placeholder** — grace must set a real secret (via `kcadm` or the admin
console) and hand it to the checkmaite backend out of band (e.g. a k8s Secret),
never commit the production value.

### What the coordinator needs to do on grace

1. Apply the client + token-exchange config (import the updated realm, or run
   `kc-token-exchange.sh`).
2. Set a real `checkmaite-svc` client secret and deliver it to the checkmaite
   backend as `MOBULA_CLIENT_SECRET` (see the checkmaite MR).
3. Confirm the `mobula` client/audience is a valid exchange target audience for
   `checkmaite-svc` (the `aud-mobula` mapper handles the claim; on stricter
   setups also allow `mobula` as a permitted audience for the client).
