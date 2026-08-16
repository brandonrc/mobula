# ADR-0011: Local auth mode — opaque tokens only, never JWT minting

Status: accepted (2026-08-16)

## Context
OIDC (ADR-0003) is the production path, but it forces every standalone,
dev, or small-team deployment to run an IdP before Mobula can fail open
anywhere safe. artifact-keeper solves the same problem with a local-auth
half: username/password login and personal access tokens stored in its own
database. Its tokens, however, are symmetric-key JWTs — which puts a
long-lived signing key on the box and gives key rotation a blast radius
covering every outstanding token.

PLAN.md Phase 2 said "Mobula never mints tokens itself". That note was
written about OIDC service-account tokens; it needs amending for local
auth, which necessarily issues *something*.

## Decision
- **Local auth mode** (`mobula serve --local-auth`): username/password
  login at `POST /api/v1/auth/login` returns an **opaque random token**
  (`mob_<8-char prefix>_<32 hex>`), never a JWT. Tokens are stored
  bcrypt-hashed at rest and looked up by their 8-character prefix. This
  amends the Phase-2 "never mints tokens" note: **Mobula stores
  credentials; it never signs them.** Symmetric-key JWT issuance à la
  artifact-keeper was rejected: a leaked or rotated signing key
  invalidates/forges every token at once, whereas an opaque-token leak is
  one row in one database.
- **Roles are a column on the local user**, resolved per request at token
  authentication time — not claims baked into a token. Role changes apply
  live; there is no claim staleness to reason about.
- **OIDC remains the production path.** Local mode targets standalone /
  dev / small deployments. The two coexist: when both are configured the
  bearer is tried as a JWT first (JWTs are dot-delimited; `mob_` tokens
  never are, so dispatch is unambiguous), then as an opaque token.
- **Brute-force posture** (mirroring artifact-keeper's local half):
  account lockout after 5 consecutive failures (5-minute lock), a
  constant-time dummy bcrypt verify for unknown usernames so login timing
  doesn't enumerate accounts, an identical `401 invalid_credentials` body
  for unknown user / wrong password / locked / disabled (lockout is
  visible only in the audit trail), and every login/logout/revocation
  decision flowing through the audit helper.

## Consequences
- A store is mandatory for local auth (`local_users` + `api_tokens`
  tables); `--local-auth` counts as configured authentication for the
  fail-closed non-loopback bind rule (#36/#45).
- Token verification costs one bcrypt per request on the PAT path; that
  is the price of never holding a signing key. Login-page metadata
  (`GET /api/v1/auth/providers`) is public; everything else under
  `/api/v1/auth/` except `login` requires an authenticated identity.
- First boot with an empty users table bootstraps `admin` with a random
  password written 0600 next to the database and printed once to the
  log (artifact-keeper pattern); `MOBULA_LOCAL_ADMIN_PASSWORD` overrides
  it for demos.
