# hexago

Go backend template using Hexagonal Architecture, DDD principles, JWT authentication, PostgreSQL, and Docker.

## Running with Docker

The stack (PostgreSQL, Redis and the API) is split across three compose files:

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | Base definition, shared by every environment. Publishes **no** host ports. |
| `docker-compose.override.yml` | Development. Loaded automatically by `docker compose up`; publishes ports on `127.0.0.1` and reads `.env`. |
| `docker-compose.prod.yml` | Production. Loaded explicitly; reads `.env.prod` and sets `ENVIRONMENT=production`. |

### Development

```sh
cp .env.example .env    # then edit the secrets (JWT_SECRET, DB_PASSWORD, ...)
docker compose up --build
```

The API listens on `http://localhost:8080` and Swagger UI is available at
`/swagger/index.html`. Postgres and Redis are published on the host loopback as
`5433` and `6380` (high ports, to avoid clashing with locally installed
instances) and are only reachable from `127.0.0.1`, so they can be inspected
with `psql`, DBeaver or `redis-cli`:

```sh
psql -h localhost -p 5433 -U postgres -d hexago
redis-cli -p 6380 -a "$REDIS_PASSWORD" --no-auth-warning   # password from .env
```

On startup the API waits for both dependencies to report healthy, runs the
migrations (`DB_AUTO_MIGRATION=true`) and seeds the admin user
(`SEED_ENABLED=true`). The bundled PostgreSQL container uses the same
`DB_PASSWORD` as the API (see `docker-compose.yml`), so one secret authenticates
both. If you are reusing a `postgres_data` volume created before this change,
recreate it with `docker compose down -v` so the container picks up the new
password. Tear everything down — including the database volume — with:

```sh
docker compose down -v
```

### Production

```sh
cp .env.prod.example .env.prod   # then replace every CHANGE_ME
docker compose --env-file .env.prod \
  -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

`--env-file` is required for interpolation (the Redis password), while the `api`
service reads its own variables through `env_file: .env.prod`. Nothing is
published to the host: put the API behind a reverse proxy or load balancer on
the same network. `.env.prod.example` already ships production defaults
(`DB_SSLMODE=require`, `DB_AUTO_MIGRATION=false`, `SEED_ENABLED=false`).

To use managed services instead of the bundled containers, override `DB_HOST`,
`DB_PORT` and `REDIS_ADDR` in `docker-compose.prod.yml` (a commented example is
included) and comment out the `postgres`/`redis` services in
`docker-compose.yml`.

## Rate limiting

Requests are limited with a token bucket stored in Redis (atomic Lua script).
Two buckets are configured:

* **`/api/v1/auth`** — keyed by client IP, with a strict budget to slow down
  credential stuffing and brute force attempts.
* **Authenticated routes** — keyed by the user ID taken from the JWT.

Exceeded requests receive `429 Too Many Requests` with `X-RateLimit-Limit`,
`X-RateLimit-Remaining` and `Retry-After`. If Redis is unreachable the limiter
**fails closed** and returns `503` rather than letting requests through
unprotected. The behaviour is controlled by the `REDIS_*` and `RATE_LIMIT_*`
variables documented in `.env.example`; set `RATE_LIMIT_ENABLED=false` to turn it
off (no Redis connection is then required).

Redis runs with AOF persistence enabled (`--appendonly yes`, see
`docker-compose.yml`), so the token buckets survive a restart instead of letting
an attacker reset the window by forcing a bounce.

## Tokens, revocation and sessions

Access tokens are HS256 JWTs valid for **15 minutes** by default
(`JWT_EXPIRATION`). When a token expires the client authenticates again; there
is no refresh token. The short lifetime bounds the damage of a leaked token,
while two additional checks make revocation immediate:

* **Denylist (`jti`)** — the token ID is stored in Redis until the token would
  have expired. `POST /api/v1/auth/logout` denies the token used in the request.
* **Token version (`tv` claim)** — each user has a version stored in Redis
  (`tokenver:user:{id}`). Tokens carry the version that was current when they
  were issued; incrementing it invalidates every token of that user at once.

Every protected request validates the signature, checks the denylist and compares
the token version, so a revoked token stops working on the next request instead
of at its natural expiration. If Redis is unreachable the API **fails closed**:
the request is rejected with `503` rather than trusting an unchecked token.

The token version lives outside PostgreSQL on purpose: revoking every session of
a user needs no schema change, and an existing database keeps working untouched.
Tokens issued before this feature carry no `tv` claim, which is read as version
`0`, the default for a user whose version was never incremented.

### Active sessions and the administrative panel

Each login records a session (`session:{jti}` plus an index per user in
`sessions:user:{id}`) with the token ID, expiration, IP and user agent. The
records expire on their own with the token, so the panel never lists stale
sessions. Three endpoints manage them, all guarded by RBAC:

| Endpoint | Permission | Effect |
| --- | --- | --- |
| `GET /api/v1/admin/users/{id}/sessions` | `sessions:read` | Lists active sessions; the session making the request is flagged `is_current`. |
| `DELETE /api/v1/admin/sessions/{jti}` | `sessions:revoke` | Revokes one session immediately (denylist + registry removal). Use this when a single token leaks. |
| `DELETE /api/v1/admin/users/{id}/sessions` | `sessions:revoke` | Revokes every session of a user by bumping the token version. Use this after a password reset or when an account is compromised. |

The seed grants the new permissions to the admin role on boot, so an existing
installation picks them up without a manual migration.

### Account status, password reset and roles

The administrative endpoints below change an account without requiring its
current password. All of them are guarded by RBAC and revoke the affected
user's tokens when the change must take effect immediately.

| Endpoint | Permission | Effect |
| --- | --- | --- |
| `PATCH /api/v1/users/{id}/status` | `users:status` | Activates or deactivates an account. Deactivating revokes every token of the user; an administrator cannot deactivate their own account or the last active administrator. |
| `POST /api/v1/users/{id}/password/reset` | `users:reset_password` | Generates a temporary password, returns it once in the response and revokes every existing token. |
| `POST /api/v1/users/{id}/roles/{role_id}` | `roles:manage` | Assigns a role by ID. Repeating the same assignment answers `409 role already assigned`. |
| `DELETE /api/v1/users/{id}/roles/{role_id}` | `roles:manage` | Removes a role by ID. Removing `admin` from the last active administrator is forbidden. |

A temporary password is valid for 24 hours. Logging in with it returns a token
whose only allowed use is `POST /api/v1/auth/change-password`, which replaces the
password and clears the temporary one. An expired temporary password is rejected
at login as `401 invalid credentials`, and every successful password change
revokes all tokens issued before it.

### Redis keys and fallback

Denylist, sessions and token versions share the Redis instance used by the rate
limiter, separated by prefix (`denylist:token:`, `session:`,
`sessions:user:`, `tokenver:user:`). Entries carry a TTL, so none of them
accumulate.

When `RATE_LIMIT_ENABLED=false` no Redis connection is opened; the API then uses
process-local implementations so the documented development setup still boots.
Those are suitable for a single instance only: the denylist and the sessions are
lost on restart and are not shared between replicas. Any deployment with more
than one instance (or that needs revocation to survive a restart) must run with
Redis enabled.

## Request limits and client IP

* **Body size** — request bodies larger than `SERVER_MAX_BODY_BYTES` (default
  `2097152`, i.e. 2 MiB) are rejected with `413 Request Entity Too Large`. This
  bounds memory usage regardless of what a client sends.
* **Trusted proxies** — the client IP used for rate limiting comes from the
  connection (`RemoteAddr`) by default, and `X-Forwarded-For`/`X-Real-IP` are
  ignored. When the API runs behind a reverse proxy or load balancer, set
  `TRUSTED_PROXIES` to that proxy's IPs/CIDRs (comma-separated) so the forwarded
  client IP is honoured without letting arbitrary clients spoof it.

## Unique usernames and emails

The `username` and the `email` are unique **among the accounts that were not
removed**. The database enforces it with partial unique indexes:

```sql
CREATE UNIQUE INDEX uniq_user_username ON "user" (username) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uniq_user_email    ON "user" (email)    WHERE deleted_at IS NULL;
```

Removing a user is a soft delete, so the row stays in the table but leaves the
index: the identity it held becomes available again and the same username or
email can be registered by a new account. Before this change the indexes
covered every row and the identity was reserved forever, which answered
`409 user already exists` to a legitimate registration.

A deactivated account (`is_active = false`) keeps holding its username and its
email: only a removal frees them. Removing an account deactivates it in the
same statement, so a removed user never keeps the `is_active` flag that says
the account is still usable.

The indexes are declared in the `UserModel` and created by the automatic
migration (`DB_AUTO_MIGRATION=true`). Environments that manage the schema by
hand need the DDL above, and a database created before this change also carries
the old full unique indexes, which keep blocking the reuse until they are
dropped:

```sql
DROP INDEX IF EXISTS idx_user_username;
DROP INDEX IF EXISTS idx_user_email;
```

A database created before the removal started deactivating the accounts also
holds rows that were deleted while still active, which can be fixed with:

```sql
UPDATE "user" SET is_active = false WHERE deleted_at IS NOT NULL AND is_active = true;
```

The indexes currently in place can be inspected with:

```sql
SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'user';
```

## Configuration

Settings are read from the environment at startup and the process **fails fast**
on a malformed value: an unparseable duration, integer, boolean, `ENVIRONMENT`
or `DB_SSLMODE` aborts the boot with an error naming the variable, instead of
silently falling back to the default. Unset or empty variables take their
default, except for the two variables without a safe one: `ENVIRONMENT` and
`DB_SSLMODE` are always required (a wrong `ENVIRONMENT` would silently expose
the docs and lower the log level, and a wrong `DB_SSLMODE` would downgrade the
database connection to plaintext). Every `.env` example ships both.

Credentials are checked with the policy that matches how they are used:

* **Hashable passwords** — every password the API stores (`ADMIN_PASSWORD`)
  passes through bcrypt, so it needs at least 8 characters and at most 72
  bytes. When `SEED_ENABLED=true` the admin identity is validated at boot:
  password, `ADMIN_USERNAME` and `ADMIN_EMAIL`.
* **Infrastructure credentials** — `DB_PASSWORD` and `REDIS_PASSWORD` are sent
  to PostgreSQL and Redis, which accept arbitrary lengths, so the 72 byte
  ceiling does not apply: only a minimum of 8 characters is enforced. An empty
  `REDIS_PASSWORD` is accepted, because the bundled Redis may run without auth.
* **Signing key** — `JWT_SECRET` is an HMAC key rather than a password and must
  be at least 32 characters.

`HASHER_COST` selects the bcrypt cost and must be between 4 and 31; the default
is 12. Costs below 10 are accepted but logged as a warning, since they weaken
every stored password.

## Documentation

* [Swagger / OpenAPI](docs/swagger.json) — generated API specification.

### Swagger UI

The interactive interface is available at `/swagger/index.html` and is only registered when the application is **not** running in production, ensuring that the explorer is never exposed in a production environment.

To regenerate the specification after modifying annotations or request/response types:

```sh
go install github.com/swaggo/swag/cmd/swag@v1.16.6

swag init -g cmd/api/main.go -o docs --parseDependency --parseInternal
```

The generated files in `docs/` are version-controlled so that the documentation available in each revision matches the code from that revision.
