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

## Request limits and client IP

* **Body size** — request bodies larger than `SERVER_MAX_BODY_BYTES` (default
  `2097152`, i.e. 2 MiB) are rejected with `413 Request Entity Too Large`. This
  bounds memory usage regardless of what a client sends.
* **Trusted proxies** — the client IP used for rate limiting comes from the
  connection (`RemoteAddr`) by default, and `X-Forwarded-For`/`X-Real-IP` are
  ignored. When the API runs behind a reverse proxy or load balancer, set
  `TRUSTED_PROXIES` to that proxy's IPs/CIDRs (comma-separated) so the forwarded
  client IP is honoured without letting arbitrary clients spoof it.

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
