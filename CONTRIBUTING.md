# Contributing to hexago

Thanks for contributing. This guide describes the local workflow, the
architectural conventions and the checks a change is expected to pass.

## Prerequisites

* Go 1.26 or newer (see `go.mod`).
* Docker and Docker Compose for the full stack (PostgreSQL and Redis), or the
  equivalent services running locally.
* [`swag`](https://github.com/swaggo/swag) when changing the OpenAPI
  annotations.

## Local setup

```sh
cp .env.example .env    # then edit JWT_SECRET, DB_PASSWORD, ...
docker compose up --build
```

The API is available at `http://localhost:8080` and Swagger UI at
`/swagger/index.html`. If you prefer to run the API on the host, start only the
dependencies with `docker compose up postgres redis` and run:

```sh
go run ./cmd/api
```

## Checks before opening a pull request

```sh
go fmt ./...
go build ./...
go vet ./...
go test ./...
```

`go test ./...` includes the structural tests in `internal/architecture`, which
enforce the hexagonal dependency rule. Run the whole suite, not just the package
you touched.

## Architecture

The project is **layer first, with feature files inside each layer**:

```text
internal/
├── core/
│   ├── domain/            # entities, domain errors, validators
│   ├── dto/               # use case input/output data
│   ├── port/primary/      # capabilities exposed by the core
│   ├── port/secondary/    # capabilities required by the core
│   ├── permission/        # RBAC permission names
│   └── usecase/           # orchestration, one file per capability
├── adapter/
│   ├── primary/http/      # routes, middleware, handlers, request/response
│   └── secondary/         # GORM repositories, JWT, hashing, Redis stores
└── infrastructure/        # configuration, connections and startup
```

Rules to preserve:

* Dependencies only point inward: `adapter -> core` and
  `infrastructure -> core`.
* `internal/core` must not import Gin, GORM, Redis, Swagger or any adapter /
  infrastructure package.
* An adapter must not import infrastructure.
* Keep transport concerns (binding, status codes, JSON) in
  `adapter/primary/http`; keep business decisions and error mapping in the use
  cases.
* Prefer a narrow port over a broad one. A consumer should depend only on the
  capability it uses.
* Do not let the password hash enter a general user read model. Credentials are
  read and written through `CredentialsRepository` only.
* Keep role queries in `RoleRepository` and profile lifecycle operations in
  `UserRepository`.

## Adding or changing an endpoint

1. Add or update the domain entity/validator and the DTOs in `internal/core`.
2. Declare the primary port if the HTTP layer needs a new capability.
3. Declare a secondary port only when a new external capability is required.
4. Implement the use case in its own file under `internal/core/usecase`.
5. Add the handler and request/response types in `adapter/primary/http`.
6. Register the route in `internal/adapter/primary/http/routes/routes.go` and
   wire the dependencies in `cmd/api/main.go`.
7. Add or update unit tests next to the use case.
8. Update the Swagger annotations and regenerate the docs (see below).

HTTP status codes are part of the public contract: map domain errors to the
status codes already used by the neighbouring endpoints instead of inventing a
new response shape.

## Tests

* Unit tests live next to the code they cover (`*_test.go`).
* Shared test doubles for the use case package live in
  `internal/core/usecase/stubs_test.go`.
* Prefer table-driven tests for validation and branching rules.
* Cover the success path and every domain error a new rule can produce.

Run a single package while iterating:

```sh
go test ./internal/core/usecase
```

## OpenAPI / Swagger

The generated files in `docs/` are version-controlled. If you change an
annotation or a request/response type, regenerate them:

```sh
go install github.com/swaggo/swag/cmd/swag@v1.16.6
swag init -g cmd/api/main.go -o docs --parseDependency --parseInternal
```

Commit the regenerated `docs/docs.go`, `docs/swagger.json` and
`docs/swagger.yaml` together with the code change.

## Commits and pull requests

* Keep each pull request focused; avoid unrelated refactors.
* Describe the behaviour change and how it was verified.
* Mention any migration or configuration change explicitly.
* Do not commit secrets or a filled `.env` file.
