# hexago

Go backend template using Hexagonal Architecture, DDD principles, JWT authentication, PostgreSQL, and Docker.

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
