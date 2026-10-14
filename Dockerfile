# syntax=docker/dockerfile:1

# --- Build stage ---------------------------------------------------------
# The dependencies are downloaded before the source is copied so that editing
# code does not invalidate the (slow) module download layer.
FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO is disabled so the binary is static and can run on a minimal base image;
# pgx and bcrypt are pure Go, so nothing requires cgo.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

# --- Runtime stage -------------------------------------------------------
# alpine (not distroless) on purpose: it ships a shell and wget, which the
# compose healthcheck uses to probe /health, and tzdata, which pgx reads when
# the DSN sets TimeZone.
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 app

COPY --from=builder /out/api /api

USER app
EXPOSE 8080
ENTRYPOINT ["/api"]
