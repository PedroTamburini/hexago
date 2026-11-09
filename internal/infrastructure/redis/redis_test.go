package redis

import (
	"io"
	"log/slog"
	"testing"

	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"github.com/alicebob/miniredis/v2"
)

func testLogger() *logger.Logger {
	return &logger.Logger{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestNewClientConnects(t *testing.T) {
	server := miniredis.RunT(t)

	client, err := NewClient(&config.Config{
		RedisAddr:     server.Addr(),
		RedisPoolSize: 2,
	}, testLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})

	if err := client.Ping(t.Context()).Err(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestNewClientFailsWhenRedisIsUnreachable(t *testing.T) {
	// Point at a port that has already been closed so the mandatory ping fails.
	server := miniredis.RunT(t)
	addr := server.Addr()
	server.Close()

	client, err := NewClient(&config.Config{RedisAddr: addr}, testLogger())
	if err == nil {
		_ = client.Close()
		t.Fatal("NewClient() error = nil, want a connection error")
	}

	if client != nil {
		t.Fatal("NewClient() returned a client alongside an error")
	}
}
