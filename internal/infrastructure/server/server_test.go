package server

import (
	"testing"

	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
)

func TestNewTLSConfig(t *testing.T) {
	t.Run("off keeps the listener plaintext", func(t *testing.T) {
		tlsConfig, err := newTLSConfig(&config.Config{TLSMode: config.TLSModeOff})
		if err != nil {
			t.Fatalf("newTLSConfig() error = %v, want nil", err)
		}
		if tlsConfig != nil {
			t.Fatal("newTLSConfig() returned a TLS config for TLS_MODE=off")
		}
	})

	t.Run("proxy keeps the listener plaintext", func(t *testing.T) {
		tlsConfig, err := newTLSConfig(&config.Config{TLSMode: config.TLSModeProxy})
		if err != nil {
			t.Fatalf("newTLSConfig() error = %v, want nil", err)
		}
		if tlsConfig != nil {
			t.Fatal("newTLSConfig() returned a TLS config for TLS_MODE=proxy")
		}
	})

	t.Run("direct rejects an unreadable certificate", func(t *testing.T) {
		_, err := newTLSConfig(&config.Config{
			TLSMode:     config.TLSModeDirect,
			TLSCertFile: "/does/not/exist/fullchain.pem",
			TLSKeyFile:  "/does/not/exist/privkey.pem",
		})
		if err == nil {
			t.Fatal("newTLSConfig() error = nil, want a certificate loading error")
		}
	})
}
