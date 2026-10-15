package database

import (
	"net/url"
	"testing"

	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
)

func TestDatabaseURLEncodesReservedCharacters(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "db.internal",
		DBPort:     "5432",
		DBUser:     "admin",
		DBPassword: "p@ss:w/rd?#&=+",
		DBName:     "hexago",
		DBSSLMode:  "require",
		DBTimeZone: "UTC",
	}

	dsn := DatabaseURL(cfg)

	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DatabaseURL produced an unparseable DSN %q: %v", dsn, err)
	}

	if parsed.Scheme != "postgres" {
		t.Fatalf("scheme = %q, want postgres", parsed.Scheme)
	}

	if parsed.Host != "db.internal:5432" {
		t.Fatalf("host = %q, want db.internal:5432", parsed.Host)
	}

	if parsed.User.Username() != "admin" {
		t.Fatalf("user = %q, want admin", parsed.User.Username())
	}

	// The password must survive the round trip even though it contains
	// characters that are structural in a URL ("@", ":", "/", "?", "#", "&").
	password, ok := parsed.User.Password()
	if !ok {
		t.Fatal("expected the DSN to carry a password")
	}
	if password != cfg.DBPassword {
		t.Fatalf("password = %q, want %q", password, cfg.DBPassword)
	}

	if parsed.Path != "/hexago" {
		t.Fatalf("path = %q, want /hexago", parsed.Path)
	}

	query := parsed.Query()
	if query.Get("sslmode") != "require" {
		t.Fatalf("sslmode = %q, want require", query.Get("sslmode"))
	}
	if query.Get("TimeZone") != "UTC" {
		t.Fatalf("TimeZone = %q, want UTC", query.Get("TimeZone"))
	}
}

func TestDatabaseURLBracketsIPv6Host(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "::1",
		DBPort:     "5432",
		DBUser:     "postgres",
		DBPassword: "secret",
		DBName:     "hexago",
		DBSSLMode:  "disable",
		DBTimeZone: "UTC",
	}

	dsn := DatabaseURL(cfg)

	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DatabaseURL produced an unparseable DSN %q: %v", dsn, err)
	}

	if parsed.Host != "[::1]:5432" {
		t.Fatalf("host = %q, want [::1]:5432", parsed.Host)
	}
}
