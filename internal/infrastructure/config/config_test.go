package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// The variables without a usable default; every case starts from a valid
	// baseline so only the field under test can make LoadConfig fail.
	base := map[string]string{
		"JWT_SECRET":      strings.Repeat("s", 32),
		"DB_PASSWORD":     "secret-password",
		"ENVIRONMENT":     "development",
		"DB_SSLMODE":      "disable",
		"TLS_MODE":        "off",
		"TRUSTED_PROXIES": "",
	}

	tests := []struct {
		name    string
		env     map[string]string
		wantErr string // substring expected in the error; empty means success
	}{
		{
			name: "defaults when only the required secrets are set",
		},
		{
			name:    "rejects a missing JWT secret",
			env:     map[string]string{"JWT_SECRET": "too-short"},
			wantErr: "JWT_SECRET",
		},
		{
			name:    "rejects a missing DB password",
			env:     map[string]string{"DB_PASSWORD": ""},
			wantErr: "DB_PASSWORD",
		},
		{
			name:    "rejects a short DB password",
			env:     map[string]string{"DB_PASSWORD": "short"},
			wantErr: "DB_PASSWORD",
		},
		{
			name:    "rejects a missing environment",
			env:     map[string]string{"ENVIRONMENT": ""},
			wantErr: "ENVIRONMENT",
		},
		{
			name:    "rejects a missing ssl mode",
			env:     map[string]string{"DB_SSLMODE": ""},
			wantErr: "DB_SSLMODE",
		},
		{
			name:    "lists every missing required variable at once",
			env:     map[string]string{"ENVIRONMENT": "", "DB_SSLMODE": ""},
			wantErr: "ENVIRONMENT, DB_SSLMODE",
		},
		{
			name:    "rejects a short redis password when rate limiting is enabled",
			env:     map[string]string{"REDIS_PASSWORD": "short"},
			wantErr: "REDIS_PASSWORD",
		},
		{
			// Redis may legitimately run without auth, so an empty password is
			// not held to the minimum length.
			name: "accepts an empty redis password",
			env:  map[string]string{"REDIS_PASSWORD": ""},
		},
		{
			name: "accepts the example redis password placeholder",
			env:  map[string]string{"REDIS_PASSWORD": "CHANGE_ME"},
		},
		{
			name:    "rejects a malformed duration",
			env:     map[string]string{"SERVER_READ_TIMEOUT": "soon"},
			wantErr: "SERVER_READ_TIMEOUT",
		},
		{
			name:    "rejects a malformed integer",
			env:     map[string]string{"REDIS_DB": "one"},
			wantErr: "REDIS_DB",
		},
		{
			name:    "rejects a malformed boolean",
			env:     map[string]string{"SEED_ENABLED": "yes please"},
			wantErr: "SEED_ENABLED",
		},
		{
			name:    "rejects an unknown environment",
			env:     map[string]string{"ENVIRONMENT": "staging"},
			wantErr: "ENVIRONMENT",
		},
		{
			name:    "rejects an unknown ssl mode",
			env:     map[string]string{"DB_SSLMODE": "definitely"},
			wantErr: "DB_SSLMODE",
		},
		{
			name:    "rejects a malformed float",
			env:     map[string]string{"RATE_LIMIT_AUTH_REFILL_RATE": "fast"},
			wantErr: "RATE_LIMIT_AUTH_REFILL_RATE",
		},
		{
			name:    "rejects a non numeric hasher cost",
			env:     map[string]string{"HASHER_COST": "fast"},
			wantErr: "HASHER_COST",
		},
		{
			name:    "rejects a hasher cost below the bcrypt minimum",
			env:     map[string]string{"HASHER_COST": "3"},
			wantErr: "HASHER_COST",
		},
		{
			name:    "rejects a hasher cost above the bcrypt maximum",
			env:     map[string]string{"HASHER_COST": "40"},
			wantErr: "HASHER_COST",
		},
		{
			name: "accepts a valid hasher cost",
			env:  map[string]string{"HASHER_COST": "12"},
		},
		{
			name: "ignores the admin password when seeding is disabled",
			env:  map[string]string{"SEED_ENABLED": "false", "ADMIN_PASSWORD": "short"},
		},
		{
			name:    "rejects a short admin password when seeding is enabled",
			env:     map[string]string{"SEED_ENABLED": "true", "ADMIN_PASSWORD": "short"},
			wantErr: "ADMIN_PASSWORD",
		},
		{
			// Four runes but eight bytes: the byte based check alone would let
			// this through, so this case pins the rune aware policy.
			name:    "rejects a multi byte admin password that is short in runes",
			env:     map[string]string{"SEED_ENABLED": "true", "ADMIN_PASSWORD": "áááá"},
			wantErr: "ADMIN_PASSWORD",
		},
		{
			name:    "rejects an invalid admin username when seeding is enabled",
			env:     map[string]string{"SEED_ENABLED": "true", "ADMIN_PASSWORD": "AdminPass123", "ADMIN_USERNAME": "Not Valid"},
			wantErr: "ADMIN_USERNAME",
		},
		{
			name:    "rejects an invalid admin email when seeding is enabled",
			env:     map[string]string{"SEED_ENABLED": "true", "ADMIN_PASSWORD": "AdminPass123", "ADMIN_EMAIL": "not-an-email"},
			wantErr: "ADMIN_EMAIL",
		},
		{
			name: "accepts a valid admin identity when seeding is enabled",
			env:  map[string]string{"SEED_ENABLED": "true", "ADMIN_PASSWORD": "AdminPass123"},
		},
		{
			name:    "rejects an unknown TLS mode",
			env:     map[string]string{"TLS_MODE": "hybrid"},
			wantErr: "TLS_MODE",
		},
		{
			name:    "rejects proxy mode without trusted proxies",
			env:     map[string]string{"TLS_MODE": "proxy"},
			wantErr: "TRUSTED_PROXIES",
		},
		{
			name: "accepts proxy mode with trusted proxies",
			env:  map[string]string{"TLS_MODE": "proxy", "TRUSTED_PROXIES": "10.0.0.0/8"},
		},
		{
			name:    "rejects direct mode without certificate",
			env:     map[string]string{"TLS_MODE": "direct"},
			wantErr: "TLS_CERT_FILE",
		},
		{
			name:    "rejects direct mode without key",
			env:     map[string]string{"TLS_MODE": "direct", "TLS_CERT_FILE": "/certs/fullchain.pem"},
			wantErr: "TLS_KEY_FILE",
		},
		{
			name: "accepts direct mode with certificate and key",
			env: map[string]string{
				"TLS_MODE":      "direct",
				"TLS_CERT_FILE": "/certs/fullchain.pem",
				"TLS_KEY_FILE":  "/certs/privkey.pem",
			},
		},
		{
			name:    "rejects production with TLS disabled",
			env:     map[string]string{"ENVIRONMENT": "production", "TLS_MODE": "off", "CORS_ALLOWED_ORIGINS": "https://app.example.com"},
			wantErr: "TLS_MODE",
		},
		{
			name:    "rejects a negative HSTS max age",
			env:     map[string]string{"TLS_HSTS_MAX_AGE": "-1h"},
			wantErr: "TLS_HSTS_MAX_AGE",
		},
		{
			name:    "rejects a malformed HSTS max age",
			env:     map[string]string{"TLS_HSTS_MAX_AGE": "forever"},
			wantErr: "TLS_HSTS_MAX_AGE",
		},
		{
			name: "accepts explicit CORS origins",
			env:  map[string]string{"CORS_ALLOWED_ORIGINS": "https://app.example.com,http://localhost:3000"},
		},
		{
			name:    "rejects an invalid CORS origin",
			env:     map[string]string{"CORS_ALLOWED_ORIGINS": "app.example.com"},
			wantErr: "CORS_ALLOWED_ORIGINS",
		},
		{
			name:    "rejects a CORS origin with a path",
			env:     map[string]string{"CORS_ALLOWED_ORIGINS": "https://app.example.com/api"},
			wantErr: "CORS_ALLOWED_ORIGINS",
		},
		{
			name:    "rejects wildcard CORS origins with credentials",
			env:     map[string]string{"CORS_ALLOWED_ORIGINS": "*", "CORS_ALLOW_CREDENTIALS": "true"},
			wantErr: "CORS_ALLOW_CREDENTIALS",
		},
		{
			name:    "rejects an invalid CORS method",
			env:     map[string]string{"CORS_ALLOWED_METHODS": "GET,FETCH"},
			wantErr: "CORS_ALLOWED_METHODS",
		},
		{
			name:    "rejects a negative CORS max age",
			env:     map[string]string{"CORS_MAX_AGE": "-1h"},
			wantErr: "CORS_MAX_AGE",
		},
		{
			name:    "rejects production without CORS origins",
			env:     map[string]string{"ENVIRONMENT": "production", "TLS_MODE": "proxy", "TRUSTED_PROXIES": "10.0.0.0/8", "CORS_ALLOWED_ORIGINS": ""},
			wantErr: "CORS_ALLOWED_ORIGINS",
		},
		{
			name:    "rejects wildcard CORS origins in production",
			env:     map[string]string{"ENVIRONMENT": "production", "TLS_MODE": "proxy", "TRUSTED_PROXIES": "10.0.0.0/8", "CORS_ALLOWED_ORIGINS": "*"},
			wantErr: "CORS_ALLOWED_ORIGINS",
		},
		{
			name: "accepts explicit CORS origins in production",
			env:  map[string]string{"ENVIRONMENT": "production", "TLS_MODE": "proxy", "TRUSTED_PROXIES": "10.0.0.0/8", "CORS_ALLOWED_ORIGINS": "https://app.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range base {
				t.Setenv(key, value)
			}
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			cfg, err := LoadConfig()

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("LoadConfig() error = %v, want nil", err)
				}
				if cfg == nil {
					t.Fatal("LoadConfig() returned no config and no error")
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadConfig() error = %v, want it to mention %q", err, tt.wantErr)
			}
			if cfg != nil {
				t.Fatal("LoadConfig() returned a config alongside an error")
			}
		})
	}
}

func TestLoadConfigCORS(t *testing.T) {
	base := map[string]string{
		"JWT_SECRET":      strings.Repeat("s", 32),
		"DB_PASSWORD":     "secret-password",
		"ENVIRONMENT":     "development",
		"DB_SSLMODE":      "disable",
		"TLS_MODE":        "off",
		"TRUSTED_PROXIES": "",
	}
	for key, value := range base {
		t.Setenv(key, value)
	}

	t.Run("development defaults", func(t *testing.T) {
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig() error = %v, want nil", err)
		}

		if len(cfg.CORSAllowedOrigins) != 1 || cfg.CORSAllowedOrigins[0] != "*" {
			t.Fatalf("CORSAllowedOrigins = %v, want [*]", cfg.CORSAllowedOrigins)
		}
		if !containsString(cfg.CORSAllowedMethods, "PATCH") {
			t.Fatalf("CORSAllowedMethods = %v, want it to contain PATCH", cfg.CORSAllowedMethods)
		}
		if !containsString(cfg.CORSExposedHeaders, "X-Request-ID") {
			t.Fatalf("CORSExposedHeaders = %v, want it to contain X-Request-ID", cfg.CORSExposedHeaders)
		}
		if cfg.CORSAllowCredentials {
			t.Fatal("CORSAllowCredentials = true, want false")
		}
		if cfg.CORSMaxAge != 12*time.Hour {
			t.Fatalf("CORSMaxAge = %v, want %v", cfg.CORSMaxAge, 12*time.Hour)
		}
	})

	t.Run("explicit overrides", func(t *testing.T) {
		t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com, https://admin.example.com")
		t.Setenv("CORS_ALLOWED_METHODS", "get, patch")
		t.Setenv("CORS_MAX_AGE", "1h")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig() error = %v, want nil", err)
		}

		if got, want := len(cfg.CORSAllowedOrigins), 2; got != want {
			t.Fatalf("len(CORSAllowedOrigins) = %d, want %d", got, want)
		}
		if got, want := cfg.CORSAllowedOrigins[1], "https://admin.example.com"; got != want {
			t.Fatalf("CORSAllowedOrigins[1] = %q, want %q", got, want)
		}
		if got, want := cfg.CORSAllowedMethods[0], "GET"; got != want {
			t.Fatalf("CORSAllowedMethods[0] = %q, want %q", got, want)
		}
		if got, want := cfg.CORSAllowedMethods[1], "PATCH"; got != want {
			t.Fatalf("CORSAllowedMethods[1] = %q, want %q", got, want)
		}
		if cfg.CORSMaxAge != time.Hour {
			t.Fatalf("CORSMaxAge = %v, want %v", cfg.CORSMaxAge, time.Hour)
		}
	})
}

func TestValidateRateLimit(t *testing.T) {
	valid := Config{
		RateLimitEnabled:      true,
		RateLimitAuthCapacity: 10,
		RateLimitAuthRefill:   1,
		RateLimitUserCapacity: 60,
		RateLimitUserRefill:   1,
		RedisAddr:             "localhost:6379",
	}

	copyWith := func(mutate func(*Config)) *Config {
		c := valid
		mutate(&c)
		return &c
	}

	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "disabled skips validation",
			cfg:  &Config{RateLimitEnabled: false},
		},
		{
			name: "enabled and valid",
			cfg:  &valid,
		},
		{
			name:    "auth capacity must be positive",
			cfg:     copyWith(func(c *Config) { c.RateLimitAuthCapacity = 0 }),
			wantErr: true,
		},
		{
			name:    "auth refill must be positive",
			cfg:     copyWith(func(c *Config) { c.RateLimitAuthRefill = 0 }),
			wantErr: true,
		},
		{
			name:    "user capacity must be positive",
			cfg:     copyWith(func(c *Config) { c.RateLimitUserCapacity = -1 }),
			wantErr: true,
		},
		{
			name:    "user refill must be positive",
			cfg:     copyWith(func(c *Config) { c.RateLimitUserRefill = 0 }),
			wantErr: true,
		},
		{
			name:    "redis addr is required when enabled",
			cfg:     copyWith(func(c *Config) { c.RedisAddr = "" }),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validateRateLimit()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateRateLimit() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateServer(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid body limit and no proxies",
			cfg:  &Config{ServerMaxBodyBytes: 2 << 20},
		},
		{
			name: "accepts bare IPs and CIDRs",
			cfg:  &Config{ServerMaxBodyBytes: 1, TrustedProxies: []string{"127.0.0.1", "10.0.0.0/8", "::1"}},
		},
		{
			name:    "rejects a non positive body limit",
			cfg:     &Config{ServerMaxBodyBytes: 0},
			wantErr: true,
		},
		{
			name:    "rejects an invalid proxy entry",
			cfg:     &Config{ServerMaxBodyBytes: 1, TrustedProxies: []string{"not-an-ip"}},
			wantErr: true,
		},
		{
			name:    "rejects a malformed CIDR",
			cfg:     &Config{ServerMaxBodyBytes: 1, TrustedProxies: []string{"10.0.0.0/99"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validateServer()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTLS(t *testing.T) {
	valid := Config{
		Environment:    EnvironmentDevelopment,
		TLSMode:        TLSModeOff,
		TLSHSTSMaxAge:  time.Hour,
		TrustedProxies: []string{"10.0.0.0/8"},
		TLSCertFile:    "/certs/fullchain.pem",
		TLSKeyFile:     "/certs/privkey.pem",
	}

	copyWith := func(mutate func(*Config)) *Config {
		c := valid
		mutate(&c)
		return &c
	}

	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "off is valid outside production",
			cfg:  &valid,
		},
		{
			name:    "off is invalid in production",
			cfg:     copyWith(func(c *Config) { c.Environment = EnvironmentProduction }),
			wantErr: true,
		},
		{
			name: "proxy is valid with trusted proxies",
			cfg:  copyWith(func(c *Config) { c.TLSMode = TLSModeProxy }),
		},
		{
			name: "proxy is valid in production with trusted proxies",
			cfg: copyWith(func(c *Config) {
				c.Environment = EnvironmentProduction
				c.TLSMode = TLSModeProxy
			}),
		},
		{
			name: "proxy requires trusted proxies",
			cfg: copyWith(func(c *Config) {
				c.TLSMode = TLSModeProxy
				c.TrustedProxies = nil
			}),
			wantErr: true,
		},
		{
			name: "direct is valid with a certificate and key",
			cfg:  copyWith(func(c *Config) { c.TLSMode = TLSModeDirect }),
		},
		{
			name: "direct requires both certificate files",
			cfg: copyWith(func(c *Config) {
				c.TLSMode = TLSModeDirect
				c.TLSKeyFile = ""
			}),
			wantErr: true,
		},
		{
			name:    "rejects a negative HSTS max age",
			cfg:     copyWith(func(c *Config) { c.TLSHSTSMaxAge = -time.Second }),
			wantErr: true,
		},
		{
			name:    "rejects an unsupported mode",
			cfg:     copyWith(func(c *Config) { c.TLSMode = "hybrid" }),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validateTLS()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateTLS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTLSEnabled(t *testing.T) {
	tests := []struct {
		mode TLSMode
		want bool
	}{
		{mode: TLSModeOff, want: false},
		{mode: TLSModeProxy, want: true},
		{mode: TLSModeDirect, want: true},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			cfg := Config{TLSMode: tt.mode}
			if got := cfg.TLSEnabled(); got != tt.want {
				t.Fatalf("TLSEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDatabaseUsesTLS(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{mode: "disable", want: false},
		{mode: "allow", want: false},
		{mode: "prefer", want: false},
		{mode: "require", want: true},
		{mode: "verify-ca", want: true},
		{mode: "verify-full", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			cfg := Config{DBSSLMode: tt.mode}
			if got := cfg.DatabaseUsesTLS(); got != tt.want {
				t.Fatalf("DatabaseUsesTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateCORS(t *testing.T) {
	valid := Config{
		Environment:        EnvironmentDevelopment,
		CORSAllowedOrigins: []string{"https://app.example.com"},
		CORSAllowedMethods: []string{"GET", "POST", "PATCH"},
		CORSAllowedHeaders: []string{"Authorization"},
		CORSMaxAge:         time.Hour,
	}

	copyWith := func(mutate func(*Config)) *Config {
		c := valid
		mutate(&c)
		return &c
	}

	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid explicit allowlist",
			cfg:  &valid,
		},
		{
			name: "wildcard is allowed in development without credentials",
			cfg:  copyWith(func(c *Config) { c.CORSAllowedOrigins = []string{"*"} }),
		},
		{
			name: "wildcard is rejected with credentials",
			cfg: copyWith(func(c *Config) {
				c.CORSAllowedOrigins = []string{"*"}
				c.CORSAllowCredentials = true
			}),
			wantErr: true,
		},
		{
			name: "production requires an allowlist",
			cfg: copyWith(func(c *Config) {
				c.Environment = EnvironmentProduction
				c.CORSAllowedOrigins = nil
			}),
			wantErr: true,
		},
		{
			name: "production rejects the wildcard",
			cfg: copyWith(func(c *Config) {
				c.Environment = EnvironmentProduction
				c.CORSAllowedOrigins = []string{"*"}
			}),
			wantErr: true,
		},
		{
			name:    "rejects an origin without a scheme",
			cfg:     copyWith(func(c *Config) { c.CORSAllowedOrigins = []string{"app.example.com"} }),
			wantErr: true,
		},
		{
			name:    "rejects an origin with a trailing slash",
			cfg:     copyWith(func(c *Config) { c.CORSAllowedOrigins = []string{"https://app.example.com/"} }),
			wantErr: true,
		},
		{
			name:    "rejects an unsupported subdomain wildcard",
			cfg:     copyWith(func(c *Config) { c.CORSAllowedOrigins = []string{"https://*.example.com"} }),
			wantErr: true,
		},
		{
			name:    "rejects an origin without a hostname",
			cfg:     copyWith(func(c *Config) { c.CORSAllowedOrigins = []string{"http://:3000"} }),
			wantErr: true,
		},
		{
			name:    "rejects an unknown method",
			cfg:     copyWith(func(c *Config) { c.CORSAllowedMethods = []string{"FETCH"} }),
			wantErr: true,
		},
		{
			name:    "rejects a negative max age",
			cfg:     copyWith(func(c *Config) { c.CORSMaxAge = -time.Second }),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validateCORS()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateCORS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCORSNormalizesMethods(t *testing.T) {
	cfg := Config{
		Environment:        EnvironmentDevelopment,
		CORSAllowedOrigins: []string{"*"},
		CORSAllowedMethods: []string{"get", " Patch "},
	}

	if err := cfg.validateCORS(); err != nil {
		t.Fatalf("validateCORS() error = %v, want nil", err)
	}

	if got, want := cfg.CORSAllowedMethods[0], "GET"; got != want {
		t.Fatalf("method[0] = %q, want %q", got, want)
	}
	if got, want := cfg.CORSAllowedMethods[1], "PATCH"; got != want {
		t.Fatalf("method[1] = %q, want %q", got, want)
	}
}
