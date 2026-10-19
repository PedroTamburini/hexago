package config

import (
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// The variables without a usable default; every case starts from a valid
	// baseline so only the field under test can make LoadConfig fail.
	base := map[string]string{
		"JWT_SECRET":  strings.Repeat("s", 32),
		"DB_PASSWORD": "secret-password",
		"ENVIRONMENT": "development",
		"DB_SSLMODE":  "disable",
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
