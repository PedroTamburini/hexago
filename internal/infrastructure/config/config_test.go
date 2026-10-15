package config

import "testing"

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
