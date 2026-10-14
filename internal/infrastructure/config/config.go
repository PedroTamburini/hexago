package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentProduction  Environment = "production"
)

type Config struct {
	ServerPort            string
	ServerShutdownTimeout time.Duration
	ServerReadTimeOut     time.Duration
	ServerWriteTimeOut    time.Duration
	ServerIdleTimeOut     time.Duration
	Environment           Environment
	DBHost                string
	DBPort                string
	DBUser                string
	DBName                string
	DBPassword            string
	DBSSLMode             string
	DBTimeZone            string
	DBMaxOpenConns        int
	DBMaxIdleConns        int
	DBConnMaxLifeTime     time.Duration
	DBAutoMigration       bool
	HasherCost            int
	JWTSecret             string
	JWTExpiration         time.Duration
	SeedEnabled           bool
	AdminUsername         string
	AdminEmail            string
	AdminPassword         string
	RedisAddr             string
	RedisPassword         string
	RedisDB               int
	RedisPoolSize         int
	RateLimitEnabled      bool
	RateLimitAuthCapacity int
	RateLimitAuthRefill   float64
	RateLimitUserCapacity int
	RateLimitUserRefill   float64
}

func (c *Config) IsProduction() bool {
	return c.Environment == EnvironmentProduction
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading .env: %w", err)
	}

	cfg := &Config{
		ServerPort:            env("SERVER_PORT", "8080"),
		ServerShutdownTimeout: envParse("SERVER_SHUTDOWN_TIMEOUT", 5*time.Second, time.ParseDuration),
		ServerReadTimeOut:     envParse("SERVER_READ_TIMEOUT", 10*time.Second, time.ParseDuration),
		ServerWriteTimeOut:    envParse("SERVER_WRITE_TIMEOUT", 10*time.Second, time.ParseDuration),
		ServerIdleTimeOut:     envParse("SERVER_IDLE_TIMEOUT", 60*time.Second, time.ParseDuration),
		Environment:           envParse("ENVIRONMENT", EnvironmentDevelopment, validEnvironment),
		DBHost:                env("DB_HOST", "localhost"),
		DBPort:                env("DB_PORT", "5432"),
		DBUser:                env("DB_USER", "postgres"),
		DBName:                env("DB_NAME", "hexago"),
		DBPassword:            env("DB_PASSWORD", ""),
		DBSSLMode:             envParse("DB_SSLMODE", "disable", validSSLMode),
		DBTimeZone:            env("DB_TIMEZONE", "UTC"),
		DBMaxOpenConns:        envParse("DB_MAX_OPEN_CONNS", 25, strconv.Atoi),
		DBMaxIdleConns:        envParse("DB_MAX_IDLE_CONNS", 25, strconv.Atoi),
		DBConnMaxLifeTime:     envParse("DB_CONN_MAX_LIFETIME", 5*time.Minute, time.ParseDuration),
		DBAutoMigration:       envParse("DB_AUTO_MIGRATION", false, strconv.ParseBool),
		HasherCost:            envParse("HASHER_COST", 12, strconv.Atoi),
		JWTSecret:             env("JWT_SECRET", ""),
		JWTExpiration:         envParse("JWT_EXPIRATION", 24*time.Hour, time.ParseDuration),
		SeedEnabled:           envParse("SEED_ENABLED", false, strconv.ParseBool),
		AdminUsername:         env("ADMIN_USERNAME", "admin.local"),
		AdminEmail:            env("ADMIN_EMAIL", "admin@hexago.local"),
		AdminPassword:         env("ADMIN_PASSWORD", ""),
		RedisAddr:             env("REDIS_ADDR", "localhost:6379"),
		RedisPassword:         env("REDIS_PASSWORD", ""),
		RedisDB:               envParse("REDIS_DB", 0, strconv.Atoi),
		RedisPoolSize:         envParse("REDIS_POOL_SIZE", 10, strconv.Atoi),
		RateLimitEnabled:      envParse("RATE_LIMIT_ENABLED", true, strconv.ParseBool),
		RateLimitAuthCapacity: envParse("RATE_LIMIT_AUTH_CAPACITY", 10, strconv.Atoi),
		RateLimitAuthRefill:   envParse("RATE_LIMIT_AUTH_REFILL_RATE", 0.2, parseFloat),
		RateLimitUserCapacity: envParse("RATE_LIMIT_USER_CAPACITY", 60, strconv.Atoi),
		RateLimitUserRefill:   envParse("RATE_LIMIT_USER_REFILL_RATE", 1.0, parseFloat),
	}

	if len(cfg.JWTSecret) < 32 || cfg.DBPassword == "" {
		return nil, errors.New("JWT_SECRET (min 32 chars) and DB_PASSWORD are required")
	}

	if cfg.SeedEnabled && cfg.AdminPassword == "" {
		return nil, errors.New("SEED_ENABLED requires ADMIN_PASSWORD to be set")
	}

	if err := cfg.validateRateLimit(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateRateLimit rejects a misconfigured limiter at boot instead of letting it
// fail on the first request. Capacity and refill must both be positive: a zero
// refill would drain the bucket forever, and a zero capacity would reject every
// request.
func (c *Config) validateRateLimit() error {
	if !c.RateLimitEnabled {
		return nil
	}

	if c.RateLimitAuthCapacity <= 0 || c.RateLimitAuthRefill <= 0 {
		return errors.New("RATE_LIMIT_AUTH_CAPACITY and RATE_LIMIT_AUTH_REFILL_RATE must be positive")
	}

	if c.RateLimitUserCapacity <= 0 || c.RateLimitUserRefill <= 0 {
		return errors.New("RATE_LIMIT_USER_CAPACITY and RATE_LIMIT_USER_REFILL_RATE must be positive")
	}

	if c.RedisAddr == "" {
		return errors.New("REDIS_ADDR is required when rate limiting is enabled")
	}

	return nil
}

func parseFloat(value string) (float64, error) {
	return strconv.ParseFloat(value, 64)
}

func env(key, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	return value
}

func envParse[T any](key string, fallback T, parse func(string) (T, error)) T {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	parsed, err := parse(value)
	if err != nil {
		log.Printf("config: invalid %s (%v); using default %v", key, err, fallback)
		return fallback
	}
	return parsed
}

func validEnvironment(value string) (Environment, error) {
	env := Environment(value)
	if env != EnvironmentDevelopment && env != EnvironmentProduction {
		return "", fmt.Errorf("must be one of %s, %s", EnvironmentDevelopment, EnvironmentProduction)
	}
	return env, nil
}

func validSSLMode(value string) (string, error) {
	switch value {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		return value, nil
	}
	return "", fmt.Errorf("must be one of disable, allow, prefer, require, verify-ca, verify-full")
}
