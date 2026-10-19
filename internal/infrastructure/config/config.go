package config

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PedroTamburini/hexago/internal/core/domain/validator"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentProduction  Environment = "production"

	// recommendedHasherCost is bcrypt's default. Lower costs are accepted (they
	// keep tests fast) but warned about, because they weaken every stored hash.
	recommendedHasherCost = 10

	// minDatabasePasswordLength is the floor for the credentials handed to
	// PostgreSQL and Redis.
	minDatabasePasswordLength = 8
)

// requiredEnvNames have no safe default, so guessing them would be actively
// dangerous: a wrong ENVIRONMENT silently exposes the docs and lowers the log
// level, and a wrong DB_SSLMODE silently downgrades the connection to plaintext.
var requiredEnvNames = []string{"ENVIRONMENT", "DB_SSLMODE"}

type Config struct {
	ServerPort            string
	ServerShutdownTimeout time.Duration
	ServerReadTimeOut     time.Duration
	ServerWriteTimeOut    time.Duration
	ServerIdleTimeOut     time.Duration
	ServerMaxBodyBytes    int
	// TrustedProxies lists the IPs/CIDRs whose forwarding headers
	// (X-Forwarded-For/X-Real-IP) may be trusted when resolving the client IP.
	// Empty means "trust no proxy", so c.ClientIP() uses the socket address.
	TrustedProxies        []string
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

	// Report every absent variable at once instead of one boot at a time.
	var missing []string
	for _, key := range requiredEnvNames {
		if os.Getenv(key) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	var parseErr error

	cfg := &Config{
		ServerPort:            env("SERVER_PORT", "8080"),
		ServerShutdownTimeout: envParse(&parseErr, "SERVER_SHUTDOWN_TIMEOUT", 5*time.Second, time.ParseDuration),
		ServerReadTimeOut:     envParse(&parseErr, "SERVER_READ_TIMEOUT", 10*time.Second, time.ParseDuration),
		ServerWriteTimeOut:    envParse(&parseErr, "SERVER_WRITE_TIMEOUT", 10*time.Second, time.ParseDuration),
		ServerIdleTimeOut:     envParse(&parseErr, "SERVER_IDLE_TIMEOUT", 60*time.Second, time.ParseDuration),
		ServerMaxBodyBytes:    envParse(&parseErr, "SERVER_MAX_BODY_BYTES", 2<<20, strconv.Atoi),
		TrustedProxies:        envList("TRUSTED_PROXIES"),
		Environment:           envParse(&parseErr, "ENVIRONMENT", EnvironmentDevelopment, validEnvironment),
		DBHost:                env("DB_HOST", "localhost"),
		DBPort:                env("DB_PORT", "5432"),
		DBUser:                env("DB_USER", "postgres"),
		DBName:                env("DB_NAME", "hexago"),
		DBPassword:            env("DB_PASSWORD", ""),
		DBSSLMode:             envParse(&parseErr, "DB_SSLMODE", "disable", validSSLMode),
		DBTimeZone:            env("DB_TIMEZONE", "UTC"),
		DBMaxOpenConns:        envParse(&parseErr, "DB_MAX_OPEN_CONNS", 25, strconv.Atoi),
		DBMaxIdleConns:        envParse(&parseErr, "DB_MAX_IDLE_CONNS", 25, strconv.Atoi),
		DBConnMaxLifeTime:     envParse(&parseErr, "DB_CONN_MAX_LIFETIME", 5*time.Minute, time.ParseDuration),
		DBAutoMigration:       envParse(&parseErr, "DB_AUTO_MIGRATION", false, strconv.ParseBool),
		HasherCost:            envParse(&parseErr, "HASHER_COST", 12, strconv.Atoi),
		JWTSecret:             env("JWT_SECRET", ""),
		JWTExpiration:         envParse(&parseErr, "JWT_EXPIRATION", 24*time.Hour, time.ParseDuration),
		SeedEnabled:           envParse(&parseErr, "SEED_ENABLED", false, strconv.ParseBool),
		AdminUsername:         env("ADMIN_USERNAME", "admin.local"),
		AdminEmail:            env("ADMIN_EMAIL", "admin@hexago.local"),
		AdminPassword:         env("ADMIN_PASSWORD", ""),
		RedisAddr:             env("REDIS_ADDR", "localhost:6379"),
		RedisPassword:         env("REDIS_PASSWORD", ""),
		RedisDB:               envParse(&parseErr, "REDIS_DB", 0, strconv.Atoi),
		RedisPoolSize:         envParse(&parseErr, "REDIS_POOL_SIZE", 10, strconv.Atoi),
		RateLimitEnabled:      envParse(&parseErr, "RATE_LIMIT_ENABLED", true, strconv.ParseBool),
		RateLimitAuthCapacity: envParse(&parseErr, "RATE_LIMIT_AUTH_CAPACITY", 10, strconv.Atoi),
		RateLimitAuthRefill:   envParse(&parseErr, "RATE_LIMIT_AUTH_REFILL_RATE", 0.2, parseFloat),
		RateLimitUserCapacity: envParse(&parseErr, "RATE_LIMIT_USER_CAPACITY", 60, strconv.Atoi),
		RateLimitUserRefill:   envParse(&parseErr, "RATE_LIMIT_USER_REFILL_RATE", 1.0, parseFloat),
	}

	// A malformed value is a deployment mistake, not something to paper over
	// with a default: report it before any connection is opened.
	if parseErr != nil {
		return nil, parseErr
	}

	if err := cfg.validateSecrets(); err != nil {
		return nil, err
	}

	if err := cfg.validateSeed(); err != nil {
		return nil, err
	}

	if err := cfg.validateHasher(); err != nil {
		return nil, err
	}

	if err := cfg.validateRateLimit(); err != nil {
		return nil, err
	}

	if err := cfg.validateServer(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateSecrets rejects the values the API cannot run without. JWT_SECRET is
// the HMAC key behind every token, so a short one is a real weakness, and the
// database password has no meaningful default.
func (c *Config) validateSecrets() error {
	if len(c.JWTSecret) < 32 {
		return errors.New("JWT_SECRET must be at least 32 characters")
	}

	if err := validateDatabasePassword("DB_PASSWORD", c.DBPassword); err != nil {
		return err
	}

	return nil
}

// validateDatabasePassword enforces the minimum length shared by the credentials
// handed to PostgreSQL and Redis.
func validateDatabasePassword(name, password string) error {
	if len(password) < minDatabasePasswordLength {
		return fmt.Errorf("%s must be at least %d characters", name, minDatabasePasswordLength)
	}

	return nil
}

// validateSeed rejects an unusable admin identity at boot. The password policy is
// the one shared with every other entry point, so the two cannot drift apart.
func (c *Config) validateSeed() error {
	if !c.SeedEnabled {
		return nil
	}

	if !validator.IsValidPassword(c.AdminPassword) {
		return errors.New("SEED_ENABLED requires ADMIN_PASSWORD to meet the password policy (min 8 characters, max 72 bytes)")
	}

	if !validator.IsValidUsername(c.AdminUsername) {
		return fmt.Errorf("ADMIN_USERNAME %q is not a valid username", c.AdminUsername)
	}

	if !validator.IsValidEmail(c.AdminEmail) {
		return fmt.Errorf("ADMIN_EMAIL %q is not a valid email", c.AdminEmail)
	}

	return nil
}

// validateHasher rejects a cost bcrypt would refuse at runtime, so a bad value
// fails the boot instead of the first login.
func (c *Config) validateHasher() error {
	if c.HasherCost < bcrypt.MinCost || c.HasherCost > bcrypt.MaxCost {
		return fmt.Errorf("HASHER_COST must be between %d and %d, got %d", bcrypt.MinCost, bcrypt.MaxCost, c.HasherCost)
	}

	if c.HasherCost < recommendedHasherCost {
		log.Printf("config: HASHER_COST=%d is below the recommended minimum %d", c.HasherCost, recommendedHasherCost)
	}

	return nil
}

// validateServer rejects invalid transport/bootstrap settings at boot instead of
// letting them surface on the first request.
func (c *Config) validateServer() error {
	if c.ServerMaxBodyBytes <= 0 {
		return errors.New("SERVER_MAX_BODY_BYTES must be positive")
	}

	return c.validateTrustedProxies()
}

// validateTrustedProxies ensures every entry is a parseable IP or CIDR. gin
// accepts bare IPs (treated as /32 or /128) in addition to CIDR blocks.
func (c *Config) validateTrustedProxies() error {
	for _, proxy := range c.TrustedProxies {
		if net.ParseIP(proxy) != nil {
			continue
		}

		if _, _, err := net.ParseCIDR(proxy); err != nil {
			return fmt.Errorf("TRUSTED_PROXIES entry %q is not a valid IP or CIDR", proxy)
		}
	}

	return nil
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

	// An empty password is valid: the bundled Redis starts without auth unless
	// REDIS_PASSWORD is set. Only a provided-but-weak password is rejected.
	if c.RedisPassword != "" {
		if err := validateDatabasePassword("REDIS_PASSWORD", c.RedisPassword); err != nil {
			return err
		}
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

// envList parses a comma-separated environment variable into a slice, trimming
// whitespace and dropping empty entries. An unset or blank value yields nil.
func envList(key string) []string {
	value := os.Getenv(key)
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			items = append(items, trimmed)
		}
	}

	return items
}

// envParse reads an environment variable into its typed form. Unset or empty
// variables fall back to the default; a malformed value is recorded once in err
// so LoadConfig can abort the boot instead of silently using the default.
func envParse[T any](err *error, key string, fallback T, parse func(string) (T, error)) T {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	parsed, parseErr := parse(value)
	if parseErr != nil {
		if *err == nil {
			*err = fmt.Errorf("invalid %s: %w", key, parseErr)
		}
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
