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
}

func (c *Config) IsProduction() bool {
	return c.Environment == EnvironmentProduction
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading .env: %w", err)
	}

	if len(env("JWT_SECRET", "")) < 32 || env("DB_PASSWORD", "") == "" {
		return nil, errors.New("JWT_SECRET (min 32 chars) and DB_PASSWORD are required")
	}

	return &Config{
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
	}, nil
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
