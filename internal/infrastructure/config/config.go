package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort            string
	ServerShutdownTimeout time.Duration
	ServerReadTimeOut     time.Duration
	ServerWriteTimeOut    time.Duration
	ServerIdleTimeOut     time.Duration
	Environment           string
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
}

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: .env file not found or error loading it: %v", err)
	}

	serverShutdownTimeout, _ := time.ParseDuration(getEnv("SERVER_SHUTDOWN_TIMEOUT", "5s"))
	serverReadTimeOut, _ := time.ParseDuration(getEnv("SERVER_READ_TIMEOUT", "10s"))
	serverWriteTimeOut, _ := time.ParseDuration(getEnv("SERVER_WRITE_TIMEOUT", "10s"))
	serverIdleTimeOut, _ := time.ParseDuration(getEnv("SERVER_IDLE_TIMEOUT", "60s"))
	dbMaxOpenConns, _ := strconv.Atoi(getEnv("DB_MAX_OPEN_CONNS", "25"))
	dbMaxIdleConns, _ := strconv.Atoi(getEnv("DB_MAX_IDLE_CONNS", "25"))
	dbConnMaxLifeTime, _ := time.ParseDuration(getEnv("DB_CONN_MAX_LIFETIME", "5m"))
	dbAutoMigration, _ := strconv.ParseBool(getEnv("DB_AUTO_MIGRATION", "false"))
	hasherCost, _ := strconv.Atoi(getEnv("HASHER_COST", "12"))

	return &Config{
		ServerPort:            getEnv("SERVER_PORT", "8080"),
		ServerShutdownTimeout: serverShutdownTimeout,
		ServerReadTimeOut:     serverReadTimeOut,
		ServerWriteTimeOut:    serverWriteTimeOut,
		ServerIdleTimeOut:     serverIdleTimeOut,
		Environment:           getEnv("ENVIRONMENT", "development"),
		DBHost:                getEnv("DB_HOST", "localhost"),
		DBPort:                getEnv("DB_PORT", "5432"),
		DBUser:                getEnv("DB_USER", "postgres"),
		DBName:                getEnv("DB_NAME", "hexago"),
		DBPassword:            getEnv("DB_PASSWORD", "postgres"),
		DBSSLMode:             getEnv("DB_SSLMODE", "disable"),
		DBTimeZone:            getEnv("DB_TIMEZONE", "America/Rio_Branco"),
		DBMaxOpenConns:        dbMaxOpenConns,
		DBMaxIdleConns:        dbMaxIdleConns,
		DBConnMaxLifeTime:     dbConnMaxLifeTime,
		DBAutoMigration:       dbAutoMigration,
		HasherCost:            hasherCost,
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
