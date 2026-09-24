package gorm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/database/gorm/model"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type Database struct {
	*gorm.DB
}

type GormLogger struct {
	*logger.Logger
	level gormlogger.LogLevel
}

func (l *GormLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	return &GormLogger{Logger: l.Logger, level: level}
}

func (l *GormLogger) Info(ctx context.Context, msg string, data ...any) {
	l.Logger.InfoContext(ctx, fmt.Sprintf(msg, data...))
}

func (l *GormLogger) Warn(ctx context.Context, msg string, data ...any) {
	l.Logger.WarnContext(ctx, fmt.Sprintf(msg, data...))
}

func (l *GormLogger) Error(ctx context.Context, msg string, data ...any) {
	l.Logger.ErrorContext(ctx, fmt.Sprintf(msg, data...))
}

func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	if l.level <= gormlogger.Silent {
		return
	} else {
		elapsed := time.Since(begin)
		sql, rows := fc()

		msg := fmt.Sprintf("[%.3fms] [rows:%d] %s", float64(elapsed.Nanoseconds())/1e6, rows, sql)

		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			l.Logger.ErrorContext(ctx, msg, "error", err)
			return
		}

		l.Logger.InfoContext(ctx, msg)
	}
}

func resolveGormLogLevel(env config.Environment) gormlogger.LogLevel {
	if env == config.EnvironmentProduction {
		return gormlogger.Silent
	}
	return gormlogger.Info
}

func DatabaseURL(cfg *config.Config) string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s&TimeZone=%s",
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBName,
		cfg.DBSSLMode,
		cfg.DBTimeZone,
	)
}

func NewPostgresConnection(cfg *config.Config, logger *logger.Logger) (*Database, error) {
	gormCfg := &gorm.Config{
		Logger: &GormLogger{Logger: logger, level: resolveGormLogLevel(cfg.Environment)},
	}
	dsn := DatabaseURL(cfg)

	db, err := gorm.Open(postgres.Open(dsn), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.DBMaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.DBMaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.DBConnMaxLifeTime)

	return &Database{db}, nil
}

func RunAutoMigrations(db *Database) error {
	return db.AutoMigrate(
		&model.UserModel{},
	)
}

// For larger projects with more robust infrastructure, prefer:

// Migrations created/tested locally (golang-migrate)
// migrate create \
//   -ext sql \
//   -dir internal/infrastructure/database/migrations \
//   add_..._to_users

// migrate ... up
// migrate ... down 1
// migrate ... up

// And applied in production via CLI in the GitLab deployment pipeline
// migrate \
//   -path ./internal/infrastructure/database/migrations \
//   -database "$DATABASE_URL" \
//   up
