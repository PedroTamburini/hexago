package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/PedroTamburini/hexago/internal/infrastructure/logger"
	goredis "github.com/redis/go-redis/v9"
)

// NewClient builds and verifies a Redis connection.
//
// The ping is mandatory: when rate limiting is enabled the application fails
// closed, so refusing to start with an unreachable Redis is preferable to
// booting and rejecting every request afterwards. The caller owns the returned
// client and must Close it during shutdown.
func NewClient(cfg *config.Config, log *logger.Logger) (*goredis.Client, error) {
	client := goredis.NewClient(&goredis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
		PoolSize: cfg.RedisPoolSize,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	log.Info("connected to redis", "addr", cfg.RedisAddr, "db", cfg.RedisDB)

	return client, nil
}
