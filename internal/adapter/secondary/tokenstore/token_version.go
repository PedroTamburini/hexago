package tokenstore

import (
	"context"
	"strconv"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	goredis "github.com/redis/go-redis/v9"
)

const tokenVersionKeyPrefix = "tokenver:user:"

type tokenVersionManager struct {
	client *goredis.Client
}

// NewTokenVersionManager builds a Redis-backed token version manager. The
// version lives outside the database on purpose: incrementing it revokes every
// token of a user without a schema change or a migration.
func NewTokenVersionManager(client *goredis.Client) portout.TokenVersionManager {
	return &tokenVersionManager{client: client}
}

// GetVersion returns 0 for users that never had their version incremented,
// which is the value embedded in tokens issued since the feature was added and
// in tokens issued before it (the claim defaults to its zero value).
func (t *tokenVersionManager) GetVersion(ctx context.Context, userID uint64) (int, error) {
	value, err := t.client.Get(ctx, tokenVersionKey(userID)).Int()
	if err == goredis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	return value, nil
}

// IncrementVersion bumps the version and returns the new one. Every token that
// carries an older version stops being accepted on the next validation.
func (t *tokenVersionManager) IncrementVersion(ctx context.Context, userID uint64) (int, error) {
	value, err := t.client.Incr(ctx, tokenVersionKey(userID)).Result()
	if err != nil {
		return 0, err
	}

	return int(value), nil
}

func tokenVersionKey(userID uint64) string {
	return tokenVersionKeyPrefix + strconv.FormatUint(userID, 10)
}

var _ portout.TokenVersionManager = (*tokenVersionManager)(nil)
