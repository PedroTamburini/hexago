package tokenstore

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	goredis "github.com/redis/go-redis/v9"
)

const (
	sessionKeyPrefix      = "session:"
	userSessionsKeyPrefix = "sessions:user:"
)

// registerSessionScript writes the session payload and indexes it under the
// user in one atomic step, so a session is never listed without its payload or
// vice versa.
//
// KEYS[1] session key ("session:{jti}")
// KEYS[2] user sessions zset ("sessions:user:{userID}")
// ARGV[1] session JSON
// ARGV[2] session TTL in milliseconds
// ARGV[3] jti (zset member)
// ARGV[4] expiration score (unix seconds, used to prune expired entries)
var registerSessionScript = goredis.NewScript(`
local sessionKey = KEYS[1]
local userKey = KEYS[2]
local payload = ARGV[1]
local ttlMs = tonumber(ARGV[2])
local jti = ARGV[3]
local score = tonumber(ARGV[4])

redis.call('SET', sessionKey, payload, 'PX', ttlMs)
redis.call('ZADD', userKey, score, jti)

-- Never shorten the index TTL of sessions that expire later than this one.
local currentTtl = redis.call('PTTL', userKey)
if currentTtl == -1 or currentTtl < ttlMs then
  redis.call('PEXPIRE', userKey, ttlMs)
end

return 1
`)

// removeSessionScript deletes the payload and the index entry atomically.
//
// KEYS[1] session key
// KEYS[2] user sessions zset
// ARGV[1] jti
var removeSessionScript = goredis.NewScript(`
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[1])
return 1
`)

// removeAllSessionsScript deletes every session payload of a user and its
// index. The members are read and deleted inside Redis, so the operation does
// not depend on the number of round trips nor on concurrent registrations
// being visible to the caller.
//
// KEYS[1] user sessions zset
// ARGV[1] session key prefix
var removeAllSessionsScript = goredis.NewScript(`
local userKey = KEYS[1]
local prefix = ARGV[1]
local jtis = redis.call('ZRANGE', userKey, 0, -1)

for i = 1, #jtis do
  redis.call('DEL', prefix .. jtis[i])
end

redis.call('DEL', userKey)
return #jtis
`)

type sessionRegistry struct {
	client *goredis.Client
}

// NewSessionRegistry builds a Redis-backed registry of active sessions.
func NewSessionRegistry(client *goredis.Client) portout.SessionRegistry {
	return &sessionRegistry{client: client}
}

func (r *sessionRegistry) Register(ctx context.Context, session portout.Session) error {
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}

	_, err = registerSessionScript.Run(
		ctx,
		r.client,
		[]string{sessionKey(session.JTI), userSessionsKey(session.UserID)},
		payload,
		ttl.Milliseconds(),
		session.JTI,
		session.ExpiresAt.Unix(),
	).Result()

	return err
}

func (r *sessionRegistry) GetByJTI(ctx context.Context, jti string) (*portout.Session, error) {
	payload, err := r.client.Get(ctx, sessionKey(jti)).Bytes()
	if err == goredis.Nil {
		return nil, domainerr.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	var session portout.Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// ListByUserID returns the sessions that have not expired yet, pruning the
// index as it goes: an expired index entry is removed together with any payload
// that outlived its index.
func (r *sessionRegistry) ListByUserID(ctx context.Context, userID uint64) ([]*portout.Session, error) {
	userKey := userSessionsKey(userID)
	now := time.Now().Unix()

	if err := r.client.ZRemRangeByScore(ctx, userKey, "-inf", strconv.FormatInt(now, 10)).Err(); err != nil {
		return nil, err
	}

	jtis, err := r.client.ZRange(ctx, userKey, 0, -1).Result()
	if err != nil {
		return nil, err
	}

	sessions := make([]*portout.Session, 0, len(jtis))
	if len(jtis) == 0 {
		return sessions, nil
	}

	keys := make([]string, 0, len(jtis))
	for _, jti := range jtis {
		keys = append(keys, sessionKey(jti))
	}

	payloads, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	for i, payload := range payloads {
		if payload == nil {
			// The payload expired before the index entry: drop the stale index.
			_ = r.client.ZRem(ctx, userKey, jtis[i]).Err()
			continue
		}

		raw, ok := payload.(string)
		if !ok {
			continue
		}

		var session portout.Session
		if err := json.Unmarshal([]byte(raw), &session); err != nil {
			continue
		}

		sessions = append(sessions, &session)
	}

	return sessions, nil
}

func (r *sessionRegistry) Remove(ctx context.Context, jti string) error {
	session, err := r.GetByJTI(ctx, jti)
	if err != nil {
		if err == domainerr.ErrSessionNotFound {
			// Already gone: removing it again is a no-op.
			return nil
		}
		return err
	}

	_, err = removeSessionScript.Run(
		ctx,
		r.client,
		[]string{sessionKey(jti), userSessionsKey(session.UserID)},
		jti,
	).Result()

	return err
}

func (r *sessionRegistry) RemoveAllByUserID(ctx context.Context, userID uint64) error {
	_, err := removeAllSessionsScript.Run(
		ctx,
		r.client,
		[]string{userSessionsKey(userID)},
		sessionKeyPrefix,
	).Result()

	return err
}

func sessionKey(jti string) string {
	return sessionKeyPrefix + jti
}

func userSessionsKey(userID uint64) string {
	return userSessionsKeyPrefix + strconv.FormatUint(userID, 10)
}

var _ portout.SessionRegistry = (*sessionRegistry)(nil)
