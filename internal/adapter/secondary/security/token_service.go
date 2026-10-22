package security

import (
	"errors"
	"strconv"
	"time"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// tokenClaims is the on-the-wire claims set. It embeds the registered claims
// (which carry the jti, subject, issuance and expiration) and adds the token
// version used to invalidate every token of a user at once.
type tokenClaims struct {
	jwt.RegisteredClaims
	TokenVersion int `json:"tv"`
}

type jwtService struct {
	secretKey  []byte
	expiration time.Duration
}

func NewJWTService(secret string, expiration time.Duration) portout.TokenService {
	return &jwtService{
		secretKey:  []byte(secret),
		expiration: expiration,
	}
}

func (s *jwtService) ExpireSeconds() int64 {
	return int64(s.expiration.Seconds())
}

// GenerateToken mints an access token for the user. tokenVersion is copied into
// the "tv" claim; incrementing the stored version invalidates the token without
// having to track it individually.
func (s *jwtService) GenerateToken(id uint64, tokenVersion int) (string, error) {
	now := time.Now()
	expiresAt := now.Add(s.expiration)
	convertedUserID := strconv.FormatUint(id, 10)

	claims := tokenClaims{
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   convertedUserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// ParseClaims validates the signature and the registered time claims and
// returns the data needed to manage the token (jti, subject, expiration and
// version).
func (s *jwtService) ParseClaims(tokenString string) (*portout.TokenClaims, error) {
	claims := &tokenClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return s.secretKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.ID == "" {
		return nil, errors.New("invalid token id")
	}

	if _, err := strconv.ParseUint(claims.Subject, 10, 64); err != nil {
		return nil, errors.New("invalid token subject")
	}

	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return nil, errors.New("invalid token time claims")
	}

	return &portout.TokenClaims{
		JTI:       claims.ID,
		Subject:   claims.Subject,
		TokenVer:  claims.TokenVersion,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}

func (s *jwtService) ValidateToken(tokenString string) (uint64, error) {
	claims, err := s.ParseClaims(tokenString)
	if err != nil {
		return 0, err
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return 0, errors.New("invalid token subject")
	}

	return userID, nil
}
