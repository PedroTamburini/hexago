package security

import (
	"errors"
	"strconv"
	"time"

	"github.com/PedroTamburini/hexago/internal/domain/port"
	"github.com/PedroTamburini/hexago/internal/infrastructure/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type jwtService struct {
	secretKey  []byte
	expiration time.Duration
}

func NewJWTService(cfg *config.Config) port.JWTService {
	return &jwtService{
		secretKey:  []byte(cfg.JWTSecret),
		expiration: cfg.JWTExpiration,
	}
}

func (s *jwtService) ExpireSeconds() int64 {
	return int64(s.expiration.Seconds())
}

func (s *jwtService) GenerateToken(id uint64) (string, error) {
	expiresAt := time.Now().Add(s.expiration)
	convertedUserID := strconv.FormatUint(id, 10)

	tokenClaims := jwt.RegisteredClaims{
		ID:        uuid.NewString(),
		Subject:   convertedUserID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)
	signedToken, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (s *jwtService) ValidateToken(tokenString string) (uint64, error) {
	claims := &jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return s.secretKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {
		return 0, err
	}

	if !token.Valid {
		return 0, errors.New("invalid token")
	}

	userID, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return 0, errors.New("invalid token subject")
	}

	return userID, nil
}
