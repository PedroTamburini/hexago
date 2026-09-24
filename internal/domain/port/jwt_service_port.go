package port

type JWTService interface {
	GenerateToken(userID uint64) (string, error)
	ExpireSeconds() int64
	ValidateToken(token string) (uint64, error)
}
