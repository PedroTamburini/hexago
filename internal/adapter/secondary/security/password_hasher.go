package security

import (
	"golang.org/x/crypto/bcrypt"

	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

type passwordHasher struct {
	cost int
}

func NewPasswordHasher(cost int) portout.PasswordHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &passwordHasher{cost: cost}
}

func (b *passwordHasher) Hash(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), b.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (b *passwordHasher) Compare(hashed, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
}
