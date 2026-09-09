package security

import "golang.org/x/crypto/bcrypt"

type PasswordHasherImpl struct {
	cost int
}

func NewPasswordHasherService(cost int) *PasswordHasherImpl {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &PasswordHasherImpl{cost: cost}
}

func (b *PasswordHasherImpl) Hash(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), b.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (b *PasswordHasherImpl) Compare(hashed, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
}
