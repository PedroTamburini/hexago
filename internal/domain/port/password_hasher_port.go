package port

type PasswordHasherService interface {
	Hash(plain string) (string, error)
	Compare(hashed string, plain string) error
}
