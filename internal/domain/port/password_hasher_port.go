package port

// PasswordHasher hashes and verifies passwords. The hashing algorithm is an
// implementation detail of the adapter that satisfies this port.
type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hashed string, plain string) error
}
