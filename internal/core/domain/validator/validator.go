package validator

import (
	"regexp"
	"unicode/utf8"
)

const (
	// minPasswordRunes is a UX/entropy floor measured in characters so a short
	// sequence of multi byte runes (e.g. emojis) is not accepted as "long".
	minPasswordRunes = 8
	// maxPasswordBytes is the hard limit imposed by bcrypt, which only consumes
	// the first 72 bytes of a password and rejects longer inputs. It must be
	// measured in bytes, not runes, because a rune may take up to 4 bytes.
	maxPasswordBytes = 72
)

var nameRegex = regexp.MustCompile(`^[\p{L}]+(?:[ '-][\p{L}]+)*$`)

func IsValidName(name string) bool {
	return len(name) <= 100 && nameRegex.MatchString(name)
}

var usernameRegex = regexp.MustCompile(`^[a-z]+\.[a-z]+$`)

func IsValidUsername(username string) bool {
	return len(username) <= 60 && usernameRegex.MatchString(username)
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9_%+-]+(?:\.[a-zA-Z0-9_%+-]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$`)

func IsValidEmail(email string) bool {
	return len(email) <= 254 && emailRegex.MatchString(email)
}

// IsValidPassword enforces the password policy shared by every entry point.
// The lower bound counts runes while the upper bound counts bytes: bcrypt
// silently ignores everything past the first 72 bytes, and a 72 rune password
// can occupy up to 288 bytes, so a rune based ceiling would let passwords
// through that the hasher cannot handle.
func IsValidPassword(password string) bool {
	return utf8.RuneCountInString(password) >= minPasswordRunes && len(password) <= maxPasswordBytes
}
