package validator

import (
	"regexp"
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
