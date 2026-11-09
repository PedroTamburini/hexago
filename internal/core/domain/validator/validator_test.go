package validator

import (
	"strings"
	"testing"
)

func TestIsValidPassword(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "empty password is rejected",
			password: "",
			want:     false,
		},
		{
			name:     "one rune below the minimum is rejected",
			password: "1234567",
			want:     false,
		},
		{
			name:     "exactly the minimum is accepted",
			password: "12345678",
			want:     true,
		},
		{
			name:     "ascii password with exactly 72 bytes is accepted",
			password: strings.Repeat("a", 72),
			want:     true,
		},
		{
			name:     "ascii password with 73 bytes is rejected",
			password: strings.Repeat("a", 73),
			want:     false,
		},
		{
			name:     "multi byte password with exactly 72 bytes is accepted",
			password: strings.Repeat("é", 36),
			want:     true,
		},
		{
			name:     "multi byte password above 72 bytes is rejected",
			password: strings.Repeat("é", 37),
			want:     false,
		},
		{
			name:     "72 emojis (288 bytes) are rejected despite the rune count",
			password: strings.Repeat("😀", 72),
			want:     false,
		},
		{
			name:     "few multi byte runes are rejected even when the byte length is high",
			password: strings.Repeat("😀", 2),
			want:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidPassword(tc.password); got != tc.want {
				t.Fatalf("IsValidPassword(%q) = %v, want %v", tc.password, got, tc.want)
			}
		})
	}
}

func TestIsValidName(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		wantValid bool
	}{
		{name: "simple name", input: "John", wantValid: true},
		{name: "full name with space", input: "John Doe", wantValid: true},
		{name: "accented letters", input: "João D'Ávila", wantValid: true},
		{name: "hyphenated name", input: "Anne-Marie", wantValid: true},
		{name: "empty name is rejected", input: "", wantValid: false},
		{name: "digits are rejected", input: "John2", wantValid: false},
		{name: "leading space is rejected", input: " John", wantValid: false},
		{name: "trailing space is rejected", input: "John ", wantValid: false},
		{name: "double space is rejected", input: "John  Doe", wantValid: false},
		{name: "symbols are rejected", input: "John@Doe", wantValid: false},
		{
			name:      "exactly 100 bytes is accepted",
			input:     strings.Repeat("a", 100),
			wantValid: true,
		},
		{
			name:      "101 bytes is rejected",
			input:     strings.Repeat("a", 101),
			wantValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidName(tc.input); got != tc.wantValid {
				t.Fatalf("IsValidName(%q) = %v, want %v", tc.input, got, tc.wantValid)
			}
		})
	}
}

func TestIsValidUsername(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		wantValid bool
	}{
		{name: "first.last", input: "john.doe", wantValid: true},
		{name: "single letters", input: "a.b", wantValid: true},
		{name: "uppercase is rejected", input: "John.Doe", wantValid: false},
		{name: "digits are rejected", input: "john.doe2", wantValid: false},
		{name: "missing dot is rejected", input: "johndoe", wantValid: false},
		{name: "multiple dots are rejected", input: "john.doe.silva", wantValid: false},
		{name: "leading dot is rejected", input: ".john", wantValid: false},
		{name: "empty is rejected", input: "", wantValid: false},
		{
			name:      "exactly 60 bytes is accepted",
			input:     strings.Repeat("a", 29) + "." + strings.Repeat("b", 30),
			wantValid: true,
		},
		{
			name:      "61 bytes is rejected",
			input:     strings.Repeat("a", 30) + "." + strings.Repeat("b", 30),
			wantValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidUsername(tc.input); got != tc.wantValid {
				t.Fatalf("IsValidUsername(%q) = %v, want %v", tc.input, got, tc.wantValid)
			}
		})
	}
}

func TestIsValidEmail(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		wantValid bool
	}{
		{name: "simple email", input: "john@example.com", wantValid: true},
		{name: "subdomain", input: "john@mail.example.com", wantValid: true},
		{name: "plus tag", input: "john+tag@example.com", wantValid: true},
		{name: "dotted local part", input: "john.doe@example.com", wantValid: true},
		{name: "missing at sign", input: "john.example.com", wantValid: false},
		{name: "missing tld", input: "john@example", wantValid: false},
		{name: "short tld", input: "john@example.c", wantValid: false},
		{name: "consecutive dots", input: "john..doe@example.com", wantValid: false},
		{name: "empty is rejected", input: "", wantValid: false},
		{
			name:      "254 bytes is accepted",
			input:     "a@" + strings.Repeat("b", 248) + ".com",
			wantValid: true,
		},
		{
			name:      "255 bytes is rejected",
			input:     "a@" + strings.Repeat("b", 249) + ".com",
			wantValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidEmail(tc.input); got != tc.wantValid {
				t.Fatalf("IsValidEmail(%q) = %v, want %v", tc.input, got, tc.wantValid)
			}
		})
	}
}
