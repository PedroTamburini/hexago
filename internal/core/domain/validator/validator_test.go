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
