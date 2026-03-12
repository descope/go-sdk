package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEmailRegex tests the simplified email regex validation
func TestEmailRegex(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		// Valid emails
		{"ValidSimple", "user@example.com", true},
		{"ValidWithDots", "user.name@example.com", true},
		{"ValidWithPlus", "user+tag@example.com", true},
		{"ValidWithHyphen", "user-name@example.com", true},
		{"ValidWithUnderscore", "user_name@example.com", true},
		{"ValidWithNumbers", "user123@example456.com", true},
		{"ValidSubdomain", "user@mail.example.com", true},
		{"ValidLongTLD", "user@example.technology", true},
		{"ValidShortTLD", "user@example.io", true},

		// Invalid emails
		{"InvalidNoAt", "userexample.com", false},
		{"InvalidNoTLD", "user@example", false},
		{"InvalidMultipleAt", "user@@example.com", false},
		{"InvalidStartWithDot", ".user@example.com", false},
		{"InvalidEndWithDot", "user.@example.com", false},
		{"InvalidSpaces", "user name@example.com", false},
		{"InvalidSpecialChars", "user@ex ample.com", false},

		{"InvalidOnlyAt", "@", false},
		{"InvalidNoLocal", "@example.com", false},
		{"InvalidNoDomain", "user@", false},
		{"InvalidTLDTooShort", "user@example.c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := emailRegex.MatchString(tt.email)
			assert.Equal(t, tt.expected, result, "Email validation mismatch for: %s", tt.email)
		})
	}
}

// TestPhoneRegex tests the phone number validation regex
func TestPhoneRegex(t *testing.T) {
	tests := []struct {
		name     string
		phone    string
		expected bool
	}{
		// Valid phones
		{"ValidInternational", "+1234567890", true},
		{"ValidWithCountryCode", "+1-555-123-4567", true},
		{"ValidLocal", "5551234567", true},
		{"ValidWithParens", "(555) 123-4567", true},
		{"ValidWithExtension", "555-123-4567 ext 123", true},
		{"ValidWithHashExt", "555-123-4567#123", true},

		// Invalid phones
		{"InvalidLetters", "555-abc-1234", false},
		{"InvalidSpecialChars", "555@123-4567", false},

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := phoneRegex.MatchString(tt.phone)
			assert.Equal(t, tt.expected, result, "Phone validation mismatch for: %s", tt.phone)
		})
	}
}
