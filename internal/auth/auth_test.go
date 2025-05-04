package auth_test

import (
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/vladimirck/chirpy/internal/auth" // Replace with the actual path to your auth package
)

func TestHashPassword(t *testing.T) {
	password := "secure_password"

	hashedPassword, err := auth.HashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashedPassword)
	assert.NotEqual(t, password, hashedPassword)
}

func TestCheckPasswordHash(t *testing.T) {
	password := "another_secret"

	hashedPassword, err := auth.HashPassword(password)
	assert.NoError(t, err)

	err = auth.CheckPasswordHash(hashedPassword, password)
	assert.NoError(t, err)

	wrongPassword := "incorrect_password"
	err = auth.CheckPasswordHash(hashedPassword, wrongPassword)
	assert.Error(t, err)
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret, err := auth.GenerateHS256Secret(32)
	assert.NoError(t, err)
	expiresIn := time.Hour * 24

	token, err := auth.MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret, err := auth.GenerateHS256Secret(32)
	assert.NoError(t, err)
	expiresIn := time.Minute * 15

	token, err := auth.MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)

	parsedUserID, err := auth.ValidateJWT(token, tokenSecret)
	assert.NoError(t, err)
	assert.Equal(t, userID, parsedUserID)

	invalidToken := "this.is.not.a.valid.token"
	_, err = auth.ValidateJWT(invalidToken, tokenSecret)
	assert.Error(t, err)

	wrongSecret, err := auth.GenerateHS256Secret(32)
	assert.NoError(t, err)
	_, err = auth.ValidateJWT(token, wrongSecret)
	assert.Error(t, err)

	expiredToken, err := auth.MakeJWT(userID, tokenSecret, -time.Minute) // Expired token
	assert.NoError(t, err)
	_, err = auth.ValidateJWT(expiredToken, tokenSecret)
	assert.Error(t, err)
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedToken string
		expectedErr   bool
	}{
		{
			name: "Valid Bearer token",
			headers: http.Header{
				"Authorization": []string{"Bearer valid_token_123"},
			},
			expectedToken: "valid_token_123",
			expectedErr:   false,
		},
		{
			name: "Valid Bearer token with extra spaces",
			headers: http.Header{
				"Authorization": []string{"Bearer   another_token   "},
			},
			expectedToken: "another_token",
			expectedErr:   false,
		},
		{
			name: "Authorization header with other scheme",
			headers: http.Header{
				"Authorization": []string{"Basic dXNlcjpwYXNz"},
			},
			expectedToken: "",
			expectedErr:   true,
		},
		{
			name: "Authorization header without Bearer scheme",
			headers: http.Header{
				"Authorization": []string{"valid_token_only"},
			},
			expectedToken: "",
			expectedErr:   true,
		},
		{
			name: "Authorization header with incorrect Bearer format",
			headers: http.Header{
				"Authorization": []string{"Bearer"},
			},
			expectedToken: "",
			expectedErr:   true,
		},
		{
			name: "Authorization header with multiple values (should take first)",
			headers: http.Header{
				"Authorization": []string{"Bearer first_token", "Bearer second_token"},
			},
			expectedToken: "first_token",
			expectedErr:   false,
		},
		{
			name:          "No Authorization header",
			headers:       http.Header{},
			expectedToken: "",
			expectedErr:   true,
		},
		{
			name: "Empty Authorization header value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedToken: "",
			expectedErr:   true,
		},
		{
			name: "Bearer with empty token",
			headers: http.Header{
				"Authorization": []string{"Bearer "},
			},
			expectedToken: "",
			expectedErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := auth.GetBearerToken(tt.headers)

			if tt.expectedErr {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestMakeRefreshToken(t *testing.T) {
	refreshToken, err := auth.MakeRefreshToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)

	// Check the length of the hex-encoded string.  256 bits = 32 bytes,
	// and each byte is represented by 2 hex characters.
	expectedLength := 64
	assert.Len(t, refreshToken, expectedLength, "Refresh token should be 64 characters long (256 bits)")

	// Check if the string is a valid hex string.
	_, err = hex.DecodeString(refreshToken)
	assert.NoError(t, err, "Refresh token should be a valid hex-encoded string")
}

func TestGetAPIKey(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name          string      // Name of the test case
		inputHeaders  http.Header // Input for the function
		expectedKey   string      // Expected successful result
		expectedError error       // Expected error (can be nil)
	}{
		{
			name: "Valid Header - Standard",
			inputHeaders: http.Header{
				"Authorization": []string{"ApiKey my-secret-token-123"},
			},
			expectedKey:   "my-secret-token-123",
			expectedError: nil,
		},
		{
			name: "Valid Header - Lowercase Scheme",
			inputHeaders: http.Header{
				"Authorization": []string{"apikey my-secret-token-abc"},
			},
			expectedKey:   "my-secret-token-abc",
			expectedError: nil, // Assumes case-insensitive scheme check
		},
		{
			name: "Valid Header - Mixed Case Scheme",
			inputHeaders: http.Header{
				"Authorization": []string{"ApIkEy my-secret-token-xyz"},
			},
			expectedKey:   "my-secret-token-xyz",
			expectedError: nil, // Assumes case-insensitive scheme check
		},
		{
			name: "Valid Header - Extra whitespace around key",
			inputHeaders: http.Header{
				"Authorization": []string{"ApiKey    my-secret-token-padded   "},
			},
			expectedKey:   "my-secret-token-padded", // Assumes TrimSpace is used
			expectedError: nil,
		},
		{
			name: "Valid Header - Lowercase Header Name",
			inputHeaders: http.Header{
				"Authorization": []string{"ApiKey my-secret-token-lower-header"}, // Header names are case-insensitive
			},
			expectedKey:   "my-secret-token-lower-header",
			expectedError: nil,
		},
		{
			name: "Missing Authorization Header",
			inputHeaders: http.Header{ // Empty header map
				"Content-Type": []string{"application/json"}, // Other headers shouldn't matter
			},
			expectedKey:   "",
			expectedError: auth.ErrMissingAuthHeader,
		},
		{
			name: "Empty Authorization Header Value",
			inputHeaders: http.Header{
				"Authorization": []string{""}, // Explicitly empty value
			},
			expectedKey:   "",
			expectedError: auth.ErrMissingAuthHeader, // .Get returns "" for empty value too
		},
		{
			name: "Malformed Header - Wrong Scheme (Bearer)",
			inputHeaders: http.Header{
				"Authorization": []string{"Bearer some-jwt-token"},
			},
			expectedKey:   "",
			expectedError: auth.ErrMalformedAuthHeader,
		},
		{
			name: "Malformed Header - No Space",
			inputHeaders: http.Header{
				"Authorization": []string{"ApiKeyNoSpaceKey"},
			},
			expectedKey:   "",
			expectedError: auth.ErrMalformedAuthHeader,
		},
		{
			name: "Malformed Header - Only Scheme",
			inputHeaders: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: auth.ErrMalformedAuthHeader,
		},
		{
			name: "Malformed Header - Scheme and Space, No Key",
			inputHeaders: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",
			expectedError: auth.ErrMalformedAuthHeader, // Handled by the TrimSpace check
		},
		{
			name: "Malformed Header - Only Space",
			inputHeaders: http.Header{
				"Authorization": []string{" "},
			},
			expectedKey:   "",
			expectedError: auth.ErrMalformedAuthHeader,
		},
	}

	// Iterate over test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test
			actualKey, actualErr := auth.GetAPIKey(tc.inputHeaders)

			// Assertions
			if actualKey != tc.expectedKey {
				t.Errorf("Expected key '%s', but got '%s'", tc.expectedKey, actualKey)
			}

			// Compare errors using errors.Is for wrapped errors, or direct comparison for specific sentinel errors
			if !errors.Is(actualErr, tc.expectedError) {
				// Direct comparison also works well for sentinel errors like these
				// if actualErr != tc.expectedError {
				t.Errorf("Expected error '%v', but got '%v'", tc.expectedError, actualErr)
			}
		})
	}
}
