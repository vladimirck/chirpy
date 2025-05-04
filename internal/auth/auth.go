package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
)

const DefaultCost = 15

func GenerateHS256Secret(length int) (string, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(randomBytes), nil
}

func HashPassword(password string) (string, error) {
	hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(password), DefaultCost)

	if err != nil {
		return "", err
	}

	return string(hashedPasswd), nil
}

func CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	timeNow := time.Now()
	timeExpireAt := timeNow.Add(expiresIn)
	claim := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(timeNow),
		ExpiresAt: jwt.NewNumericDate(timeExpireAt),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claim := jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&claim,
		func(*jwt.Token) (interface{}, error) {
			return []byte(tokenSecret), nil
		},
	)

	if err != nil {
		fmt.Printf("Error while parsing the token string: %s\n", err)
		return uuid.UUID{}, err
	}

	UUIDString, err := token.Claims.GetSubject()

	if err != nil {
		fmt.Printf("Error while getting the UUID string: %s\n", err)
		return uuid.UUID{}, err
	}

	UUID, err := uuid.Parse(UUIDString)

	if err != nil {
		fmt.Printf("Error while getting the UUID String into a UUID: %s\n", err)
		return uuid.UUID{}, err
	}

	return UUID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authString := headers.Get("Authorization")
	if !strings.Contains(authString, "Bearer ") {
		return "", fmt.Errorf("The header does not contains the token in the appropiate format")
	}

	authFields := strings.Fields(authString)
	if len(authFields) != 2 {
		return "", fmt.Errorf("The header does not contains the token in the appropiate format")
	}

	return authFields[1], nil
}

var (
	// ErrMissingAuthHeader indicates the Authorization header was not found.
	ErrMissingAuthHeader = errors.New("authorization header missing")
	// ErrMalformedAuthHeader indicates the Authorization header value is not in the expected format.
	ErrMalformedAuthHeader = errors.New("malformed authorization header")
)

const authScheme = "apikey" // Use lowercase for case-insensitive comparison

// GetAPIKey extracts an API key from the Authorization header.
// Expects the format "Authorization: ApiKey <key>".
// The scheme "ApiKey" comparison is case-insensitive.
func GetAPIKey(headers http.Header) (string, error) {
	// http.Header.Get canonicalizes the key, so "Authorization", "authorization", etc., all work.
	authHeaderValue := headers.Get("Authorization")
	if authHeaderValue == "" {
		return "", ErrMissingAuthHeader
	}

	// Expecting "ApiKey <key>"
	parts := strings.SplitN(authHeaderValue, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != authScheme {
		return "", ErrMalformedAuthHeader // Covers cases like "ApiKey", "Bearer token", "ApiKeykey", "ApiKey<no space>"
	}

	// Check if the key part is empty after the scheme
	apiKey := strings.TrimSpace(parts[1])
	if apiKey == "" {
		return "", ErrMalformedAuthHeader // Covers "ApiKey "
	}

	return apiKey, nil
}

func MakeRefreshToken() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}
