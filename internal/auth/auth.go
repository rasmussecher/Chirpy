package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	println("NOW HASING PASSWORD:", password)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return string(hash), nil
}

func CheckPasswordHash(hash, password string) error {
	fmt.Println(password)
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	})
	signed, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		fmt.Println("An error occured in MakeJWT():", err)
	}
	return signed, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}

	subject, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.UUID{}, err
	}

	return subject, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	const prefix = "Bearer "
	if len(authHeader) < len(prefix) || authHeader[:len(prefix)] != prefix {
		return "", fmt.Errorf("authorization header format must be 'Bearer {token}'")
	}

	token := authHeader[len(prefix):]

	return token, nil
}

func GetApiKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	const prefix = "ApiKey "
	if len(authHeader) < len(prefix) || authHeader[:len(prefix)] != prefix {
		return "", fmt.Errorf("authorization header format must be 'ApiKey {token}'")
	}

	token := authHeader[len(prefix):]

	return token, nil
}

func MakeRefreshToken() (string, error) {
	var refreshToken [32]byte
	_, err := rand.Read(refreshToken[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(refreshToken[:]), nil
}
