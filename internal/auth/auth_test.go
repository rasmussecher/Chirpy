package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPasswordAndCheckPasswordHash_Success(t *testing.T) {
	password := "mySecretPassword123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty hash")
	}

	// Check that the hash matches the password
	err = CheckPasswordHash(hash, password)
	if err != nil {
		t.Errorf("CheckPasswordHash failed for correct password: %v", err)
	}
}

func TestCheckPasswordHash_WrongPassword(t *testing.T) {
	password := "correctPassword"
	wrongPassword := "wrongPassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	err = CheckPasswordHash(hash, wrongPassword)
	if err == nil {
		t.Error("CheckPasswordHash did not fail for incorrect password")
	}
	if err != bcrypt.ErrMismatchedHashAndPassword {
		t.Errorf("Expected ErrMismatchedHashAndPassword, got: %v", err)
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword returned error for empty password: %v", err)
	}
	if hash == "" {
		t.Error("HashPassword returned empty hash for empty password")
	}
}

func TestCheckPasswordHash_InvalidHash(t *testing.T) {
	invalidHash := "notAValidHash"
	password := "anyPassword"
	err := CheckPasswordHash(invalidHash, password)
	if err == nil {
		t.Error("CheckPasswordHash did not fail for invalid hash")
	}
}

func TestMakeJWTAndValidateJWT_Success(t *testing.T) {
	userID := uuid.New()
	secret := "supersecret"
	expiresIn := time.Minute * 5

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}
	if token == "" {
		t.Fatal("MakeJWT returned empty token")
	}

	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned error: %v", err)
	}
	if parsedID != userID {
		t.Errorf("ValidateJWT returned wrong userID: got %v, want %v", parsedID, userID)
	}
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	secret := "supersecret"
	invalidToken := "this.is.not.a.valid.jwt"

	_, err := ValidateJWT(invalidToken, secret)
	if err == nil {
		t.Error("ValidateJWT did not fail for invalid token")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()
	secret := "supersecret"
	wrongSecret := "wrongsecret"
	expiresIn := time.Minute * 5

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Error("ValidateJWT did not fail for wrong secret")
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	userID := uuid.New()
	secret := "supersecret"
	expiresIn := -time.Minute // already expired

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Error("ValidateJWT did not fail for expired token")
	}
}

func TestValidateJWT_InvalidUUIDSubject(t *testing.T) {
	// Create a JWT with an invalid UUID as subject
	secret := "supersecret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Minute)),
		Subject:   "not-a-uuid",
	})
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	_, err = ValidateJWT(signed, secret)
	if err == nil {
		t.Error("ValidateJWT did not fail for invalid UUID subject")
	}
}
