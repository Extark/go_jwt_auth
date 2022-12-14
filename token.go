package go_jwt_auth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"strings"
	"time"
)

// generateToken creates a new token and save inside it all the data you need (es. uuid of the user)
// data is an any type, and represents the data to save inside the token
// tokenExpireTimeHours is a int type, represents the duration in hours of the token
// encryptionKey is a string type, represents a secret value to encrypt the token
func generateToken(data any, tokenExpireTimeHours int, encryptionKey string, isRefreshToken bool) (string, error) {
	//Generate claim struct and populate it
	claims := jwt.MapClaims{}

	if !isRefreshToken {
		claims["authorized"] = true
	}
	claims["data"] = data

	if isRefreshToken {
		claims["expire"] = time.Now().Add(time.Hour * 24 * 30).Unix()
	} else {
		claims["expire"] = time.Now().Add(time.Hour * time.Duration(tokenExpireTimeHours)).Unix()
	}

	//Generate token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(encryptionKey))
}

// isTokenValid check if the passed token is valid
// token is a string type and represents the token assigned to the user
// encryptionKey is a string type, represents a secret value to encrypt the token
func isTokenValid(token string, encryptionKey string) (data any, err error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(encryptionKey), nil
	})
	if err != nil {
		return nil, err
	}

	// Check if the parsed token is ok and gets the payload
	payload, ok := parsedToken.Claims.(jwt.MapClaims)
	if !(ok && parsedToken.Valid) {
		return nil, errors.New("invalid token")
	}

	return payload["data"], nil
}

// extractToken extracts the token from the header
func extractToken(r *http.Request) (token string) {
	bearerToken := r.Header.Get("Authorization")
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1]
	}

	return ""
}
