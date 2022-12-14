package go_jwt_auth

import "net/http"

// CreateTokens this method creates an access token and a refresh token and return it. Is important call this method only after the check of user and password.
// data is an any type, and represents the data to save inside the token
// tokenExpireTimeHours is a int type, represents the duration in hours of the token
// encryptionKey is a string type, represents a secret value to encrypt the token
func CreateTokens(data any, tokenExpireTimeHours int, encryptionKey string) (access string, refresh string, err error) {
	// generate the access token
	if access, err = generateToken(data, tokenExpireTimeHours, encryptionKey, false); err != nil {
		return "", "", err
	}

	// generate the refresh token
	if refresh, err = generateToken(data, tokenExpireTimeHours, encryptionKey, true); err != nil {
		return "", "", err
	}

	return access, refresh, err
}

// GetTokenData this method gets the value of the data inside the JWT token and gets a response only if the token is valid
func GetTokenData(token string, encryptionKey string) (data any, err error) {
	//Check if is valid and in this case it returns the data string
	return isTokenValid(token, encryptionKey)
}

// ExtractAndGetTokenData this method gets the value of the data inside the JWT token and gets a response only if the token is valid
func ExtractAndGetTokenData(r *http.Request, encryptionKey string) (data any, err error) {
	token := extractToken(r)
	return isTokenValid(token, encryptionKey)
}
