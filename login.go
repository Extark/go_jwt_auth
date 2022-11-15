package go_jwt_auth

import "github.com/extark/go_jwt_auth/utils"

// CreateAuthorization this method creates an access token and a refresh token and return it. Is important call this method only after the check of user and password.
// data is an any type, and represents the data to save inside the token
// tokenExpireTimeHours is a int type, represents the duration in hours of the token
// encryptionKey is a string type, represents a secret value to encrypt the token
func CreateAuthorization(data any, tokenExpireTimeHours int, encryptionKey string) (access string, refresh string, err error) {
	// generate the access token
	if access, err = utils.GenerateToken(data, tokenExpireTimeHours, encryptionKey, false); err != nil {
		return "", "", err
	}

	// generate the refresh token
	if refresh, err = utils.GenerateToken(data, tokenExpireTimeHours, encryptionKey, true); err != nil {
		return "", "", err
	}

	return access, refresh, err
}
