package go_jwt_auth

type StandardError struct {
	Error string `json:"error"`
}

type Auth interface {
	CreateTokens() (access string, refresh string, err error)
}
