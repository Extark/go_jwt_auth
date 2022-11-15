package go_jwt_auth

type Auth interface {
	CreateTokens() (access string, refresh string, err error)
}
