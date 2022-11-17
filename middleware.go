package go_jwt_auth

import (
	"encoding/json"
	"net/http"
)

// JwtAuthMiddleware checks if the token is authorized to access at the resources
func JwtAuthMiddleware(next http.HandlerFunc, encryptionKey string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		//set the header content type
		writer.Header().Set("Content-Type", "application/json")
		//try to extract the token
		token := extractToken(request)
		if token == "" {
			writer.WriteHeader(http.StatusForbidden)
			json.NewEncoder(writer).Encode(StandardError{Error: "missing auth token"})
			return
		}

		//check if the token is valid
		if _, err := isTokenValid(token, encryptionKey); err != nil {
			writer.WriteHeader(http.StatusForbidden)
			json.NewEncoder(writer).Encode(StandardError{Error: err.Error()})
			return
		}

		//send all to the request
		next.ServeHTTP(writer, request)
	}
}
