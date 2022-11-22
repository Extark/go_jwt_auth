package go_jwt_auth

import (
	"encoding/json"
	"fmt"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"log"
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

func JwtCasbinAuthMiddleware(next http.HandlerFunc, adapter *gormadapter.Adapter, encryptionKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//set the header content type
		w.Header().Set("Content-Type", "application/json")
		//instance some vars
		obj := r.URL.Path
		action := r.Method
		//try to extract the token and check if is valid
		data, err := ExtractAndGetTokenData(r, encryptionKey)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(StandardError{Error: "the passed token is invalid"})
			return
		}

		//casbin enforces policy
		ok, err := enforce(fmt.Sprintf("%s", data), obj, action, adapter)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(StandardError{Error: "error occurred when authorizing user"})
			return
		}

		if !ok {
			log.Print(err)
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(StandardError{Error: "this route is forbidden for the current user"})
			return
		}

		//send all to the request
		next.ServeHTTP(w, r)
	}
}
