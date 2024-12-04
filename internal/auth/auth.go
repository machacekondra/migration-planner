package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/kubev2v/migration-planner/internal/image"
)

const UsernameKey image.Key = 1

// AuthMiddleware handles authentication.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// FIXME: They way UI download the image can't put headers...
		var err error
		username := ""
		if !strings.HasSuffix(r.URL.Path, "/image") {
			accessToken := r.Header.Get("Authorization")
			if accessToken == "" || len(accessToken) < len("Bearer ") {
				http.Error(w, "No token provided", http.StatusUnauthorized)
				return
			}

			accessToken = accessToken[len("Bearer "):]
			username, err = getUsername(accessToken)
			if err != nil && !strings.HasSuffix(r.URL.Path, "/image") {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}
		ctx := context.WithValue(r.Context(), UsernameKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getUsername(accessToken string) (string, error) {
	// Log the user
	parts := strings.Split(accessToken, ".")
	if len(parts) > 1 {
		// decode base64 string
		decodedBytes, err := base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("error decoding: %s", err)
		}
		var data map[string]interface{}

		// Unmarshal the JSON string into the map
		err = json.Unmarshal(decodedBytes, &data)
		if err != nil {
			return "", fmt.Errorf("error: %s", err)
		}

		return data["preferred_username"].(string), nil
	}

	return "", fmt.Errorf("invalid token")
}
