package midgardclient

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/aporeto-inc/gaia/v1/golang"
)

// ExtractJWTFromHeader extracts the JWT from the given http.Header.
func ExtractJWTFromHeader(header http.Header) (string, error) {

	auth := header.Get("Authorization")

	if auth == "" {
		return "", fmt.Errorf("Missing Authorization Header")
	}

	parts := strings.Split(auth, " ")

	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("Invalid Authorization Header")
	}

	return parts[1], nil
}

// normalizeAuth normalizes the response to a simple structure.
func normalizeAuth(a *gaia.Auth) (claims []string) {

	if a.Claims.Subject != "" {
		claims = append(claims, "@auth:subject="+a.Claims.Subject)
	}

	for key, value := range a.Claims.Data {
		if value != "" {
			claims = append(claims, "@auth:"+strings.ToLower(key)+"="+value)
		}
	}

	return
}
