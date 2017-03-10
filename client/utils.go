package midgardclient

import (
	"fmt"
	"net/http"
	"strings"

	midgardmodels "github.com/aporeto-inc/gaia/midgardmodels/current/golang"
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
func normalizeAuth(a *midgardmodels.Auth) []string {

	ret := []string{
		"@auth:realm=" + a.Claims.Realm,
		"@auth:subject=" + a.Claims.Subject,
	}

	for key, value := range a.Claims.Data {
		ret = append(ret, "@auth:"+strings.ToLower(key)+"="+value)
	}

	return ret
}
