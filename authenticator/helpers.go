package authenticator

import (
	"net/http"
	"strings"
)

func tokenFromRequest(req *http.Request) string {

	authHeader := req.Header.Get("Authorization")

	if authHeader != "" {

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			return ""
		}

		return parts[1]
	}

	return req.URL.Query().Get("token")
}
