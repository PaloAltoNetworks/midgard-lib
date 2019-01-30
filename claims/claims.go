package claims

import jwt "github.com/dgrijalva/jwt-go"

// MidgardClaims is a struct to represeting the data some a Midgard issued claims.
type MidgardClaims struct {
	Realm  string            `json:"realm"`
	Quota  int               `json:"quota,omitempty"`
	Data   map[string]string `json:"data"`
	Opaque map[string]string `json:"opaque,omitempty"`

	jwt.StandardClaims
}

// NewMidgardClaims returns a new Claims.
func NewMidgardClaims() *MidgardClaims {
	return &MidgardClaims{
		Data:           map[string]string{},
		StandardClaims: jwt.StandardClaims{},
	}
}
