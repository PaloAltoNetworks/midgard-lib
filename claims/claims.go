package claims

import jwt "github.com/dgrijalva/jwt-go"

// MidgardClaims is a struct to represeting the data some a Midgard issued claims.
type MidgardClaims struct {
	Realm string            `json:"realm"`
	Data  map[string]string `json:"data"`

	jwt.StandardClaims
}

// NewMidgardClaims returns a new Claims.
func NewMidgardClaims() *MidgardClaims {
	return &MidgardClaims{
		Data:           map[string]string{},
		StandardClaims: jwt.StandardClaims{},
	}
}
