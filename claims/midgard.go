package claims

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	// JWTSharedSecret sets the shared secret for signing JWT.
	JWTSharedSecret []byte

	// JWTIssuer sets the issuer to use for generating JWT.
	JWTIssuer string

	// JWTAudience sets the audience to use for generating JWT.
	JWTAudience string
)

// MidgardClaims represents the claims used by Midgard.
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

// FromToken returns a validated Claims and and eventual error from a token
func (c *MidgardClaims) FromToken(tokenString string) error {

	token, err := jwt.ParseWithClaims(tokenString, c, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return JWTSharedSecret, nil
	})

	if err != nil {
		return err
	}

	c = token.Claims.(*MidgardClaims)

	if !c.VerifyAudience(JWTAudience, false) {
		return fmt.Errorf("Audience '%s' is not acceptable", c.Audience)
	}

	if !c.VerifyIssuer(JWTIssuer, false) {
		return fmt.Errorf("Issuer '%s' is not acceptable", c.Issuer)
	}

	return nil
}

// JWT will return the signed JWT string.
func (c *MidgardClaims) JWT() (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	s, _ := token.SignedString(JWTSharedSecret)
	return s, nil
}

func (c *MidgardClaims) String() string {

	return fmt.Sprintf("<midgardclaims realm: %s stdclaims: <claims: %v> data: %v>",
		c.Realm,
		c.StandardClaims,
		c.Data,
	)
}
