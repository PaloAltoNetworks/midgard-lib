package claims

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	vinceAccountKey  = "vinceAccount"
	vincePasswordKey = "vincePassword"
)

func findVinceKey(k string, metadata map[string]interface{}) (string, error) {

	if v, ok := metadata[k]; ok && v.(string) != "" {
		return v.(string), nil
	}

	return "", fmt.Errorf("Metadata must contain the key '%s'", k)
}

// VinceClaims represents the claims used by a Aporeto Vince.
type VinceClaims struct {
	Account  string
	Password string

	jwt.StandardClaims
}

// NewVinceClaims returns a new VinceClaims.
func NewVinceClaims() *VinceClaims {

	return &VinceClaims{
		StandardClaims: jwt.StandardClaims{},
	}
}

func (c *VinceClaims) fromMetadata(metadata map[string]interface{}) error {

	var err error

	c.Account, err = findVinceKey(vinceAccountKey, metadata)
	if err != nil {
		return err
	}
	c.Subject = c.Account

	c.Password, err = findVinceKey(vincePasswordKey, metadata)
	if err != nil {
		return err
	}

	return nil
}

// ToMidgardClaims returns the MidgardClaims from VinceClaims.
func (c *VinceClaims) ToMidgardClaims() *MidgardClaims {

	now := time.Now()

	return &MidgardClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  JWTAudience,
			Issuer:    JWTIssuer,
			ExpiresAt: now.Add(JWTValidity).Unix(),
			IssuedAt:  now.Unix(),
			Subject:   c.Subject,
		},
		Realm: "Vince",
		Data: map[string]string{
			"account": c.Account,
		},
	}
}
