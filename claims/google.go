package claims

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	// JWTGoogleClientID is the Google client ID.
	JWTGoogleClientID string

	// JWTGoogleValidationURL is the URL that will be used to validate a JWT.
	JWTGoogleValidationURL string

	// JWTGoogleIssuer sets the Google issuer value.
	JWTGoogleIssuer = "accounts.google.com"
)

// GoogleClaims represents the claims used by google.
type GoogleClaims struct {
	Name         string `json:"name"`
	GivenName    string `json:"given_name"`
	FamilyName   string `json:"family_name"`
	Email        string `json:"email"`
	Organization string `json:"hd"`

	ExpiresAt int64 `json:"exp,string"`
	IssuedAt  int64 `json:"iat,string"`

	jwt.StandardClaims
}

// NewGoogleClaims returns a new Claims.
func NewGoogleClaims() *GoogleClaims {

	return &GoogleClaims{
		StandardClaims: jwt.StandardClaims{},
	}
}

// FromToken verifies and returns the google claims for the given token.
func (c *GoogleClaims) FromToken(token string) error {

	resp, err := http.Get(JWTGoogleValidationURL + "?id_token=" + token)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Google did not validate the token.")
	}

	if err := json.NewDecoder(resp.Body).Decode(c); err != nil {
		return err
	}

	if !c.VerifyAudience(JWTGoogleClientID, false) {
		return fmt.Errorf("Audience '%s' is not acceptable.", c.Audience)
	}

	if !c.VerifyIssuer(JWTGoogleIssuer, false) {
		return fmt.Errorf("Issuer '%s' is not acceptable.", c.Issuer)
	}

	return nil
}

// ToMidgardClaims returns the MidgardClaims from google claims.
func (c *GoogleClaims) ToMidgardClaims() *MidgardClaims {

	now := time.Now()

	org := c.Organization
	if org == "" {
		org = "gmail.com"
	}

	return &MidgardClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  JWTAudience,
			Issuer:    JWTIssuer,
			ExpiresAt: now.Add(JWTValidity).Unix(),
			IssuedAt:  now.Unix(),
			Subject:   c.Subject,
		},
		Realm: "google",
		Data: map[string]string{
			"email":        c.Email,
			"givenName":    c.GivenName,
			"familyName":   c.FamilyName,
			"name":         c.Name,
			"organization": org,
		},
	}
}
