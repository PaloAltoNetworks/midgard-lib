package claims

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/aporeto-inc/elemental"
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

// FromMetadata reads the claims from metadata.
func (c *VinceClaims) FromMetadata(metadata map[string]interface{}, vinceURL string, certPool *x509.CertPool) error {

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

	if err := c.authentify(vinceURL, certPool); err != nil {
		return elemental.NewError("Not Authorized", "Authentication failed", "midgard", http.StatusUnauthorized)
	}

	return nil
}

func (c *VinceClaims) authentify(vinceURL string, certPool *x509.CertPool) error {

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				RootCAs:            certPool,
			},
		},
	}

	request, err := http.NewRequest(http.MethodGet, vinceURL+"/check", nil)
	request.Header.Set("Authorization", c.Account+" "+c.Password)
	if err != nil {
		return err
	}
	request.Close = true

	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Unauthorized")
	}

	return nil
}

// ToMidgardClaims returns the MidgardClaims from VinceClaims.
func (c *VinceClaims) ToMidgardClaims() *MidgardClaims {

	now := time.Now()

	return &MidgardClaims{
		StandardClaims: jwt.StandardClaims{
			Audience: JWTAudience,
			Issuer:   JWTIssuer,
			IssuedAt: now.Unix(),
			Subject:  c.Subject,
		},
		Realm: "Vince",
		Data: map[string]string{
			"account":      c.Account,
			"organization": c.Account,
		},
	}
}
