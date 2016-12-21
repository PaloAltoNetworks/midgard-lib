package claims

import (
	"crypto/x509"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// CertificateClaims represents the claims used by a certificate.
type CertificateClaims struct {
	Organizations       []string
	OrganizationalUnits []string
	CommonName          string
	Email               string

	jwt.StandardClaims
}

// NewCertificateClaims returns a new CertificateClaims.
func NewCertificateClaims() *CertificateClaims {

	return &CertificateClaims{
		StandardClaims:      jwt.StandardClaims{},
		Organizations:       []string{},
		OrganizationalUnits: []string{},
	}
}

// FromCertificate verifies and returns the google claims for the given token.
func (c *CertificateClaims) FromCertificate(certificate *x509.Certificate) error {

	if certificate.Subject.Organization == nil || len(certificate.Subject.Organization) == 0 {
		return fmt.Errorf("Your certificate doesn't contain any O.")
	}

	if certificate.Subject.CommonName == "" {
		return fmt.Errorf("Your certificate doesn't contain a CN.")
	}

	c.Organizations = certificate.Subject.Organization
	c.OrganizationalUnits = certificate.Subject.OrganizationalUnit
	c.CommonName = certificate.Subject.CommonName
	c.Subject = certificate.SerialNumber.String()
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = certificate.NotAfter.Unix()

	return nil
}

// ToMidgardClaims returns the MidgardClaims from google claims.
func (c *CertificateClaims) ToMidgardClaims() *MidgardClaims {

	now := time.Now()

	data := map[string]string{
		"commonName":   c.CommonName,
		"organization": c.Organizations[0],
	}

	if c.OrganizationalUnits != nil && len(c.OrganizationalUnits) > 0 {
		data["organizationalUnit"] = c.OrganizationalUnits[0]
	}

	return &MidgardClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  JWTAudience,
			Issuer:    JWTIssuer,
			ExpiresAt: now.Add(JWTValidity).Unix(),
			IssuedAt:  now.Unix(),
			Subject:   c.Subject,
		},
		Realm: "certificate",
		Data:  data,
	}
}
