package midgardclient

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"go.aporeto.io/gaia"
	"go.aporeto.io/midgard-lib/claims"
	"go.aporeto.io/tg/tglib"
)

// ParseCredentials parses the credential data.
func ParseCredentials(data []byte) (creds *gaia.Credential, tlsConfig *tls.Config, err error) {

	creds = &gaia.Credential{}
	if err = json.Unmarshal(data, creds); err != nil {
		return nil, nil, fmt.Errorf("unable to decode app credential: %s", err)
	}

	caData, err := base64.StdEncoding.DecodeString(creds.CertificateAuthority)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode ca: %s", err)
	}

	certData, err := base64.StdEncoding.DecodeString(creds.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode certificate: %s", err)
	}

	keyData, err := base64.StdEncoding.DecodeString(creds.CertificateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode key: %s", err)
	}

	capool, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read system cert pool: %s", err)
	}

	// Here we cannot differentiate from:
	// - failed to add ca
	// - ca already in pool
	// So we just skip...
	capool.AppendCertsFromPEM(caData)

	cert, key, err := tglib.ReadCertificate(certData, keyData, "")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse certificate: %s", err)
	}

	clientCert, err := tglib.ToTLSCertificate(cert, key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to convert certificate: %s", err)
	}

	return creds, &tls.Config{
		RootCAs:      capool,
		Certificates: []tls.Certificate{clientCert},
	}, nil

}

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

// VerifyTokenSignature verifies the jwt locally using the given certificate.
func VerifyTokenSignature(tokenString string, cert *x509.Certificate) ([]string, error) {

	c := &claims.MidgardClaims{}

	token, err := jwt.ParseWithClaims(tokenString, c, func(token *jwt.Token) (interface{}, error) {

		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}

		return cert.PublicKey.(*ecdsa.PublicKey), nil

	})

	if err != nil {
		return nil, err
	}

	return normalizeAuth(token.Claims.(*claims.MidgardClaims)), nil
}

// normalizeAuth normalizes the response to a simple structure.
func normalizeAuth(c *claims.MidgardClaims) (claims []string) {

	if c.Subject != "" {
		claims = append(claims, "@auth:subject="+c.Subject)
	}

	for key, value := range c.Data {
		if value != "" {
			claims = append(claims, "@auth:"+strings.ToLower(key)+"="+value)
		}
	}

	return
}
