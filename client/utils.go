// Copyright 2019 Aporeto Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package midgardclient

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"go.aporeto.io/gaia"
	"go.aporeto.io/gaia/types"
	"go.aporeto.io/tg/tglib"
)

// ParseCredentials parses the credential data.
func ParseCredentials(data []byte) (creds *gaia.Credential, tlsConfig *tls.Config, err error) {

	creds = &gaia.Credential{}
	if err = json.Unmarshal(data, creds); err != nil {
		return nil, nil, fmt.Errorf("unable to decode app credential: %s", err)
	}

	tlsConfig, err = CredsToTLSConfig(creds)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to derive tls config from creds: %s", err)
	}

	return creds, tlsConfig, nil
}

// CredsToTLSConfig converts Crendential to *tlsConfig
func CredsToTLSConfig(creds *gaia.Credential) (tlsConfig *tls.Config, err error) {

	caData, err := base64.StdEncoding.DecodeString(creds.CertificateAuthority)
	if err != nil {
		return nil, fmt.Errorf("unable to decode ca: %s", err)
	}

	certData, err := base64.StdEncoding.DecodeString(creds.Certificate)
	if err != nil {
		return nil, fmt.Errorf("unable to decode certificate: %s", err)
	}

	keyData, err := base64.StdEncoding.DecodeString(creds.CertificateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode key: %s", err)
	}

	capool, err := tglib.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to read system cert pool: %s", err)
	}

	// Here we cannot differentiate from:
	// - failed to add ca
	// - ca already in pool
	// So we just skip...
	capool.AppendCertsFromPEM(caData)

	cert, key, err := tglib.ReadCertificate(certData, keyData, "")
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %s", err)
	}

	clientCert, err := tglib.ToTLSCertificate(cert, key)
	if err != nil {
		return nil, fmt.Errorf("unable to convert certificate: %s", err)
	}

	return &tls.Config{
		RootCAs:      capool,
		Certificates: []tls.Certificate{clientCert},
	}, nil

}

// ExtractJWTFromHeader extracts the JWT from the given http.Header.
func ExtractJWTFromHeader(header http.Header) (string, error) {

	auth := header.Get("Authorization")

	if auth == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(auth, " ")

	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid authorization header")
	}

	return parts[1], nil
}

// VerifyTokenSignature verifies the jwt locally using the given certificate.
// Deprecated: VerifyTokenSignature is deprecated in favor of VerifyToken()
func VerifyTokenSignature(tokenString string, cert *x509.Certificate) ([]string, error) {

	fmt.Println("DEPRECATED: midgardclient.VerifyTokenSignature is deprecated in favor of midgardclient.VerifyToken")
	c, err := VerifyToken(tokenString, cert)
	if err != nil {
		return nil, err
	}

	return NormalizeAuth(c), nil
}

// VerifyToken verifies the jwt locally using the given certificate.
func VerifyToken(tokenString string, cert *x509.Certificate) (*types.MidgardClaims, error) {

	c := &types.MidgardClaims{}

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

	return token.Claims.(*types.MidgardClaims), nil
}

// UnsecureClaimsFromToken gets a token and returns the Aporeto
// claims contained inside. It is Unsecure in the sense that
// It doesn't verify the token signature, so the token must be
// first verified in order to use this function securely.
func UnsecureClaimsFromToken(token string) ([]string, error) {

	c := &types.MidgardClaims{}
	p := jwt.Parser{}

	if _, _, err := p.ParseUnverified(token, c); err != nil {
		return nil, err
	}

	return NormalizeAuth(c), nil
}

// NormalizeAuth normalizes the response to a simple structure.
func NormalizeAuth(c *types.MidgardClaims) (claims []string) {

	if c == nil {
		return
	}

	cache := map[string]struct{}{}

	if c.Subject != "" {
		cache["@auth:subject="+c.Subject] = struct{}{}
	}

	for key, value := range c.Data {
		if value != "" {
			cache["@auth:"+strings.ToLower(key)+"="+value] = struct{}{}
		}
	}

	// remove duplicates
	for key := range cache {
		claims = append(claims, key)
	}

	sort.Strings(claims)

	return
}
