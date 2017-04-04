package midgardclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	midgardmodels "github.com/aporeto-inc/gaia/midgardmodels/current/golang"
	"github.com/aporeto-inc/midgard-lib/ldaputils"

	"github.com/Sirupsen/logrus"
)

// Logger is the main logger for midgard client.
var Logger = logrus.New()

var log = Logger.WithField("package", "github.com/aporeto-inc/midgard/client")

// A Client allows to interract with a midgard server.
type Client struct {
	url          string
	clientCAPool *x509.CertPool
	rootCAPool   *x509.CertPool
	skipVerify   bool
	httpClient   *http.Client
}

// NewClient returns a new Client.
func NewClient(url string) *Client {

	CAPool, err := x509.SystemCertPool()
	if err != nil {
		CAPool = x509.NewCertPool()
	}

	return NewClientWithCAPool(url, CAPool, nil, true)
}

// NewClientWithCAPool returns a new Client configured with the given x509.CAPool.
func NewClientWithCAPool(url string, rootCAPool *x509.CertPool, clientCAPool *x509.CertPool, skipVerify bool) *Client {

	if url == "" {
		panic("Missing Midgard URL.")
	}

	return &Client{
		url:          url,
		rootCAPool:   rootCAPool,
		clientCAPool: clientCAPool,
		skipVerify:   skipVerify,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: skipVerify,
					ClientCAs:          clientCAPool,
					RootCAs:            rootCAPool,
				},
			},
		},
	}
}

// Authentify authentifies the information included in the given http.Header and
// returns a list of tag string containing the claims.
func (a *Client) Authentify(token string) ([]string, error) {

	request, err := http.NewRequest(http.MethodGet, a.url+"/auth?token="+token, nil)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Unable to create request.")
		return nil, err
	}

	resp, err := a.httpClient.Do(request)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Midgard could not be reached.")
		return nil, err
	}

	if resp.StatusCode != 200 {
		log.WithFields(logrus.Fields{
			"token": token,
		}).Debug("Midgard rejected the token.")
		return nil, fmt.Errorf("Unauthorized")
	}

	auth := midgardmodels.NewAuth()

	defer resp.Body.Close() // nolint: errcheck

	if err := json.NewDecoder(resp.Body).Decode(auth); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Could not decode json.")
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"token": token,
	}).Debug("Successfully authenticated.")

	return normalizeAuth(auth), nil
}

// IssueFromGoogle issues a Midgard jwt from a Google JWT.
func (a *Client) IssueFromGoogle(googleJWT string) (string, error) {

	return a.IssueFromGoogleWithValidity(googleJWT, 24*time.Hour)
}

// IssueFromGoogleWithValidity issues a Midgard jwt from a Google JWT for the given validity duration.
func (a *Client) IssueFromGoogleWithValidity(googleJWT string, validity time.Duration) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Realm = midgardmodels.IssueRealmGoogle
	issueRequest.Data = googleJWT
	issueRequest.Validity = fmt.Sprintf("%s", validity)

	return a.sendRequest(a.httpClient, issueRequest, false)
}

// IssueFromCertificate issues a Midgard jwt from a certificate.
func (a *Client) IssueFromCertificate(certificates []tls.Certificate) (string, error) {
	return a.IssueFromCertificateWithValidity(certificates, 24*time.Hour)
}

// IssueFromCertificateWithValidity issues a Midgard jwt from a certificate for the given validity duration.
func (a *Client) IssueFromCertificateWithValidity(certificates []tls.Certificate, validity time.Duration) (string, error) {

	// Here we need a custom client per request so we can pass the client certificates.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: a.skipVerify,
				ClientCAs:          a.clientCAPool,
				RootCAs:            a.rootCAPool,
				Certificates:       certificates,
			},
		},
	}

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Realm = midgardmodels.IssueRealmCertificate
	issueRequest.Validity = fmt.Sprintf("%s", validity)

	return a.sendRequest(client, issueRequest, true)
}

// IssueFromLDAP issues a Midgard jwt from a LDAP.
func (a *Client) IssueFromLDAP(info *ldaputils.LDAPInfo, vinceAccount string) (string, error) {
	return a.IssueFromLDAPWithValidity(info, vinceAccount, 24*time.Hour)
}

// IssueFromLDAPWithValidity issues a Midgard jwt from a LDAP for the given validity duration.
func (a *Client) IssueFromLDAPWithValidity(info *ldaputils.LDAPInfo, vinceAccount string, validity time.Duration) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Realm = midgardmodels.IssueRealmLdap
	issueRequest.Validity = fmt.Sprintf("%s", validity)
	issueRequest.Metadata = info.ToMap()
	if vinceAccount != "" {
		issueRequest.Metadata["account"] = vinceAccount
	}

	return a.sendRequest(a.httpClient, issueRequest, false)
}

// IssueFromVince issues a Midgard jwt from a Vince.
func (a *Client) IssueFromVince(account string, password string) (string, error) {
	return a.IssueFromVinceWithValidity(account, password, 24*time.Hour)
}

// IssueFromVinceWithValidity issues a Midgard jwt from a Vince for the given validity duration.
func (a *Client) IssueFromVinceWithValidity(account string, password string, validity time.Duration) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"vinceAccount": account, "vincePassword": password}
	issueRequest.Realm = midgardmodels.IssueRealmVince
	issueRequest.Validity = fmt.Sprintf("%s", validity)

	return a.sendRequest(a.httpClient, issueRequest, false)
}

// IssueFromAWSIdentityDocument issues a Midgard jwt from a signed AWS identity document.
func (a *Client) IssueFromAWSIdentityDocument(doc string) (string, error) {
	return a.IssueFromAWSIdentityDocumentWithValidity(doc, 24*time.Hour)
}

// IssueFromAWSIdentityDocumentWithValidity issues a Midgard jwt from a signed AWS identity document for the given validity duration.
func (a *Client) IssueFromAWSIdentityDocumentWithValidity(doc string, validity time.Duration) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"doc": doc}
	issueRequest.Realm = midgardmodels.IssueRealmAwsidentitydocument
	issueRequest.Validity = fmt.Sprintf("%s", validity)

	return a.sendRequest(a.httpClient, issueRequest, false)
}

func (a *Client) sendRequest(client *http.Client, issueRequest *midgardmodels.Issue, closeConn bool) (string, error) {

	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(issueRequest); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
			"realm": issueRequest.Realm,
		}).Error("Could not encode request object.")
		return "", err
	}

	request, err := http.NewRequest(http.MethodPost, a.url+"/issue", buffer)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
			"realm": issueRequest.Realm,
		}).Error("Unable to create request.")
		return "", err
	}

	if closeConn {
		request.Close = true
	}

	resp, err := client.Do(request)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
			"realm": issueRequest.Realm,
		}).Error("Midgard could not be reached.")
		return "", err
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)

		log.WithFields(logrus.Fields{
			"realm": issueRequest.Realm,
			"body":  string(body),
			"error": err.Error(),
		}).Error("Midgard could not issue a token.")
		return "", fmt.Errorf("Could not issue token. Response code %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(issueRequest); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
			"realm": issueRequest.Realm,
		}).Error("Midgard Client could not decode the data.")
		return "", err
	}

	log.WithFields(logrus.Fields{
		"token": issueRequest.Token,
		"realm": issueRequest.Realm,
	}).Debug("Token successfully issued.")

	return issueRequest.Token, nil
}
