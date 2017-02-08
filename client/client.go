package midgardclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aporeto-inc/midgard-lib/claims"
	"github.com/aporeto-inc/midgard-lib/models"

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
	}
}

// Authentify authentifies the information included in the given http.Header and
// returns a list of tag string containing the claims.
func (a *Client) Authentify(token string) ([]string, error) {

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: a.skipVerify,
				ClientCAs:          a.clientCAPool,
				RootCAs:            a.rootCAPool,
			},
		},
	}

	request, err := http.NewRequest(http.MethodGet, a.url+"/auth?token="+token, nil)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Unable to create request.")
		return nil, err
	}
	request.Close = true

	resp, err := client.Do(request)
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
		return nil, fmt.Errorf("Unauthorized.")
	}

	auth := models.NewAuth()

	defer resp.Body.Close()
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

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: a.skipVerify,
				RootCAs:            a.rootCAPool,
			},
		},
	}

	issueRequest := models.NewIssue()
	issueRequest.Realm = models.IssueRealmGoogle
	issueRequest.Data = googleJWT

	return a.sendRequest(client, issueRequest)
}

// IssueFromCertificate issues a Midgard jwt from a certificate.
func (a *Client) IssueFromCertificate(certificates []tls.Certificate) (string, error) {

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

	issueRequest := models.NewIssue()
	issueRequest.Realm = models.IssueRealmCertificate

	return a.sendRequest(client, issueRequest)
}

// IssueFromLDAP issues a Midgard jwt from a LDAP.
func (a *Client) IssueFromLDAP(info *claims.LDAPInfo) (string, error) {

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: a.skipVerify,
				ClientCAs:          a.clientCAPool,
				RootCAs:            a.rootCAPool,
			},
		},
	}

	issueRequest := models.NewIssue()
	issueRequest.Metadata = info.ToMap()
	issueRequest.Realm = models.IssueRealmLdap

	return a.sendRequest(client, issueRequest)
}

// IssueFromVince issues a Midgard jwt from a Vince.
func (a *Client) IssueFromVince(account string, password string) (string, error) {

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: a.skipVerify,
				ClientCAs:          a.clientCAPool,
				RootCAs:            a.rootCAPool,
			},
		},
	}

	issueRequest := models.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"vinceAccount": account, "vincePassword": password}
	issueRequest.Realm = models.IssueRealmVince

	return a.sendRequest(client, issueRequest)
}

func (a *Client) sendRequest(client *http.Client, issueRequest *models.Issue) (string, error) {

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
	request.Close = true

	resp, err := client.Do(request)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
			"realm": issueRequest.Realm,
		}).Error("Midgard could not be reached.")
		return "", err
	}

	if resp.StatusCode != 200 {
		log.WithFields(logrus.Fields{
			"realm": issueRequest.Realm,
		}).Debug("Midgard could not issue a token.")
		return "", fmt.Errorf("Could not issue token. Response code %d", resp.StatusCode)
	}

	defer resp.Body.Close()
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
