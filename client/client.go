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

	log "github.com/Sirupsen/logrus"
)

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
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
		}).Error("Unable to create request.")
		return nil, err
	}
	request.Close = true

	resp, err := client.Do(request)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
		}).Error("Midgard could not be reached.")
		return nil, err
	}

	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"token":   token,
		}).Debug("Midgard rejected the token.")
		return nil, fmt.Errorf("Unauthorized.")
	}

	auth := models.NewAuth()

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(auth); err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
		}).Error("Could not decode json.")
		return nil, err
	}

	log.WithFields(log.Fields{
		"package": "midgardclient",
		"token":   token,
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

	req := models.NewIssue()
	req.Realm = models.IssueRealmGoogle
	req.Data = googleJWT

	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(req); err != nil {
		log.WithFields(log.Fields{
			"package":     "midgardclient",
			"error":       err.Error(),
			"googletoken": googleJWT,
			"realm":       "google",
		}).Error("Could not encode request object.")
		return "", err
	}

	request, err := http.NewRequest(http.MethodPost, a.url+"/issue", buffer)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
		}).Error("Unable to create request.")
		return "", err
	}
	request.Close = true

	resp, err := client.Do(request)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "google",
		}).Error("Midgard could not be reached.")
		return "", err
	}

	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{
			"package":     "midgardclient",
			"googletoken": googleJWT,
			"realm":       "google",
		}).Debug("Midgard could not issue a token.")
		return "", fmt.Errorf("Could not issue token. Response code %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(req); err != nil {
		log.WithFields(log.Fields{
			"package":     "midgardclient",
			"error":       err.Error(),
			"googletoken": googleJWT,
			"realm":       "google",
		}).Error("Midgard client could not decode the data.")
		return "", err
	}

	log.WithFields(log.Fields{
		"package":     "midgardclient",
		"googletoken": googleJWT,
		"token":       req.Token,
		"realm":       "google",
	}).Debug("Token successfully issued.")

	return req.Token, nil
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

	req := models.NewIssue()
	req.Realm = models.IssueRealmCertificate

	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(req); err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "certificate",
		}).Error("Could not encode request object.")
		return "", err
	}

	request, err := http.NewRequest(http.MethodPost, a.url+"/issue", buffer)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
		}).Error("Unable to create request.")
		return "", err
	}
	request.Close = true

	resp, err := client.Do(request)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "certificate",
		}).Error("Midgard could not be reached.")
		return "", err
	}

	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "certificate",
		}).Debug("Midgard could not issue a token.")
		return "", fmt.Errorf("Could not issue token. Response code %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(req); err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "certificate",
		}).Error("Midgard Client could not decode the data.")
		return "", err
	}

	log.WithFields(log.Fields{
		"package": "midgardclient",
		"token":   req.Token,
		"realm":   "certificate",
	}).Debug("Token successfully issued.")

	return req.Token, nil
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

	req := models.NewIssue()
	req.Realm = models.IssueRealmLdap

	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(req); err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "certificate",
		}).Error("Could not encode request object.")
		return "", err
	}

	request, err := http.NewRequest(http.MethodPost, a.url+"/issue", buffer)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
		}).Error("Unable to create request.")
		return "", err
	}
	request.Close = true

	resp, err := client.Do(request)
	if err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "certificate",
		}).Error("Midgard could not be reached.")
		return "", err
	}

	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "certificate",
		}).Debug("Midgard could not issue a token.")
		return "", fmt.Errorf("Could not issue token. Response code %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(req); err != nil {
		log.WithFields(log.Fields{
			"package": "midgardclient",
			"error":   err.Error(),
			"realm":   "certificate",
		}).Error("Midgard Client could not decode the data.")
		return "", err
	}

	log.WithFields(log.Fields{
		"package": "midgardclient",
		"token":   req.Token,
		"realm":   "certificate",
	}).Debug("Token successfully issued.")

	return req.Token, nil
}
