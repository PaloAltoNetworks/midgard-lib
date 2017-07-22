package midgardclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aporeto-inc/gaia/midgardmodels/v1/golang"
	"github.com/aporeto-inc/midgard-lib/ldaputils"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/log"
)

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
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				IdleConnTimeout:     120 * time.Second,
				MaxIdleConnsPerHost: 100,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: skipVerify,
					ClientCAs:          clientCAPool,
					RootCAs:            rootCAPool,
				},
			},
		},
	}
}

// Authentify authentifies the information included in the given token and
// returns a list of tag string containing the claims.
func (a *Client) Authentify(token string) ([]string, error) {

	return a.AuthentifyWithTracking(token, nil)
}

// AuthentifyWithTracking authentifies the information using the given token and
// returns a list of tag string containing the claims.
func (a *Client) AuthentifyWithTracking(token string, span opentracing.Span) ([]string, error) {

	var sp opentracing.Span
	if span != nil {
		sp = opentracing.StartSpan("midgardlib.client.authentify", opentracing.ChildOf(span.Context()))
	} else {
		sp = opentracing.StartSpan("midgardlib.client.authentify")
	}
	defer sp.Finish()

	request, err := http.NewRequest(http.MethodGet, a.url+"/auth?token="+token, nil)
	if err != nil {

		ext.Error.Set(sp, true)
		sp.LogEvent("Unable to create request")
		sp.LogFields(log.Error(err))

		return nil, err
	}

	if sp.Tracer() != nil {
		if err = sp.Tracer().Inject(sp.Context(), opentracing.TextMap, opentracing.HTTPHeadersCarrier(request.Header)); err != nil {
			return nil, err
		}
	}

	resp, err := a.httpClient.Do(request)
	if err != nil {

		ext.Error.Set(sp, true)
		sp.LogEvent("Midgard could not be reached")
		sp.LogFields(log.Error(err))

		return nil, err
	}

	if resp.StatusCode != 200 {

		ext.Error.Set(sp, true)
		sp.LogEvent("Midgard rejected the token")

		return nil, fmt.Errorf("Unauthorized")
	}

	auth := midgardmodels.NewAuth()

	defer resp.Body.Close() // nolint: errcheck

	if err := json.NewDecoder(resp.Body).Decode(auth); err != nil {

		ext.Error.Set(sp, true)
		sp.LogEvent("Could not decode json")
		sp.LogFields(log.Error(err))

		return nil, err
	}

	return normalizeAuth(auth), nil
}

// IssueFromGoogle issues a Midgard jwt from a Google JWT.
func (a *Client) IssueFromGoogle(googleJWT string) (string, error) {

	return a.IssueFromGoogleWithValidity(googleJWT, 24*time.Hour, nil)
}

// IssueFromGoogleWithValidity issues a Midgard jwt from a Google JWT for the given validity duration.
func (a *Client) IssueFromGoogleWithValidity(googleJWT string, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Realm = midgardmodels.IssueRealmGoogle
	issueRequest.Data = googleJWT
	issueRequest.Validity = validity.String()

	return a.sendRequest(a.httpClient, issueRequest, false, span)
}

// IssueFromCertificate issues a Midgard jwt from a certificate.
func (a *Client) IssueFromCertificate(certificates []tls.Certificate) (string, error) {

	return a.IssueFromCertificateWithValidity(certificates, 24*time.Hour, nil)
}

// IssueFromCertificateWithValidity issues a Midgard jwt from a certificate for the given validity duration.
func (a *Client) IssueFromCertificateWithValidity(certificates []tls.Certificate, validity time.Duration, span opentracing.Span) (string, error) {

	// Here we need a custom client per request so we can pass the client certificates.
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			MaxIdleConnsPerHost: 100,
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
	issueRequest.Validity = validity.String()

	return a.sendRequest(client, issueRequest, true, span)
}

// IssueFromLDAP issues a Midgard jwt from a LDAP.
func (a *Client) IssueFromLDAP(info *ldaputils.LDAPInfo, vinceAccount string) (string, error) {
	return a.IssueFromLDAPWithValidity(info, vinceAccount, 24*time.Hour, nil)
}

// IssueFromLDAPWithValidity issues a Midgard jwt from a LDAP for the given validity duration.
func (a *Client) IssueFromLDAPWithValidity(info *ldaputils.LDAPInfo, vinceAccount string, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Realm = midgardmodels.IssueRealmLdap
	issueRequest.Validity = validity.String()
	issueRequest.Metadata = info.ToMap()
	if vinceAccount != "" {
		issueRequest.Metadata["account"] = vinceAccount
	}

	return a.sendRequest(a.httpClient, issueRequest, false, span)
}

// IssueFromVince issues a Midgard jwt from a Vince.
func (a *Client) IssueFromVince(account string, password string) (string, error) {

	return a.IssueFromVinceWithValidity(account, password, 24*time.Hour, nil)
}

// IssueFromVinceWithValidity issues a Midgard jwt from a Vince for the given validity duration.
func (a *Client) IssueFromVinceWithValidity(account string, password string, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"vinceAccount": account, "vincePassword": password}
	issueRequest.Realm = midgardmodels.IssueRealmVince
	issueRequest.Validity = validity.String()

	return a.sendRequest(a.httpClient, issueRequest, false, span)
}

// IssueFromAWSIdentityDocument issues a Midgard jwt from a signed AWS identity document.
func (a *Client) IssueFromAWSIdentityDocument(doc string) (string, error) {

	return a.IssueFromAWSIdentityDocumentWithValidity(doc, 24*time.Hour, nil)
}

// IssueFromAWSIdentityDocumentWithValidity issues a Midgard jwt from a signed AWS identity document for the given validity duration.
func (a *Client) IssueFromAWSIdentityDocumentWithValidity(doc string, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"doc": doc}
	issueRequest.Realm = midgardmodels.IssueRealmAwsidentitydocument
	issueRequest.Validity = validity.String()

	return a.sendRequest(a.httpClient, issueRequest, false, span)
}

func (a *Client) sendRequest(client *http.Client, issueRequest *midgardmodels.Issue, closeConn bool, span opentracing.Span) (string, error) {

	var sp opentracing.Span
	if span != nil {
		sp = opentracing.StartSpan("midgardlib.client.issue", opentracing.ChildOf(span.Context()))
	} else {
		sp = opentracing.StartSpan("midgardlib.client.issue")
	}
	defer sp.Finish()

	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(issueRequest); err != nil {
		return "", err
	}

	request, err := http.NewRequest(http.MethodPost, a.url+"/issue", buffer)
	if err != nil {
		return "", err
	}

	if sp.Tracer() != nil {
		if err = sp.Tracer().Inject(sp.Context(), opentracing.TextMap, opentracing.HTTPHeadersCarrier(request.Header)); err != nil {
			return "", err
		}
	}

	if closeConn {
		request.Close = true
	}

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Could not issue token. Response code %d", resp.StatusCode)
	}

	defer resp.Body.Close() // nolint: errcheck
	if err := json.NewDecoder(resp.Body).Decode(issueRequest); err != nil {
		return "", err
	}

	return issueRequest.Token, nil
}
