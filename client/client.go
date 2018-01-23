package midgardclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aporeto-inc/addedeffect/tokensnip"

	"github.com/opentracing/opentracing-go/log"

	"github.com/aporeto-inc/elemental"
	"github.com/aporeto-inc/gaia/midgardmodels/v1/golang"
	"github.com/aporeto-inc/midgard-lib/ldaputils"
	"github.com/opentracing/opentracing-go"
)

// A Client allows to interract with a midgard server.
type Client struct {
	TrackingType string

	url        string
	tlsConfig  *tls.Config
	httpClient *http.Client
	closeConn  bool
}

// NewClient returns a new Client.
func NewClient(url string) *Client {

	CAPool, err := x509.SystemCertPool()
	if err != nil {
		CAPool = x509.NewCertPool()
	}

	return NewClientWithTLS(
		url,
		&tls.Config{
			InsecureSkipVerify: true,
			RootCAs:            CAPool,
		},
	)
}

// NewClientWithTLS returns a new Client configured with the given x509.CAPool.
func NewClientWithTLS(url string, tlsConfig *tls.Config) *Client {

	if url == "" {
		panic("Missing Midgard URL.")
	}

	return &Client{
		url:       url,
		tlsConfig: tlsConfig,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// SetKeepAliveEnabled sets if the connection should be reused of not.
func (a *Client) SetKeepAliveEnabled(e bool) {
	a.closeConn = e
}

// Authentify authentifies the information included in the given token and
// returns a list of tag string containing the claims.
func (a *Client) Authentify(token string) ([]string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return a.AuthentifyWithTracking(ctx, token, nil)
}

// AuthentifyWithTracking authentifies the information using the given token and
// returns a list of tag string containing the claims.
func (a *Client) AuthentifyWithTracking(ctx context.Context, token string, span opentracing.Span) ([]string, error) {

	var sp opentracing.Span
	if span != nil {
		sp = opentracing.StartSpan("midgardlib.client.authentify", opentracing.ChildOf(span.Context()))
		defer sp.Finish()
	}

	builder := func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, a.url+"/auth?token="+token, nil)
	}

	resp, err := a.sendRetry(ctx, builder, token, sp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, elemental.NewError("Unauthorized", fmt.Sprintf("Authentication rejected with error: %s", resp.Status), "midgard-lib", http.StatusUnauthorized)
	}

	auth := midgardmodels.NewAuth()

	defer resp.Body.Close() // nolint: errcheck

	if err := json.NewDecoder(resp.Body).Decode(auth); err != nil {
		return nil, err
	}

	return normalizeAuth(auth), nil
}

// IssueFromGoogle issues a Midgard jwt from a Google JWT.
func (a *Client) IssueFromGoogle(googleJWT string) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return a.IssueFromGoogleWithValidity(ctx, googleJWT, 24*time.Hour, nil)
}

// IssueFromGoogleWithValidity issues a Midgard jwt from a Google JWT for the given validity duration.
func (a *Client) IssueFromGoogleWithValidity(ctx context.Context, googleJWT string, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Realm = midgardmodels.IssueRealmGoogle
	issueRequest.Data = googleJWT
	issueRequest.Validity = validity.String()

	var sp opentracing.Span
	if span != nil {
		sp = opentracing.StartSpan("midgardlib.client.issue.google", opentracing.ChildOf(span.Context()))
		defer sp.Finish()
	}

	return a.sendRequest(ctx, issueRequest, sp)
}

// IssueFromCertificate issues a Midgard jwt from a certificate.
func (a *Client) IssueFromCertificate(certificates []tls.Certificate) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return a.IssueFromCertificateWithValidity(ctx, 24*time.Hour, nil)
}

// IssueFromCertificateWithValidity issues a Midgard jwt from a certificate for the given validity duration.
func (a *Client) IssueFromCertificateWithValidity(ctx context.Context, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Realm = midgardmodels.IssueRealmCertificate
	issueRequest.Validity = validity.String()

	var sp opentracing.Span
	if span != nil {
		sp = opentracing.StartSpan("midgardlib.client.issue.certificate", opentracing.ChildOf(span.Context()))
		defer sp.Finish()
	}

	return a.sendRequest(ctx, issueRequest, sp)
}

// IssueFromLDAP issues a Midgard jwt from a LDAP.
func (a *Client) IssueFromLDAP(info *ldaputils.LDAPInfo, vinceAccount string) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return a.IssueFromLDAPWithValidity(ctx, info, vinceAccount, 24*time.Hour, nil)
}

// IssueFromLDAPWithValidity issues a Midgard jwt from a LDAP for the given validity duration.
func (a *Client) IssueFromLDAPWithValidity(ctx context.Context, info *ldaputils.LDAPInfo, vinceAccount string, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Realm = midgardmodels.IssueRealmLdap
	issueRequest.Validity = validity.String()
	issueRequest.Metadata = info.ToMap()
	if vinceAccount != "" {
		issueRequest.Metadata["account"] = vinceAccount
	}

	var sp opentracing.Span
	if span != nil {
		sp = opentracing.StartSpan("midgardlib.client.issue.ldap", opentracing.ChildOf(span.Context()))
		defer sp.Finish()
	}

	return a.sendRequest(ctx, issueRequest, sp)
}

// IssueFromVince issues a Midgard jwt from a Vince.
func (a *Client) IssueFromVince(account string, password string) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return a.IssueFromVinceWithValidity(ctx, account, password, 24*time.Hour, nil)
}

// IssueFromVinceWithValidity issues a Midgard jwt from a Vince for the given validity duration.
func (a *Client) IssueFromVinceWithValidity(ctx context.Context, account string, password string, validity time.Duration, span opentracing.Span) (string, error) {

	return a.IssueFromVinceWithOTPAndValidity(ctx, account, password, "", validity, span)
}

// IssueFromVinceWithOTPAndValidity issues a Midgard jwt from a Vince for the given one time password and validity duration.
func (a *Client) IssueFromVinceWithOTPAndValidity(ctx context.Context, account string, password string, otp string, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"vinceAccount": account, "vincePassword": password, "vinceOTP": otp}
	issueRequest.Realm = midgardmodels.IssueRealmVince
	issueRequest.Validity = validity.String()

	var sp opentracing.Span
	if span != nil {
		sp = opentracing.StartSpan("midgardlib.client.issue.vince", opentracing.ChildOf(span.Context()))
		defer sp.Finish()
	}

	return a.sendRequest(ctx, issueRequest, sp)
}

// IssueFromAWSIdentityDocument issues a Midgard jwt from a signed AWS identity document.
func (a *Client) IssueFromAWSIdentityDocument(doc string) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return a.IssueFromAWSIdentityDocumentWithValidity(ctx, doc, 24*time.Hour, nil)
}

// IssueFromAWSIdentityDocumentWithValidity issues a Midgard jwt from a signed AWS identity document for the given validity duration.
func (a *Client) IssueFromAWSIdentityDocumentWithValidity(ctx context.Context, doc string, validity time.Duration, span opentracing.Span) (string, error) {

	issueRequest := midgardmodels.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"doc": doc}
	issueRequest.Realm = midgardmodels.IssueRealmAwsidentitydocument
	issueRequest.Validity = validity.String()

	var sp opentracing.Span
	if span != nil {
		sp = opentracing.StartSpan("midgardlib.client.issue.aws", opentracing.ChildOf(span.Context()))
		defer sp.Finish()
	}

	return a.sendRequest(ctx, issueRequest, sp)
}

func (a *Client) sendRequest(ctx context.Context, issueRequest *midgardmodels.Issue, span opentracing.Span) (string, error) {

	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(issueRequest); err != nil {
		return "", err
	}

	builder := func() (*http.Request, error) {
		return http.NewRequest(http.MethodPost, a.url+"/issue", buffer)
	}

	resp, err := a.sendRetry(ctx, builder, "", span)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != 200 {

		// Read the response body
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("midgard did not issue a token and client could not read why: %s (statusCode: %d)", err, resp.StatusCode)
		}

		// Try to decode the errors
		errs, err := elemental.DecodeErrors(data)
		if err != nil {
			return "", fmt.Errorf("midgard did not issue a token and client could not decode why: %s (statusCode: %d)", err, resp.StatusCode)
		}

		return "", errs
	}

	if err := json.NewDecoder(resp.Body).Decode(issueRequest); err != nil {
		return "", err
	}

	return issueRequest.Token, nil
}

func (a *Client) sendRetry(ctx context.Context, requestBuilder func() (*http.Request, error), token string, span opentracing.Span) (*http.Response, error) {

	for {

		request, err := requestBuilder()
		if err != nil {
			return nil, err
		}

		if a.closeConn {
			request.Close = true
		}

		if a.TrackingType != "" {
			request.Header.Set("X-External-Tracking-Type", a.TrackingType)
		}

		if span != nil {
			if t := span.Tracer(); t != nil {
				if err = t.Inject(span.Context(), opentracing.TextMap, opentracing.HTTPHeadersCarrier(request.Header)); err != nil {
					return nil, err
				}
			}
		}

		resp, err := a.httpClient.Do(request)
		if err == nil {
			return resp, nil
		}

		err = tokensnip.Snip(err, token)
		if span != nil {
			span.SetTag("error", true)
			span.LogFields(log.Error(err))
		}

		select {
		case <-time.After(3 * time.Second):
			continue
		case <-ctx.Done():
			return nil, err
		}
	}
}
