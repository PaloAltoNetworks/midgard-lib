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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/log"
	"go.aporeto.io/elemental"
	"go.aporeto.io/gaia"
	"go.aporeto.io/midgard-lib/ldaputils"
	"go.aporeto.io/midgard-lib/tokenmanager/providers"
	"go.aporeto.io/tg/tglib"
)

// A Client allows to interract with a midgard server.
type Client struct {
	TrackingType string

	url        string
	tlsConfig  *tls.Config
	httpClient *http.Client
}

// NewClient returns a new Client.
func NewClient(url string) *Client {

	CAPool, err := tglib.GetSystemCertPool()
	if err != nil {
		panic(fmt.Sprintf("Unable to load system cert pool: %s", err))
	}

	return NewClientWithTLS(
		url,
		&tls.Config{
			RootCAs: CAPool,
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
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: tlsConfig,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Authentify authentifies the information included in the given token and
// returns a list of tag string containing the claims.
func (a *Client) Authentify(ctx context.Context, token string) ([]string, error) {

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.authentify")
	defer span.Finish()

	builder := func() (*http.Request, error) {
		authn := gaia.NewAuthn()
		authn.Token = token
		data, err := json.Marshal(authn)
		if err != nil {
			return nil, err
		}
		return http.NewRequest(http.MethodPost, a.url+"/authn", bytes.NewBuffer(data))
	}

	resp, err := a.sendRetry(subctx, builder, token)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, elemental.NewError("Unauthorized", fmt.Sprintf("Authentication rejected with error: %s", resp.Status), "midgard-lib", http.StatusUnauthorized)
	}

	auth := gaia.NewAuthn()

	defer resp.Body.Close() // nolint: errcheck

	if err := json.NewDecoder(resp.Body).Decode(auth); err != nil {
		return nil, err
	}

	if auth.Claims == nil {
		return nil, elemental.NewError("Unauthorized", "No claims returned. Token may be invalid", "midgard-lib", http.StatusUnauthorized)
	}

	return NormalizeAuth(auth.Claims), nil
}

// IssueFromGoogle issues a Midgard jwt from a Google JWT for the given validity duration.
func (a *Client) IssueFromGoogle(ctx context.Context, googleJWT string, validity time.Duration, options ...Option) (string, error) {

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Realm = gaia.IssueRealmGoogle
	issueRequest.Data = googleJWT
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.google")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromCertificate issues a Midgard jwt from a certificate for the given validity duration.
func (a *Client) IssueFromCertificate(ctx context.Context, validity time.Duration, options ...Option) (string, error) {

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Realm = gaia.IssueRealmCertificate
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.certificate")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromLDAP issues a Midgard JWT from an LDAP config for the given validity duration.
func (a *Client) IssueFromLDAP(ctx context.Context, info *ldaputils.LDAPInfo, namespace string, provider string, validity time.Duration, options ...Option) (string, error) {

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Realm = gaia.IssueRealmLDAP
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	issueRequest.Metadata = info.ToMap()
	issueRequest.Metadata["namespace"] = namespace
	issueRequest.Metadata["provider"] = provider

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.ldap")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromVince issues a Midgard jwt from a Vince for the given one time password and validity duration.
func (a *Client) IssueFromVince(ctx context.Context, account string, password string, otp string, validity time.Duration, options ...Option) (string, error) {

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"vinceAccount": account, "vincePassword": password, "vinceOTP": otp}
	issueRequest.Realm = gaia.IssueRealmVince
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.vince")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromAWSSecurityToken issues a Midgard jwt from a security token from amazon.
// If you don't pass anything, this function will try to retrieve the token using aws magic ip.
func (a *Client) IssueFromAWSSecurityToken(ctx context.Context, accessKeyID, secretAccessKey, token string, validity time.Duration, options ...Option) (string, error) {

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	s := &struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string
		Token           string
	}{}

	if accessKeyID == "" && secretAccessKey == "" && token == "" {
		awsToken, err := providers.AWSServiceRoleToken()
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal([]byte(awsToken), &s); err != nil {
			return "", err
		}
	} else {
		s.AccessKeyID = accessKeyID
		s.SecretAccessKey = secretAccessKey
		s.Token = token
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Metadata = map[string]interface{}{
		"accessKeyID":     s.AccessKeyID,
		"secretAccessKey": s.SecretAccessKey,
		"token":           s.Token,
	}

	issueRequest.Realm = gaia.IssueRealmAWSSecurityToken
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.aws")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromGCPIdentityToken issues a Midgard jwt from a signed GCP identity document for the given validity duration.
func (a *Client) IssueFromGCPIdentityToken(ctx context.Context, token string, validity time.Duration, options ...Option) (string, error) {

	var err error

	if token == "" {
		token, err = providers.GCPServiceAccountToken(ctx, validity)
		if err != nil {
			return "", err
		}
	}

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"token": token}
	issueRequest.Realm = gaia.IssueRealmGCPIdentityToken
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.gcp")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromOIDCStep1 issues a Midgard jwt from a OICD provider. This is performing the first step to
// validate the issue requests and OIDC provider. It will return the OIDC auth endpoint
func (a *Client) IssueFromOIDCStep1(ctx context.Context, namespace string, provider string, redirectURL string) (string, error) {

	issueRequest := gaia.NewIssue()
	issueRequest.Metadata = map[string]interface{}{
		"namespace":        namespace,
		"OIDCProviderName": provider,
		"redirectURL":      redirectURL,
	}
	issueRequest.Realm = gaia.IssueRealmOIDC

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.oidc.step1")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromOIDCStep2 issues a Midgard jwt from a OICD provider. This is performing the second step to
// to exchange the code for a Midgard HWT.
func (a *Client) IssueFromOIDCStep2(ctx context.Context, code string, state string, validity time.Duration, options ...Option) (string, error) {

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Metadata = map[string]interface{}{
		"code":  code,
		"state": state,
	}
	issueRequest.Realm = gaia.IssueRealmOIDC
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.oidc.step2")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromSAMLStep1 issues a Midgard jwt from a SAML provider. This is performing the first step to
// validate the issue requests and OIDC provider. It will return the OIDC auth endpoint
func (a *Client) IssueFromSAMLStep1(ctx context.Context, namespace string, provider string, redirectURL string) (string, error) {

	issueRequest := gaia.NewIssue()
	issueRequest.Metadata = map[string]interface{}{
		"namespace":        namespace,
		"SAMLProviderName": provider,
		"redirectURL":      redirectURL,
	}
	issueRequest.Realm = gaia.IssueRealmSAML

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.saml.step1")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromSAMLStep2 issues a Midgard jwt from a SAML provider. This is performing the second step to
// to exchange the code for a Midgard HWT.
func (a *Client) IssueFromSAMLStep2(ctx context.Context, response string, state string, validity time.Duration, options ...Option) (string, error) {

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Metadata = map[string]interface{}{
		"SAMLResponse": response,
		"relayState":   state,
	}
	issueRequest.Realm = gaia.IssueRealmSAML
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.saml.step2")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

// IssueFromAzureIdentityToken issues a Midgard jwt from a signed Azure identity document for the given validity duration.
func (a *Client) IssueFromAzureIdentityToken(ctx context.Context, token string, validity time.Duration, options ...Option) (string, error) {

	var err error

	if token == "" {
		token, err = providers.AzureServiceIdentityToken()
		if err != nil {
			return "", err
		}
	}

	opts := issueOpts{}
	for _, opt := range options {
		opt(&opts)
	}

	issueRequest := gaia.NewIssue()
	issueRequest.Metadata = map[string]interface{}{"token": token}
	issueRequest.Realm = gaia.IssueRealmAzureIdentityToken
	issueRequest.Validity = validity.String()
	issueRequest.Quota = opts.quota
	issueRequest.Opaque = opts.opaque
	issueRequest.Audience = opts.audience

	span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.issue.azure")
	defer span.Finish()

	return a.sendRequest(subctx, issueRequest)
}

func (a *Client) sendRequest(ctx context.Context, issueRequest *gaia.Issue) (string, error) {

	buffer := &bytes.Buffer{}
	if err := json.NewEncoder(buffer).Encode(issueRequest); err != nil {
		return "", err
	}
	body := buffer.Bytes()

	builder := func() (*http.Request, error) {

		return http.NewRequest(http.MethodPost, a.url+"/issue", bytes.NewBuffer(body))
	}

	resp, err := a.sendRetry(ctx, builder, "")
	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusFound {
		return resp.Header.Get("Location"), nil
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

func (a *Client) sendRetry(ctx context.Context, requestBuilder func() (*http.Request, error), token string) (*http.Response, error) {

	for {

		span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.client.send")
		defer span.Finish()

		request, err := requestBuilder()
		if err != nil {
			return nil, err
		}

		request.Close = true

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

		if uerr, ok := err.(*url.Error); ok {
			switch uerr.Err.(type) {
			case x509.UnknownAuthorityError, x509.CertificateInvalidError, x509.HostnameError:
				return nil, err
			}
		}

		err = snipToken(err, token)
		if span != nil {
			span.SetTag("error", true)
			span.LogFields(log.Error(err))
		}

		select {
		case <-time.After(3 * time.Second):
			continue
		case <-subctx.Done():
			return nil, err
		}
	}
}

func snipToken(err error, token string) error {

	if len(token) == 0 || err == nil {
		return err
	}

	return fmt.Errorf("%s",
		strings.Replace(
			err.Error(),
			token,
			"[snip]",
			-1),
	)
}
