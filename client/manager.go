package midgardclient

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/opentracing/opentracing-go/log"
	"go.uber.org/zap"

	opentracing "github.com/opentracing/opentracing-go"
)

// A TokenManager issues an renew tokens periodically.
type TokenManager struct {
	client    *Client
	validity  time.Duration
	tlsConfig *tls.Config
}

// NewMidgardTokenManager returns a new TokenManager backed by midgard.
func NewMidgardTokenManager(url string, validity time.Duration, tlsConfig *tls.Config) *TokenManager {

	return &TokenManager{
		client:    NewClientWithTLS(url, tlsConfig),
		validity:  validity,
		tlsConfig: tlsConfig,
	}
}

// Issue issues a token.
func (m *TokenManager) Issue(ctx context.Context) (token string, err error) {

	return m.client.IssueFromCertificate(ctx, m.validity)
}

// Run runs the token renewal job.
func (m *TokenManager) Run(ctx context.Context, tokenCh chan string) {

	nextRefresh := time.Now().Add(m.validity / 2)

	for {

		select {
		case <-time.After(time.Minute):

			now := time.Now()
			if now.Before(nextRefresh) {
				break
			}

			span, subctx := opentracing.StartSpanFromContext(ctx, "midgardlib.tokenmanager.renew")

			token, err := m.Issue(subctx)
			if err != nil {
				span.SetTag("error", true)
				span.LogFields(log.Error(err))
				span.Finish()
				zap.L().Error("Unable to renew Midgard token", zap.Error(err))
				break
			}

			tokenCh <- token

			nextRefresh = now.Add(m.validity / 2)
			zap.L().Info("Midgard token renewed")
			span.Finish()

		case <-ctx.Done():
			return
		}
	}
}

// SimpleTokenManager is a simple implementation of a token Manager that simply returns the token that was setup initially
type SimpleTokenManager struct {
	token string
}

// NewSimpleTokenManager returns a new SimpleTokenManager backed by midgard.
func NewSimpleTokenManager(token string) *SimpleTokenManager {

	return &SimpleTokenManager{
		token: token,
	}
}

// Issue issues a token.
func (m *SimpleTokenManager) Issue(ctx context.Context) (token string, err error) {

	return m.token, nil
}

// Run runs the token renewal job.
func (m *SimpleTokenManager) Run(ctx context.Context, tokenCh chan string) {

	return
}
