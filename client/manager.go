package midgardclient

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/opentracing/opentracing-go"
	"go.uber.org/zap"
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
func (m *TokenManager) Issue(ctx context.Context, span opentracing.Span) (token string, err error) {

	return m.client.IssueFromCertificateWithValidity(ctx, m.validity, span)
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

			token, err := m.Issue(ctx, nil)
			if err != nil {
				zap.L().Error("Unable to renew Midgard token", zap.Error(err))
				break
			}

			tokenCh <- token

			nextRefresh = now.Add(m.validity / 2)
			zap.L().Info("Midgard token renewed")

		case <-ctx.Done():
			return
		}
	}
}
