package tokenmanager

import (
	"context"
	"time"

	"go.aporeto.io/manipulate"
	"go.uber.org/zap"
)

var tickDuration = 1 * time.Minute

// TokenIssuerFunc is the type of function that can be used
// to retrieve a token.
type TokenIssuerFunc func(context.Context, time.Duration) (string, error)

// A PeriodicTokenManager issues an renew tokens periodically.
type PeriodicTokenManager struct {
	validity   time.Duration
	issuerFunc TokenIssuerFunc
}

// NewPeriodicTokenManager returns a new PeriodicTokenManager backed by midgard.
func NewPeriodicTokenManager(validity time.Duration, issuerFunc TokenIssuerFunc) manipulate.TokenManager {

	if issuerFunc == nil {
		panic("issuerFunc cannot be nil")
	}

	return &PeriodicTokenManager{
		issuerFunc: issuerFunc,
		validity:   validity,
	}
}

// Issue issues a token.
func (m *PeriodicTokenManager) Issue(ctx context.Context) (token string, err error) {

	return m.issuerFunc(ctx, m.validity)
}

// Run runs the token renewal job.
func (m *PeriodicTokenManager) Run(ctx context.Context, tokenCh chan string) {

	nextRefresh := time.Now().Add(m.validity / 2)

	for {

		select {

		case <-time.After(tickDuration):

			now := time.Now()
			if now.Before(nextRefresh) {
				break
			}

			subctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			token, err := m.Issue(subctx)
			cancel()

			if err != nil {
				zap.L().Error("Unable to renew token", zap.Error(err))
				break
			}

			tokenCh <- token

			nextRefresh = now.Add(m.validity / 2)
			zap.L().Info("Token renewed")

		case <-ctx.Done():
			return
		}
	}
}
