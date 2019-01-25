package tokenmanager

import (
	"context"
	"crypto/tls"
	"time"

	"go.aporeto.io/manipulate"
	midgardclient "go.aporeto.io/midgard-lib/client"
)

// NewX509TokenManager returns a new X509TokenManager.
func NewX509TokenManager(url string, validity time.Duration, tlsConfig *tls.Config) manipulate.TokenManager {

	cl := midgardclient.NewClientWithTLS(url, tlsConfig)

	return &PeriodicTokenManager{
		validity: validity,
		issuerFunc: func(ctx context.Context, v time.Duration) (string, error) {
			return cl.IssueFromCertificate(ctx, v)
		},
	}
}
