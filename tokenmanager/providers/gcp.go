package providers

import (
	"context"
	"time"

	"cloud.google.com/go/compute/metadata"
)

var (
	identitySuffix = "instance/service-accounts/default/identity?audience=aporeto&format=full"
)

// GCPServiceAccountToken will retrieve the service account
// token and call the midgard library.
func GCPServiceAccountToken(ctx context.Context, validity time.Duration) (string, error) {

	return metadata.Get(identitySuffix)
}
