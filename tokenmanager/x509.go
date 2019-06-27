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

package tokenmanager

import (
	"context"
	"crypto/tls"
	"time"

	midgardclient "go.aporeto.io/midgard-lib/client"
)

// NewX509TokenManager returns a new X509TokenManager.
func NewX509TokenManager(url string, validity time.Duration, tlsConfig *tls.Config) *PeriodicTokenManager {

	cl := midgardclient.NewClientWithTLS(url, tlsConfig)

	return &PeriodicTokenManager{
		validity: validity,
		issuerFunc: func(ctx context.Context, v time.Duration) (string, error) {
			return cl.IssueFromCertificate(ctx, v)
		},
	}
}
