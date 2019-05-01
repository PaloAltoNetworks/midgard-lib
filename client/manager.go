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
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/log"
	"go.uber.org/zap"
)

// A TokenManager issues an renew tokens periodically.
type TokenManager struct {
	client   *Client
	validity time.Duration
}

// NewMidgardTokenManager returns a new TokenManager backed by midgard.
func NewMidgardTokenManager(url string, validity time.Duration, tlsConfig *tls.Config) *TokenManager {

	fmt.Fprintln(os.Stderr, "DEPRECATED: NewMidgardTokenManager() is deprecated in favor or go.aporeto.io/midgardlib/tokenmanager.NewX509TokenManager()")

	return &TokenManager{
		client:   NewClientWithTLS(url, tlsConfig),
		validity: validity,
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
