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
	"time"

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
func NewPeriodicTokenManager(validity time.Duration, issuerFunc TokenIssuerFunc) *PeriodicTokenManager {

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
