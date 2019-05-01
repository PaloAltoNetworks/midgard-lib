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
