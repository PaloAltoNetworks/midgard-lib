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

type issueOpts struct {
	quota                 int
	opaque                map[string]string
	audience              string
	restrictedNamespace   string
	restrictedPermissions []string
	restrictedNetworks    []string
}

// An Option is the type of various options
// You can add the issue requests.
type Option func(*issueOpts)

// OptQuota sets the maximum time the issued token
// can be used.
func OptQuota(quota int) Option {

	if quota < 0 {
		panic("quota must be a positive number")
	}

	return func(opts *issueOpts) {
		opts.quota = quota
	}
}

// OptOpaque passes opaque data that will be
// included in the JWT.
func OptOpaque(opaque map[string]string) Option {

	return func(opts *issueOpts) {
		opts.opaque = opaque
	}
}

// OptAudience passes the requested audience for the token.
// Using audience is deprecated. Switch to OptLimitAuthz.
func OptAudience(audience string) Option {

	return func(opts *issueOpts) {
		opts.audience = audience
	}
}

// OptRestrictNamespace asks for a restricted token on the given namespace.
func OptRestrictNamespace(namespace string) Option {

	return func(opts *issueOpts) {
		opts.restrictedNamespace = namespace
	}
}

// OptRestrictPermissions asks for a restricted token on the given permissions.
func OptRestrictPermissions(permissions []string) Option {

	return func(opts *issueOpts) {
		opts.restrictedPermissions = permissions
	}
}

// OptRestrictNetworks asks for a restricted token on the given networks.
func OptRestrictNetworks(networks []string) Option {

	return func(opts *issueOpts) {
		opts.restrictedNetworks = networks
	}
}
