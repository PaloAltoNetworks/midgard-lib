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

package claims

import jwt "github.com/dgrijalva/jwt-go"

// MidgardClaims is a struct to represeting the data some a Midgard issued claims.
type MidgardClaims struct {
	Realm  string            `msgpack:"realm" json:"realm"`
	Quota  int               `msgpack:"quota,omitempty" json:"quota,omitempty"`
	Data   map[string]string `msgpack:"data" json:"data"`
	Opaque map[string]string `msgpack:"opaque,omitempty" json:"opaque,omitempty"`

	jwt.StandardClaims
}

// NewMidgardClaims returns a new Claims.
func NewMidgardClaims() *MidgardClaims {
	return &MidgardClaims{
		Data:           map[string]string{},
		StandardClaims: jwt.StandardClaims{},
	}
}
