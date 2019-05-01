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

import (
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/smartystreets/goconvey/convey"
)

func TestClaims_NewClaims(t *testing.T) {

	Convey("Given I create new claims", t, func() {

		c := NewMidgardClaims()

		Convey("Then the claims should be correct", func() {
			So(c.Data, ShouldResemble, map[string]string{})
			So(c.StandardClaims, ShouldResemble, jwt.StandardClaims{})
		})
	})
}
