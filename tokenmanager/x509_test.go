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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/manipulate"
)

func TestTOkenManager_NewX509TokenManager(t *testing.T) {

	Convey("Given I can NewX509TokenManager ", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "{}", http.StatusForbidden)
		}))
		defer ts.Close()

		t := NewX509TokenManager(ts.URL, 10*time.Second, &tls.Config{})

		Convey("Then t should should implement manipulate.TokenManager", func() {
			So(t, ShouldImplement, (*manipulate.TokenManager)(nil))
		})

		Convey("Then it should be correctly initialized", func() {
			tt := t.(*PeriodicTokenManager)
			So(tt.validity, ShouldEqual, 10*time.Second)
			So(tt.issuerFunc, ShouldNotBeNil)
		})

		Convey("When I call the the issue func", func() {

			tt := t.(*PeriodicTokenManager)
			token, err := tt.issuerFunc(context.Background(), 10*time.Second)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then token should be empty", func() {
				So(token, ShouldEqual, "")
			})
		})
	})
}
