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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func newValidAzureToken() string {
	token := &AzureToken{
		AccessToken: "the role",
	}

	data, _ := json.Marshal(token) // nolint errcheck

	return string(data)
}

func Test_AzureServiceIdentityToken(t *testing.T) {

	Convey("When I call AzureServiceIdentityToken with no errors", t, func() {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				fmt.Fprintln(w, newValidAzureToken())
			}
		}))
		defer ts.Close()

		azureServiceTokenURL = ts.URL
		token, err := AzureServiceIdentityToken()

		Convey("Then err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then the token should be correct", func() {
			So(token, ShouldResemble, "the role")
		})

	})

	Convey("When I call AzureServiceIdentityToken and the token cannot be decoded", t, func() {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				fmt.Fprintln(w, `bad data`)
			}
		}))
		defer ts.Close()

		azureServiceTokenURL = ts.URL
		_, err := AzureServiceIdentityToken()

		Convey("Then err should  not be nil", func() {
			So(err, ShouldNotBeNil)
		})

	})

	Convey("When I call AzureServiceIdentityToken without info (calling Azure) but can't retrieve token (comm error)", t, func() {

		ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/latest/meta-data/iam/security-credentials/" {
				fmt.Fprintln(w, `the-role`)
			}
		}))
		defer ts2.Close()

		azureServiceTokenURL = "nope"
		_, err := AzureServiceIdentityToken()

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
		})
	})

}
