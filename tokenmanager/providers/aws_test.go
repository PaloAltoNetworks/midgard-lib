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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestClient_AWSServiceRoleToken(t *testing.T) {

	Convey("When I call AWSServiceRoleToken (calling aws)", t, func() {

		tokenResponse := `{
                        "AccessKeyId": "x",
                        "SecretAccessKey": "y",
                        "Token": "z"
                        }`
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/iam/security-credentials/":
				fmt.Fprintf(w, `role`)
			case "/iam/security-credentials/role":
				fmt.Fprint(w, tokenResponse)
			default:
				fmt.Fprintln(w, "bad response")
			}
		}))
		defer ts.Close()

		metadataPath = ts.URL + "/"
		token, err := AWSServiceRoleToken()

		Convey("Then err should be nil and the response should be correct", func() {
			So(err, ShouldBeNil)
			So(token, ShouldResemble, tokenResponse)
		})
	})

	Convey("When I call AWSServiceRoleToken  but can't retrieve role (comm error)", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusForbidden)
		}))
		defer ts.Close()

		metadataPath = ts.URL + "/"
		_, err := AWSServiceRoleToken()

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
		})
	})

	Convey("When I call AWSServiceRoleToken without info (calling aws) but can't retrieve token (comm error)", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/iam/security-credentials/":
				fmt.Fprint(w, `role`)
			default:
				http.Error(w, "nope", http.StatusForbidden)
			}
		}))
		defer ts.Close()

		metadataPath = ts.URL + "/"
		_, err := AWSServiceRoleToken()

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, `unable to retrieve token from magic url: 403 Forbidden`)
		})
	})
}
