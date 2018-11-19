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
