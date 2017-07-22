package midgardclient

import (
	"net/http"
	"testing"

	"github.com/aporeto-inc/gaia/midgardmodels/v1/golang"
	. "github.com/smartystreets/goconvey/convey"
)

func TestUtils_extractJWT(t *testing.T) {

	Convey("Given I have some http Header", t, func() {

		h := http.Header{}

		Convey("When I extract the token of a valid Authorization header", func() {

			h.Add("Authorization", "Bearer thetoken")
			token, err := ExtractJWTFromHeader(h)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then token should be thetoken", func() {
				So(token, ShouldEqual, "thetoken")
			})
		})

		Convey("When I extract the token of a missing Authorization header", func() {

			token, err := ExtractJWTFromHeader(h)

			Convey("Then err should be not nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then err.Error should be correct", func() {
				So(err.Error(), ShouldEqual, "Missing Authorization Header")
			})

			Convey("Then token should be empty", func() {
				So(token, ShouldBeEmpty)
			})
		})

		Convey("When I extract the token of a malformed Authorization header", func() {

			h.Add("Authorization", "Bearer")
			token, err := ExtractJWTFromHeader(h)

			Convey("Then err should be not nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then err.Error should be correct", func() {
				So(err.Error(), ShouldEqual, "Invalid Authorization Header")
			})

			Convey("Then token should be empty", func() {
				So(token, ShouldBeEmpty)
			})
		})

		Convey("When I extract the token of a invalid type Authorization header", func() {

			h.Add("Authorization", "NotBeaer thetoken")
			token, err := ExtractJWTFromHeader(h)

			Convey("Then err should be not nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then err.Error should be correct", func() {
				So(err.Error(), ShouldEqual, "Invalid Authorization Header")
			})

			Convey("Then token should be empty", func() {
				So(token, ShouldBeEmpty)
			})
		})
	})
}

func TestUtils_normalizeAuth(t *testing.T) {

	Convey("Given I have a Auth object", t, func() {

		auth := midgardmodels.NewAuth()
		auth.Claims.Realm = "realm"
		auth.Claims.Subject = "subject"
		auth.Claims.Data["d1"] = "v1"
		auth.Claims.Data["d2"] = "v2"

		Convey("When I normalize it", func() {

			v := normalizeAuth(auth)

			Convey("Then the subject should be correct", func() {
				So(v, ShouldContain, "@auth:subject=subject")
			})

			Convey("Then the d1 should be correct", func() {
				So(v, ShouldContain, "@auth:d1=v1")
			})

			Convey("Then the d2 should be correct", func() {
				So(v, ShouldContain, "@auth:d2=v2")
			})
		})
	})
}
