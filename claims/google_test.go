package claims

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGoogleClaims_NewGoogleClaims(t *testing.T) {

	Convey("Given I create a new Google claim", t, func() {

		c := NewGoogleClaims()

		Convey("Then claims be not be nil", func() {
			So(c, ShouldNotBeNil)
		})

		Convey("Then claims be implement interface TokenIssuer", func() {
			So(c, ShouldImplement, (*TokenIssuer)(nil))
		})
	})
}

func TestGoogleClaims_ToMidgardClaims(t *testing.T) {

	Convey("Given I have a Google claim", t, func() {

		c := NewGoogleClaims()
		c.Name = "Jean Mouloud"
		c.GivenName = "Jean"
		c.FamilyName = "Mouloud"
		c.Email = "jm@world.com"
		c.ExpiresAt = 253370764800
		c.IssuedAt = 1474932961
		c.Subject = "subject"

		JWTAudience = "audience"
		JWTIssuer = "issuer"
		JWTValidity = 24 * time.Hour

		Convey("When I convert it to a Midgard claims", func() {

			m := c.ToMidgardClaims()

			Convey("Then Realm should be correct", func() {
				So(m.Realm, ShouldEqual, "google")
			})

			Convey("Then Name should be correct", func() {
				So(m.Data["name"], ShouldEqual, "Jean Mouloud")
			})

			Convey("Then GivenName should be correct", func() {
				So(m.Data["givenName"], ShouldEqual, "Jean")
			})

			Convey("Then FamilyName should be correct", func() {
				So(m.Data["familyName"], ShouldEqual, "Mouloud")
			})

			Convey("Then Email should be correct", func() {
				So(m.Data["email"], ShouldEqual, "jm@world.com")
			})

			Convey("Then Issuer should be correct", func() {
				So(m.Issuer, ShouldEqual, "issuer")
			})

			Convey("Then Audience should be correct", func() {
				So(m.Audience, ShouldEqual, "audience")
			})

			Convey("Then Subject should be correct", func() {
				So(m.Subject, ShouldEqual, "subject")
			})

			Convey("Then ExpiresAt should be correct", func() {
				So(m.ExpiresAt, ShouldEqual, time.Unix(m.IssuedAt, 0).Add(24*time.Hour).Unix())
			})
		})
	})
}

func TestGoogleClaims_FromToken(t *testing.T) {

	Convey("Given I have a google claims a fake google server verification and a fake valid token", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `{
                "name": "Antoine Mercadal",
                "given_name": "Antoine",
                "family_name": "Mercadal",
                "email": "antoine@aporeto.com",
                "exp": "253370764800",
                "aud": "gogole.issuer",
                "iss": "gogole.issuer",
                "iat": "1474932961"
            }`)
		}))
		defer ts.Close()

		JWTGoogleValidationURL = ts.URL
		JWTGoogleIssuer = "gogole.issuer"
		JWTGoogleClientID = "gogole.issuer"

		t := "fake-token"
		c := NewGoogleClaims()

		Convey("When I call FromToken", func() {

			err := c.FromToken(t)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then Name should be correct", func() {
				So(c.Name, ShouldEqual, "Antoine Mercadal")
			})

			Convey("Then GivenName should be correct", func() {
				So(c.GivenName, ShouldEqual, "Antoine")
			})

			Convey("Then FamilyName should be correct", func() {
				So(c.FamilyName, ShouldEqual, "Mercadal")
			})

			Convey("Then Email should be correct", func() {
				So(c.Email, ShouldEqual, "antoine@aporeto.com")
			})

			Convey("Then IssuedAt should be correct", func() {
				So(c.IssuedAt, ShouldEqual, 1474932961)
			})

			Convey("Then ExpiresAt should be correct", func() {
				So(c.ExpiresAt, ShouldEqual, 253370764800)
			})
		})
	})

	Convey("Given I have a google claims a fake down google server verification and a fake valid token", t, func() {

		JWTGoogleValidationURL = "htt://non"
		JWTGoogleIssuer = "gogole.issuer"
		JWTGoogleClientID = "gogole.issuer"

		t := "fake-token"
		c := NewGoogleClaims()

		Convey("When I call FromToken", func() {

			err := c.FromToken(t)

			Convey("Then err should be not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a google claims a fake google that returns a non 200 code", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
		}))
		defer ts.Close()

		JWTGoogleValidationURL = ts.URL
		JWTGoogleIssuer = "gogole.issuer"
		JWTGoogleClientID = "gogole.issuer"

		t := "fake-token"
		c := NewGoogleClaims()

		Convey("When I call FromToken", func() {

			err := c.FromToken(t)

			Convey("Then err should be not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a google claims a fake google server that returns broken json", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `broken json}`)
		}))
		defer ts.Close()

		JWTGoogleValidationURL = ts.URL
		JWTGoogleIssuer = "gogole.issuer"
		JWTGoogleClientID = "gogole.issuer"

		t := "fake-token"
		c := NewGoogleClaims()

		Convey("When I call FromToken", func() {

			err := c.FromToken(t)

			Convey("Then err should be not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a google claims a fake google server that returns a bad audience", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `{
                "name": "Antoine Mercadal",
                "given_name": "Antoine",
                "family_name": "Mercadal",
                "email": "antoine@aporeto.com",
                "exp": "253370764800",
                "aud": "bad",
                "iss": "gogole.issuer",
                "iat": "1474932961"
            }`)
		}))
		defer ts.Close()

		JWTGoogleValidationURL = ts.URL
		JWTGoogleIssuer = "gogole.issuer"
		JWTGoogleClientID = "gogole.issuer"

		t := "fake-token"
		c := NewGoogleClaims()

		Convey("When I call FromToken", func() {

			err := c.FromToken(t)

			Convey("Then err should be not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a google claims a fake google server that returns a bad issuer", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `{
                "name": "Antoine Mercadal",
                "given_name": "Antoine",
                "family_name": "Mercadal",
                "email": "antoine@aporeto.com",
                "exp": "253370764800",
                "aud": "gogole.issuer",
                "iss": "bad",
                "iat": "1474932961"
            }`)
		}))
		defer ts.Close()

		JWTGoogleValidationURL = ts.URL
		JWTGoogleIssuer = "gogole.issuer"
		JWTGoogleClientID = "gogole.issuer"

		t := "fake-token"
		c := NewGoogleClaims()

		Convey("When I call FromToken", func() {

			err := c.FromToken(t)

			Convey("Then err should be not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}
