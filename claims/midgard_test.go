package claims

import (
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/smartystreets/goconvey/convey"
)

func at(t time.Time, f func()) {
	jwt.TimeFunc = func() time.Time {
		return t
	}
	f()
	jwt.TimeFunc = time.Now
}

func TestMidgardClaims_NewMidgardClaims(t *testing.T) {

	Convey("Given I create a new Midgard claims", t, func() {

		c := NewMidgardClaims()

		Convey("Then claims be not be nil", func() {
			So(c, ShouldNotBeNil)
		})
	})
}

func TestMidgardClaims_FromToken(t *testing.T) {

	at(time.Unix(1474935878, 0), func() {
		Convey("Given I have a Midgard claims and a valid signed Token", t, func() {

			c := NewMidgardClaims()
			JWTSharedSecret = []byte("very-good-secret")
			JWTAudience = "aporeto.com"
			JWTIssuer = "midgard.aporeto.com"

			token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6ImNlcnRpZmljYXRlIiwiZGF0YSI6eyJjb21tb25OYW1lIjoic3VwZXJhZG1pbiIsIm9yZ2FuaXphdGlvbiI6ImFwb3JldG8uY29tIiwib3JnYW5pemF0aW9uYWxVbml0IjoiU3VwZXJBZG1pbiJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTUwNjQ0NTMyMywiaWF0IjoxNDc0OTMxMDk1LCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTAyMzcyMDczNDQyOTkzNDM0ODkifQ.y3a1_18RR07UDKX1l_stqPu0vmn4EahP-PxKHqvSMG8"

			Convey("When I run FromToken", func() {

				err := c.FromToken(token)

				Convey("Then err should be nil", func() {
					So(err, ShouldBeNil)
				})

				Convey("Then Realm should be correct", func() {
					So(c.Realm, ShouldEqual, "certificate")
				})

				Convey("Then Issuer should be correct", func() {
					So(c.Issuer, ShouldEqual, "midgard.aporeto.com")
				})

				Convey("Then Audience should be correct", func() {
					So(c.Audience, ShouldEqual, "aporeto.com")
				})

				Convey("Then Subject should be correct", func() {
					So(c.Subject, ShouldEqual, "10237207344299343489")
				})

				Convey("Then ExpiresAt should be correct", func() {
					So(c.ExpiresAt, ShouldEqual, 1506445323)
				})

				Convey("Then IssuedAt should be correct", func() {
					So(c.IssuedAt, ShouldEqual, 1474931095)
				})

				Convey("Then data organization should be correct", func() {
					So(c.Data["organization"], ShouldEqual, "aporeto.com")
				})

				Convey("Then data organizationalunit should be correct", func() {
					So(c.Data["organizationalUnit"], ShouldEqual, "SuperAdmin")
				})

				Convey("Then data commonName should be correct", func() {
					So(c.Data["commonName"], ShouldEqual, "superadmin")
				})
			})
		})
	})

	at(time.Unix(1474935878, 0), func() {
		Convey("Given I have a Midgard claims and a valid bad signed Token", t, func() {

			c := NewMidgardClaims()
			JWTSharedSecret = []byte("not-a-very-good-secret")
			JWTAudience = "aporeto.com"
			JWTIssuer = "midgard.aporeto.com"

			token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6ImNlcnRpZmljYXRlIiwiZGF0YSI6eyJjb21tb25OYW1lIjoic3VwZXJhZG1pbiIsIm9yZ2FuaXphdGlvbiI6ImFwb3JldG8uY29tIiwib3JnYW5pemF0aW9uYWxVbml0IjoiU3VwZXJBZG1pbiJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTUwNjQ0NTMyMywiaWF0IjoxNDc0OTMxMDk1LCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTAyMzcyMDczNDQyOTkzNDM0ODkifQ.y3a1_18RR07UDKX1l_stqPu0vmn4EahP-PxKHqvSMG8"

			Convey("When I run FromToken", func() {

				err := c.FromToken(token)

				Convey("Then err should not be nil", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("Then err message should be correct", func() {
					So(err.Error(), ShouldEqual, "signature is invalid")
				})
			})
		})
	})

	at(time.Unix(1474935878, 0), func() {
		Convey("Given I have a Midgard claims and a valid signed Token with bad audience", t, func() {

			c := NewMidgardClaims()
			JWTSharedSecret = []byte("very-good-secret")
			JWTAudience = "not.aporeto.com"
			JWTIssuer = "midgard.aporeto.com"

			token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6ImNlcnRpZmljYXRlIiwiZGF0YSI6eyJjb21tb25OYW1lIjoic3VwZXJhZG1pbiIsIm9yZ2FuaXphdGlvbiI6ImFwb3JldG8uY29tIiwib3JnYW5pemF0aW9uYWxVbml0IjoiU3VwZXJBZG1pbiJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTUwNjQ0NTMyMywiaWF0IjoxNDc0OTMxMDk1LCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTAyMzcyMDczNDQyOTkzNDM0ODkifQ.y3a1_18RR07UDKX1l_stqPu0vmn4EahP-PxKHqvSMG8"

			Convey("When I run FromToken", func() {

				err := c.FromToken(token)

				Convey("Then err should not be nil", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("Then err message should be correct", func() {
					So(err.Error(), ShouldEqual, "Audience 'aporeto.com' is not acceptable.")
				})
			})
		})
	})

	at(time.Unix(1474935878, 0), func() {
		Convey("Given I have a Midgard claims and a valid signed Token with bad issuer", t, func() {

			c := NewMidgardClaims()
			JWTSharedSecret = []byte("very-good-secret")
			JWTAudience = "aporeto.com"
			JWTIssuer = "not.midgard.aporeto.com"

			token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6ImNlcnRpZmljYXRlIiwiZGF0YSI6eyJjb21tb25OYW1lIjoic3VwZXJhZG1pbiIsIm9yZ2FuaXphdGlvbiI6ImFwb3JldG8uY29tIiwib3JnYW5pemF0aW9uYWxVbml0IjoiU3VwZXJBZG1pbiJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTUwNjQ0NTMyMywiaWF0IjoxNDc0OTMxMDk1LCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTAyMzcyMDczNDQyOTkzNDM0ODkifQ.y3a1_18RR07UDKX1l_stqPu0vmn4EahP-PxKHqvSMG8"

			Convey("When I run FromToken", func() {

				err := c.FromToken(token)

				Convey("Then err should not be nil", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("Then err message should be correct", func() {
					So(err.Error(), ShouldEqual, "Issuer 'midgard.aporeto.com' is not acceptable.")
				})
			})
		})
	})

	at(time.Unix(1474935878, 0), func() {
		Convey("Given I have a Midgard claims and a valid signed Token with invalid signature alg", t, func() {

			c := NewMidgardClaims()
			JWTSharedSecret = []byte("very-good-secret")
			JWTAudience = "aporeto.com"
			JWTIssuer = "not.midgard.aporeto.com"

			token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6ImNlcnRpZmljYXRlIiwiZGF0YSI6eyJjb21tb25OYW1lIjoic3VwZXJhZG1pbiIsIm9yZ2FuaXphdGlvbiI6ImFwb3JldG8uY29tIiwib3JnYW5pemF0aW9uYWxVbml0IjoiU3VwZXJBZG1pbiJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTUwNjQ0NTMyMywiaWF0IjoxNDc0OTMxMDk1LCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTAyMzcyMDczNDQyOTkzNDM0ODkifQ.y3a1_18RR07UDKX1l_stqPu0vmn4EahP-PxKHqvSMG8"

			Convey("When I run FromToken", func() {

				err := c.FromToken(token)

				Convey("Then err should not be nil", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("Then err message should be correct", func() {
					So(err.Error(), ShouldEqual, "Unexpected signing method: RS256")
				})
			})
		})
	})

	at(time.Unix(64588839777, 0), func() {
		Convey("Given I have a Midgard claims and an expired signed Token", t, func() {

			c := NewMidgardClaims()
			JWTSharedSecret = []byte("very-good-secret")
			JWTAudience = "aporeto.com"
			JWTIssuer = "not.midgard.aporeto.com"

			token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6ImNlcnRpZmljYXRlIiwiZGF0YSI6eyJjb21tb25OYW1lIjoic3VwZXJhZG1pbiIsIm9yZ2FuaXphdGlvbiI6ImFwb3JldG8uY29tIiwib3JnYW5pemF0aW9uYWxVbml0IjoiU3VwZXJBZG1pbiJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTUwNjQ0NTMyMywiaWF0IjoxNDc0OTMxMDk1LCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTAyMzcyMDczNDQyOTkzNDM0ODkifQ.y3a1_18RR07UDKX1l_stqPu0vmn4EahP-PxKHqvSMG8"

			Convey("When I run FromToken", func() {

				err := c.FromToken(token)

				Convey("Then err should not be nil", func() {
					So(err, ShouldNotBeNil)
				})

				Convey("Then err message should be correct", func() {
					So(err.Error(), ShouldEqual, "token is expired by 2562047h47m16.854775807s")
				})
			})
		})
	})
}

func TestMidgardClaims_JWT(t *testing.T) {

	Convey("Given I have a Midgard Claims", t, func() {

		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6ImNlcnRpZmljYXRlIiwiZGF0YSI6eyJjb21tb25OYW1lIjoic3VwZXJhZG1pbiIsIm9yZ2FuaXphdGlvbiI6ImFwb3JldG8uY29tIiwib3JnYW5pemF0aW9uYWxVbml0IjoiU3VwZXJBZG1pbiJ9LCJhdWQiOiJhcG9yZXRvLmNvbSIsImV4cCI6MTUwNjQ0NTMyMywiaWF0IjoxNDc0OTMxMDk1LCJpc3MiOiJtaWRnYXJkLmFwb3JldG8uY29tIiwic3ViIjoiMTAyMzcyMDczNDQyOTkzNDM0ODkifQ.y3a1_18RR07UDKX1l_stqPu0vmn4EahP-PxKHqvSMG8"

		c := NewMidgardClaims()

		JWTSharedSecret = []byte("very-good-secret")
		JWTAudience = "aporeto.com"
		JWTIssuer = "midgard.aporeto.com"

		c.Realm = "certificate"
		c.Issuer = "midgard.aporeto.com"
		c.Audience = "aporeto.com"
		c.Subject = "10237207344299343489"
		c.ExpiresAt = 1506445323
		c.IssuedAt = 1474931095
		c.Data["organization"] = "aporeto.com"
		c.Data["organizationalUnit"] = "SuperAdmin"
		c.Data["commonName"] = "superadmin"

		Convey("When I run JWT", func() {

			jwt, err := c.JWT()

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the generated token should be correct", func() {
				So(jwt, ShouldEqual, token)
			})
		})
	})
}
