package claims

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestCertificateClaims_NewCertificateClaims(t *testing.T) {

	Convey("Given I create a new Certificate claims", t, func() {

		c := NewCertificateClaims()

		Convey("Then claims be not be nil", func() {
			So(c, ShouldNotBeNil)
		})

		Convey("Then claims be implement interface TokenIssuer", func() {
			So(c, ShouldImplement, (*TokenIssuer)(nil))
		})
	})
}

func TestCertificateClaims_FromCertificate(t *testing.T) {

	Convey("Given I have a Certificate claims and a certificate", t, func() {

		c := NewCertificateClaims()
		certPEM, _ := ioutil.ReadFile("../fixtures/client-cert.pem")
		certBlock, _ := pem.Decode(certPEM)
		cert, _ := x509.ParseCertificate(certBlock.Bytes)

		Convey("When I run FromCertificate", func() {

			err := c.FromCertificate(cert)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then Organization should be correct", func() {
				So(c.Organizations[0], ShouldEqual, "aporeto.com")
			})

			Convey("Then OrganizationalUnit should be correct", func() {
				So(c.OrganizationalUnits[0], ShouldEqual, "SuperAdmin")
			})

			Convey("Then CommonName should be correct", func() {
				So(c.CommonName, ShouldEqual, "superadmin")
			})

			Convey("Then Subject should be correct", func() {
				So(c.Subject, ShouldEqual, "10237207344299343489")
			})
		})
	})

	Convey("Given I have a Certificate claims and a certificate with missing organization", t, func() {

		c := NewCertificateClaims()
		cert := &x509.Certificate{
			Subject: pkix.Name{},
		}

		Convey("When I run FromCertificate", func() {

			err := c.FromCertificate(cert)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then err.Error() should be correct", func() {
				So(err.Error(), ShouldEqual, "Your certificate doesn't contain any O")
			})
		})
	})

	Convey("Given I have a Certificate claims and a certificate with missing common name", t, func() {

		c := NewCertificateClaims()
		cert := &x509.Certificate{
			Subject: pkix.Name{
				Organization:       []string{"polom"},
				OrganizationalUnit: []string{"polom"},
			},
		}

		Convey("When I run FromCertificate", func() {

			err := c.FromCertificate(cert)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then err.Error() should be correct", func() {
				So(err.Error(), ShouldEqual, "Your certificate doesn't contain a CN")
			})
		})
	})
}

func TestCertificateClaims_ToMidgardClaims(t *testing.T) {

	Convey("Given I have a Certificate claim", t, func() {

		c := NewCertificateClaims()
		c.Organizations = []string{"Organization", "Organization2"}
		c.OrganizationalUnits = []string{"ou1", "ou2"}
		c.CommonName = "CommonName"
		c.ExpiresAt = 253370764800
		c.IssuedAt = 1474932961
		c.Subject = "123456"

		JWTAudience = "audience"
		JWTIssuer = "issuer"

		Convey("When I convert it to a Midgard claims", func() {

			m := c.ToMidgardClaims()
			m.ExpiresAt = time.Now().Add(24 * time.Hour).Unix()

			Convey("Then Realm should be correct", func() {
				So(m.Realm, ShouldEqual, "certificate")
			})

			Convey("Then data CommonName should be correct", func() {
				So(m.Data["commonName"], ShouldEqual, "CommonName")
			})

			Convey("Then data Organization should be correct", func() {
				So(m.Data["organization"], ShouldEqual, "Organization")
			})

			Convey("Then data OrganizationalUnit should be correct", func() {
				So(m.Data["ou:ou1"], ShouldEqual, "true")
				So(m.Data["ou:ou2"], ShouldEqual, "true")
			})

			Convey("Then Issuer should be correct", func() {
				So(m.Issuer, ShouldEqual, "issuer")
			})

			Convey("Then Audience should be correct", func() {
				So(m.Audience, ShouldEqual, "audience")
			})

			Convey("Then Subject should be correct", func() {
				So(m.Subject, ShouldEqual, "123456")
			})

			Convey("Then ExpiresAt should be correct", func() {
				So(m.ExpiresAt, ShouldEqual, time.Unix(m.IssuedAt, 0).Add(24*time.Hour).Unix())
			})
		})
	})
}
