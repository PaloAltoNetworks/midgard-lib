package claims

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestVinceClaims_NewVinceClaims(t *testing.T) {

	Convey("Given I create a new Vince claims", t, func() {

		c := NewVinceClaims()

		Convey("Then claims be not be nil", func() {
			So(c, ShouldNotBeNil)
		})

		Convey("Then claims be implement interface TokenIssuer", func() {
			So(c, ShouldImplement, (*TokenIssuer)(nil))
		})
	})
}

func TestVinceClaims_FromMetadata(t *testing.T) {

	Convey("Given I have a Vince claim", t, func() {

		c := NewVinceClaims()

		Convey("When I call FromMetadata using valid metadata", func() {

			m := map[string]interface{}{
				"vinceAccount":  "aporeto",
				"vincePassword": "secret",
			}

			err := c.fromMetadata(m)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When I call FromMetadata using metadata with missing account", func() {

			m := map[string]interface{}{
				"vincePassword": "secret",
			}

			err := c.fromMetadata(m)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "Metadata must contain the key 'vinceAccount'")
			})
		})

		Convey("When I call FromMetadata using metadata with missing password", func() {

			m := map[string]interface{}{
				"vinceAccount": "aporeto",
			}

			err := c.fromMetadata(m)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "Metadata must contain the key 'vincePassword'")
			})
		})
	})
}

func TestVinceClaims_ToMidgardClaims(t *testing.T) {

	Convey("Given I have a Vince claim and valid metdata", t, func() {

		c := NewVinceClaims()
		m := map[string]interface{}{
			"vinceAccount":  "aporeto",
			"vincePassword": "secret",
		}

		c.fromMetadata(m)

		Convey("When I run ToMidgardClaims()", func() {

			mc := c.ToMidgardClaims()

			Convey("Then the realm should be correct", func() {
				So(mc.Realm, ShouldEqual, "Vince")
			})

			Convey("Then the data should be correct", func() {
				So(mc.Data["account"], ShouldEqual, "aporeto")
			})

			Convey("Then the subject should be correct", func() {
				So(mc.Subject, ShouldEqual, "aporeto")
			})
		})
	})
}
