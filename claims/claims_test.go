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
