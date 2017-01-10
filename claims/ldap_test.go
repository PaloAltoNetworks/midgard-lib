package claims

import (
	"testing"

	ldap "gopkg.in/ldap.v2"

	. "github.com/smartystreets/goconvey/convey"
)

func TestLDAPClais_LDAPInfo(t *testing.T) {

	Convey("Given I create a new LDAPInfo with valid metadata", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":  "123:123",
			"bindDN":       "cn=admin,dc=toto,dc=com",
			"bindPassword": "toto",
			"username":     "lskywalker",
			"password":     "secret",
			"baseDN":       "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then info should not be nil", func() {
			So(i, ShouldNotBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing LDAPAddress", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"bindDN":       "cn=admin,dc=toto,dc=com",
			"bindPassword": "toto",
			"username":     "lskywalker",
			"password":     "secret",
			"baseDN":       "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPAddress'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing bindDN", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":  "123:123",
			"bindPassword": "toto",
			"username":     "lskywalker",
			"password":     "secret",
			"baseDN":       "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'bindDN'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing bindPassword", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress": "123:123",
			"bindDN":      "cn=admin,dc=toto,dc=com",
			"username":    "lskywalker",
			"password":    "secret",
			"baseDN":      "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'bindPassword'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing username", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":  "123:123",
			"bindDN":       "cn=admin,dc=toto,dc=com",
			"bindPassword": "toto",
			"password":     "secret",
			"baseDN":       "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'username'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing password", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":  "123:123",
			"bindDN":       "cn=admin,dc=toto,dc=com",
			"bindPassword": "toto",
			"username":     "lskywalker",
			"baseDN":       "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'password'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing baseDN", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":  "123:123",
			"bindDN":       "cn=admin,dc=toto,dc=com",
			"bindPassword": "toto",
			"username":     "lskywalker",
			"password":     "secret",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'baseDN'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})
}

func TestLDAPClaims_NewLDAPClaims(t *testing.T) {

	Convey("Given I create a new LDAP claim", t, func() {

		c := NewLDAPClaims()

		Convey("Then claims be not be nil", func() {
			So(c, ShouldNotBeNil)
		})

		Convey("Then claims be implement interface TokenIssuer", func() {
			So(c, ShouldImplement, (*TokenIssuer)(nil))
		})
	})
}

func TestLDAPClaims_populateClaim(t *testing.T) {

	Convey("Given I have a LDAPClaim and an ldap.Entry", t, func() {

		c := NewLDAPClaims()

		entry := &ldap.Entry{
			DN: "ou=ou1,ou=ou2,dc=toto,dc=com",
			Attributes: []*ldap.EntryAttribute{
				&ldap.EntryAttribute{Name: "uid", Values: []string{"lsk"}},
				&ldap.EntryAttribute{Name: "userPassword", Values: []string{"1234"}},
				&ldap.EntryAttribute{Name: "objectClass", Values: []string{"class"}},
				&ldap.EntryAttribute{Name: "empty", Values: []string{}},
				&ldap.EntryAttribute{Name: "empty", Values: []string{""}},
				&ldap.EntryAttribute{Name: "givenName", Values: []string{"Wesh Gros"}},
				&ldap.EntryAttribute{Name: "FamilyName", Values: []string{"Gros"}},
			},
		}

		Convey("When I call populateClaim", func() {
			err := c.populateClaim(entry)

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the claim should be correctly populated", func() {
				So(c.Attributes["organizationalUnit"], ShouldEqual, "ou1")
				So(c.Attributes["organization"], ShouldEqual, "toto.com")
				So(c.Attributes["empty"], ShouldEqual, "")
				So(c.Attributes["userPassword"], ShouldEqual, "")
				So(c.Attributes["password"], ShouldEqual, "")
				So(c.Attributes["givenName"], ShouldEqual, "Wesh_Gros")
				So(c.Attributes["FamilyName"], ShouldEqual, "Gros")
			})
		})
	})

	Convey("Given I have a LDAPClaim and an ldap.Entry with a bad DN", t, func() {

		c := NewLDAPClaims()

		entry := &ldap.Entry{
			DN: "not a dn",
		}

		Convey("When I call populateClaim", func() {
			err := c.populateClaim(entry)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a LDAPClaim and an ldap.Entry with a missing uid", t, func() {

		c := NewLDAPClaims()

		entry := &ldap.Entry{
			DN: "ou=ou1,ou=ou2,dc=toto,dc=com",
		}

		Convey("When I call populateClaim", func() {
			err := c.populateClaim(entry)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestLDAPClaims_ToMidgardClaim(t *testing.T) {

	Convey("Given I have a LDAPClaim and an ldap.Entry", t, func() {

		c := NewLDAPClaims()

		entry := &ldap.Entry{
			DN: "ou=ou1,ou=ou2,dc=toto,dc=com",
			Attributes: []*ldap.EntryAttribute{
				&ldap.EntryAttribute{Name: "uid", Values: []string{"lskywalker"}},
				&ldap.EntryAttribute{Name: "userPassword", Values: []string{"1234"}},
				&ldap.EntryAttribute{Name: "objectClass", Values: []string{"class"}},
				&ldap.EntryAttribute{Name: "empty", Values: []string{}},
				&ldap.EntryAttribute{Name: "empty", Values: []string{""}},
				&ldap.EntryAttribute{Name: "givenName", Values: []string{"Wesh Gros"}},
				&ldap.EntryAttribute{Name: "FamilyName", Values: []string{"Gros"}},
			},
		}

		c.populateClaim(entry)

		Convey("When I call ToMidgardClaims", func() {
			mc := c.ToMidgardClaims()

			Convey("Then the Midgard should be correct", func() {
				So(mc.Audience, ShouldEqual, JWTAudience)
				So(mc.Issuer, ShouldEqual, JWTIssuer)
				So(mc.ExpiresAt, ShouldNotBeEmpty)
				So(mc.IssuedAt, ShouldNotBeEmpty)
				So(mc.Subject, ShouldEqual, "lskywalker")
				So(mc.Realm, ShouldEqual, "LDAP")
				So(mc.Data["uid"], ShouldEqual, "lskywalker")
				So(mc.Data["givenName"], ShouldEqual, "Wesh_Gros")
				So(mc.Data["FamilyName"], ShouldEqual, "Gros")
			})
		})
	})
}

func TestLDAPClaims_FromLDAPInfo(t *testing.T) {

	Convey("Given I have a LDAPClaim and LDAPInfo", t, func() {

		i, _ := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":  "123:123",
			"bindDN":       "cn=admin,dc=toto,dc=com",
			"bindPassword": "toto",
			"username":     "lskywalker",
			"password":     "secret",
			"baseDN":       "secret",
		})

		c := NewLDAPClaims()

		Convey("When I call FromLDAPINfo with no LDAP Server", func() {
			err := c.FromLDAPINfo(i)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When I call FromLDAPINfo with no LDAPInfo", func() {
			err := c.FromLDAPINfo(nil)

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}
