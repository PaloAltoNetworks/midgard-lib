package claims

import (
	"testing"

	ldap "gopkg.in/ldap.v2"

	. "github.com/smartystreets/goconvey/convey"
)

func TestLDAPClais_LDAPInfo(t *testing.T) {

	Convey("Given I create a new LDAPInfo with valid metadata", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":      "123:123",
			"LDAPBindDN":       "cn=admin,dc=toto,dc=com",
			"LDAPBindPassword": "toto",
			"LDAPUsername":     "lskywalker",
			"LDAPPassword":     "secret",
			"LDAPBaseDN":       "ou=zoupla,dc=toto,dc=com",
		}, nil)

		Convey("Then err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then info should not be nil", func() {
			So(i, ShouldNotBeNil)
		})

		Convey("Then info should be correct", func() {
			So(i.Address, ShouldEqual, "123:123")
			So(i.BindDN, ShouldEqual, "cn=admin,dc=toto,dc=com")
			So(i.BindPassword, ShouldEqual, "toto")
			So(i.Username, ShouldEqual, "lskywalker")
			So(i.Password, ShouldEqual, "secret")
			So(i.BaseDN, ShouldEqual, "ou=zoupla,dc=toto,dc=com")
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing LDAPAddress", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPBindDN":       "cn=admin,dc=toto,dc=com",
			"LDAPBindPassword": "toto",
			"LDAPUsername":     "lskywalker",
			"LDAPPassword":     "secret",
			"LDAPBaseDN":       "ou=zoupla,dc=toto,dc=com",
		}, nil)

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
			"LDAPAddress":      "123:123",
			"LDAPBindPassword": "toto",
			"LDAPUsername":     "lskywalker",
			"LDAPPassword":     "secret",
			"LDAPBaseDN":       "ou=zoupla,dc=toto,dc=com",
		}, nil)

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPBindDN'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing bindPassword", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":  "123:123",
			"LDAPBindDN":   "cn=admin,dc=toto,dc=com",
			"LDAPUsername": "lskywalker",
			"LDAPPassword": "secret",
			"LDAPBaseDN":   "ou=zoupla,dc=toto,dc=com",
		}, nil)

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPBindPassword'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing username", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":      "123:123",
			"LDAPBindDN":       "cn=admin,dc=toto,dc=com",
			"LDAPBindPassword": "toto",
			"LDAPPassword":     "secret",
			"LDAPBaseDN":       "ou=zoupla,dc=toto,dc=com",
		}, nil)

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPUsername'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing password", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":      "123:123",
			"LDAPBindDN":       "cn=admin,dc=toto,dc=com",
			"LDAPBindPassword": "toto",
			"LDAPUsername":     "lskywalker",
			"LDAPBaseDN":       "ou=zoupla,dc=toto,dc=com",
		}, nil)

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPPassword'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing baseDN", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":      "123:123",
			"LDAPBindDN":       "cn=admin,dc=toto,dc=com",
			"LDAPBindPassword": "toto",
			"LDAPUsername":     "lskywalker",
			"LDAPPassword":     "secret",
		}, nil)

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPBaseDN'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with no metadata and defautMetada", t, func() {

		i, err := NewLDAPInfo(nil,
			map[string]interface{}{
				"LDAPAddress":      "123:123",
				"LDAPBindDN":       "cn=admin,dc=toto,dc=com",
				"LDAPBindPassword": "toto",
				"LDAPUsername":     "lskywalker",
				"LDAPPassword":     "secret",
				"LDAPBaseDN":       "ou=zoupla,dc=toto,dc=com",
			})

		Convey("Then err should not be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then info should be correct", func() {
			So(i.Address, ShouldEqual, "123:123")
			So(i.BindDN, ShouldEqual, "cn=admin,dc=toto,dc=com")
			So(i.BindPassword, ShouldEqual, "toto")
			So(i.Username, ShouldEqual, "lskywalker")
			So(i.Password, ShouldEqual, "secret")
			So(i.BaseDN, ShouldEqual, "ou=zoupla,dc=toto,dc=com")
		})
	})

	Convey("Given I create a new LDAPInfo with a combination metadata and defautMetada", t, func() {

		i, err := NewLDAPInfo(
			map[string]interface{}{
				"LDAPAddress": "123:123",
				"LDAPBindDN":  "cn=admin,dc=toto,dc=com",
				"LDAPBaseDN":  "ou=zoupla,dc=toto,dc=com",
			},
			map[string]interface{}{
				"LDAPAddress":      "default:123:123",
				"LDAPBindDN":       "default:n=admin,dc=toto,dc=com",
				"LDAPBindPassword": "default:toto",
				"LDAPUsername":     "default:lskywalker",
				"LDAPPassword":     "default:secret",
				"LDAPBaseDN":       "default:ou=zoupla,dc=toto,dc=com",
			})

		Convey("Then err should not be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then info should be correct", func() {
			So(i.Address, ShouldEqual, "123:123")
			So(i.BindDN, ShouldEqual, "cn=admin,dc=toto,dc=com")
			So(i.BindPassword, ShouldEqual, "default:toto")
			So(i.Username, ShouldEqual, "default:lskywalker")
			So(i.Password, ShouldEqual, "default:secret")
			So(i.BaseDN, ShouldEqual, "ou=zoupla,dc=toto,dc=com")
		})
	})

	Convey("Given I create a new LDAPInfo nothing", t, func() {

		i, err := NewLDAPInfo(nil, nil)

		Convey("Then err should not be be nil", func() {
			So(err, ShouldNotBeNil)
		})

		Convey("Then LDAPInfo should be nil", func() {
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
				So(c.Attributes["ou:ou1"], ShouldEqual, "true")
				So(c.Attributes["ou:ou2"], ShouldEqual, "true")
				So(c.Attributes["dc:toto"], ShouldEqual, "true")
				So(c.Attributes["dc:com"], ShouldEqual, "true")
				So(c.Attributes["empty"], ShouldEqual, "")
				So(c.Attributes["userPassword"], ShouldEqual, "")
				So(c.Attributes["LDAPPassword"], ShouldEqual, "")
				So(c.Attributes["givenName"], ShouldEqual, "Wesh Gros")
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
				So(mc.Data["givenName"], ShouldEqual, "Wesh Gros")
				So(mc.Data["FamilyName"], ShouldEqual, "Gros")
			})
		})
	})
}

func TestLDAPClaims_FromLDAPInfo(t *testing.T) {

	Convey("Given I have a LDAPClaim and LDAPInfo", t, func() {

		i, _ := NewLDAPInfo(map[string]interface{}{
			"LDAPAddress":      "123:123",
			"LDAPBindDN":       "cn=admin,dc=toto,dc=com",
			"LDAPBindPassword": "toto",
			"LDAPUsername":     "lskywalker",
			"LDAPPassword":     "secret",
			"LDAPBaseDN":       "secret",
		}, nil)

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
