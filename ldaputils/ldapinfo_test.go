package ldaputils

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestLDAPUtils_LDAPInfo(t *testing.T) {

	Convey("Given I create a new LDAPInfo with valid metadata", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			LDAPAddressKey:              "123:123",
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPBindPasswordKey:         "toto",
			LDAPBindSearchFilterKey:     "uid={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPPasswordKey:             "secret",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
		})

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
			So(i.BindSearchFilter, ShouldEqual, "uid={USERNAME}")
			So(i.ConnSecurityProtocol, ShouldEqual, "TLS")
			So(i.Username, ShouldEqual, "lskywalker")
			So(i.Password, ShouldEqual, "secret")
			So(i.BaseDN, ShouldEqual, "ou=zoupla,dc=toto,dc=com")
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing LDAPAddress", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPBindPasswordKey:         "toto",
			LDAPBindSearchFilterKey:     "uid={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPPasswordKey:             "secret",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
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
			LDAPAddressKey:              "123:123",
			LDAPBindPasswordKey:         "toto",
			LDAPBindSearchFilterKey:     "uid={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPPasswordKey:             "secret",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
		})

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
			LDAPAddressKey:              "123:123",
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPBindSearchFilterKey:     "uid={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPPasswordKey:             "secret",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPBindPassword'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing bindSearchFilter", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			LDAPAddressKey:              "123:123",
			LDAPBindPasswordKey:         "toto",
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPPasswordKey:             "secret",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPBindSearchFilter'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing connSecurityProtocol", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			LDAPAddressKey:          "123:123",
			LDAPBindPasswordKey:     "toto",
			LDAPBindDNKey:           "cn=admin,dc=toto,dc=com",
			LDAPBindSearchFilterKey: "uid={USERNAME}",
			LDAPUsernameKey:         "lskywalker",
			LDAPPasswordKey:         "secret",
			LDAPBaseDNKey:           "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPConnSecurityProtocol'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo with metadata and missing username", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			LDAPAddressKey:              "123:123",
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPBindPasswordKey:         "toto",
			LDAPBindSearchFilterKey:     "uid={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPPasswordKey:             "secret",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
		})

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
			LDAPAddressKey:              "123:123",
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPBindPasswordKey:         "toto",
			LDAPBindSearchFilterKey:     "uid={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
		})

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
			LDAPAddressKey:              "123:123",
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPBindPasswordKey:         "toto",
			LDAPBindSearchFilterKey:     "uid={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPPasswordKey:             "secret",
		})

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Metadata must contain the key 'LDAPBaseDN'")
		})

		Convey("Then info should be nil", func() {
			So(i, ShouldBeNil)
		})
	})

	Convey("Given I create a new LDAPInfo nothing", t, func() {

		i, err := NewLDAPInfo(nil)

		Convey("Then err should not be be nil", func() {
			So(err, ShouldNotBeNil)
		})

		Convey("Then LDAPInfo should be nil", func() {
			So(i, ShouldBeNil)
		})
	})
}

func TestLDAPUtils_GetUserQueryString(t *testing.T) {

	Convey("Given I create a new LDAPInfo with valid metadata", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			LDAPAddressKey:              "123:123",
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPBindPasswordKey:         "toto",
			LDAPBindSearchFilterKey:     "uid={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPPasswordKey:             "secret",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then info should not be nil", func() {
			So(i, ShouldNotBeNil)
		})

		Convey("Then info should be correct", func() {
			So(i.GetUserQueryString(), ShouldEqual, "uid=lskywalker")
		})
	})

	Convey("Given I create a new LDAPInfo with valid metadata", t, func() {

		i, err := NewLDAPInfo(map[string]interface{}{
			LDAPAddressKey:              "123:123",
			LDAPBindDNKey:               "cn=admin,dc=toto,dc=com",
			LDAPBindPasswordKey:         "toto",
			LDAPBindSearchFilterKey:     "uid={USERNAME},khg={USERNAME}",
			LDAPConnSecurityProtocolKey: "TLS",
			LDAPUsernameKey:             "lskywalker",
			LDAPPasswordKey:             "secret",
			LDAPBaseDNKey:               "ou=zoupla,dc=toto,dc=com",
		})

		Convey("Then err should be nil", func() {
			So(err, ShouldBeNil)
		})

		Convey("Then info should not be nil", func() {
			So(i, ShouldNotBeNil)
		})

		Convey("Then info should be correct", func() {
			So(i.GetUserQueryString(), ShouldEqual, "uid=lskywalker,khg=lskywalker")
		})
	})
}
