package ldaputils

import (
	"fmt"
	"strings"
)

const (
	userQueryString = "{USERNAME}"
)

// LDAPInfo holds information to authenticate a user using an LDAP Server.
type LDAPInfo struct {
	Address              string                 `msgpack:"LDAPAddress" json:"LDAPAddress"`
	BindDN               string                 `msgpack:"LDAPBindDN" json:"LDAPBindDN"`
	BindPassword         string                 `msgpack:"LDAPBindPassword" json:"LDAPBindPassword"`
	BindSearchFilter     string                 `msgpack:"LDAPBindSearchFilter" json:"LDAPBindSearchFilter"`
	SubjectKey           string                 `msgpack:"LDAPSubjectKey" json:"LDAPSubjectKey"`
	IgnoreKeys           map[string]interface{} `msgpack:"LDAPIgnoredKeys" json:"LDAPIgnoredKeys"`
	BaseDN               string                 `msgpack:"LDAPBaseDN" json:"LDAPBaseDN"`
	ConnSecurityProtocol string                 `msgpack:"LDAPConnSecurityProtocol" json:"LDAPConnSecurityProtocol"`
	Username             string                 `msgpack:"LDAPUsername" json:"LDAPUsername"`
	Password             string                 `msgpack:"LDAPPassword" json:"LDAPPassword"`
}

// NewLDAPInfo returns a new LDAPInfo, or an error
func NewLDAPInfo(metadata map[string]interface{}) (*LDAPInfo, error) {

	if metadata == nil {
		return nil, fmt.Errorf("you must provide at least metadata or defaultMetadata")
	}

	info := &LDAPInfo{}

	var err error

	info.Address, err = findLDAPKey(LDAPAddressKey, metadata)
	if err != nil {
		return nil, err
	}

	info.BindDN, err = findLDAPKey(LDAPBindDNKey, metadata)
	if err != nil {
		return nil, err
	}

	info.BindPassword, err = findLDAPKey(LDAPBindPasswordKey, metadata)
	if err != nil {
		return nil, err
	}

	info.BindSearchFilter, err = findLDAPKey(LDAPBindSearchFilterKey, metadata)
	if err != nil {
		return nil, err
	}

	info.SubjectKey, err = findLDAPKey(LDAPSubjectKey, metadata)
	if err != nil {
		return nil, err
	}

	info.IgnoreKeys, err = findLDAPKeyMap(LDAPIgnoredKeys, metadata)
	if err != nil {
		return nil, err
	}

	info.ConnSecurityProtocol, err = findLDAPKey(LDAPConnSecurityProtocolKey, metadata)
	if err != nil {
		return nil, err
	}

	info.Username, err = findLDAPKey(LDAPUsernameKey, metadata)
	if err != nil {
		return nil, err
	}

	info.Password, err = findLDAPKey(LDAPPasswordKey, metadata)
	if err != nil {
		return nil, err
	}

	info.BaseDN, err = findLDAPKey(LDAPBaseDNKey, metadata)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// ToMap convert the LDAPInfo into a map[string]interface{}.
func (i *LDAPInfo) ToMap() map[string]interface{} {

	return map[string]interface{}{
		LDAPAddressKey:              i.Address,
		LDAPBindDNKey:               i.BindDN,
		LDAPBindPasswordKey:         i.BindPassword,
		LDAPBindSearchFilterKey:     i.BindSearchFilter,
		LDAPSubjectKey:              i.SubjectKey,
		LDAPIgnoredKeys:             i.IgnoreKeys,
		LDAPUsernameKey:             i.Username,
		LDAPPasswordKey:             i.Password,
		LDAPBaseDNKey:               i.BaseDN,
		LDAPConnSecurityProtocolKey: i.ConnSecurityProtocol,
	}
}

// GetUserQueryString returns the query string based on the filter and username provided.
func (i *LDAPInfo) GetUserQueryString() string {

	return strings.Replace(i.BindSearchFilter, userQueryString, i.Username, -1)
}
