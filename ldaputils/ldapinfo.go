package ldaputils

import "fmt"

// LDAPInfo holds information to authenticate a user using an LDAP Server.
type LDAPInfo struct {
	Address              string `json:"LDAPAddress"`
	BindDN               string `json:"LDAPBindDN"`
	BindPassword         string `json:"LDAPBindPassword"`
	BindSearchFilter     string `json:"LDAPBindSearchFilter"`
	BaseDN               string `json:"LDAPBaseDN"`
	ConnSecurityProtocol string `json:"LDAPConnSecurityProtocol"`
	Username             string `json:"LDAPUsername"`
	Password             string `json:"LDAPPassword"`
}

// NewLDAPInfo returns a new LDAPInfo, or an error
func NewLDAPInfo(metadata map[string]interface{}) (*LDAPInfo, error) {

	if metadata == nil {
		return nil, fmt.Errorf("You must provide at least metadata or defaultMetdata")
	}

	if metadata == nil {
		metadata = map[string]interface{}{}
	}

	info := &LDAPInfo{}

	var err error

	info.Address, err = findLDAPKey(ldapAddressKey, metadata)
	if err != nil {
		return nil, err
	}

	info.BindDN, err = findLDAPKey(ldapBindDNKey, metadata)
	if err != nil {
		return nil, err
	}

	info.BindPassword, err = findLDAPKey(ldapBindPasswordKey, metadata)
	if err != nil {
		return nil, err
	}

	info.BindSearchFilter, err = findLDAPKey(ldapBindSearchFilterKey, metadata)
	if err != nil {
		return nil, err
	}

	info.ConnSecurityProtocol, err = findLDAPKey(ldapConnSecurityProtocolKey, metadata)
	if err != nil {
		return nil, err
	}

	info.Username, err = findLDAPKey(ldapUsernameKey, metadata)
	if err != nil {
		return nil, err
	}

	info.Password, err = findLDAPKey(ldapPasswordKey, metadata)
	if err != nil {
		return nil, err
	}

	info.BaseDN, err = findLDAPKey(ldapBaseDNKey, metadata)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// ToMap convert the LDAPInfo into a map[string]interface{}.
func (i *LDAPInfo) ToMap() map[string]interface{} {

	return map[string]interface{}{
		ldapAddressKey:              i.Address,
		ldapBindDNKey:               i.BindDN,
		ldapBindPasswordKey:         i.BindPassword,
		ldapBindSearchFilterKey:     i.BindSearchFilter,
		ldapUsernameKey:             i.Username,
		ldapPasswordKey:             i.Password,
		ldapBaseDNKey:               i.BaseDN,
		ldapConnSecurityProtocolKey: i.ConnSecurityProtocol,
	}
}
