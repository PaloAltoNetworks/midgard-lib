package claims

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	ldap "gopkg.in/ldap.v2"
)

const defaultMultiKeyValue = "true"

// LDAPInfo holds information to authenticate a user using an LDAP Server.
type LDAPInfo struct {
	Address      string
	BindDN       string
	BindPassword string
	BaseDN       string
	Username     string
	Password     string
}

// NewLDAPInfo returns a new LDAPInfo, or an error
func NewLDAPInfo(metadata map[string]interface{}, defaultMetadata map[string]interface{}) (*LDAPInfo, error) {

	if metadata == nil && defaultMetadata == nil {
		return nil, fmt.Errorf("You must provide at least metadata or defaultMetdata")
	}

	if metadata == nil {
		metadata = map[string]interface{}{}
	}

	if defaultMetadata == nil {
		defaultMetadata = map[string]interface{}{}
	}

	info := &LDAPInfo{}

	if _, ok := metadata["LDAPAddress"]; !ok {
		if _, ok := defaultMetadata["LDAPAddress"]; !ok {
			return nil, fmt.Errorf("Metadata must contain the key 'LDAPAddress'")
		}
		info.Address = defaultMetadata["LDAPAddress"].(string)
	} else {
		info.Address = metadata["LDAPAddress"].(string)
	}

	if _, ok := metadata["bindDN"]; !ok {
		if _, ok := defaultMetadata["bindDN"]; !ok {
			return nil, fmt.Errorf("Metadata must contain the key 'bindDN'")
		}
		info.BindDN = defaultMetadata["bindDN"].(string)
	} else {
		info.BindDN = metadata["bindDN"].(string)
	}

	if _, ok := metadata["bindPassword"]; !ok {
		if _, ok := defaultMetadata["bindPassword"]; !ok {
			return nil, fmt.Errorf("Metadata must contain the key 'bindPassword'")
		}
		info.BindPassword = defaultMetadata["bindPassword"].(string)
	} else {
		info.BindPassword = metadata["bindPassword"].(string)
	}

	if _, ok := metadata["username"]; !ok {
		if _, ok := defaultMetadata["username"]; !ok {
			return nil, fmt.Errorf("Metadata must contain the key 'username'")
		}
		info.Username = defaultMetadata["username"].(string)
	} else {
		info.Username = metadata["username"].(string)
	}

	if _, ok := metadata["password"]; !ok {
		if _, ok := defaultMetadata["password"]; !ok {
			return nil, fmt.Errorf("Metadata must contain the key 'password'")
		}
		info.Password = defaultMetadata["password"].(string)
	} else {
		info.Password = metadata["password"].(string)
	}

	if _, ok := metadata["baseDN"]; !ok {
		if _, ok := defaultMetadata["password"]; !ok {
			return nil, fmt.Errorf("Metadata must contain the key 'baseDN'")
		}
		info.BaseDN = defaultMetadata["baseDN"].(string)
	} else {
		info.BaseDN = metadata["baseDN"].(string)
	}

	return info, nil
}

// LDAPClaims represents the claims used by a LDAP.
type LDAPClaims struct {
	Attributes map[string]string

	jwt.StandardClaims
}

// NewLDAPClaims returns a new CertificateClaims.
func NewLDAPClaims() *LDAPClaims {

	return &LDAPClaims{
		Attributes:     map[string]string{},
		StandardClaims: jwt.StandardClaims{},
	}
}

// FromLDAPINfo verifies and returns the ldap claims for the given metadata.
func (c *LDAPClaims) FromLDAPINfo(info *LDAPInfo) error {

	if info == nil {
		return fmt.Errorf("LDAPInfo cannot be nil")
	}

	entry, err := c.retrieveEntry(info)
	if err != nil {
		return err
	}

	return c.populateClaim(entry)
}

// ToMidgardClaims returns the MidgardClaims from google claims.
func (c *LDAPClaims) ToMidgardClaims() *MidgardClaims {

	now := time.Now()

	return &MidgardClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  JWTAudience,
			Issuer:    JWTIssuer,
			ExpiresAt: now.Add(JWTValidity).Unix(),
			IssuedAt:  now.Unix(),
			Subject:   c.Subject,
		},
		Realm: "LDAP",
		Data:  c.Attributes,
	}
}

func (c *LDAPClaims) retrieveEntry(info *LDAPInfo) (*ldap.Entry, error) {

	l, err := ldap.Dial("tcp", info.Address)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	if err = l.Bind(info.BindDN, info.BindPassword); err != nil {
		return nil, err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		info.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(uid=%s))", info.Username),
		nil,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) != 1 {
		return nil, fmt.Errorf("User does not exist or too many entries returned")
	}

	return sr.Entries[0], nil
}

func (c *LDAPClaims) populateClaim(entry *ldap.Entry) error {

	var subject string

	dns, err := ldap.ParseDN(entry.DN)
	if err != nil {
		return err
	}

	if subject = entry.GetAttributeValue("uid"); subject == "" {
		return fmt.Errorf("Unable to find uid in LDAP entry")
	}
	c.Subject = subject

	for _, rdn := range dns.RDNs {
		attr := rdn.Attributes[0]
		if attr.Type == "ou" {
			c.Attributes["ou:"+attr.Value] = defaultMultiKeyValue
		}
		if attr.Type == "dc" {
			c.Attributes["dc:"+attr.Value] = defaultMultiKeyValue
		}
	}

	c.Attributes["dn"] = entry.DN

	for _, attr := range entry.Attributes {
		if attr.Name == "userPassword" || attr.Name == "objectClass" {
			continue
		}

		if len(attr.Values) == 0 || attr.Values[0] == "" {
			continue
		}

		if len(attr.Values) == 1 {
			c.Attributes[attr.Name] = attr.Values[0]
		} else {
			for _, v := range attr.Values {
				c.Attributes[attr.Name+":"+v] = defaultMultiKeyValue
			}
		}
	}

	return nil
}
