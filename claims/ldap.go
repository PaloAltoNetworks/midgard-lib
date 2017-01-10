package claims

import (
	"fmt"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	ldap "gopkg.in/ldap.v2"
)

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
func NewLDAPInfo(metadata map[string]interface{}) (*LDAPInfo, error) {

	info := &LDAPInfo{}

	if _, ok := metadata["LDAPAddress"]; !ok {
		return nil, fmt.Errorf("Metadata must contain the key 'LDAPAddress'")
	}
	info.Address = metadata["LDAPAddress"].(string)

	if _, ok := metadata["bindDN"]; !ok {
		return nil, fmt.Errorf("Metadata must contain the key 'bindDN'")
	}
	info.BindDN = metadata["bindDN"].(string)

	if _, ok := metadata["bindPassword"]; !ok {
		return nil, fmt.Errorf("Metadata must contain the key 'bindPassword'")
	}
	info.BindPassword = metadata["bindPassword"].(string)

	if _, ok := metadata["username"]; !ok {
		return nil, fmt.Errorf("Metadata must contain the key 'username'")
	}
	info.Username = metadata["username"].(string)

	if _, ok := metadata["password"]; !ok {
		return nil, fmt.Errorf("Metadata must contain the key 'password'")
	}
	info.Password = metadata["password"].(string)

	if _, ok := metadata["baseDN"]; !ok {
		return nil, fmt.Errorf("Metadata must contain the key 'baseDN'")
	}
	info.BaseDN = metadata["baseDN"].(string)

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

	var subOrgs []string
	var organization string
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
			subOrgs = append(subOrgs, attr.Value)
		}
		if attr.Type == "dc" {
			if len(organization) == 0 {
				organization = attr.Value
			} else {
				organization = organization + "." + attr.Value
			}
		}
	}

	if len(subOrgs) > 0 {
		c.Attributes["organizationalUnit"] = subOrgs[0]
	}

	if organization != "" {
		c.Attributes["organization"] = organization
	}

	c.Attributes["dn"] = strings.Replace(entry.DN, " ", "_", -1)

	for _, attr := range entry.Attributes {
		if attr.Name == "userPassword" || attr.Name == "objectClass" {
			continue
		}

		if len(attr.Values) == 0 || attr.Values[0] == "" {
			continue
		}

		c.Attributes[attr.Name] = strings.Replace(attr.Values[0], " ", "_", -1)
	}

	return nil
}
