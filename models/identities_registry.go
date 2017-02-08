package models

import "github.com/aporeto-inc/elemental"

func init() {

	elemental.RegisterIdentity(RootIdentity)
	elemental.RegisterIdentity(IssueIdentity)
	elemental.RegisterIdentity(AuthIdentity)
}

// IdentifiableForIdentity returns a new instance of the Identifiable for the given identity name.
func IdentifiableForIdentity(identity string) elemental.Identifiable {

	switch identity {
	case RootIdentity.Name:
		return NewRoot()
	case IssueIdentity.Name:
		return NewIssue()
	case AuthIdentity.Name:
		return NewAuth()
	default:
		return nil
	}
}

// AllIdentities returns all existing identities.
func AllIdentities() []elemental.Identity {

	return []elemental.Identity{
		RootIdentity,
		IssueIdentity,
		AuthIdentity,
	}
}
