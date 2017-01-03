package models

import "github.com/aporeto-inc/elemental"

var relationshipsRegistry elemental.RelationshipsRegistry

// Relationships returns the model relationships.
func Relationships() elemental.RelationshipsRegistry {

	return relationshipsRegistry
}

func init() {
	relationshipsRegistry = elemental.RelationshipsRegistry{}

	//
	// Main Relationship for root
	//
	RootMainRelationship := &elemental.Relationship{
		AllowsRetrieve: true,
	}

	// Children relationship for auth in root
	RootMainRelationship.AddChild(
		elemental.IdentityFromName("auth"),
		&elemental.Relationship{
			AllowsRetrieveMany: true,
			AllowsInfo:         true,
		},
	)
	// Children relationship for issue in root
	RootMainRelationship.AddChild(
		elemental.IdentityFromName("issue"),
		&elemental.Relationship{
			AllowsCreate: true,
		},
	)

	relationshipsRegistry[elemental.IdentityFromName("root")] = RootMainRelationship

	//
	// Main Relationship for issue
	//
	IssueMainRelationship := &elemental.Relationship{}

	relationshipsRegistry[elemental.IdentityFromName("issue")] = IssueMainRelationship

	//
	// Main Relationship for auth
	//
	AuthMainRelationship := &elemental.Relationship{}

	relationshipsRegistry[elemental.IdentityFromName("auth")] = AuthMainRelationship

}
