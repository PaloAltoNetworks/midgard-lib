package claims

// TokenIssuer is the interface a token issuer must implement.
type TokenIssuer interface {
	ToMidgardClaims() *MidgardClaims
}
