package midgardclient

type issueOpts struct {
	quota    int
	opaque   map[string]string
	audience string
}

// An Option is the type of various options
// You can add the issue requests.
type Option func(*issueOpts)

// OptQuota sets the maximum time the issued token
// can be used.
var OptQuota = func(quota int) Option {

	if quota < 0 {
		panic("quota must be a positive number")
	}

	return func(opts *issueOpts) {
		opts.quota = quota
	}
}

// OptOpaque passes opaque data that will be
// included in the JWT.
var OptOpaque = func(opaque map[string]string) Option {

	return func(opts *issueOpts) {
		opts.opaque = opaque
	}
}

// OptAudience passes the requested audience for the token.
var OptAudience = func(audience string) Option {

	return func(opts *issueOpts) {
		opts.audience = audience
	}
}
