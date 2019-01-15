package midgardclient

type issueOpts struct {
	quota int
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
