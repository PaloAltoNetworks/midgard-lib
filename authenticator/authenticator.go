// Package authenticator provides a ready to use Midgard-backed authenticator for
// any Bahamut Server.
//
// It also provide a way to hijack the authentication process by passing CustomAuthRequestFunc
// for API calls, and CustomAuthSessionFunc for authenticating WebSocket sessions.
// Those function return CustomAuthResultOK to assume the authentication is a success,
// CustomAuthResultNOK to fail the authentication, or CustomAuthResultContinue to continue
// standard authentication process.
package authenticator

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/aporeto-inc/addedeffect/cache"
	"github.com/aporeto-inc/elemental"

	midgardclient "github.com/aporeto-inc/midgard-lib/client"
)

// CustomAuthResult represents the result of a CustomAuthRequestFunc or CustomAuthSessionFunc.
type CustomAuthResult int

const (
	// CustomAuthResultOK indicates a successful custom authentication.
	CustomAuthResultOK CustomAuthResult = iota

	// CustomAuthResultNOK indicates a failed custom authentication.
	CustomAuthResultNOK

	// CustomAuthResultContinue indicates that the custom auth function
	// doesn't apply. The authentication will continue as usual.
	CustomAuthResultContinue
)

// CustomAuthRequestFunc is the type of functions that can be used to
// decide custom authentication operations for requests. It returns a CustomAuthResult.
type CustomAuthRequestFunc func(*elemental.Request) (CustomAuthResult, error)

// CustomAuthSessionFunc is the type of functions that can be used to
// decide custom authentication operations sessions. It returns a CustomAuthResult.
type CustomAuthSessionFunc func(elemental.SessionHolder) (CustomAuthResult, error)

// A MidgardAuthenticator is a bahamut.Authenticator compliant structure to authentify
// requests using a Midgard token. It supports custom authentication hijacking, a caching mechanism
// and safe guard to not overload midgard in case of a lot of concurrent authentication requests.
type MidgardAuthenticator struct {
	cache                 cache.Cacher
	cacheValidity         time.Duration
	customAuthRequestFunc CustomAuthRequestFunc
	customAuthSessionFunc CustomAuthSessionFunc
	midgardClient         *midgardclient.Client
	pendingCache          cache.Cacher
}

// NewMidgardAuthenticator returns a new *MidgardAuthenticator.
func NewMidgardAuthenticator(
	midgardURL string,
	serverCAPool *x509.CertPool,
	clientCAPool *x509.CertPool,
	skipVerify bool,
	customAuthRequestFunc CustomAuthRequestFunc,
	customAuthSessionFunc CustomAuthSessionFunc,
	cacheValidity time.Duration,
) *MidgardAuthenticator {

	return &MidgardAuthenticator{
		cache:                 cache.NewMemoryCache(),
		cacheValidity:         cacheValidity,
		customAuthSessionFunc: customAuthSessionFunc,
		midgardClient:         midgardclient.NewClientWithCAPool(midgardURL, serverCAPool, clientCAPool, skipVerify),
		pendingCache:          cache.NewMemoryCache(),
		customAuthRequestFunc: customAuthRequestFunc,
	}
}

// AuthenticateSession authenticates the given session.
// It will return true if the authentication is a success, false in case of failure
// and an eventual error in case of error.
func (a *MidgardAuthenticator) AuthenticateSession(sessionHolder elemental.SessionHolder) (bool, error) {

	if a.customAuthSessionFunc != nil {

		result, err := a.customAuthSessionFunc(sessionHolder)
		if err != nil {
			return false, err
		}

		switch result {
		case CustomAuthResultOK:
			return true, nil
		case CustomAuthResultNOK:
			return false, nil
		}
	}

	ok, claims, err := a.commonAuth(sessionHolder.GetToken())
	sessionHolder.SetClaims(claims)

	return ok, err
}

// AuthenticateRequest authenticates the request from the given bahamut.Context.
// It will return true if the authentication is a success, false in case of failure
// and an eventual error in case of error.
func (a *MidgardAuthenticator) AuthenticateRequest(req *elemental.Request, claimsHolder elemental.ClaimsHolder) (bool, error) {

	if a.customAuthRequestFunc != nil {

		result, err := a.customAuthRequestFunc(req)
		if err != nil {
			return false, err
		}

		switch result {
		case CustomAuthResultOK:
			return true, nil
		case CustomAuthResultNOK:
			return false, nil
		}
	}

	// TODO: I think that if the context already have some identity, we could skip the auth part,
	// as it means it's coming from a push session already authenticated.
	//
	// But I'm not sure ;)

	ok, claims, err := a.commonAuth(req.Password)
	claimsHolder.SetClaims(claims)

	return ok, err
}

func (a *MidgardAuthenticator) commonAuth(token string) (bool, []string, error) {

	if wg := a.pendingCache.Get(token); wg != nil {
		wg.(*sync.WaitGroup).Wait()
	}

	if i := a.cache.Get(token); i != nil {
		return true, i.([]string), nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	a.pendingCache.Set(token, &wg)
	defer func() {
		wg.Done()
		a.pendingCache.Del(token)
	}()

	identity, err := a.midgardClient.Authentify(token)
	if err != nil {
		return false, nil, nil
	}

	a.cache.SetWithExpiration(token, identity, a.cacheValidity)

	return true, identity, nil
}
