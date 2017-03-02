package authenticator

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aporeto-inc/addedeffect/cache"
	"github.com/aporeto-inc/bahamut"
	"github.com/aporeto-inc/squall/log"

	midgardclient "github.com/aporeto-inc/midgard-lib/client"
)

// CustomAuthResult represents the result of the custom auth function.
type CustomAuthResult int

const (
	// CustomAuthResultOK represents a successful custom authentication.
	CustomAuthResultOK CustomAuthResult = iota

	// CustomAuthResultNOK represents a unsuccessful custom authentication.
	CustomAuthResultNOK

	// CustomAuthResultContinue represents that the custom auth function
	// doesn't apply. The authentication will continue as usual.
	CustomAuthResultContinue
)

// CustomAuthRequestFunc is the type of a function that can be ran to
// decide custom authentication operations for requests. It returns a CustomAuthResult.
type CustomAuthRequestFunc func(*bahamut.Context) (CustomAuthResult, error)

// CustomAuthSessionFunc is the type of a function that can be ran to
// decide custom authentication operations sessions. It returns a CustomAuthResult.
type CustomAuthSessionFunc func(*bahamut.PushSession) (CustomAuthResult, error)

// An MidgardAuthenticator is the enforcer of the authorizations of all API calls.
//
// It implements the bahamut.MidgardAuthenticator interface.
type MidgardAuthenticator struct {
	cache                 cache.Cacher
	cacheValidity         time.Duration
	customAuthRequestFunc CustomAuthRequestFunc
	customAuthSessionFunc CustomAuthSessionFunc
	midgardClient         *midgardclient.Client
	pendingCache          cache.Cacher
}

// NewMidgardAuthenticator creates a new MidgardAuthenticator to use with Bahamut.
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
func (a *MidgardAuthenticator) AuthenticateSession(session *bahamut.PushSession) (bool, error) {

	if a.customAuthSessionFunc != nil {

		result, err := a.customAuthSessionFunc(session)
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

	ok, identity, err := a.commonAuth(session.Parameters.Get("token"))
	session.Identity = identity

	return ok, err
}

// AuthenticateRequest authenticates the request from the given context.
func (a *MidgardAuthenticator) AuthenticateRequest(ctx *bahamut.Context) (bool, error) {

	if a.customAuthRequestFunc != nil {

		result, err := a.customAuthRequestFunc(ctx)
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

	ok, identity, err := a.commonAuth(ctx.Request.Password)
	ctx.Identity = identity

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
		log.Entry.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Debug("ReST Authentication rejected.")
		return false, nil, nil
	}

	log.Entry.WithFields(logrus.Fields{
		"identity": identity,
	}).Debug("Sucessfully authenticated ReST request.")

	a.cache.SetWithExpiration(token, identity, a.cacheValidity)

	return true, identity, nil
}
