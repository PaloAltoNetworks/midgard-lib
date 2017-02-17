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

// CustomAuthFunc is the type of a function that can be ran to
// decide custom authentication operations. It returns a CustomAuthResult.
type CustomAuthFunc func(*bahamut.Context) (CustomAuthResult, error)

// An MidgardAuthenticator is the enforcer of the authorizations of all API calls.
//
// It implements the bahamut.MidgardAuthenticator interface.
type MidgardAuthenticator struct {
	midgardClient  *midgardclient.Client
	cache          cache.Cacher
	pendingCache   cache.Cacher
	customAuthFunc CustomAuthFunc
}

// NewMidgardAuthenticator creates a new MidgardAuthenticator to use with Bahamut.
func NewMidgardAuthenticator(midgardURL string, serverCAPool *x509.CertPool, clientCAPool *x509.CertPool, skipVerify bool, customAuthFunc CustomAuthFunc) *MidgardAuthenticator {

	return &MidgardAuthenticator{
		midgardClient:  midgardclient.NewClientWithCAPool(midgardURL, serverCAPool, clientCAPool, skipVerify),
		customAuthFunc: customAuthFunc,
		cache:          cache.NewMemoryCache(),
		pendingCache:   cache.NewMemoryCache(),
	}
}

// IsAuthenticated is the main method that returns whether the client is authenticated or not.
func (a *MidgardAuthenticator) IsAuthenticated(ctx *bahamut.Context) (bool, error) {

	if a.customAuthFunc != nil {

		result, err := a.customAuthFunc(ctx)
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

	token := ctx.Request.Password

	if wg := a.pendingCache.Get(token); wg != nil {
		wg.(*sync.WaitGroup).Wait()
	}

	if i := a.cache.Get(token); i != nil {
		ctx.UserInfo = i
		return true, nil
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
			"error":   err.Error(),
			"context": ctx.String(),
		}).Debug("ReST Authentication rejected.")
		return false, nil
	}

	log.Entry.WithFields(logrus.Fields{
		"context":  ctx.String(),
		"identity": identity,
	}).Debug("Sucessfully authenticated ReST request.")

	a.cache.SetWithExpiration(token, identity, 10*time.Minute)

	ctx.UserInfo = identity

	return true, nil
}
