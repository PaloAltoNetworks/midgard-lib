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
	"net/http"
	"sync"
	"time"

	"github.com/aporeto-inc/bahamut"

	"github.com/aporeto-inc/addedeffect/cache"
	"github.com/aporeto-inc/elemental"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/opentracing/opentracing-go/log"

	midgardclient "github.com/aporeto-inc/midgard-lib/client"
)

// CustomAuthRequestFunc is the type of functions that can be used to
// decide custom authentication operations for requests. It returns a bahamut.AuthAction.
type CustomAuthRequestFunc func(*elemental.Request) (bahamut.AuthAction, error)

// CustomAuthSessionFunc is the type of functions that can be used to
// decide custom authentication operations sessions. It returns a bahamut.AuthAction.
type CustomAuthSessionFunc func(elemental.SessionHolder) (bahamut.AuthAction, error)

// A RateLimiter a is the interface of a structure that can be used a rate limiter.
type RateLimiter interface {
	RateLimit(*http.Request) (bool, error)
}

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
	rateLimiter           RateLimiter
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
		pendingCache:          cache.NewMemoryCache(),
		cacheValidity:         cacheValidity,
		customAuthSessionFunc: customAuthSessionFunc,
		midgardClient:         midgardclient.NewClientWithCAPool(midgardURL, serverCAPool, clientCAPool, skipVerify),
		customAuthRequestFunc: customAuthRequestFunc,
	}
}

// SetUnauthenticatedRateLimiter sets a rate limiter to use for unauthenticated calls.
func (a *MidgardAuthenticator) SetUnauthenticatedRateLimiter(limiter RateLimiter) {

	a.rateLimiter = limiter
}

// SetTrackingType sets the tracking type to send to the client
func (a *MidgardAuthenticator) SetTrackingType(trackingType string) {

	a.midgardClient.TrackingType = trackingType
}

// AuthenticateSession authenticates the given session.
// It will return true if the authentication is a success, false in case of failure
// and an eventual error in case of error.
func (a *MidgardAuthenticator) AuthenticateSession(sessionHolder elemental.SessionHolder, spanHolder elemental.SpanHolder) (bahamut.AuthAction, error) {

	sp := spanHolder.NewChildSpan("midgardlib.authenticator.authenticate.session")
	defer sp.Finish()

	if a.customAuthSessionFunc != nil {

		result, err := a.customAuthSessionFunc(sessionHolder)
		if err != nil {
			ext.Error.Set(sp, true)
			sp.LogEventWithPayload("Error from custom auth function", err.Error())
			return bahamut.AuthActionKO, err
		}

		if result != bahamut.AuthActionContinue {
			sp.LogEvent("Session authentication handled from custom auth function")
			sp.LogFields(log.Bool("granted", result == bahamut.AuthActionOK))
			return result, nil
		}
	}

	action, claims, err := a.commonAuth(sessionHolder.GetToken(), sp)
	if err != nil {
		ext.Error.Set(sp, true)
		sp.LogEventWithPayload("Unable to authenticate session", err.Error())
		return bahamut.AuthActionKO, err
	}

	sessionHolder.SetClaims(claims)
	sp.SetTag("claims", claims)

	return action, nil
}

// AuthenticateRequest authenticates the request from the given bahamut.Context.
// It will return true if the authentication is a success, false in case of failure
// and an eventual error in case of error.
func (a *MidgardAuthenticator) AuthenticateRequest(req *elemental.Request, claimsHolder elemental.ClaimsHolder) (bahamut.AuthAction, error) {

	sp := req.NewChildSpan("midgardlib.authenticator.authenticate.request")
	defer sp.Finish()

	if a.customAuthRequestFunc != nil {

		result, err := a.customAuthRequestFunc(req)
		if err != nil {
			ext.Error.Set(sp, true)
			sp.LogEventWithPayload("Error from custom auth function", err.Error())
			return bahamut.AuthActionKO, err
		}

		if result != bahamut.AuthActionContinue {
			sp.LogEvent("request authentication handled from custom auth function")
			sp.LogFields(log.Bool("granted", result == bahamut.AuthActionOK))
			return result, nil
		}
	}

	// TODO: I think that if the context already have some identity, we could skip the auth part,
	// as it means it's coming from a push session already authenticated.
	//
	// But I'm not sure ;)

	action, claims, err := a.commonAuth(req.Password, sp)

	if err != nil {
		ext.Error.Set(sp, true)
		sp.LogEventWithPayload("Unable to authenticate request", err.Error())
		return bahamut.AuthActionKO, err
	}

	claimsHolder.SetClaims(claims)
	sp.SetTag("claims", claims)

	return action, nil
}

func (a *MidgardAuthenticator) commonAuth(token string, span opentracing.Span) (bahamut.AuthAction, []string, error) {

	if wg := a.pendingCache.Get(token); wg != nil {
		wg.(*sync.WaitGroup).Wait()
	}

	if i := a.cache.Get(token); i != nil {
		span.LogEvent("Authenticated from cache")
		return bahamut.AuthActionContinue, i.([]string), nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	a.pendingCache.Set(token, &wg)
	defer func() {
		wg.Done()
		a.pendingCache.Del(token)
	}()

	identity, err := a.midgardClient.AuthentifyWithTracking(token, span)
	if err != nil {
		return bahamut.AuthActionContinue, nil, err
	}

	a.cache.SetWithExpiration(token, identity, a.cacheValidity)

	span.LogEvent("Authenticated from Midgard")
	return bahamut.AuthActionContinue, identity, nil
}

// RateLimit is the implementation of the bahamut.RateLimiter interface.
func (a *MidgardAuthenticator) RateLimit(req *http.Request) (bool, error) {

	if a.rateLimiter == nil {
		return false, nil
	}

	// If it's not empty and it is cached, we don't rate limit
	if token := tokenFromRequest(req); token != "" && a.cache.Exists(token) {
		return false, nil
	}

	return a.rateLimiter.RateLimit(req)
}
