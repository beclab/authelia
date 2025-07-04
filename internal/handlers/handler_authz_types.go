package handlers

import (
	"net/url"
	"time"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
)

// Authz is a type which is a effectively is a middlewares.RequestHandler for authorization requests.
type Authz struct {
	config AuthzConfig

	strategies []AuthnStrategy

	handleGetObject HandlerAuthzGetObject

	handleGetAutheliaURL HandlerAuthzGetAutheliaURL

	handleAuthorized   HandlerAuthzAuthorized
	handleUnauthorized HandlerAuthzUnauthorized

	resultMutate AuthzResultMutate

	legacy bool
}

type AuthzResultMutate func(ctx *middlewares.AutheliaCtx, result AuthzResult, authn *Authn, required authorization.Level, rule *authorization.AccessControlRule) (AuthzResult, error)

// HandlerAuthzUnauthorized is a Authz handler func that handles unauthorized responses.
type HandlerAuthzUnauthorized func(ctx *middlewares.AutheliaCtx, authn *Authn, redirectionURL *url.URL)

// HandlerAuthzAuthorized is a Authz handler func that handles authorized responses.
type HandlerAuthzAuthorized func(ctx *middlewares.AutheliaCtx, authn *Authn)

// HandlerAuthzGetAutheliaURL is a Authz handler func that handles retrieval of the Portal URL.
type HandlerAuthzGetAutheliaURL func(ctx *middlewares.AutheliaCtx) (portalURL *url.URL, err error)

// HandlerAuthzGetRedirectionURL is a Authz handler func that handles retrieval of the Redirection URL.
type HandlerAuthzGetRedirectionURL func(ctx *middlewares.AutheliaCtx, object *authorization.Object) (redirectionURL *url.URL, err error)

// HandlerAuthzGetObject is a Authz handler func that handles retrieval of the authorization.Object to authorize.
type HandlerAuthzGetObject func(ctx *middlewares.AutheliaCtx) (object authorization.Object, err error)

// HandlerAuthzVerifyObject is a Authz handler func that handles authorization of the authorization.Object.
type HandlerAuthzVerifyObject func(ctx *middlewares.AutheliaCtx, object authorization.Object) (err error)

// AuthnType is an auth type.
type AuthnType int

const (
	// AuthnTypeNone is a nil Authentication AuthnType.
	AuthnTypeNone AuthnType = iota

	// AuthnTypeCookie is an Authentication AuthnType based on the Cookie header.
	AuthnTypeCookie

	// AuthnTypeProxyAuthorization is an Authentication AuthnType based on the Proxy-Authorization header.
	AuthnTypeProxyAuthorization

	// AuthnTypeAuthorization is an Authentication AuthnType based on the Authorization header.
	AuthnTypeAuthorization
)

// Authn is authentication.
type Authn struct {
	Username string
	Method   string

	Details authentication.UserDetails
	Level   authentication.Level
	Object  authorization.Object
	Type    AuthnType

	Token authentication.ValidResult
}

// AuthzConfig represents the configuration elements of the Authz type.
type AuthzConfig struct {
	RefreshInterval time.Duration
	Domains         []AuthzDomain
}

// AuthzDomain represents a domain for the AuthzConfig.
type AuthzDomain struct {
	Name      string
	PortalURL *url.URL
}

// AuthzBuilder is a builder pattern for the Authz type.
type AuthzBuilder struct {
	config           AuthzConfig
	impl             AuthzImplementation
	strategies       []AuthnStrategy
	resultMutateFunc AuthzResultMutate
}

// AuthnStrategy is a strategy used for Authz authentication.
type AuthnStrategy interface {
	Get(ctx *middlewares.AutheliaCtx, provider session.SessionProvider) (authn Authn, err error)
	CanHandleUnauthorized() (handle bool)
	HandleUnauthorized(ctx *middlewares.AutheliaCtx, authn *Authn, redirectionURL *url.URL)
}

// AuthzResult is a result for Authz response handling determination.
type AuthzResult int

const (
	// AuthzResultForbidden means the user is forbidden the access to a resource.
	AuthzResultForbidden AuthzResult = iota

	// AuthzResultUnauthorized means the user can access the resource with more permissions.
	AuthzResultUnauthorized

	// AuthzResultAuthorized means the user is authorized given her current permissions.
	AuthzResultAuthorized
)

// AuthzImplementation represents an Authz implementation.
type AuthzImplementation int

// AuthnStrategy names.
const (
	AuthnStrategyCookieSession                       = "CookieSession"
	AuthnStrategyHeaderAuthorization                 = "HeaderAuthorization"
	AuthnStrategyHeaderProxyAuthorization            = "HeaderProxyAuthorization"
	AuthnStrategyHeaderAuthRequestProxyAuthorization = "HeaderAuthRequestProxyAuthorization"
	AuthnStrategyHeaderLegacy                        = "HeaderLegacy"
)

const (
	// AuthzImplLegacy is the legacy Authz implementation (VerifyGET).
	AuthzImplLegacy AuthzImplementation = iota

	// AuthzImplForwardAuth is the modern Forward Auth Authz implementation which is used by Caddy and Traefik.
	AuthzImplForwardAuth

	// AuthzImplAuthRequest is the modern Auth Request Authz implementation which is used by NGINX and modelled after
	// the ingress-nginx k8s ingress.
	AuthzImplAuthRequest

	// AuthzImplExtAuthz is the modern ExtAuthz Authz implementation which is used by Envoy.
	AuthzImplExtAuthz
)

// String returns the text representation of this AuthzImplementation.
func (i AuthzImplementation) String() string {
	switch i {
	case AuthzImplLegacy:
		return "Legacy"
	case AuthzImplForwardAuth:
		return "ForwardAuth"
	case AuthzImplAuthRequest:
		return "AuthRequest"
	case AuthzImplExtAuthz:
		return "ExtAuthz"
	default:
		return ""
	}
}
