package handlers

import (
	"fmt"
	"net/url"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
)

// Handler is the middlewares.RequestHandler for Authz.
func (authz *Authz) Handler(ctx *middlewares.AutheliaCtx) {
	var (
		object      authorization.Object
		autheliaURL *url.URL
		provider    *session.Session
		err         error
	)

	ctx.Logger.Debug("******************* start to auth ******************")

	if isValidBackendRequest(ctx) {
		ctx.Logger.Debug("backend provider request, pass through")

		ctx.ReplyStatusCode(fasthttp.StatusOK)

		return
	}

	if object, err = authz.handleGetObject(ctx); err != nil {
		ctx.Logger.Errorf("Error getting original request object: %v", err)

		ctx.ReplyUnauthorized()

		return
	}

	// if !utils.IsURISecure(object.URL) {
	// 	ctx.Logger.Errorf("Target URL '%s' has an insecure scheme '%s', only the 'https' and 'wss' schemes are supported so session cookies can be transmitted securely", object.URL.String(), object.URL.Scheme)

	// 	ctx.ReplyUnauthorized()

	// 	return
	// }.

	if provider, err = ctx.GetSessionProviderByTargetURL(object.URL); err != nil {
		ctx.Logger.WithError(err).Errorf("Target URL '%s' does not appear to be configured as a session domain", object.URL.String())

		ctx.ReplyUnauthorized()

		return
	}

	if autheliaURL, err = authz.getAutheliaURL(ctx, provider); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred trying to determine the URL of the portal")

		ctx.ReplyUnauthorized()

		return
	}

	var (
		authn    Authn
		strategy AuthnStrategy
	)

	if authn, strategy, err = authz.authn(ctx, provider); err != nil {
		authn.Object = object

		ctx.Logger.WithError(err).Error("Error occurred while attempting to authenticate a request")

		switch strategy {
		case nil:
			ctx.ReplyUnauthorized()
		default:
			strategy.HandleUnauthorized(ctx, &authn, authz.getRedirectionURL(&object, autheliaURL))
		}

		return
	}

	authn.Object = object
	authn.Method = friendlyMethod(authn.Object.Method)

	username := authn.Details.Username
	if username == "" {
		username = string(ctx.RequestCtx.UserValueBytes(authorization.TerminusUserHeader).([]byte))
	}

	ruleHasSubject, required, rule := ctx.Providers.Authorizer.GetRequiredLevel(
		authorization.Subject{
			Username: username,
			Groups:   authn.Details.Groups,
			IP:       ctx.RemoteIP(),
		},
		object,
	)

	result := isAuthzResult(authn.Level, required, ruleHasSubject)
	if authz.resultMutate != nil {
		if newResult, err := authz.resultMutate(ctx, result, &authn, required, rule); err != nil {
			ctx.Logger.Error("authz result mutating error, ", err)
		} else {
			result = newResult
		}
	}

	switch result {
	case AuthzResultForbidden:
		ctx.Logger.Infof("Access to '%s' is forbidden to user '%s'", object.URL.String(), authn.Username)
		ctx.ReplyForbidden()
	case AuthzResultUnauthorized:
		var handler HandlerAuthzUnauthorized

		if strategy != nil {
			handler = strategy.HandleUnauthorized
		} else {
			handler = authz.handleUnauthorized
		}

		handler(ctx, &authn, authz.getRedirectionURL(&object, autheliaURL))
	case AuthzResultAuthorized:
		authz.handleAuthorized(ctx, &authn)
	}
}

func (authz *Authz) getAutheliaURL(ctx *middlewares.AutheliaCtx, provider *session.Session) (autheliaURL *url.URL, err error) {
	if authz.handleGetAutheliaURL == nil {
		return nil, nil
	}

	switch au := ctx.Providers.Authorizer.(type) {
	case *authorization.TsAuthorizer:

		loginPortal := au.LoginPortal(ctx.RequestCtx)
		if loginPortal != "" {
			if portalURL, err := url.ParseRequestURI(loginPortal); err != nil {
				return nil, err
			} else {
				return portalURL, nil
			}
		}
	default:
	}

	if autheliaURL, err = authz.handleGetAutheliaURL(ctx); err != nil {
		return nil, err
	}

	if autheliaURL != nil || authz.legacy {
		return autheliaURL, nil
	}

	if provider.Config.AutheliaURL != nil {
		if authz.legacy {
			return nil, nil
		}

		return provider.Config.AutheliaURL, nil
	}

	return nil, fmt.Errorf("authelia url lookup failed")
}

func (authz *Authz) getRedirectionURL(object *authorization.Object, autheliaURL *url.URL) (redirectionURL *url.URL) {
	if autheliaURL == nil {
		return nil
	}

	redirectionURL, _ = url.ParseRequestURI(autheliaURL.String())

	qry := redirectionURL.Query()

	qry.Set(queryArgRD, object.URL.String())

	if object.Method != "" {
		qry.Set(queryArgRM, object.Method)
	}

	redirectionURL.RawQuery = qry.Encode()

	return redirectionURL
}

func (authz *Authz) authn(ctx *middlewares.AutheliaCtx, provider *session.Session) (authn Authn, strategy AuthnStrategy, err error) {
	for _, strategy = range authz.strategies {
		if authn, err = strategy.Get(ctx, provider); err != nil {
			if strategy.CanHandleUnauthorized() {
				return Authn{Type: authn.Type, Level: authentication.NotAuthenticated}, strategy, err
			}

			return Authn{Type: authn.Type, Level: authentication.NotAuthenticated}, nil, err
		}

		if authn.Level != authentication.NotAuthenticated {
			break
		}
	}

	if strategy.CanHandleUnauthorized() {
		return authn, strategy, err
	}

	return authn, nil, nil
}
