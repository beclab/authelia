package handlers

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
)

func handleAuthzGetObjectLegacy(ctx *middlewares.AutheliaCtx) (object authorization.Object, err error) {
	var (
		targetURL *url.URL
		method    []byte
	)

	if targetURL, err = ctx.GetXOriginalURLOrXForwardedURL(); err != nil {
		return object, fmt.Errorf("failed to get target URL: %w", err)
	}

	if method = ctx.XForwardedMethod(); len(method) == 0 {
		method = ctx.Method()
	}

	if hasInvalidMethodCharacters(method) {
		return object, fmt.Errorf("header 'X-Forwarded-Method' with value '%s' has invalid characters", method)
	}

	return authorization.NewObjectRaw(targetURL, method), nil
}

func handleAuthzUnauthorizedLegacy(ctx *middlewares.AutheliaCtx, authn *Authn, redirectionURL *url.URL) {
	var (
		statusCode int
	)

	if authn.Type == AuthnTypeAuthorization {
		handleAuthzUnauthorizedAuthorizationBasic(ctx, authn)

		return
	}

	switch {
	case ctx.IsXHR() || !ctx.AcceptsMIME("text/html") || redirectionURL == nil:
		statusCode = fasthttp.StatusUnauthorized
	default:
		switch authn.Object.Method {
		case fasthttp.MethodGet, fasthttp.MethodOptions, "":
			statusCode = fasthttp.StatusFound
		default:
			statusCode = fasthttp.StatusSeeOther
		}
	}

	if redirectionURL != nil {
		ctx.Logger.Infof("[legacy] Access to %s (method %s) is not authorized to user %s, responding with status code %d with location redirect to %s", authn.Object.URL.String(), authn.Method, authn.Username, statusCode, redirectionURL.String())

		mode := ctx.RequestCtx.Request.Header.PeekBytes(headerUnauthError)
		if len(mode) == 0 {
			mode = ctx.RequestCtx.Request.Header.Cookie(string(headerUnauthError))
		}

		switch string(mode) {
		case NonRedirectMode:
			ctx.Logger.Infof("[legacy] Access to %s (method %s) is not authorized to user %s, responding in non-redirect mode", authn.Object.URL.String(), authn.Method, authn.Username)
			ctx.ReplyUnauthorized()

			userSession, err := ctx.GetSession()

			// tell the client, it's unauthorized and need to 2fa verify or not.
			if err != nil {
				ctx.Logger.Error("Unable to retrieve user session, ", err)
			} else {
				data := map[string]interface{}{
					"fa2": userSession.AuthenticationLevel >= authentication.OneFactor,
				}

				jsonData, err := json.Marshal(data)

				if err != nil {
					ctx.Logger.Error("parse json error, ", err)
				} else {
					ctx.SetBody(jsonData)
				}
			}

		default:
			ctx.SpecialRedirect(redirectionURL.String(), statusCode)
		}
	} else {
		ctx.Logger.Infof("[legacy] Access to %s (method %s) is not authorized to user %s, responding with status code %d", authn.Object.URL.String(), authn.Method, authn.Username, statusCode)
		ctx.ReplyUnauthorized()
	}
}
