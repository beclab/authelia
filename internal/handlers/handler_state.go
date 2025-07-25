package handlers

import (
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"k8s.io/klog/v2"
)

// StateGET is the handler serving the user state.
func StateGET(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession
		provider    session.SessionProvider
		err         error
	)

	if provider, err = ctx.GetSessionProvider(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		ctx.ReplyForbidden()

		return
	}

	klog.Info("StateGET: Searching user session from provider")
	if userSession, err = provider.SearchSession(ctx.RequestCtx); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		ctx.ReplyForbidden()

		return
	}

	stateResponse := StateResponse{
		Username:              userSession.Username,
		AuthenticationLevel:   userSession.AuthenticationLevel,
		DefaultRedirectionURL: ctx.Configuration.DefaultRedirectionURL,
	}

	if err = ctx.SetJSONBody(stateResponse); err != nil {
		ctx.Logger.Errorf("Unable to set state response in body: %s", err)
	} else {
		token := ctx.RequestCtx.Request.Header.Cookie(session.AUTH_TOKEN)
		klog.Info("StateGET: Setting access token to cookie if it has changed")
		if string(token) != userSession.AccessToken {
			setTokenToCookie(ctx, &AccessTokenCookieInfo{
				AccessToken: userSession.AccessToken,
				Username:    userSession.Username,
			})
		}
	}
}
