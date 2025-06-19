package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/utils"
)

// FirstFactorPOST is the handler performing the first factory.
//
//nolint:gocyclo // TODO: Consider refactoring time permitting.
func FirstFactorPOST(delayFunc middlewares.TimingAttackDelayFunc) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var successful bool

		requestTime := time.Now()

		if delayFunc != nil {
			defer delayFunc(ctx, requestTime, &successful)
		}

		bodyJSON := bodyFirstFactorRequest{}

		if err := ctx.ParseBody(&bodyJSON); err != nil {
			ctx.Logger.Errorf(logFmtErrParseRequestBody, regulation.AuthType1FA, err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		if bannedUntil, err := ctx.Providers.Regulator.Regulate(ctx, bodyJSON.Username); err != nil {
			if errors.Is(err, regulation.ErrUserIsBanned) {
				_ = markAuthenticationAttempt(ctx, false, &bannedUntil, bodyJSON.Username, regulation.AuthType1FA, nil)

				ctx.SetStatusCode(http.StatusTooManyRequests)
				ctx.SetJSONError(authentication.ErrTooManyRetries.Error())

				return
			}

			ctx.Logger.Errorf(logFmtErrRegulationFail, regulation.AuthType1FA, bodyJSON.Username, err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		if bodyJSON.AcceptCookie != nil {
			ctx.SetUserValueBytes(authentication.AuthnAcceptCookeKey, bodyJSON.AcceptCookie)
		}

		ctxUser := ctx.UserValueBytes(authorization.TerminusUserHeader)
		if ctxUser == nil {
			ctx.Logger.Errorf("user not found in request ctx")
			respondUnauthorized(ctx, messageAuthenticationFailed)
			return
		}

		if string(ctxUser.([]byte)) != bodyJSON.Username {
			err := errors.New("login user mismatch")
			_ = markAuthenticationAttempt(ctx, false, nil, bodyJSON.Username, regulation.AuthType1FA, err)

			ctx.Logger.Errorf("login failed, %s, %s, %s", err.Error(), bodyJSON.Username, string(ctxUser.([]byte)))
			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		userPasswordOk, validRes, err := ctx.Providers.UserProvider.CheckUserPassword(bodyJSON.Username, bodyJSON.Password)
		if err != nil {
			_ = markAuthenticationAttempt(ctx, false, nil, bodyJSON.Username, regulation.AuthType1FA, err)

			switch err {
			case authentication.ErrInvalidUserPwd, authentication.ErrInvalidToken:
				ctx.SetStatusCode(http.StatusBadRequest)
				ctx.SetJSONError(err.Error())
			case authentication.ErrTooManyRetries:
				ctx.SetStatusCode(http.StatusTooManyRequests)
				ctx.SetJSONError(err.Error())
			default:
				respondUnauthorized(ctx, messageAuthenticationFailed)
			}

			return
		}

		if !userPasswordOk {
			_ = markAuthenticationAttempt(ctx, false, nil, bodyJSON.Username, regulation.AuthType1FA, nil)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		if err = markAuthenticationAttempt(ctx, true, nil, bodyJSON.Username, regulation.AuthType1FA, nil); err != nil {
			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		// get first factor login target domain.
		if bodyJSON.TargetURL != "" {
			targetUrl, err := url.Parse(bodyJSON.TargetURL)

			if err != nil {
				ctx.Logger.Errorf("request target url error, %s", err)

				respondUnauthorized(ctx, messageAuthenticationFailed)

				return
			}

			ctx.RequestTargetDomain = targetUrl.Host
		}

		// TODO: write tests.
		provider, err := ctx.GetSessionProvider()
		if err != nil {
			ctx.Logger.Errorf("%s", err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		userSession := provider.NewDefaultUserSession()
		userSession.AccessToken = validRes.AccessToken

		// Reset all values from previous session except OIDC workflow before regenerating the cookie.
		if err = ctx.SaveSession(userSession); err != nil {
			ctx.Logger.Errorf(logFmtErrSessionReset, regulation.AuthType1FA, bodyJSON.Username, err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		if err = ctx.RegenerateSession(); err != nil {
			ctx.Logger.Errorf(logFmtErrSessionRegenerate, regulation.AuthType1FA, bodyJSON.Username, err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		// Check if bodyJSON.KeepMeLoggedIn can be deref'd and derive the value based on the configuration and JSON data.
		keepMeLoggedIn := !provider.GetConfig().DisableRememberMe && bodyJSON.KeepMeLoggedIn != nil && *bodyJSON.KeepMeLoggedIn

		// Set the cookie to expire if remember me is enabled and the user has asked us to.
		if keepMeLoggedIn {
			err = provider.UpdateExpiration(ctx.RequestCtx, provider.GetConfig().RememberMe)
			if err != nil {
				ctx.Logger.Errorf(logFmtErrSessionSave, "updated expiration", regulation.AuthType1FA, bodyJSON.Username, err)

				respondUnauthorized(ctx, messageAuthenticationFailed)

				return
			}
		}

		// Get the details of the given user from the user provider.
		userDetails, err := ctx.Providers.UserProvider.GetDetails(bodyJSON.Username, validRes.AccessToken)
		if err != nil {
			ctx.Logger.Errorf(logFmtErrObtainProfileDetails, regulation.AuthType1FA, bodyJSON.Username, err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		ctx.Logger.Tracef(logFmtTraceProfileDetails, bodyJSON.Username, userDetails.Groups, userDetails.Emails)

		userSession.SetOneFactor(ctx.Clock.Now(), userDetails, keepMeLoggedIn)

		if refresh, refreshInterval := getProfileRefreshSettings(ctx.Configuration.AuthenticationBackend); refresh {
			userSession.RefreshTTL = ctx.Clock.Now().Add(refreshInterval)
		}

		if validRes != nil {
			userSession.AccessToken = validRes.AccessToken
			userSession.RefreshToken = validRes.RefreshToken
			ctx.AccessToken = validRes.AccessToken
			provider.SetTargetDomain(ctx.RequestTargetDomain)
			ctx.Providers.SessionProvider.SetByToken(validRes.AccessToken, provider)
		}

		if err = ctx.SaveSession(userSession); err != nil {
			ctx.Logger.Errorf(logFmtErrSessionSave, "updated profile", regulation.AuthType1FA, bodyJSON.Username, err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		successful = true

		if bodyJSON.Workflow == workflowOpenIDConnect {
			handleOIDCWorkflowResponse(ctx, bodyJSON.TargetURL, bodyJSON.WorkflowID)
		} else {
			cookie := true
			if bodyJSON.AcceptCookie != nil {
				cookie = *bodyJSON.AcceptCookie
			}
			requestTermiPass := false
			if bodyJSON.RequestTermiPass != nil {
				requestTermiPass = *bodyJSON.RequestTermiPass
			}
			Handle1FAResponse(ctx, bodyJSON.TargetURL, bodyJSON.RequestMethod, &userSession, cookie, requestTermiPass)
		}
	}
}

func getProfileRefreshSettings(cfg schema.AuthenticationBackend) (refresh bool, refreshInterval time.Duration) {
	if cfg.LDAP != nil {
		if cfg.RefreshInterval == schema.ProfileRefreshDisabled {
			refresh = false
			refreshInterval = 0
		} else {
			refresh = true

			if cfg.RefreshInterval != schema.ProfileRefreshAlways {
				refreshInterval, _ = utils.ParseDurationString(cfg.RefreshInterval)
			} else {
				refreshInterval = schema.RefreshIntervalAlways
			}
		}
	}

	return refresh, refreshInterval
}
