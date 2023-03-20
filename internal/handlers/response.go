package handlers

import (
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session"
	sess "github.com/authelia/authelia/v4/internal/session"
)

type AccessTokenCookieInfo struct {
	AccessToken  string
	RefreshToken string
	Username     string
}

func setTokenToCookie(ctx *middlewares.AutheliaCtx, tokenInfo *AccessTokenCookieInfo) {
	if tokenInfo.AccessToken != "" {
		klog.Infof("set access token in cookie and header for user %s", tokenInfo.Username)

		cookie := &fasthttp.Cookie{}
		cookie.SetKey("auth_token")
		cookie.SetValue(tokenInfo.AccessToken)
		cookie.SetDomain(ctx.Providers.SessionProvider.Config.Domain)
		cookie.SetPath("/")
		cookie.SetMaxAge(int(ctx.Providers.SessionProvider.Config.Expiration))

		ctx.Response.Header.SetCookie(cookie)

		refreshCookie := &fasthttp.Cookie{}
		refreshCookie.CopyTo(cookie)
		refreshCookie.SetKey("auth_refresh_token")
		refreshCookie.SetValue(tokenInfo.RefreshToken)

		ctx.Response.Header.SetCookie(refreshCookie)

		ctx.Response.Header.SetBytesK(headerRemoteAccessToken, tokenInfo.AccessToken)
		ctx.Response.Header.SetBytesK(headerRemoteRefreshToken, tokenInfo.RefreshToken)
	}
}

// Handle1FAResponse handle the redirection upon 1FA authentication.
func Handle1FAResponse(ctx *middlewares.AutheliaCtx,
	targetURI, requestMethod string,
	session *session.UserSession) {
	var err error

	sessionId := getSessionId(ctx)

	require2FaResp := func(r *authorization.AccessControlRule, parsedURI *url.URL) {
		if r != nil {
			getRule := func(subject authorization.Subject, object authorization.Object) *authorization.AccessControlRule {
				return r
			}

			upsertResourceAuthLevelInSession(ctx, parsedURI, session, requestMethod, getRule, authentication.OneFactor)

			if err = ctx.SaveSession(*session); err != nil {
				ctx.Logger.Errorf(logFmtErrSessionSave, "updated profile", regulation.AuthType1FA, session.Username, err)

				respondUnauthorized(ctx, messageAuthenticationFailed)

				return
			}
		} // update rule.

		if err = ctx.SetJSONBody(redirectResponse{
			AccessToken:  session.AccessToken,
			RefreshToken: session.RefreshToken,
			FA2:          true,
			SessionID:    string(sessionId),
		}); err != nil {
			ctx.Logger.Errorf("Unable to set token in body: %s", err)

			ctx.ReplyError(err, "Unable to set token in body")
		}
	}

	redirectResp := func(targetURI string) {
		if err = ctx.SetJSONBody(redirectResponse{
			Redirect:     targetURI,
			AccessToken:  session.AccessToken,
			RefreshToken: session.RefreshToken,
			FA2:          false,
			SessionID:    string(sessionId),
		}); err != nil {
			ctx.Logger.Errorf("Unable to set redirection URL in body: %s", err)
		} else {
			setTokenToCookie(ctx, &AccessTokenCookieInfo{
				AccessToken:  session.AccessToken,
				RefreshToken: session.RefreshToken,
				Username:     session.Username,
			})
		}
	}

	defaultResp := func(r *authorization.AccessControlRule, parsedURI *url.URL) {
		if !ctx.Providers.Authorizer.IsSecondFactorEnabled() && ctx.Configuration.DefaultRedirectionURL != "" {
			redirectResp(ctx.Configuration.DefaultRedirectionURL)
		} else {
			require2FaResp(r, parsedURI)
		}
	}

	if len(targetURI) == 0 {
		defaultResp(nil, nil)
		return
	}

	var targetURL *url.URL

	if targetURL, err = url.ParseRequestURI(targetURI); err != nil {
		ctx.Error(fmt.Errorf("unable to parse target URL %s: %s", targetURI, err), messageAuthenticationFailed)

		return
	}

	_, requiredLevel, rule := ctx.Providers.Authorizer.GetRequiredLevel(
		authorization.Subject{
			Username: session.Username,
			Groups:   session.Groups,
			IP:       ctx.RemoteIP(),
		},
		authorization.NewObject(targetURL, requestMethod))

	ctx.Logger.Debugf("Required level for the URL %s is %d", targetURI, requiredLevel)

	if requiredLevel == authorization.TwoFactor {
		ctx.Logger.Warnf("%s requires 2FA, cannot be redirected yet", targetURI)

		require2FaResp(rule, targetURL)

		return
	}

	if !ctx.IsSafeRedirectionTargetURI(targetURL) {
		ctx.Logger.Debugf("Redirection URL %s is not safe", targetURI)

		defaultResp(rule, targetURL)

		return
	}

	ctx.Logger.Debugf("Redirection URL %s is safe", targetURI)
	redirectResp(targetURI)
}

func getSessionId(ctx *middlewares.AutheliaCtx) []byte {
	var sessionId []byte

	provider, err := ctx.GetSessionProvider()

	if err != nil {
		ctx.Logger.Errorf("unable to save user session: %s", err)
	} else {
		sessionId = ctx.RequestCtx.Request.Header.Cookie(provider.Config.Name)
		if len(sessionId) == 0 {
			sessionId = ctx.Request.Header.Peek(middlewares.DefaultSessionKeyName)
			if len(sessionId) == 0 {
				ctx.Logger.Error("Unable to retrieve user cookie")
			}
		}
	}

	return sessionId
}

// Handle2FAResponse handle the redirection upon 2FA authentication.
func Handle2FAResponse(ctx *middlewares.AutheliaCtx, targetURI string, session *session.UserSession) {
	var err error

	if len(targetURI) == 0 {
		if len(ctx.Configuration.DefaultRedirectionURL) == 0 {
			ctx.ReplyOK()

			return
		}

		if err = ctx.SetJSONBody(redirectResponse{Redirect: ctx.Configuration.DefaultRedirectionURL}); err != nil {
			ctx.Logger.Errorf("Unable to set default redirection URL in body: %s", err)
		} else {
			setTokenToCookie(ctx, &AccessTokenCookieInfo{
				AccessToken:  session.AccessToken,
				RefreshToken: session.RefreshToken,
				Username:     session.Username,
			})
		}

		return
	}

	var (
		parsedURI *url.URL
		safe      bool
	)

	if parsedURI, err = url.ParseRequestURI(targetURI); err != nil {
		ctx.Error(fmt.Errorf("unable to determine if URI '%s' is safe to redirect to: failed to parse URI '%s': %w", targetURI, targetURI, err), messageMFAValidationFailed)
		return
	}

	updateSession2FaLevel(ctx, parsedURI, session)

	safe = ctx.IsSafeRedirectionTargetURI(parsedURI)

	if safe {
		ctx.Logger.Debugf("Redirection URL %s is safe", targetURI)

		if err = ctx.SetJSONBody(redirectResponse{Redirect: targetURI}); err != nil {
			ctx.Logger.Errorf("Unable to set redirection URL in body: %s", err)
		} else {
			setTokenToCookie(ctx, &AccessTokenCookieInfo{
				AccessToken:  session.AccessToken,
				RefreshToken: session.RefreshToken,
				Username:     session.Username,
			})
		}

		return
	}

	ctx.ReplyOK()
}

// handleOIDCWorkflowResponse handle the redirection upon authentication in the OIDC workflow.
func handleOIDCWorkflowResponse(ctx *middlewares.AutheliaCtx, targetURI, workflowID string) {
	switch {
	case len(workflowID) != 0:
		handleOIDCWorkflowResponseWithID(ctx, workflowID)
	case len(targetURI) != 0:
		handleOIDCWorkflowResponseWithTargetURL(ctx, targetURI)
	default:
		ctx.Error(fmt.Errorf("invalid post data: must contain either a target url or a workflow id"), messageAuthenticationFailed)
	}
}

func handleOIDCWorkflowResponseWithTargetURL(ctx *middlewares.AutheliaCtx, targetURI string) {
	var (
		issuerURL *url.URL
		targetURL *url.URL
		err       error
	)

	if targetURL, err = url.ParseRequestURI(targetURI); err != nil {
		ctx.Error(fmt.Errorf("unable to parse target URL '%s': %w", targetURI, err), messageAuthenticationFailed)

		return
	}

	issuerURL = ctx.RootURL()

	if targetURL.Host != issuerURL.Host {
		ctx.Error(fmt.Errorf("unable to redirect to '%s': target host '%s' does not match expected issuer host '%s'", targetURL, targetURL.Host, issuerURL.Host), messageAuthenticationFailed)

		return
	}

	var userSession session.UserSession

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Error(fmt.Errorf("unable to redirect to '%s': failed to lookup session: %w", targetURL, err), messageAuthenticationFailed)

		return
	}

	if userSession.IsAnonymous() {
		ctx.Error(fmt.Errorf("unable to redirect to '%s': user is anonymous", targetURL), messageAuthenticationFailed)

		return
	}

	if err = ctx.SetJSONBody(redirectResponse{Redirect: targetURL.String()}); err != nil {
		ctx.Logger.Errorf("Unable to set default redirection URL in body: %s", err)
	}
}

func handleOIDCWorkflowResponseWithID(ctx *middlewares.AutheliaCtx, id string) {
	var (
		workflowID uuid.UUID
		client     *oidc.Client
		consent    *model.OAuth2ConsentSession
		err        error
	)

	if workflowID, err = uuid.Parse(id); err != nil {
		ctx.Error(fmt.Errorf("unable to parse consent session challenge id '%s': %w", id, err), messageAuthenticationFailed)

		return
	}

	if consent, err = ctx.Providers.StorageProvider.LoadOAuth2ConsentSessionByChallengeID(ctx, workflowID); err != nil {
		ctx.Error(fmt.Errorf("unable to load consent session by challenge id '%s': %w", id, err), messageAuthenticationFailed)

		return
	}

	if consent.Responded() {
		ctx.Error(fmt.Errorf("consent has already been responded to '%s': %w", id, err), messageAuthenticationFailed)

		return
	}

	if client, err = ctx.Providers.OpenIDConnect.GetFullClient(consent.ClientID); err != nil {
		ctx.Error(fmt.Errorf("unable to get client for client with id '%s' with consent challenge id '%s': %w", id, consent.ChallengeID, err), messageAuthenticationFailed)

		return
	}

	var userSession session.UserSession

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Error(fmt.Errorf("unable to redirect for authorization/consent for client with id '%s' with consent challenge id '%s': failed to lookup session: %w", client.ID, consent.ChallengeID, err), messageAuthenticationFailed)

		return
	}

	if userSession.IsAnonymous() {
		ctx.Error(fmt.Errorf("unable to redirect for authorization/consent for client with id '%s' with consent challenge id '%s': user is anonymous", client.ID, consent.ChallengeID), messageAuthenticationFailed)

		return
	}

	if !client.IsAuthenticationLevelSufficient(userSession.AuthenticationLevel) {
		ctx.Logger.Warnf("OpenID Connect client '%s' requires 2FA, cannot be redirected yet", client.ID)
		ctx.ReplyOK()

		return
	}

	var (
		targetURL *url.URL
		form      url.Values
	)

	targetURL = ctx.RootURL()

	if form, err = consent.GetForm(); err != nil {
		ctx.Error(fmt.Errorf("unable to get authorization form values from consent session with challenge id '%s': %w", consent.ChallengeID, err), messageAuthenticationFailed)

		return
	}

	form.Set(queryArgConsentID, workflowID.String())

	targetURL.Path = path.Join(targetURL.Path, oidc.EndpointPathAuthorization)
	targetURL.RawQuery = form.Encode()

	if err = ctx.SetJSONBody(redirectResponse{Redirect: targetURL.String()}); err != nil {
		ctx.Logger.Errorf("Unable to set default redirection URL in body: %s", err)
	}
}

func markAuthenticationAttempt(ctx *middlewares.AutheliaCtx, successful bool, bannedUntil *time.Time, username string, authType string, errAuth error) (err error) {
	// We only Mark if there was no underlying error.
	ctx.Logger.Debugf("Mark %s authentication attempt made by user '%s'", authType, username)

	var (
		requestURI, requestMethod string
	)

	referer := ctx.Request.Header.Referer()
	if referer != nil {
		refererURL, err := url.ParseRequestURI(string(referer))
		if err == nil {
			requestURI = refererURL.Query().Get(queryArgRD)
			requestMethod = refererURL.Query().Get(queryArgRM)
		}
	}

	if err = ctx.Providers.Regulator.Mark(ctx, successful, bannedUntil != nil, username, requestURI, requestMethod, authType); err != nil {
		ctx.Logger.Errorf("Unable to mark %s authentication attempt by user '%s': %+v", authType, username, err)

		return err
	}

	if successful {
		ctx.Logger.Debugf("Successful %s authentication attempt made by user '%s'", authType, username)
	} else {
		switch {
		case errAuth != nil:
			ctx.Logger.Errorf("Unsuccessful %s authentication attempt by user '%s': %+v", authType, username, errAuth)
		case bannedUntil != nil:
			ctx.Logger.Errorf("Unsuccessful %s authentication attempt by user '%s' and they are banned until %s", authType, username, bannedUntil)
		default:
			ctx.Logger.Errorf("Unsuccessful %s authentication attempt by user '%s'", authType, username)
		}
	}

	return nil
}

func respondUnauthorized(ctx *middlewares.AutheliaCtx, message string) {
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.SetJSONError(message)
}

// SetStatusCodeResponse writes a response status code and an appropriate body on either a
// *fasthttp.RequestCtx or *middlewares.AutheliaCtx.
func SetStatusCodeResponse(ctx *fasthttp.RequestCtx, statusCode int) {
	ctx.Response.Reset()

	middlewares.SetContentTypeTextPlain(ctx)

	ctx.SetStatusCode(statusCode)
	ctx.SetBodyString(fmt.Sprintf("%d %s", statusCode, fasthttp.StatusMessage(statusCode)))
}

// update resource auth level in session.
func updateSession2FaLevel(ctx *middlewares.AutheliaCtx, parsedURI *url.URL, session *session.UserSession) {
	getRule := func(subject authorization.Subject, object authorization.Object) *authorization.AccessControlRule {
		_, _, r := ctx.Providers.Authorizer.GetRequiredLevel(
			subject,
			object,
		)

		return r
	}

	upsertResourceAuthLevelInSession(ctx, parsedURI, session, "POST", getRule, authentication.TwoFactor)

	if err := ctx.SaveSession(*session); err != nil {
		ctx.Logger.Errorf(logFmtErrSessionSave, "updated profile", regulation.AuthType1FA, session.Username, err)
	}
}

func upsertResourceAuthLevelInSession(ctx *middlewares.AutheliaCtx, parsedURI *url.URL,
	session *session.UserSession,
	requestMethod string,
	getRule func(subject authorization.Subject, object authorization.Object) *authorization.AccessControlRule,
	level authentication.Level,
) {
	subject := authorization.Subject{
		Username: session.Username,
		Groups:   session.Groups,
		IP:       ctx.RemoteIP(),
	}
	object := authorization.NewObject(parsedURI, requestMethod)

	var rule *sess.ResourceAuthenticationLevel

	for i, r := range session.ResourceAuthenticationLevels {
		if r.Rule.IsMatch(subject, object) {
			ctx.Logger.Debug("find resource authed rule, ", r.Rule.Domains, r.Level, r.AuthTime)

			session.ResourceAuthenticationLevels[i].AuthTime = time.Now()
			session.ResourceAuthenticationLevels[i].Level = level

			rule = r
		}
	}

	if rule != nil {
		r := getRule(subject, object)

		if r != nil {
			ctx.Logger.Debugf("Get match rule for the URL %s", parsedURI.String())

			session.ResourceAuthenticationLevels = append(session.ResourceAuthenticationLevels,
				&sess.ResourceAuthenticationLevel{
					Rule:     r,
					Level:    level,
					AuthTime: time.Now(),
				},
			)
		} else {
			ctx.Logger.Error("Can not get url for the URL ", parsedURI.String(), " to update seesion")
		}
	}
}
