package middlewares

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/utils"
)

// NewRequestLogger create a new request logger for the given request.
func NewRequestLogger(ctx *AutheliaCtx) *logrus.Entry {
	return logging.Logger().WithFields(logrus.Fields{
		"method":    string(ctx.Method()),
		"path":      string(ctx.Path()),
		"remote_ip": ctx.RemoteIP().String(),
	})
}

// NewAutheliaCtx instantiate an AutheliaCtx out of a RequestCtx.
func NewAutheliaCtx(requestCTX *fasthttp.RequestCtx, configuration schema.Configuration, providers Providers) (ctx *AutheliaCtx) {
	ctx = new(AutheliaCtx)
	ctx.RequestCtx = requestCTX
	ctx.Providers = providers
	ctx.Configuration = configuration
	ctx.Logger = NewRequestLogger(ctx)
	ctx.Clock = utils.RealClock{}

	return ctx
}

// AvailableSecondFactorMethods returns the available 2FA methods.
func (ctx *AutheliaCtx) AvailableSecondFactorMethods() (methods []string) {
	methods = make([]string, 0, 4)

	if !ctx.Configuration.TOTP.Disable {
		methods = append(methods, model.SecondFactorMethodTOTP)
	}

	if !ctx.Configuration.Webauthn.Disable {
		methods = append(methods, model.SecondFactorMethodWebauthn)
	}

	if !ctx.Configuration.DuoAPI.Disable {
		methods = append(methods, model.SecondFactorMethodDuo)
	}

	if !ctx.Configuration.TerminusPass.Disable {
		methods = append(methods, model.SecondFactorMethodTerminusPass)
	}

	return methods
}

// Error reply with an error and display the stack trace in the logs.
func (ctx *AutheliaCtx) Error(err error, message string) {
	ctx.SetJSONError(message)

	ctx.Logger.Error(err)
}

// SetJSONError sets the body of the response to an JSON error KO message.
func (ctx *AutheliaCtx) SetJSONError(message string) {
	if replyErr := ctx.ReplyJSON(ErrorResponse{Status: "KO", Message: message}, 0); replyErr != nil {
		ctx.Logger.Error(replyErr)
	}
}

// ReplyError reply with an error but does not display any stack trace in the logs.
func (ctx *AutheliaCtx) ReplyError(err error, message string) {
	b, marshalErr := json.Marshal(ErrorResponse{Status: "KO", Message: message})

	if marshalErr != nil {
		ctx.Logger.Error(marshalErr)
	}

	ctx.SetContentTypeApplicationJSON()
	ctx.SetBody(b)
	ctx.Logger.Debug(err)
}

// ReplyStatusCode resets a response and replies with the given status code and relevant message.
func (ctx *AutheliaCtx) ReplyStatusCode(statusCode int) {
	ctx.Response.Reset()
	ctx.SetStatusCode(statusCode)
	ctx.SetContentTypeTextPlain()
	ctx.SetBodyString(fmt.Sprintf("%d %s", statusCode, fasthttp.StatusMessage(statusCode)))
}

// ReplyJSON writes a JSON response.
func (ctx *AutheliaCtx) ReplyJSON(data any, statusCode int) (err error) {
	var (
		body []byte
	)

	if body, err = json.Marshal(data); err != nil {
		return fmt.Errorf("unable to marshal JSON body: %w", err)
	}

	if statusCode > 0 {
		ctx.SetStatusCode(statusCode)
	}

	ctx.SetContentTypeApplicationJSON()
	ctx.SetBody(body)

	return nil
}

// ReplyUnauthorized response sent when user is unauthorized.
func (ctx *AutheliaCtx) ReplyUnauthorized() {
	ctx.ReplyStatusCode(fasthttp.StatusUnauthorized)
}

// ReplyForbidden response sent when access is forbidden to user.
func (ctx *AutheliaCtx) ReplyForbidden() {
	ctx.ReplyStatusCode(fasthttp.StatusForbidden)
}

// ReplyBadRequest response sent when bad request has been sent.
func (ctx *AutheliaCtx) ReplyBadRequest() {
	ctx.ReplyStatusCode(fasthttp.StatusBadRequest)
}

// XForwardedMethod returns the content of the X-Forwarded-Method header.
func (ctx *AutheliaCtx) XForwardedMethod() (method []byte) {
	return ctx.Request.Header.PeekBytes(headerXForwardedMethod)
}

// XForwardedProto returns the content of the X-Forwarded-Proto header.
func (ctx *AutheliaCtx) XForwardedProto() (proto []byte) {
	proto = ctx.Request.Header.PeekBytes(headerXForwardedProto)

	if proto == nil {
		scheme := ctx.Request.Header.PeekBytes(headerXForwardedScheme)
		if scheme != nil {
			return scheme
		}

		if ctx.IsTLS() {
			return protoHTTPS
		}

		return protoHTTP
	}

	return proto
}

// XForwardedHost returns the content of the X-Forwarded-Host header.
func (ctx *AutheliaCtx) XForwardedHost() (host []byte) {
	return ctx.Request.Header.PeekBytes(headerXForwardedHost)
}

// GetXForwardedHost returns the content of the X-Forwarded-Host header falling back to the Host header.
func (ctx *AutheliaCtx) GetXForwardedHost() (host []byte) {
	host = ctx.XForwardedHost()

	if host == nil {
		return ctx.RequestCtx.Host()
	}

	return host
}

// XForwardedURI returns the content of the X-Forwarded-Uri header.
func (ctx *AutheliaCtx) XForwardedURI() (host []byte) {
	return ctx.Request.Header.PeekBytes(headerXForwardedURI)
}

// GetXForwardedURI returns the content of the X-Forwarded-URI header, falling back to the start-line request path.
func (ctx *AutheliaCtx) GetXForwardedURI() (uri []byte) {
	uri = ctx.XForwardedURI()

	if len(uri) == 0 {
		return ctx.RequestURI()
	}

	return uri
}

// XOriginalMethod returns the content of the X-Original-Method header.
func (ctx *AutheliaCtx) XOriginalMethod() []byte {
	return ctx.Request.Header.PeekBytes(headerXOriginalMethod)
}

// XOriginalURL returns the content of the X-Original-URL header.
func (ctx *AutheliaCtx) XOriginalURL() []byte {
	return ctx.Request.Header.PeekBytes(headerXOriginalURL)
}

// XAutheliaURL returns the content of the X-Authelia-URL header which is used to communicate the location of the
// portal when using proxies like Envoy.
func (ctx *AutheliaCtx) XAutheliaURL() []byte {
	return ctx.Request.Header.PeekBytes(headerXAutheliaURL)
}

// QueryArgRedirect returns the content of the 'rd' query argument.
func (ctx *AutheliaCtx) QueryArgRedirect() []byte {
	return ctx.QueryArgs().PeekBytes(qryArgRedirect)
}

// QueryArgAutheliaURL returns the content of the 'authelia_url' query argument.
func (ctx *AutheliaCtx) QueryArgAutheliaURL() []byte {
	return ctx.QueryArgs().PeekBytes(qryArgAutheliaURL)
}

// AuthzPath returns the 'authz_path' value.
func (ctx *AutheliaCtx) AuthzPath() (uri []byte) {
	if uv := ctx.UserValueBytes(keyUserValueAuthzPath); uv != nil {
		return []byte(uv.(string))
	}

	return nil
}

// BasePath returns the base_url as per the path visited by the client.
func (ctx *AutheliaCtx) BasePath() string {
	if baseURL := ctx.UserValueBytes(keyUserValueBaseURL); baseURL != nil {
		return baseURL.(string)
	}

	return ""
}

// BasePathSlash is the same as BasePath but returns a final slash as well.
func (ctx *AutheliaCtx) BasePathSlash() string {
	if baseURL := ctx.UserValueBytes(keyUserValueBaseURL); baseURL != nil {
		return baseURL.(string) + strSlash
	}

	return strSlash
}

// RootURL returns the Root URL.
func (ctx *AutheliaCtx) RootURL() (issuerURL *url.URL) {
	return &url.URL{
		Scheme: string(ctx.XForwardedProto()),
		Host:   string(ctx.GetXForwardedHost()),
		Path:   ctx.BasePath(),
	}
}

// RootURLSlash is the same as RootURL but includes a final slash as well.
func (ctx *AutheliaCtx) RootURLSlash() (issuerURL *url.URL) {
	return &url.URL{
		Scheme: string(ctx.XForwardedProto()),
		Host:   string(ctx.GetXForwardedHost()),
		Path:   ctx.BasePathSlash(),
	}
}

// GetTargetURICookieDomain returns the session provider for the targetURI domain.
func (ctx *AutheliaCtx) GetTargetURICookieDomain(targetURI *url.URL) string {
	if targetURI == nil {
		return ""
	}

	hostname := targetURI.Hostname()

	// find the domain from the request URI.
	// subdomain is in priority, then domain, then root domain.
	lowestSubdomainLevel := 0
	foundDomain := ""
	for _, domain := range ctx.Configuration.Session.Cookies {
		ctx.Logger.Debug("cookie config domain: ", domain.Domain, " match suffix with, ", hostname)

		if utils.HasDomainSuffix(hostname, domain.Domain) {
			level := len(strings.Split(domain.Domain, "."))
			if level > lowestSubdomainLevel &&
				(foundDomain == "" || utils.HasDomainSuffix(domain.Domain, foundDomain)) { // found domain is a parent domain of the current domain
				lowestSubdomainLevel = level
				foundDomain = domain.Domain
			}
		}
	}

	return foundDomain
}

// IsSafeRedirectionTargetURI returns true if the targetURI is within the scope of a cookie domain and secure.
func (ctx *AutheliaCtx) IsSafeRedirectionTargetURI(targetURI *url.URL) bool {
	if !utils.IsURISecure(targetURI) {
		return false
	}

	return ctx.GetTargetURICookieDomain(targetURI) != ""
}

// GetCookieDomain returns the cookie domain for the current request.
func (ctx *AutheliaCtx) GetCookieDomain() (domain string, err error) {
	var targetURI *url.URL

	if targetURI, err = ctx.GetXOriginalURLOrXForwardedURL(); err != nil {
		return "", fmt.Errorf("unable to retrieve cookie domain: %s", err)
	}

	return ctx.GetTargetURICookieDomain(targetURI), nil
}

// GetSessionProviderByTargetURL returns the session provider for the Request's domain.
func (ctx *AutheliaCtx) GetSessionProviderByTargetURL(targetURL *url.URL) (provider session.SessionProvider, err error) {
	domain := ctx.GetTargetURICookieDomain(targetURL)

	if domain == "" && !ctx.BackendRequest {
		return nil, fmt.Errorf("unable to retrieve domain session: %v", targetURL)
	}

	token := ctx.AccessToken

	if token == "" {
		token = string(ctx.RequestCtx.Request.Header.PeekBytes(HeaderTerminusAuthorization))
	}

	return ctx.Providers.SessionProvider.Get(domain, ctx.RequestTargetDomain, token, ctx.BackendRequest)
}

// GetSessionProvider returns the session provider for the Request's domain.
func (ctx *AutheliaCtx) GetSessionProvider() (provider session.SessionProvider, err error) {
	if ctx.session == nil {
		var domain string

		if domain, err = ctx.GetCookieDomain(); err != nil {
			return nil, err
		}

		if ctx.session, err = ctx.GetCookieDomainSessionProvider(domain); err != nil {
			return nil, err
		}
	}

	return ctx.session, nil
}

// GetCookieDomainSessionProvider returns the session provider for the provided domain.
func (ctx *AutheliaCtx) GetCookieDomainSessionProvider(domain string) (provider session.SessionProvider, err error) {
	if domain == "" && !ctx.BackendRequest {
		return nil, fmt.Errorf("unable to retrieve domain session: %w", err)
	}

	token := ctx.AccessToken

	if token == "" {
		token = string(ctx.RequestCtx.Request.Header.PeekBytes(HeaderTerminusAuthorization))
	}

	return ctx.Providers.SessionProvider.Get(domain, ctx.RequestTargetDomain, token, ctx.BackendRequest)
}

// GetSession returns the user session provided the cookie provider could be discovered. It is recommended to get the
// provider itself if you also need to update or destroy sessions.
func (ctx *AutheliaCtx) GetSession() (userSession session.UserSession, err error) {
	var provider session.SessionProvider

	if provider, err = ctx.GetSessionProvider(); err != nil {
		return userSession, err
	}

	if userSession, err = provider.GetSession(ctx.RequestCtx); err != nil {
		ctx.Logger.Error("Unable to retrieve user session")
		return provider.NewDefaultUserSession(), nil
	}

	if userSession.CookieDomain != provider.GetConfig().Domain {
		ctx.Logger.Warnf("Destroying session cookie as the cookie domain '%s' does not match the requests detected cookie domain '%s' which may be a sign a user tried to move this cookie from one domain to another", userSession.CookieDomain, provider.GetConfig().Domain)

		if err = provider.DestroySession(ctx.RequestCtx); err != nil {
			ctx.Logger.WithError(err).Error("Error occurred trying to destroy the session cookie")
		}

		userSession = provider.NewDefaultUserSession()
	}

	return userSession, nil
}

// SaveSession saves the content of the session.
func (ctx *AutheliaCtx) SaveSession(userSession session.UserSession) error {
	provider, err := ctx.GetSessionProvider()
	if err != nil {
		return fmt.Errorf("unable to save user session: %s", err)
	}

	err = provider.SaveSession(ctx.RequestCtx, userSession)
	if err != nil {
		return err
	}

	return nil
}

// RegenerateSession regenerates a user session.
func (ctx *AutheliaCtx) RegenerateSession() error {
	provider, err := ctx.GetSessionProvider()
	if err != nil {
		return fmt.Errorf("unable to regenerate user session: %s", err)
	}

	return provider.RegenerateSession(ctx.RequestCtx)
}

// DestroySession destroys a user session.
func (ctx *AutheliaCtx) DestroySession() error {
	provider, err := ctx.GetSessionProvider()
	if err != nil {
		return fmt.Errorf("unable to destroy user session: %s", err)
	}

	session, err := ctx.GetSession()
	if err != nil {
		return fmt.Errorf("unable to destroy user session: %s", err)
	}

	if session.AccessToken != "" {
		switch p := ctx.Providers.UserProvider.(type) {
		case *authentication.KubesphereUserProvider:
			err = p.Logout(session.Username, session.AccessToken)
			if err != nil {
				ctx.Logger.Error("cannot logout from kubesphere, ", err)
			}
		default:
		}

		ctx.Logger.Infof("session destroyed, clear token, %s", session.AccessToken)

		provider.RemoveSessionID(session.AccessToken)
		ctx.Providers.SessionProvider.RevokeByToken(session.AccessToken)
	}

	return provider.DestroySession(ctx.RequestCtx)
}

// ReplyOK is a helper method to reply ok.
func (ctx *AutheliaCtx) ReplyOK() {
	ctx.SetContentTypeApplicationJSON()
	ctx.SetBody(okMessageBytes)
}

func (ctx *AutheliaCtx) ReplyCode0() {
	ctx.SetContentTypeApplicationJSON()
	ctx.SetBody(code0MessageBytes)
}

// ParseBody parse the request body into the type of value.
func (ctx *AutheliaCtx) ParseBody(value any) error {
	err := json.Unmarshal(ctx.PostBody(), &value)

	if err != nil {
		return fmt.Errorf("unable to parse body: %w", err)
	}

	valid, err := govalidator.ValidateStruct(value)

	if err != nil {
		return fmt.Errorf("unable to validate body: %w", err)
	}

	if !valid {
		return fmt.Errorf("body is not valid")
	}

	return nil
}

// SetContentTypeApplicationJSON sets the Content-Type header to 'application/json; charset=utf-8'.
func (ctx *AutheliaCtx) SetContentTypeApplicationJSON() {
	ctx.SetContentTypeBytes(contentTypeApplicationJSON)
}

// SetContentTypeTextPlain efficiently sets the Content-Type header to 'text/plain; charset=utf-8'.
func (ctx *AutheliaCtx) SetContentTypeTextPlain() {
	ctx.SetContentTypeBytes(contentTypeTextPlain)
}

// SetContentTypeTextHTML efficiently sets the Content-Type header to 'text/html; charset=utf-8'.
func (ctx *AutheliaCtx) SetContentTypeTextHTML() {
	ctx.SetContentTypeBytes(contentTypeTextHTML)
}

// SetContentTypeApplicationYAML efficiently sets the Content-Type header to 'application/yaml; charset=utf-8'.
func (ctx *AutheliaCtx) SetContentTypeApplicationYAML() {
	ctx.SetContentTypeBytes(contentTypeApplicationYAML)
}

// SetContentSecurityPolicy sets the Content-Security-Policy header.
func (ctx *AutheliaCtx) SetContentSecurityPolicy(value string) {
	ctx.Response.Header.SetBytesK(headerContentSecurityPolicy, value)
}

// SetContentSecurityPolicyBytes sets the Content-Security-Policy header.
func (ctx *AutheliaCtx) SetContentSecurityPolicyBytes(value []byte) {
	ctx.Response.Header.SetBytesKV(headerContentSecurityPolicy, value)
}

// SetJSONBody Set json body.
func (ctx *AutheliaCtx) SetJSONBody(value any) error {
	return ctx.ReplyJSON(OKResponse{Status: "OK", Data: value}, 0)
}

// RemoteIP return the remote IP taking X-Forwarded-For header into account if provided.
func (ctx *AutheliaCtx) RemoteIP() net.IP {
	XForwardedFor := ctx.Request.Header.PeekBytes(headerXForwardedFor)
	if XForwardedFor != nil {
		ips := strings.Split(string(XForwardedFor), ",")

		if len(ips) > 0 {
			return net.ParseIP(strings.Trim(ips[0], " "))
		}
	}

	return ctx.RequestCtx.RemoteIP()
}

func (ctx *AutheliaCtx) GetXForwardedFor() []string {
	XForwardedFor := ctx.Request.Header.PeekBytes(headerXForwardedFor)
	if XForwardedFor != nil {
		return strings.Split(string(XForwardedFor), ",")
	}

	return nil
}

// GetXForwardedURL returns the parsed X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-URI request header as a
// *url.URL.
func (ctx *AutheliaCtx) GetXForwardedURL() (requestURI *url.URL, err error) {
	forwardedProto, forwardedHost, forwardedURI := ctx.XForwardedProto(), ctx.GetXForwardedHost(), ctx.GetXForwardedURI()

	if forwardedProto == nil {
		return nil, ErrMissingXForwardedProto
	}

	if forwardedHost == nil {
		return nil, ErrMissingXForwardedHost
	}

	value := utils.BytesJoin(forwardedProto, protoHostSeparator, forwardedHost, forwardedURI)

	if requestURI, err = url.ParseRequestURI(string(value)); err != nil {
		return nil, fmt.Errorf("failed to parse X-Forwarded Headers: %w", err)
	}

	return requestURI, nil
}

// GetXOriginalURL returns the parsed X-OriginalURL request header as a *url.URL.
func (ctx *AutheliaCtx) GetXOriginalURL() (requestURI *url.URL, err error) {
	value := ctx.XOriginalURL()

	if value == nil {
		return nil, ErrMissingXOriginalURL
	}

	if requestURI, err = url.ParseRequestURI(string(value)); err != nil {
		return nil, fmt.Errorf("failed to parse X-Original-URL header: %w", err)
	}

	return requestURI, nil
}

// GetXOriginalURLOrXForwardedURL returns the parsed X-Original-URL request header if it's available or the parsed
// X-Forwarded request headers if not.
func (ctx *AutheliaCtx) GetXOriginalURLOrXForwardedURL() (requestURI *url.URL, err error) {
	requestURI, err = ctx.GetXOriginalURL()

	switch {
	case err == nil:
		return requestURI, nil
	case errors.Is(err, ErrMissingXOriginalURL):
		return ctx.GetXForwardedURL()
	default:
		return requestURI, err
	}
}

// IssuerURL returns the expected Issuer.
func (ctx *AutheliaCtx) IssuerURL() (issuerURL *url.URL, err error) {
	issuerURL = &url.URL{
		Scheme: strProtoHTTPS,
	}

	if scheme := ctx.XForwardedProto(); scheme != nil {
		issuerURL.Scheme = string(scheme)
	}

	if host := ctx.GetXForwardedHost(); len(host) != 0 {
		issuerURL.Host = string(host)
	} else {
		return nil, ErrMissingXForwardedHost
	}

	if base := ctx.BasePath(); base != "" {
		issuerURL.Path = path.Join(issuerURL.Path, base)
	}

	return issuerURL, nil
}

// IsXHR returns true if the request is a XMLHttpRequest.
func (ctx *AutheliaCtx) IsXHR() (xhr bool) {
	if requestedWith := ctx.Request.Header.PeekBytes(headerXRequestedWith); requestedWith != nil && strings.EqualFold(string(requestedWith), headerValueXRequestedWithXHR) {
		return true
	}

	return false
}

// AcceptsMIME takes a mime type and returns true if the request accepts that type or the wildcard type.
func (ctx *AutheliaCtx) AcceptsMIME(mime string) (acceptsMime bool) {
	accepts := strings.Split(string(ctx.Request.Header.PeekBytes(headerAccept)), ",")

	for _, accept := range accepts {
		mimeType := strings.Trim(strings.SplitN(accept, ";", 2)[0], " ")
		if mimeType == mime || mimeType == "*/*" {
			return true
		}
	}

	return false
}

// SpecialRedirect performs a redirect similar to fasthttp.RequestCtx except it allows statusCode 401 and includes body
// content in the form of a link to the location.
func (ctx *AutheliaCtx) SpecialRedirect(uri string, statusCode int) {
	if statusCode < fasthttp.StatusMovedPermanently ||
		(statusCode > fasthttp.StatusSeeOther &&
			statusCode != fasthttp.StatusTemporaryRedirect &&
			statusCode != fasthttp.StatusPermanentRedirect &&
			statusCode != fasthttp.StatusUnauthorized &&
			statusCode != fasthttp.StatusBadRequest) {
		statusCode = fasthttp.StatusFound
	}

	ctx.SetContentTypeTextHTML()
	ctx.SetStatusCode(statusCode)

	u := fasthttp.AcquireURI()

	ctx.URI().CopyTo(u)
	u.Update(uri)

	ctx.Response.Header.SetBytesKV(headerLocation, u.FullURI())

	ctx.SetBodyString(fmt.Sprintf("<a href=\"%s\">%d %s</a>", utils.StringHTMLEscape(string(u.FullURI())), statusCode, fasthttp.StatusMessage(statusCode)))

	fasthttp.ReleaseURI(u)
}

// RecordAuthn records authentication metrics.
func (ctx *AutheliaCtx) RecordAuthn(success, regulated bool, method string) {
	if ctx.Providers.Metrics == nil {
		return
	}

	ctx.Providers.Metrics.RecordAuthn(success, regulated, method)
}
