package server

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/templates"
)

// ServeTemplatedFile serves a templated version of a specified file,
// this is utilised to pass information between the backend and frontend
// and generate a nonce to support a restrictive CSP while using material-ui.
func ServeTemplatedFile(t templates.Template, opts *TemplatedFileOptions) middlewares.RequestHandler {
	isDevEnvironment := os.Getenv(environment) == dev
	ext := path.Ext(t.Name())

	return func(ctx *middlewares.AutheliaCtx) {
		var err error

		logoOverride := strFalse

		if opts.AssetPath != "" {
			if _, err = os.Stat(filepath.Join(opts.AssetPath, fileLogo)); err == nil {
				logoOverride = strTrue
			}
		}

		switch ext {
		case extHTML:
			ctx.SetContentTypeTextHTML()
		case extJSON:
			ctx.SetContentTypeApplicationJSON()
		default:
			ctx.SetContentTypeTextPlain()
		}

		nonce := ctx.Providers.Random.StringCustom(32, random.CharSetAlphaNumeric)

		switch {
		case ctx.Configuration.Server.Headers.CSPTemplate != "":
			ctx.Response.Header.Add(fasthttp.HeaderContentSecurityPolicy, strings.ReplaceAll(ctx.Configuration.Server.Headers.CSPTemplate, placeholderCSPNonce, nonce))
		case isDevEnvironment:
			ctx.Response.Header.Add(fasthttp.HeaderContentSecurityPolicy, fmt.Sprintf(tmplCSPDevelopment, nonce))
		default:
			ctx.Response.Header.Add(fasthttp.HeaderContentSecurityPolicy, fmt.Sprintf(tmplCSPDefault, nonce))
		}

		var (
			rememberMe string
			provider   session.SessionProvider
		)

		if provider, err = ctx.GetSessionProvider(); err == nil {
			rememberMe = strconv.FormatBool(!provider.GetConfig().DisableRememberMe)
		}

		data := &bytes.Buffer{}

		if err = t.Execute(data, opts.CommonData(ctx.BasePath(), ctx.RootURLSlash().String(), nonce, logoOverride, rememberMe)); err != nil {
			ctx.RequestCtx.Error("an error occurred", fasthttp.StatusServiceUnavailable)
			ctx.Logger.WithError(err).Errorf("Error occcurred rendering template")

			return
		}

		switch {
		case ctx.IsHead():
			ctx.Response.ResetBody()
			ctx.Response.SkipBody = true
			ctx.Response.Header.Set(fasthttp.HeaderContentLength, strconv.Itoa(data.Len()))
		default:
			if _, err = data.WriteTo(ctx.Response.BodyWriter()); err != nil {
				ctx.RequestCtx.Error("an error occurred", fasthttp.StatusServiceUnavailable)
				ctx.Logger.WithError(err).Errorf("Error occcurred writing body")

				return
			}
		}
	}
}

// ServeTemplatedOpenAPI serves templated OpenAPI related files.
func ServeTemplatedOpenAPI(t templates.Template, opts *TemplatedFileOptions) middlewares.RequestHandler {
	ext := path.Ext(t.Name())

	spec := ext == extYML

	return func(ctx *middlewares.AutheliaCtx) {
		var nonce string

		if spec {
			ctx.Response.Header.Add(fasthttp.HeaderContentSecurityPolicy, tmplCSPSwagger)
		} else {
			nonce = ctx.Providers.Random.StringCustom(32, random.CharSetAlphaNumeric)
			ctx.Response.Header.Add(fasthttp.HeaderContentSecurityPolicy, fmt.Sprintf(tmplCSPSwaggerNonce, nonce, nonce))
		}

		switch ext {
		case extHTML:
			ctx.SetContentTypeTextHTML()
		case extYML:
			ctx.SetContentTypeApplicationYAML()
		default:
			ctx.SetContentTypeTextPlain()
		}

		var err error

		data := &bytes.Buffer{}

		if err = t.Execute(data, opts.OpenAPIData(ctx.BasePath(), ctx.RootURLSlash().String(), nonce)); err != nil {
			ctx.RequestCtx.Error("an error occurred", fasthttp.StatusServiceUnavailable)
			ctx.Logger.WithError(err).Errorf("Error occcurred rendering template")

			return
		}

		switch {
		case ctx.IsHead():
			ctx.Response.ResetBody()
			ctx.Response.SkipBody = true
			ctx.Response.Header.Set(fasthttp.HeaderContentLength, strconv.Itoa(data.Len()))
		default:
			if _, err = data.WriteTo(ctx.Response.BodyWriter()); err != nil {
				ctx.RequestCtx.Error("an error occurred", fasthttp.StatusServiceUnavailable)
				ctx.Logger.WithError(err).Errorf("Error occcurred writing body")

				return
			}
		}
	}
}

// ETagRootURL dynamically matches the If-None-Match header and adds the ETag header.
func ETagRootURL(next middlewares.RequestHandler) middlewares.RequestHandler {
	etags := map[string][]byte{}

	h := sha1.New() //nolint:gosec // Usage is for collision avoidance not security.
	mu := &sync.Mutex{}

	return func(ctx *middlewares.AutheliaCtx) {
		k := ctx.RootURLSlash().String()

		mu.Lock()

		etag, ok := etags[k]

		mu.Unlock()

		if ok && bytes.Equal(etag, ctx.Request.Header.PeekBytes(headerIfNoneMatch)) {
			ctx.Response.Header.SetBytesKV(headerETag, etag)
			ctx.Response.Header.SetBytesKV(headerCacheControl, headerValueCacheControlETaggedAssets)

			ctx.SetStatusCode(fasthttp.StatusNotModified)

			return
		}

		next(ctx)

		if ctx.Response.SkipBody || ctx.Response.StatusCode() != fasthttp.StatusOK {
			// Skip generating the ETag as the response body should be empty.
			return
		}

		mu.Lock()

		h.Write(ctx.Response.Body())
		sum := h.Sum(nil)
		h.Reset()

		etagNew := make([]byte, hex.EncodedLen(len(sum)))

		hex.Encode(etagNew, sum)

		if !ok || !bytes.Equal(etag, etagNew) {
			etags[k] = etagNew
		}

		mu.Unlock()

		ctx.Response.Header.SetBytesKV(headerETag, etagNew)
		ctx.Response.Header.SetBytesKV(headerCacheControl, headerValueCacheControlETaggedAssets)
	}
}

func writeHealthCheckEnv(disabled bool, scheme, host, path string, port int) (err error) {
	if disabled {
		return nil
	}

	_, err = os.Stat("/app/healthcheck.sh")
	if err != nil {
		return nil
	}

	_, err = os.Stat("/app/.healthcheck.env")
	if err != nil {
		return nil
	}

	file, err := os.OpenFile("/app/.healthcheck.env", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	defer func() {
		_ = file.Close()
	}()

	if host == "0.0.0.0" {
		host = localhost
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	_, err = file.WriteString(fmt.Sprintf(healthCheckEnv, scheme, host, port, path))

	return err
}

// NewTemplatedFileOptions returns a new *TemplatedFileOptions.
func NewTemplatedFileOptions(config *schema.Configuration) (opts *TemplatedFileOptions) {
	opts = &TemplatedFileOptions{
		AssetPath:              config.Server.AssetPath,
		DuoSelfEnrollment:      strFalse,
		RememberMe:             strconv.FormatBool(!config.Session.DisableRememberMe),
		ResetPassword:          strconv.FormatBool(!config.AuthenticationBackend.PasswordReset.Disable),
		ResetPasswordCustomURL: config.AuthenticationBackend.PasswordReset.CustomURL.String(),
		Theme:                  config.Theme,

		EndpointsPasswordReset: !(config.AuthenticationBackend.PasswordReset.Disable || config.AuthenticationBackend.PasswordReset.CustomURL.String() != ""),
		EndpointsWebauthn:      !config.Webauthn.Disable,
		EndpointsTOTP:          !config.TOTP.Disable,
		EndpointsDuo:           !config.DuoAPI.Disable,
		EndpointsOpenIDConnect: !(config.IdentityProviders.OIDC == nil),
		EndpointsAuthz:         config.Server.Endpoints.Authz,
	}

	if config.PrivacyPolicy.Enabled {
		opts.PrivacyPolicyURL = config.PrivacyPolicy.PolicyURL.String()
		opts.PrivacyPolicyAccept = strconv.FormatBool(config.PrivacyPolicy.RequireUserAcceptance)
	}

	if !config.DuoAPI.Disable {
		opts.DuoSelfEnrollment = strconv.FormatBool(config.DuoAPI.EnableSelfEnrollment)
	}

	return opts
}

// TemplatedFileOptions is a struct which is used for many templated files.
type TemplatedFileOptions struct {
	AssetPath              string
	DuoSelfEnrollment      string
	RememberMe             string
	ResetPassword          string
	ResetPasswordCustomURL string
	PrivacyPolicyURL       string
	PrivacyPolicyAccept    string
	Session                string
	Theme                  string

	EndpointsPasswordReset bool
	EndpointsWebauthn      bool
	EndpointsTOTP          bool
	EndpointsDuo           bool
	EndpointsOpenIDConnect bool

	EndpointsAuthz map[string]schema.ServerAuthzEndpoint
}

// CommonData returns a TemplatedFileCommonData with the dynamic options.
func (options *TemplatedFileOptions) CommonData(base, baseURL, nonce, logoOverride, rememberMe string) TemplatedFileCommonData {
	if rememberMe != "" {
		return options.commonDataWithRememberMe(base, baseURL, nonce, logoOverride, rememberMe)
	}

	return TemplatedFileCommonData{
		Base:                   base,
		BaseURL:                baseURL,
		CSPNonce:               nonce,
		LogoOverride:           logoOverride,
		DuoSelfEnrollment:      options.DuoSelfEnrollment,
		RememberMe:             options.RememberMe,
		ResetPassword:          options.ResetPassword,
		ResetPasswordCustomURL: options.ResetPasswordCustomURL,
		PrivacyPolicyURL:       options.PrivacyPolicyURL,
		PrivacyPolicyAccept:    options.PrivacyPolicyAccept,
		Session:                options.Session,
		Theme:                  options.Theme,
	}
}

// CommonDataWithRememberMe returns a TemplatedFileCommonData with the dynamic options.
func (options *TemplatedFileOptions) commonDataWithRememberMe(base, baseURL, nonce, logoOverride, rememberMe string) TemplatedFileCommonData {
	return TemplatedFileCommonData{
		Base:                   base,
		BaseURL:                baseURL,
		CSPNonce:               nonce,
		LogoOverride:           logoOverride,
		DuoSelfEnrollment:      options.DuoSelfEnrollment,
		RememberMe:             rememberMe,
		ResetPassword:          options.ResetPassword,
		ResetPasswordCustomURL: options.ResetPasswordCustomURL,
		Session:                options.Session,
		Theme:                  options.Theme,
	}
}

// OpenAPIData returns a TemplatedFileOpenAPIData with the dynamic options.
func (options *TemplatedFileOptions) OpenAPIData(base, baseURL, nonce string) TemplatedFileOpenAPIData {
	return TemplatedFileOpenAPIData{
		Base:     base,
		BaseURL:  baseURL,
		CSPNonce: nonce,

		Session:        options.Session,
		PasswordReset:  options.EndpointsPasswordReset,
		Webauthn:       options.EndpointsWebauthn,
		TOTP:           options.EndpointsTOTP,
		Duo:            options.EndpointsDuo,
		OpenIDConnect:  options.EndpointsOpenIDConnect,
		EndpointsAuthz: options.EndpointsAuthz,
	}
}

// TemplatedFileCommonData is a struct which is used for many templated files.
type TemplatedFileCommonData struct {
	Base                   string
	BaseURL                string
	CSPNonce               string
	LogoOverride           string
	DuoSelfEnrollment      string
	RememberMe             string
	ResetPassword          string
	ResetPasswordCustomURL string
	PrivacyPolicyURL       string
	PrivacyPolicyAccept    string
	Session                string
	Theme                  string
}

// TemplatedFileOpenAPIData is a struct which is used for the OpenAPI spec file.
type TemplatedFileOpenAPIData struct {
	Base          string
	BaseURL       string
	CSPNonce      string
	Session       string
	PasswordReset bool
	Webauthn      bool
	TOTP          bool
	Duo           bool
	OpenIDConnect bool

	EndpointsAuthz map[string]schema.ServerAuthzEndpoint
}
