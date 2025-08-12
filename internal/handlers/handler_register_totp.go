package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/storage"
)

// Deprecated
// identityRetrieverFromSession retriever computing the identity from the cookie session.
func identityRetrieverFromSession(ctx *middlewares.AutheliaCtx) (identity *session.Identity, err error) {
	var userSession session.UserSession

	if userSession, err = ctx.GetSession(); err != nil {
		return nil, fmt.Errorf("error retrieving user session for request: %w", err)
	}

	if len(userSession.Emails) == 0 {
		return nil, fmt.Errorf("user %s does not have any email address", userSession.Username)
	}

	return &session.Identity{
		Username:    userSession.Username,
		DisplayName: userSession.DisplayName,
		Email:       userSession.Emails[0],
	}, nil
}

func isTokenUserValidFor2FARegistration(ctx *middlewares.AutheliaCtx, username string) bool {
	userSession, err := ctx.GetSession()

	return err == nil && userSession.Username == username
}

// Deprecated
// TOTPIdentityStart the handler for initiating the identity validation.
var TOTPIdentityStart = middlewares.IdentityVerificationStart(middlewares.IdentityVerificationStartArgs{
	MailTitle:             "Register your mobile",
	MailButtonContent:     "Register",
	TargetEndpoint:        "/one-time-password/register",
	ActionClaim:           ActionTOTPRegistration,
	IdentityRetrieverFunc: identityRetrieverFromSession,
}, nil)

// Deprecated
func totpIdentityFinish(ctx *middlewares.AutheliaCtx, username string) (err error) {
	var (
		config *model.TOTPConfiguration
	)

	if config, err = ctx.Providers.TOTP.Generate(username); err != nil {
		ctx.Error(fmt.Errorf("unable to generate TOTP key: %s", err), messageUnableToRegisterOneTimePassword)
	}

	if err = ctx.Providers.StorageProvider.SaveTOTPConfiguration(ctx, *config); err != nil {
		ctx.Error(fmt.Errorf("unable to save TOTP secret in DB: %s", err), messageUnableToRegisterOneTimePassword)
		return
	}

	response := TOTPKeyResponse{
		OTPAuthURL:   config.URI(),
		Base32Secret: string(config.Secret),
	}

	if err = ctx.SetJSONBody(response); err != nil {
		ctx.Logger.Errorf("Unable to set TOTP key response in body: %s", err)
	}

	ctxLogEvent(ctx, username, "Second Factor Method Added", map[string]any{"Action": "Second Factor Method Added", "Category": "Time-based One Time Password"})

	return
}

// TOTPIdentityFinish the handler for finishing the identity validation.
var TOTPIdentityFinish = middlewares.IdentityVerificationFinish(
	middlewares.IdentityVerificationFinishArgs{
		ActionClaim:          ActionTOTPRegistration,
		IsTokenUserValidFunc: isTokenUserValidFor2FARegistration,
	}, func(ctx *middlewares.AutheliaCtx, username string) { totpIdentityFinish(ctx, username) })

// Deprecated
// TOTP All in one register api.
func TOTPIdentityVerificationAll(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession
		err         error
	)

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		// In that case we reply ok to avoid user enumeration.
		ctx.Logger.Error(err)
		ctx.ReplyOK()

		return
	}

	var config *model.TOTPConfiguration

	ctx.Providers.StorageProvider.BeginTX(ctx.RequestCtx)
	defer func() {
		if err != nil {
			ctx.Providers.StorageProvider.Rollback(ctx.RequestCtx)
		} else {
			ctx.Providers.StorageProvider.Commit(ctx.RequestCtx)
		}
	}()

	if config, err = ctx.Providers.StorageProvider.LoadTOTPConfiguration(ctx, userSession.Username); err != nil {
		if !errors.Is(err, storage.ErrNoTOTPConfiguration) {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetJSONError("Could not find TOTP Configuration for user.")
			ctx.Logger.Errorf("Failed to lookup TOTP configuration for user '%s' with unknown error: %v", userSession.Username, err)
			return
		}
	}

	if err == nil {
		response := TOTPKeyResponse{
			OTPAuthURL:   config.URI(),
			Base32Secret: string(config.Secret),
		}

		if err = ctx.SetJSONBody(response); err != nil {
			ctx.Logger.Errorf("Unable to perform TOTP configuration response: %s", err)
		}

		ctx.SetStatusCode(fasthttp.StatusOK)
		return
	}

	identity, err := identityRetrieverFromSession(ctx)
	if err != nil {
		// In that case we reply ok to avoid user enumeration.
		ctx.Logger.Error(err)
		ctx.ReplyOK()

		return
	}

	var jti uuid.UUID

	if jti, err = uuid.NewRandom(); err != nil {
		ctx.Error(err, messageOperationFailed)
		return
	}

	verification := model.NewIdentityVerification(jti, identity.Username, ActionTOTPRegistration, ctx.RemoteIP())

	if err = ctx.Providers.StorageProvider.SaveIdentityVerification(ctx, verification); err != nil {
		ctx.Error(err, messageOperationFailed)
		return
	}

	err = ctx.Providers.StorageProvider.ConsumeIdentityVerification(
		ctx,
		verification.JTI.String(),
		model.NewNullIP(ctx.RemoteIP()))
	if err != nil {
		ctx.Error(err, messageOperationFailed)
		return
	}

	err = totpIdentityFinish(ctx, verification.Username)
}

type TotpBindResponse struct {
	Base32Secret string `json:"base32_secret"`
}

func totpURI(ctx *middlewares.AutheliaCtx, username, secret string) (uri string) {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", ctx.Configuration.TOTP.Issuer)
	v.Set("period", strconv.FormatUint(uint64(ctx.Configuration.TOTP.Period), 10))
	v.Set("algorithm", ctx.Configuration.TOTP.Algorithm)
	v.Set("digits", strconv.Itoa(int(ctx.Configuration.TOTP.Digits)))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + ctx.Configuration.TOTP.Issuer + ":" + username,
		RawQuery: v.Encode(),
	}

	return u.String()
}

// TOTP bind with lldap
func TOTPIdentityVerificationBindLldap(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession
		err         error
	)

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		// In that case we reply ok to avoid user enumeration.
		ctx.Logger.Error(err)
		ctx.ReplyOK()

		return
	}

	url := fmt.Sprintf("http://%s:%d/auth/totp/bind",
		ctx.Configuration.AuthenticationBackend.LLDAP.Server,
		*ctx.Configuration.AuthenticationBackend.LLDAP.Port)

	client := resty.New()
	resp, err := client.SetTimeout(5*time.Second).R().
		SetHeader("Content-Type", "application/json").SetAuthToken(userSession.AccessToken).
		Post(url)
	if err != nil {
		ctx.Logger.Errorf("Failed to bind TOTP with LLDAP: %v", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetJSONError("Could not find TOTP Configuration for user.")
		return
	}

	if resp.StatusCode() != http.StatusOK {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetJSONError("Could not find TOTP Configuration for user.")
		ctx.Logger.Errorf("Failed to bind TOTP with LLDAP: %s", resp.String())
		return
	}

	var response TotpBindResponse
	err = json.Unmarshal(resp.Body(), &response)
	if err != nil {
		ctx.Error(err, "Failed to parse TOTP bind response")
		return
	}

	r := TOTPKeyResponse{
		OTPAuthURL:   totpURI(ctx, userSession.Username, response.Base32Secret),
		Base32Secret: response.Base32Secret,
	}

	if err = ctx.SetJSONBody(r); err != nil {
		ctx.Logger.Errorf("Unable to set TOTP key response in body: %v", err)
	}

	ctxLogEvent(ctx, userSession.Username, "Second Factor Method Added", map[string]any{"Action": "Second Factor Method Added", "Category": "Time-based One Time Password"})
}
