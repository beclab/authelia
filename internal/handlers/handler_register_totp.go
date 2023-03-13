package handlers

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/session"
)

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

// TOTPIdentityStart the handler for initiating the identity validation.
var TOTPIdentityStart = middlewares.IdentityVerificationStart(middlewares.IdentityVerificationStartArgs{
	MailTitle:             "Register your mobile",
	MailButtonContent:     "Register",
	TargetEndpoint:        "/one-time-password/register",
	ActionClaim:           ActionTOTPRegistration,
	IdentityRetrieverFunc: identityRetrieverFromSession,
}, nil)

func totpIdentityFinish(ctx *middlewares.AutheliaCtx, username string) {
	var (
		config *model.TOTPConfiguration
		err    error
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
}

// TOTPIdentityFinish the handler for finishing the identity validation.
var TOTPIdentityFinish = middlewares.IdentityVerificationFinish(
	middlewares.IdentityVerificationFinishArgs{
		ActionClaim:          ActionTOTPRegistration,
		IsTokenUserValidFunc: isTokenUserValidFor2FARegistration,
	}, totpIdentityFinish)

// TOTP All in one register api.
func TOTPIdentityVerificationAll(ctx *middlewares.AutheliaCtx) {
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

	totpIdentityFinish(ctx, verification.Username)
}
