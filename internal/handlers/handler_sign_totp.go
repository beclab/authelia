package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/go-resty/resty/v2"
	"k8s.io/klog/v2"
)

// TimeBasedOneTimePasswordPOST validate the TOTP passcode provided by the user.
func TimeBasedOneTimePasswordPOST(ctx *middlewares.AutheliaCtx) {
	bodyJSON := bodySignTOTPRequest{}

	var (
		userSession session.UserSession
		err         error
	)

	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, regulation.AuthTypeTOTP, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		respondInvalidToken(ctx)

		return
	}

	isValid, err := totpVerify(fmt.Sprintf("http://%s:%d",
		ctx.Configuration.AuthenticationBackend.LLDAP.Server,
		*ctx.Configuration.AuthenticationBackend.LLDAP.Port),
		userSession.AccessToken, bodyJSON.Token)
	if err != nil {
		ctx.Logger.Errorf("Failed to perform TOTP verification: %+v", err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if isValid == nil || isValid.Token == "" || isValid.RefreshToken == "" {
		ctx.Logger.Errorf("Invalid TOTP verification response: is nil or missing tokens")
		_ = markAuthenticationAttempt(ctx, false, nil, userSession.Username, regulation.AuthTypeTOTP, nil)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if err = markAuthenticationAttempt(ctx, true, nil, userSession.Username, regulation.AuthTypeTOTP, nil); err != nil {
		respondUnauthorized(ctx, messageMFAValidationFailed)
		return
	}

	if err = ctx.RegenerateSession(); err != nil {
		ctx.Logger.Errorf(logFmtErrSessionRegenerate, regulation.AuthTypeTOTP, userSession.Username, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	userSession.SetTwoFactorTOTP(ctx.Clock.Now())
	userSession.AccessToken = isValid.Token
	userSession.RefreshToken = isValid.RefreshToken

	if err = ctx.SaveSession(userSession); err != nil {
		ctx.Logger.Errorf(logFmtErrSessionSave, "authentication time", regulation.AuthTypeTOTP, userSession.Username, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if bodyJSON.Workflow == workflowOpenIDConnect {
		handleOIDCWorkflowResponse(ctx, bodyJSON.TargetURL, bodyJSON.WorkflowID)
	} else {
		Handle2FAResponse(ctx, bodyJSON.TargetURL, &userSession)
	}
}

type loginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

func totpVerify(baseURL, accessToken, token string) (*loginResponse, error) {
	url := fmt.Sprintf("%s/auth/totp/verify", baseURL)
	client := resty.New()
	m := map[string]string{
		"token": token,
	}
	resp, err := client.SetTimeout(10*time.Second).R().
		SetHeader("Content-Type", "application/json").SetAuthToken(accessToken).
		SetBody(m).
		Post(url)
	if err != nil {
		klog.Infof("send request failed: %v", err)
		return nil, err
	}
	if resp.StatusCode() != http.StatusOK {
		klog.Infof("not 200, %v, body: %v", resp.StatusCode(), string(resp.Body()))
		return nil, errors.New(resp.String())
	}
	var response loginResponse
	err = json.Unmarshal(resp.Body(), &response)
	if err != nil {
		klog.Infof("unmarshal failed: %v", err)
		return nil, err
	}
	klog.Infof("TotpVerify res: %v", response)
	return &response, nil
}
