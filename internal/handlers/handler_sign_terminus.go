// Copyright 2023 bytetrade
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/terminus"
	"github.com/go-resty/resty/v2"
	"k8s.io/klog/v2"
)

func TerminusPassSendPOST(ctx *middlewares.AutheliaCtx) {
	userSession, err := ctx.GetSession()
	if err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	identity, err := identityRetrieverFromSession(ctx)
	if err != nil {
		ctx.Logger.Error(err)
		ctx.ReplyError(err, "cannot get data from session")

		return
	}

	if userSession.TPConfig == nil {
		config, err := terminus.NewOTPConfig(identity.Username, identity.Email)
		if err != nil {
			ctx.Logger.Error(err)
			ctx.ReplyError(err, "init otp error")

			return
		}

		userSession.TPConfig = config
	}

	code, err := userSession.TPConfig.GenerateCode()
	if err != nil {
		ctx.Logger.Error(err)
		ctx.ReplyError(err, "generate otp code error")

		return
	}

	if err = ctx.SaveSession(userSession); err != nil {
		ctx.Logger.Errorf(logFmtErrSessionSave, "send otp", regulation.AuthTypeTerminus, userSession.Username, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	// send code to terminus notification.
	if err = terminus.SendCodeToNnotification(code); err != nil {
		ctx.Error(fmt.Errorf("unable to send code to terminus notification: %w", err), messageOperationFailed)
		return
	}

	ctx.ReplyOK()
}

func TerminusPassPOST(ctx *middlewares.AutheliaCtx) {
	bodyJSON := bodySignTerminusRequest{}

	var (
		userSession session.UserSession
		err         error
	)

	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, regulation.AuthTypeTerminus, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	isValid := userSession.TPConfig.ValidateCode(bodyJSON.Code)

	if !isValid {
		_ = markAuthenticationAttempt(ctx, false, nil, userSession.Username, regulation.AuthTypeTerminus, nil)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if err = markAuthenticationAttempt(ctx, true, nil, userSession.Username, regulation.AuthTypeTerminus, nil); err != nil {
		respondUnauthorized(ctx, messageMFAValidationFailed)
		return
	}

	if err = ctx.RegenerateSession(); err != nil {
		ctx.Logger.Errorf(logFmtErrSessionRegenerate, regulation.AuthTypeTOTP, userSession.Username, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	userSession.SetTwoFactorTerminusPass(ctx.Clock.Now())

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

func TermipassSignPOST(ctx *middlewares.AutheliaCtx) {
	bodyJSON := bodySignTermipassRequest{}

	var (
		userSession session.UserSession
		err         error
	)

	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, regulation.AuthTypeTerminus, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	var (
		parsedURI *url.URL
	)

	if parsedURI, err = url.ParseRequestURI(bodyJSON.TargetUrl); err != nil {
		ctx.Error(fmt.Errorf("failed to parse URI '%s': %w", bodyJSON.TargetUrl, err), messageMFAValidationFailed)
		return
	}

	nameToken := strings.Split(bodyJSON.TerminusName, "@")
	if len(nameToken) < 2 {
		ctx.Logger.Errorf("invalid terminus name %s, %+v", bodyJSON.TerminusName, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	token, err := verifyTermipassSign(bodyJSON.JWS, nameToken[0])
	if err != nil {
		ctx.Logger.Errorf("verify termipass sign error, %+v, %s", err, bodyJSON.JWS)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if token != bodyJSON.AuthTokenID {
		ctx.Logger.Errorf("verify termipass sign token is different, %s, %s", token, bodyJSON.AuthTokenID)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	session := ctx.Providers.SessionProvider.GetByToken(token)
	sessionId := session.GetSessionID(token)

	// change context session to signed session
	ctx.RequestCtx.Request.Header.SetCookie(session.Config.Name, sessionId)

	if userSession, err = session.GetSession(ctx.RequestCtx); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	userSession.SetTwoFactorTerminusPass(ctx.Clock.Now())

	if err = session.SaveSession(ctx.RequestCtx, userSession); err != nil {
		ctx.Logger.Errorf(logFmtErrSessionSave, "authentication time", regulation.AuthTypeTOTP, userSession.Username, err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	updateSession2FaLevel(ctx, parsedURI, &userSession)

	// ignore cookie from client
	cookie := ctx.RequestCtx.Request.Header.Cookie(session.Config.Name)

	if len(cookie) > 0 {
		klog.Info("clear session cookie for termipass sign")
		ctx.RequestCtx.Request.Header.DelCookie(session.Config.Name)
	}

	// send notification to other termipass
	authorizer, ok := ctx.Providers.Authorizer.(*authorization.TsAuthorizer)
	if !ok {
		ctx.Logger.Errorf("Authorizer invalid , %s", userSession.Username)

		ctx.ReplyError(errors.New("unable to get nonce"), "Unable to get nonce")
		return
	}

	nonce := authorizer.GetUserBackendNonce(userSession.Username)
	if nonce == "" {
		ctx.Logger.Errorf("Unable to get user terminuce nonce , %s", userSession.Username)

		ctx.ReplyError(errors.New("unable to get nonce"), "Unable to get nonce")
		return
	}

	payload := `{"eventType": "system.cancel.sign"}`
	message := `{"id": "` + bodyJSON.ID + `"}`
	if err = sendNotificationToTermipass(userSession.Username, nonce, payload, message); err != nil {
		ctx.Logger.Errorf("Unable to send notification to user' termipass , %s", userSession.Username)

		ctx.ReplyError(err, "Unable to send notification")
		return
	}

	ctx.ReplyOK()
}

func verifyTermipassSign(jws string, name string) (token string, err error) {
	httpClient := resty.New().SetTimeout(2 * time.Second)

	type verify struct {
		Verify  bool               `json:"verify"`
		Payload *TermipassSignBody `json:"payload"`
		DID     string             `json:"did"`
		Name    string             `json:"name"`
	}

	type verifyResponse struct {
		Code    int     `json:"code"`
		Message *string `json:"message,omitempty"`
		Data    *verify `json:"data,omitempty"`
	}

	url := fmt.Sprintf("http://vault-server:3010/verify/%s", name)
	resp, err := httpClient.R().
		SetBody(
			&struct {
				JWS string `json:"jws"`
			}{JWS: jws},
		).
		SetResult(&verifyResponse{}).
		Post(url)

	if err != nil {
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		return "", errors.New(string(resp.Body()))
	}

	verifyRes, ok := resp.Result().(*verifyResponse)
	if !ok {
		return "", errors.New("invalid response")
	}

	klog.Infof("verify result: %+v", err)

	if verifyRes.Code != 0 {
		return "", errors.New(*verifyRes.Message)
	}

	if verifyRes.Data == nil || !verifyRes.Data.Verify {
		return "", errors.New("vault cannot verified")
	}

	checksum := md5(verifyRes.Data.Payload.AuthTokenID + AuthTokenSalt)
	if checksum != verifyRes.Data.Payload.AuthTokenID {
		return "", errors.New("invalid token in payload")
	}

	return verifyRes.Data.Payload.AuthTokenID, nil
}
