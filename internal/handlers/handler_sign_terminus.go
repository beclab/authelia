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
	"fmt"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/terminus"
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
