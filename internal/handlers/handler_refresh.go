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
	"net/http"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
)

func RefreshSessionAndTokenPOST(ctx *middlewares.AutheliaCtx) {
	bodyJSON := bodyRefreshRequest{}

	var (
		userSession session.UserSession
		err         error
	)

	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "refresh token", err)

		respondUnauthorized(ctx, "request body error")

		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if userSession.RefreshToken != bodyJSON.RefreshToken {
		msg := "Invalid refresh token"
		ctx.Logger.WithError(err).Error(msg)

		respondUnauthorized(ctx, msg)

		return
	}

	validRes, err := ctx.Providers.UserProvider.Refresh(userSession.Username, bodyJSON.RefreshToken)
	if err != nil {
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

	if validRes != nil {
		ctx.Logger.Debug("refresh session with new token")

		if err = ctx.RegenerateSession(); err != nil {
			ctx.Logger.Errorf(logFmtErrSessionRegenerate, "refresh token", userSession.Username, err)

			respondUnauthorized(ctx, messageMFAValidationFailed)

			return
		}

		provider, err := ctx.GetSessionProvider()
		if err != nil {
			ctx.Logger.Errorf("%s", err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		userSession.AccessToken = validRes.AccessToken
		userSession.RefreshToken = validRes.RefreshToken
		ctx.AccessToken = validRes.AccessToken
		ctx.Providers.SessionProvider.SetByToken(validRes.AccessToken, provider)

		if err = ctx.SaveSession(userSession); err != nil {
			ctx.Logger.Errorf(logFmtErrSessionSave, "updated profile", "refresh token", userSession.Username, err)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}
	}

	sessionId := getSessionId(ctx)

	if err = ctx.SetJSONBody(redirectResponse{
		AccessToken:  userSession.AccessToken,
		RefreshToken: userSession.RefreshToken,
		SessionID:    string(sessionId),
	}); err != nil {
		ctx.Logger.Errorf("Unable to response new token : %s", err)
	} else {
		setTokenToCookie(ctx, &AccessTokenCookieInfo{
			AccessToken:  userSession.AccessToken,
			RefreshToken: userSession.RefreshToken,
			Username:     userSession.Username,
		})
	}
}
