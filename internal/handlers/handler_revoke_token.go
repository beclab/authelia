// Copyright 2024 bytetrade
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handlers

import (
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/valyala/fasthttp"
)

type revokeBody struct {
	RevokeToken string `json:"revokeToken"`
}

func RevokeTokenPOST(ctx *middlewares.AutheliaCtx) {
	body := revokeBody{}

	var (
		userSession session.UserSession
		err         error
	)

	if err = ctx.ParseBody(&body); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "revoke token", err)

		respondUnauthorized(ctx, "request body error")

		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

		respondInvalidToken(ctx)

		return
	}

	userInfo, err := ctx.Providers.UserProvider.GetDetails(userSession.Username, userSession.AccessToken)
	if err != nil {
		ctx.Logger.Error(err)
		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if revokeSession := ctx.Providers.SessionProvider.GetByToken(body.RevokeToken); revokeSession != nil {
		if sessionId := revokeSession.GetSessionID(body.RevokeToken); sessionId != "" {
			// change context session to signed session
			ctx.RequestCtx.Request.Header.SetCookie(session.AUTH_TOKEN, sessionId)

			revokeUserSession, err := revokeSession.GetSession(ctx.RequestCtx)
			if err != nil {
				ctx.Logger.WithError(err).Error("Error occurred retrieving user session")

				ctx.SetStatusCode(fasthttp.StatusNotFound)
				ctx.SetJSONError("token invalid")

				return
			}

			if revokeUserSession.Username == userInfo.Username || userInfo.Groups[0] == "owner" || userInfo.Groups[0] == "admin" {
				switch p := ctx.Providers.UserProvider.(type) {
				case *authentication.KubesphereUserProvider:
					err = p.Logout(revokeUserSession.Username, revokeUserSession.AccessToken)
					if err != nil {
						ctx.Logger.Error("cannot logout from kubesphere, ", err)
					}
				case *authentication.LLDAPUserProvider:
				default:
				}

				ctx.Logger.Infof("session destroyed, clear token, %s", revokeUserSession.AccessToken)

				revokeSession.RemoveSessionID(revokeUserSession.AccessToken)

				revokeSession.DestroySession(ctx.RequestCtx)
			} else {
				ctx.SetJSONError("token belongs to anther user")
				ctx.ReplyForbidden()
			}
		} // end of session find

		ctx.Providers.SessionProvider.RevokeByToken(body.RevokeToken)
	}

	ctx.ReplyOK()
}
