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
	"encoding/base64"
	"os"
	"strings"
	"time"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/google/uuid"
	"k8s.io/klog/v2"
)

var (
	AuthTokenSalt = uuid.NewString()
)

func TerminusApp2FACheck(
	ctx *middlewares.AutheliaCtx,
	result AuthzResult,
	authn *Authn,
	required authorization.Level,
	rule *authorization.AccessControlRule,
) (AuthzResult, error) {
	if rule == nil {
		return result, nil
	}

	switch {
	case required == authorization.Bypass:
		return AuthzResultAuthorized, nil
	case result == AuthzResultForbidden:
		return result, nil
	default:
		return checkResourceAuthLevel(ctx, result, authn, rule)
	}
}

func checkResourceAuthLevel(ctx *middlewares.AutheliaCtx, result AuthzResult,
	authn *Authn, rule *authorization.AccessControlRule,
) (AuthzResult, error) {
	ctx.Logger.Debug("starting authz result mutate, ", result, " ", rule.Resources, " ", rule.Policy.String(), " ", rule.DefaultRule)

	provider, err := ctx.GetSessionProviderByTargetURL(authn.Object.URL)

	if err != nil {
		ctx.Logger.WithError(err).Errorf("Target URL '%s' does not appear to be configured as a session domain", authn.Object.URL.String())

		return result, err
	}

	userSession, err := provider.GetSession(ctx.RequestCtx)

	if err != nil {
		return result, err
	}

	if rule.Policy == authorization.OneFactor && authn.Level >= authentication.OneFactor {
		return AuthzResultAuthorized, nil
	}

	// others resource of app.
	if rule.DefaultRule {
		return result, nil
	}

	return mutatingAuthzResult(ctx, provider, userSession, rule)
}

func mutatingAuthzResult(ctx *middlewares.AutheliaCtx,
	provider session.SessionProvider,
	userSession session.UserSession,
	rule *authorization.AccessControlRule,
) (AuthzResult, error) {
	var (
		sessionModified bool        = false
		mutatedResult   AuthzResult = AuthzResultUnauthorized
	)

	for i, r := range userSession.ResourceAuthenticationLevels {
		if rule.IsMatch(r.Subject, r.Object) &&
			rule.Policy == authorization.TwoFactor &&
			r.Level >= authentication.TwoFactor {
			ctx.Logger.Debug("find resource authed rule, ", rule.Domains, r.Level, r.AuthTime)

			switch {
			case rule.OneTimeValid:
				// one time valid policy, return authorized and downgrade authentication level.
				userSession.ResourceAuthenticationLevels[i].Level = authentication.OneFactor
				sessionModified = true
				mutatedResult = AuthzResultAuthorized
			default:
				if rule.ValidDuration <= 0 || rule.ValidDuration > time.Now().UTC().Sub(r.AuthTime.UTC()) {
					mutatedResult = AuthzResultAuthorized
				} else {
					mutatedResult = AuthzResultUnauthorized
				}
			} // end switch.

			break
		}
	} // end loop.

	if sessionModified {
		// update session.
		if err := provider.SaveSession(ctx.RequestCtx, userSession); err != nil {
			ctx.Logger.Errorf("Unable to save updated user session: %+v", err)
		}
	}

	return mutatedResult, nil
}

func isValidBackendRequest(ctx *middlewares.AutheliaCtx) bool {
	backendToken := ctx.RequestCtx.Request.Header.PeekBytes(utils.TerminusAccessTokenHeader)

	if isValidOsSystemRequest(backendToken) {
		return true
	}

	return len(backendToken) > 0 && func() bool {
		auth, ok := ctx.Providers.Authorizer.(*authorization.TsAuthorizer)
		if !ok {
			return false
		}

		return auth.ValidBackendRequest(ctx.RequestCtx, string(backendToken))
	}()
}

func isValidOsSystemRequest(token []byte) bool {
	origKey := string(token)

	prefix := "appservice:"
	if !strings.HasPrefix(origKey, prefix) {
		return false
	}

	key := strings.Replace(origKey, prefix, "", 1)

	secret := os.Getenv("APP_RANDOM_KEY")
	if secret == "" {
		return false
	}

	decodeKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		klog.Error("app service random key decode error, ", err, ", ", origKey)
		return false
	}

	_, err = AesDecrypt(decodeKey, []byte(secret))
	if err != nil {
		klog.Error("app service random key decrypt error, ", err, ", ", origKey)
		return false
	}

	// TODO: content verify
	return true
}
