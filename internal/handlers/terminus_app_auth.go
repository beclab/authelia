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
	"time"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
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
	ctx.Logger.Debug("starting authz result mutate, ", result, " ", rule.Resources, " ", rule.Policy.String())
	provider, err := ctx.GetSessionProviderByTargetURL(authn.Object.URL)

	if err != nil {
		ctx.Logger.WithError(err).Errorf("Target URL '%s' does not appear to be configured as a session domain", authn.Object.URL.String())

		return result, err
	}

	userSession, err := provider.GetSession(ctx.RequestCtx)

	if err != nil {
		return result, err
	}

	subject := authorization.Subject{
		Username: authn.Details.Username,
		Groups:   authn.Details.Groups,
		IP:       ctx.RemoteIP(),
	}

	if err != nil {
		return result, err
	}

	if rule.Policy == authorization.OneFactor && authn.Level >= authentication.OneFactor {
		return AuthzResultAuthorized, nil
	}

	var (
		sessionModified bool        = false
		mutatedResult   AuthzResult = AuthzResultUnauthorized
	)

	for i, r := range userSession.ResourceAuthenticationLevels {
		if r.Rule.IsMatch(subject, authn.Object) &&
			rule.Policy == authorization.TwoFactor &&
			r.Level >= authentication.TwoFactor {
			ctx.Logger.Debug("find resource authed rule, ", r.Rule.Domains, r.Level, r.AuthTime)

			switch {
			case rule.OneTimeValid:
				// one time valid policy, return authorized and downgrade authentication level.
				userSession.ResourceAuthenticationLevels[i].Level = authentication.OneFactor
				sessionModified = true
				mutatedResult = AuthzResultAuthorized
			default:
				if rule.ValidDuration <= 0 || rule.ValidDuration <= time.Now().UTC().Sub(r.AuthTime) {
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
		if err = provider.SaveSession(ctx.RequestCtx, userSession); err != nil {
			ctx.Logger.Errorf("Unable to save updated user session: %+v", err)
		}
	}

	return mutatedResult, nil
}
