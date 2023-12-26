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

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/valyala/fasthttp"
)

type validateBody struct {
	User     string `json:"user"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

func ValidatePOST(ctx *middlewares.AutheliaCtx) {
	body := validateBody{}

	err := ctx.ParseBody(&body)
	if err != nil {
		ctx.Error(fmt.Errorf("unable to parse body during validate: %s", err), messageOperationFailed)
		return
	}

	// validate TOTP
	config, err := ctx.Providers.StorageProvider.LoadTOTPConfiguration(ctx, body.User)
	if err != nil {
		ctx.Logger.Errorf("Failed to load TOTP configuration: %+v", err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	isValid, err := ctx.Providers.TOTP.Validate(body.TOTP, config)
	if err != nil {
		ctx.Logger.Errorf("Failed to perform TOTP verification: %+v", err)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	if !isValid {
		_ = markAuthenticationAttempt(ctx, false, nil, body.User, regulation.AuthTypeTOTP, nil)

		respondUnauthorized(ctx, messageMFAValidationFailed)

		return
	}

	// validate user and password
	validator, ok := ctx.Providers.UserProvider.(*authentication.KubesphereUserProvider)
	if !ok {
		respondUnauthorized(ctx, "validator not found")
		return
	}

	err = validator.ValiidateUserPassword(body.User, body.Password)
	if err != nil {
		_ = markAuthenticationAttempt(ctx, false, nil, body.User, regulation.AuthType1FA, err)

		respondUnauthorized(ctx, messageAuthenticationFailed)

		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)

}
