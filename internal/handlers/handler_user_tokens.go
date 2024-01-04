// Copyright 2024 bytetrade
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

import "github.com/authelia/authelia/v4/internal/middlewares"

// list user logon tokens and  session info
func ListTokenGET(ctx *middlewares.AutheliaCtx) {
	user := ctx.QueryArgs().PeekBytes([]byte("user"))
	infos, err := ctx.Providers.SessionProvider.GetUserTokens(string(user))

	if err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user token infos")
		ctx.ReplyError(err, "Error occurred retrieving user token infos")
		return
	}

	if err = ctx.SetJSONBody(infos); err != nil {
		ctx.Logger.Errorf("Unable to set user token infos response in body: %s", err)
	}
}
