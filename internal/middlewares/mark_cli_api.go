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

package middlewares

import (
	"strings"

	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/valyala/fasthttp"
	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

const OLARES_CLI_SERVICE_ACCOUNT = "system:serviceaccount:os-framework:olares-cli-sa"

func MarkCliApi(next RequestHandler) RequestHandler {
	return func(ctx *AutheliaCtx) {
		tokenData := ctx.Request.Header.Peek("Olares-CLI-Authorization")
		if len(tokenData) == 0 {
			ctx.Logger.Error("cli api request missing authorization header")
			ctx.ReplyForbidden()
			return
		}

		tokens := strings.Split(string(tokenData), " ")
		if len(tokens) != 2 || tokens[0] != "Bearer" || len(tokens[1]) == 0 {
			ctx.Logger.Error("cli api request invalid authorization header")
			ctx.ReplyForbidden()
			return
		}

		token := tokens[1]

		config, err := ctrl.GetConfig()
		if err != nil {
			ctx.Logger.Error("cli api request get kube config error, ", err)
			ctx.ReplyForbidden()
			return
		}

		client, err := authv1.NewForConfig(config)
		if err != nil {
			ctx.Logger.Error("cli api request create authentication client error, ", err)
			ctx.ReplyForbidden()
			return
		}

		review, err := client.TokenReviews().Create(ctx.RequestCtx, &v1.TokenReview{
			Spec: v1.TokenReviewSpec{
				Token: token,
			},
		}, metav1.CreateOptions{})

		if err != nil {
			ctx.Logger.Error("cli api request token review error, ", err)
			ctx.ReplyForbidden()
			return
		}

		if !review.Status.Authenticated {
			ctx.Logger.Error("cli api request token not authenticated")
			ctx.ReplyForbidden()
			return
		}

		if review.Status.User.Username != OLARES_CLI_SERVICE_ACCOUNT {
			ctx.Logger.Error("cli api request token user invalid: ", review.Status.User.Username)
			ctx.ReplyForbidden()
			return
		}

		ctx.CliApiRequest = true
		ctx.CliServiceAccountToken = token

		next(ctx)
	}
}

func MarkCliAsAdmin(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		sa := ctx.Request.Header.Peek(string(authorization.TerminusUserHeader))
		if len(sa) != 0 && string(sa) == OLARES_CLI_SERVICE_ACCOUNT {
			ctx.Request.Header.Set(string(authorization.TerminusUserHeader), authorization.AdminUser)
		}

		next(ctx)
	}
}
