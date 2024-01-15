package middlewares

import (
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
)

// Require1FA check if user has enough permissions to execute the next handler.
func Require2FA(next RequestHandler) RequestHandler {
	return func(ctx *AutheliaCtx) {
		if s, err := ctx.GetSession(); err != nil || s.AuthenticationLevel < authentication.TwoFactor {
			if err != nil {
				ctx.Logger.Error("middleware get session error, ", err)
			}

			ctx.Logger.Debug("get session: ", authorization.PrettyJSON(s))
			ctx.ReplyForbidden()

			return
		}

		next(ctx)
	}
}
