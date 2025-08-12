package middlewares

import (
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/valyala/fasthttp"
)

// Require1FA check if user has enough permissions to execute the next handler.
func Require1FA(next RequestHandler) RequestHandler {
	return func(ctx *AutheliaCtx) {
		if s, err := ctx.GetSession(); err != nil {
			ctx.Logger.Error("middleware get session error, ", err)
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetJSONError(authentication.ErrInvalidToken.Error())
			return

		} else if s.AuthenticationLevel < authentication.OneFactor {

			ctx.Logger.Debug("get session: ", authorization.PrettyJSON(s))
			ctx.Logger.Debug("headers: ", ctx.Request.Header.String())
			ctx.ReplyForbidden()

			return
		}

		next(ctx)
	}
}
