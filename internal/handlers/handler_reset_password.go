package handlers

import (
	"net/http"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"k8s.io/klog/v2"
)

func ResetPassword(ctx *middlewares.AutheliaCtx) {
	username := ctx.UserValue("user").(string)
	if len(username) == 0 {
		ctx.SetStatusCode(http.StatusBadRequest)
		ctx.SetJSONError("empty username")
		return
	}
	bodyJSON := PasswordReset{}

	var (
		userSession session.UserSession
		err         error
	)
	ctx.Logger.Errorf(logFmtErrParseRequestBody, "xxxxxpassword reset request data", string(ctx.PostBody()))
	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "password reset request data", err)
		ctx.SetStatusCode(http.StatusBadRequest)
		ctx.SetJSONError(err.Error())
		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session")
		//respondInvalidToken(ctx)
		ctx.ReplyOK()
		return
	}

	klog.V(0).Infof("username: %s", username)
	klog.Infof("username2: %s", username)

	klog.Infof("usersession: %s,token: %s", userSession.Username, userSession.AccessToken)

	err = ctx.Providers.UserProvider.ResetPassword(username, bodyJSON.CurrentPassword, bodyJSON.Password, userSession.AccessToken)
	if err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "password reset", err)
		ctx.SetStatusCode(http.StatusBadRequest)
		ctx.SetJSONError(err.Error())
		return
	}
	sess := ctx.Providers.SessionProvider.GetByToken(userSession.AccessToken)
	if sess != nil {
		sess.ClearUserTokenCache(username)
	}

	ctx.SetStatusCode(http.StatusOK)
	return
}
