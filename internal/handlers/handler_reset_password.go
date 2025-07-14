package handlers

import (
	"net/http"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/go-resty/resty/v2"
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
	info, err := utils.GetUserInfoFromBFL(resty.New(), username)
	if err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "get user info ", err)
		ctx.SetStatusCode(http.StatusBadRequest)
		ctx.SetJSONError(err.Error())
	}

	err = ctx.Providers.UserProvider.ResetPassword(username, bodyJSON.CurrentPassword, bodyJSON.Password, userSession.AccessToken, func() bool {
		return CanChangePasswordWithoutCurrentPassword(userSession.Groups, info.OwnerRole)
	}())
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

const (
	Owner  string = "owner"
	Admin  string = "admin"
	Normal string = "normal"
)

func CanChangePasswordWithoutCurrentPassword(operatorPermissions []string, targetPermission string) bool {
	for _, perm := range operatorPermissions {
		switch perm {
		case Owner:
			if targetPermission == Admin || targetPermission == Normal {
				return true
			}
		case Admin:
			if targetPermission == Normal {
				return true
			}
		case Normal:
			continue
		}
	}
	return false
}
