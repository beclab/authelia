package handlers

import (
	"net/http"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/go-resty/resty/v2"
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
		token       string
	)
	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "password reset request data", err)
		ctx.SetStatusCode(http.StatusBadRequest)
		ctx.SetJSONError(err.Error())
		return
	}

	if ctx.CliApiRequest {
		token = ctx.CliServiceAccountToken
	} else {
		if userSession, err = ctx.GetSession(); err != nil {
			ctx.Logger.WithError(err).Error("Error occurred retrieving user session")
			//respondInvalidToken(ctx)
			ctx.ReplyOK()
			return
		}

		token = userSession.AccessToken
	}
	info, err := utils.GetUserInfoFromBFL(resty.New(), username)
	if err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "get user info ", err)
		ctx.SetStatusCode(http.StatusBadRequest)
		ctx.SetJSONError(err.Error())
	}

	err = ctx.Providers.UserProvider.ResetPassword(username, bodyJSON.CurrentPassword, bodyJSON.Password, token, func() bool {
		if ctx.CliApiRequest {
			// CLI API request, allow password reset
			return true
		}

		return CanChangePasswordWithoutCurrentPassword(userSession.Groups, info.OwnerRole)
	}(), ctx.CliApiRequest)
	if err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "password reset", err)
		ctx.SetStatusCode(http.StatusBadRequest)
		ctx.SetJSONError(err.Error())
		return
	}

	var sess session.SessionProvider
	// if request from olares-cli, user session if empty
	if !ctx.CliApiRequest && userSession.Username == username {
		klog.Info("clear token cache for user ", username, " himself")
		sess, err = ctx.GetSessionProvider()
		if err != nil {
			ctx.Logger.Errorf("failed to get session provider for user %s: %v", username, err)
			ctx.SetStatusCode(http.StatusInternalServerError)
			ctx.SetJSONError(err.Error())
			return
		}
	} else {
		if !info.IsEphemeral {
			domain := info.Zone
			klog.Infof("clear token cache for user %s in domain %s", username, domain)
			sess, err = ctx.Providers.SessionProvider.Get(domain, domain, "", false)
			if err != nil {
				ctx.Logger.Errorf("failed to get session for user %s in domain %s: %v", username, domain, err)
			}
		} else {
			klog.Info("do not clear token cache for ephemeral user ", username)
		}
	}

	if sess != nil {
		sess.ClearUserTokenCache(username)
	} else {
		klog.Warning("session provider not found for user ", username)
	}

	ctx.SetStatusCode(http.StatusOK)
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
