package handlers

import (
	"fmt"
	"net/url"

	"github.com/authelia/authelia/v4/internal/middlewares"
)

type logoutBody struct {
	TargetURL string `json:"targetURL"`
}

type logoutResponseBody struct {
	SafeTargetURL bool `json:"safeTargetURL"`
}

// LogoutPOST is the handler logging out the user attached to the given cookie.
func LogoutPOST(ctx *middlewares.AutheliaCtx) {
	body := logoutBody{}
	responseBody := logoutResponseBody{SafeTargetURL: false}

	err := ctx.ParseBody(&body)
	if err != nil {
		ctx.Error(fmt.Errorf("unable to parse body during logout: %s", err), messageOperationFailed)
	}

	userSession, err := ctx.GetSession()
	if err != nil {
		ctx.Logger.WithError(err).Error("Error occurred retrieving user session during logout")
	}

	err = ctx.DestroySession()
	if err != nil {
		ctx.Error(fmt.Errorf("unable to destroy session during logout: %s", err), messageOperationFailed)
	}

	redirectionURL, err := url.ParseRequestURI(body.TargetURL)
	if err == nil {
		responseBody.SafeTargetURL = ctx.IsSafeRedirectionTargetURI(redirectionURL)
	}

	if body.TargetURL != "" {
		ctx.Logger.Debugf("Logout target url is %s, safe %t", body.TargetURL, responseBody.SafeTargetURL)
	}

	err = ctx.SetJSONBody(responseBody)
	if err != nil {
		ctx.Error(fmt.Errorf("unable to set body during logout: %s", err), messageOperationFailed)
	}

	if userSession.Username != "" {
		ctx.Logger.Infof("User %s logged out successfully", userSession.Username)
		TopicLogout.send(ctx, userSession.Username)
	} else {
		ctx.Logger.Info("User logged out successfully")
	}
}
