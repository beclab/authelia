package handlers

import (
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
)

func ListUserGET(ctx *middlewares.AutheliaCtx) {
	lldapProvider, ok := ctx.Providers.UserProvider.(*authentication.LLDAPUserProvider)
	if !ok {
		ctx.Logger.Error("UserListGET is only implemented for LLDAP user provider")
		ctx.ReplyForbidden()
		return
	}

	users, err := lldapProvider.ListUser(ctx)
	if err != nil {
		ctx.Logger.WithError(err).Error("Failed to list users")
		ctx.ReplyError(err, "Failed to list users")
		return
	}

	if err = ctx.SetJSONBody(users); err != nil {
		ctx.Logger.Errorf("Unable to set user list response in body: %s", err)
		ctx.ReplyError(err, "Unable to set user list response in body")
		return
	}
}
