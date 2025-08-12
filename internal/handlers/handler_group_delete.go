package handlers

import (
	"fmt"
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/valyala/fasthttp"
)

// DeleteGroup handles DELETE requests to delete a specific group.
// DELETE /api/groups/{groupName}
func DeleteGroup(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession
		err         error
	)
	groupName := ctx.UserValue("groupName").(string)
	if len(groupName) == 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetJSONError("group name is required")
		return
	}
	if isInternalGroup(groupName) {
		ctx.Logger.Errorf("group name %s is protected", groupName)
		respondBadRequest(ctx, fmt.Errorf("group name %s is protected", groupName))
		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.Errorf("Error occurred retrieving user session")
		respondInvalidToken(ctx)
		return
	}
	lldapProvider, ok := ctx.Providers.UserProvider.(*authentication.LLDAPUserProvider)
	if !ok {
		message := "LLDAP provider not available"
		ctx.Logger.Errorf(message)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	hasPermission, err := checkGroupModifyPermission(lldapProvider, userSession, groupName)
	if err != nil {
		message := fmt.Sprintf("failed to check permission %v", err)
		ctx.Logger.Errorf(message)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	if !hasPermission {
		respondBadRequest(ctx, fmt.Errorf("you have not permission to modify group %s", groupName))
		return
	}

	err = lldapProvider.DeleteGroup(userSession.AccessToken, groupName)
	if err != nil {
		message := fmt.Sprintf("failed to delete group %v", err)
		ctx.Logger.Errorf(message)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	TopicGroupDeleted.send(ctx, groupName, userSession.Username)
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}
