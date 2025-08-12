package handlers

import (
	"fmt"
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/pkg/errors"
	"github.com/valyala/fasthttp"
)

// RemoveUserFromGroup handles DELETE requests to remove a user from a specific group.
// DELETE /api/groups/{groupName}/users
func RemoveUserFromGroup(ctx *middlewares.AutheliaCtx) {
	bodyJSON := RemoveUserFromGroupRequest{}
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
		respondBadRequest(ctx, fmt.Errorf("can not remove user from group %s", groupName))
		return
	}

	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "add user to group", err)
		respondBadRequest(ctx, errors.Wrapf(err, "parse add user to group body err"))
		return
	}
	if bodyJSON.Username == "" {
		respondBadRequest(ctx, errors.New("username is required"))
		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.Errorf("Error occurred retrieving user session")
		respondInvalidToken(ctx)
		return
	}
	lldapProvider, ok := ctx.Providers.UserProvider.(*authentication.LLDAPUserProvider)
	if !ok {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, "LLDAP provider not available")
		return
	}

	hasPermission, err := checkGroupModifyPermission(lldapProvider, userSession, groupName)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to check permission %v", err))
		return
	}
	if !hasPermission {
		respondBadRequest(ctx, fmt.Errorf("you have not permission to modify group %s", groupName))
		return
	}

	err = lldapProvider.RemoveUserFromGroup(userSession.AccessToken, bodyJSON.Username, groupName)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to add user to group %v", err))
		return
	}
	TopicGroupRemoveUser.send(ctx, groupName, userSession.Username, map[string]interface{}{
		"user": bodyJSON.Username,
	})

	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}
