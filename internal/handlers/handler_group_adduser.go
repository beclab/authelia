package handlers

import (
	"fmt"
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/pkg/errors"
	"github.com/valyala/fasthttp"
)

// AddUserToGroup handles POST requests to add a user to a specific group.
// POST /api/groups/{groupName}/users
func AddUserToGroup(ctx *middlewares.AutheliaCtx) {
	bodyJSON := AddUserToGroupRequest{}
	var (
		userSession session.UserSession
		err         error
	)
	groupName := ctx.UserValue("groupName").(string)
	if len(groupName) == 0 {
		respondBadRequest(ctx, errors.New("group name is required"))
		return
	}

	if isInternalGroup(groupName) {
		respondBadRequest(ctx, fmt.Errorf("can not add user to group %s", groupName))
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

	err = lldapProvider.AddUserToGroup(userSession.AccessToken, bodyJSON.Username, groupName)
	if err != nil {
		message := fmt.Sprintf("failed to add user to group %v", err)
		ctx.Logger.Errorf(message)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	TopicGroupAddUser.send(ctx, groupName, userSession.Username, map[string]interface{}{
		"user": bodyJSON.Username,
	})
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}
