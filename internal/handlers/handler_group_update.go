package handlers

import (
	"fmt"
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/pkg/errors"
	"github.com/valyala/fasthttp"
)

// UpdateGroup handles PUT requests to update a specific group's attributes.
// PUT /api/groups/{groupName}
func UpdateGroup(ctx *middlewares.AutheliaCtx) {
	bodyJSON := UpdateGroupRequest{}
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
		ctx.Logger.Errorf("group name %s is protected", groupName)
		respondBadRequest(ctx, fmt.Errorf("group name %s is protected", groupName))
		return
	}

	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "update group", err)
		respondBadRequest(ctx, errors.Wrapf(err, "update group"))
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

	err = lldapProvider.UpdateGroup(userSession.AccessToken, groupName, bodyJSON.RemoveAttributes, bodyJSON.InsertAttributes)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to update group %v", err))
		return
	}

	TopicGroupModify.send(ctx, groupName, userSession.Username)
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}
