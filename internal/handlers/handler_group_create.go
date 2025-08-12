package handlers

import (
	"fmt"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/pkg/errors"
	"github.com/valyala/fasthttp"
)

// CreateGroup handles POST requests to create a new group.
// POST /api/groups
func CreateGroup(ctx *middlewares.AutheliaCtx) {
	bodyJSON := CreateGroupRequest{}

	var (
		userSession session.UserSession
		err         error
	)

	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "create group", err)
		respondBadRequest(ctx, errors.Wrapf(err, "parse create group body err"))
		return
	}
	if bodyJSON.Name == "" {
		ctx.Logger.Errorf("empty group name")
		respondBadRequest(ctx, errors.New("group name is required"))
		return
	}

	if isInternalGroup(bodyJSON.Name) {
		ctx.Logger.Errorf("group name %s is reserved", bodyJSON.Name)
		respondBadRequest(ctx, fmt.Errorf("group name %s is reserved", bodyJSON.Name))
		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.Errorf("Error occurred retrieving user session")
		respondInvalidToken(ctx)
		return
	}

	if !canCreateGroup(userSession.OwnerRole) {
		respondBadRequest(ctx, fmt.Errorf("role %s no permission to create group", userSession.OwnerRole))
		return
	}

	lldapProvider, ok := ctx.Providers.UserProvider.(*authentication.LLDAPUserProvider)
	if !ok {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, "LLDAP provider not available")
		return
	}

	groups, err := lldapProvider.GroupList(userSession.AccessToken, nil)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get group list %v", err))
		return
	}
	isAlreadyExists := false
	for _, group := range groups {
		if group.DisplayName == bodyJSON.Name {
			isAlreadyExists = true
			break
		}
	}
	if isAlreadyExists {
		message := fmt.Sprintf("group name %s already exists", bodyJSON.Name)
		respondWithStatusCode(ctx, fasthttp.StatusBadRequest, message)
		return
	}

	err = lldapProvider.CreateGroup(userSession.AccessToken, bodyJSON.Name, userSession.Username)
	if err != nil {
		message := fmt.Sprintf("failed to create group %s,err %v", bodyJSON.Name, err)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	TopicGroupCreated.send(ctx, bodyJSON.Name, userSession.Username)

	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}
