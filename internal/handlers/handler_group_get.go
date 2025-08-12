package handlers

import (
	"fmt"
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/valyala/fasthttp"
)

// GetGroup handles GET requests to retrieve details of a specific group.
// GET /api/groups/{groupName}
func GetGroup(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession
		err         error
	)
	groupName := ctx.UserValue("groupName").(string)

	if isInternalGroup(groupName) {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
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
	group, err := lldapProvider.GetGroup(userSession.AccessToken, groupName)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to list group err %v", err))
		return
	}
	creator := getCreatorFromAttributes(group.Attributes)
	if userSession.Username != creator && userSession.OwnerRole != RoleOwner {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	if err = ctx.SetJSONBody(group); err != nil {
		ctx.Logger.Errorf("unable to set groups response in body %v", err)
	}
	return
}
