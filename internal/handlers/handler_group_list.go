package handlers

import (
	"fmt"
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/valyala/fasthttp"
)

// GroupList handles GET requests to retrieve a list of groups.
// GET /api/groups
func GroupList(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession
		err         error
	)
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
	groups, err := lldapProvider.GroupList(userSession.AccessToken, &authentication.GroupListOptions{
		OwnerRole: userSession.OwnerRole,
		Username:  userSession.Username,
	})
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to list group err %v", err))
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	if err = ctx.SetJSONBody(groups); err != nil {
		ctx.Logger.Errorf("unable to set groups response in body %v", err)
	}
	return
}
