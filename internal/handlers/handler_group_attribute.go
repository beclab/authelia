package handlers

import (
	"fmt"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/session"
	lgenerated "github.com/beclab/lldap-client/pkg/generated"
	"github.com/pkg/errors"
	"github.com/valyala/fasthttp"
)

// CreateGroupAttribute handles POST requests to create a new group attribute schema.
// POST /api/groups/attributes/schema
func CreateGroupAttribute(ctx *middlewares.AutheliaCtx) {
	bodyJSON := CreateGroupAttributeRequest{}

	var (
		userSession session.UserSession
		err         error
	)
	if err = ctx.ParseBody(&bodyJSON); err != nil {
		ctx.Logger.Errorf(logFmtErrParseRequestBody, "create group attribute", err)
		respondBadRequest(ctx, errors.Wrapf(err, "create group attribute"))
		return
	}

	if bodyJSON.Name == "" {
		respondBadRequest(ctx, errors.New("attribute name is required"))
		return
	}

	if isInternalAttributeSchema(bodyJSON.Name) {
		respondBadRequest(ctx, errors.Errorf("group attribute %s is internal group attribute schema", bodyJSON.Name))
		return
	}

	if bodyJSON.AttributeType != lgenerated.AttributeTypeString &&
		bodyJSON.AttributeType != lgenerated.AttributeTypeInteger &&
		bodyJSON.AttributeType != lgenerated.AttributeTypeDateTime &&
		bodyJSON.AttributeType != lgenerated.AttributeTypeJpegPhoto {

		respondBadRequest(ctx, errors.New("invalid group attribute type"))
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
	err = lldapProvider.CreateGroupAttribute(userSession.AccessToken, bodyJSON.Name, bodyJSON.AttributeType,
		bodyJSON.IsList, bodyJSON.IsVisible)
	if err != nil {
		message := fmt.Sprintf("failed to create group attribute %v", err)
		ctx.Logger.Errorf(message)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}

// GetGroupAttributeSchema handles GET requests to retrieve group attribute schema.
// GET /api/groups/attributes/schema
func GetGroupAttributeSchema(ctx *middlewares.AutheliaCtx) {
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
		message := "LLDAP provider not available"
		ctx.Logger.Errorf(message)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	resp, err := lldapProvider.GetGroupAttributeSchema(userSession.AccessToken)
	if err != nil {
		message := fmt.Sprintf("failed to get group attribute schema %v", err)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	if err = ctx.SetJSONBody(resp); err != nil {
		message := fmt.Sprintf("failed to set group attribute schema json body %v", err)
		ctx.Logger.Errorf(message)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}

// DeleteGroupAttributeSchema handles DELETE requests to delete a group attribute schema.
// DELETE /api/groups/attributes/schema/{name}
func DeleteGroupAttributeSchema(ctx *middlewares.AutheliaCtx) {
	var (
		userSession session.UserSession
		err         error
	)

	name := ctx.UserValue("name").(string)

	if isInternalAttributeSchema(name) {
		respondBadRequest(ctx, fmt.Errorf("group attribute %s can not be deleted", name))
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
	err = lldapProvider.DeleteGroupAttributeSchema(userSession.AccessToken, name)
	if err != nil {
		message := fmt.Sprintf("failed to delete group attribute schema %v", err)
		ctx.Logger.Errorf(message)
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, message)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}
