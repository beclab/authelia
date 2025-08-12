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

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleNormal = "normal"
)

var internalGroups = map[string]bool{
	"lldap_admin":           true,
	"lldap_password_manage": true,
	"lldap_strict_readonly": true,
	"lldap_regular":         true,
}

var internalAttributeSchema = map[string]bool{
	"creation_date": true,
	"display_name":  true,
	"group_id":      true,
	"uuid":          true,
}

type CreateGroupRequest struct {
	Name string `json:"name"`
}

type AddUserToGroupRequest struct {
	Username string `json:"username"`
}

type RemoveUserFromGroupRequest struct {
	Username string `json:"username"`
}

type UpdateGroupRequest struct {
	RemoveAttributes []string                         `json:"removeAttributes"`
	InsertAttributes []lgenerated.AttributeValueInput `json:"insertAttributes"`
}

type CreateGroupAttributeRequest struct {
	Name          string                   `json:"name"`
	AttributeType lgenerated.AttributeType `json:"attributeType"`
	IsList        bool                     `json:"isList"`
	IsVisible     bool                     `json:"isVisible"`
}

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

	err = lldapProvider.AddUserToGroup(userSession.AccessToken, bodyJSON.Username, groupName)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to add user to group %v", err))
		return
	}
	TopicGroupAddUser.send(ctx, groupName, userSession.Username, map[string]interface{}{
		"user": bodyJSON.Username,
	})
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}

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

	err = lldapProvider.DeleteGroup(userSession.AccessToken, groupName)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to delete group %v", err))
		return
	}
	TopicGroupDeleted.send(ctx, groupName, userSession.Username)
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}

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
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, "LLDAP provider not available")
		return
	}
	err = lldapProvider.CreateGroupAttribute(userSession.AccessToken, bodyJSON.Name, bodyJSON.AttributeType,
		bodyJSON.IsList, bodyJSON.IsVisible)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to create group attribute %v", err))
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
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, "LLDAP provider not available")
		return
	}
	resp, err := lldapProvider.GetGroupAttributeSchema(userSession.AccessToken)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to get group attribute schema %v", err))
		return
	}
	if err = ctx.SetJSONBody(resp); err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to set group attribute schema json body %v", err))
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
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, "LLDAP provider not available")
		return
	}
	err = lldapProvider.DeleteGroupAttributeSchema(userSession.AccessToken, name)
	if err != nil {
		respondWithStatusCode(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("failed to delete group attribute schema %v", err))
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	return
}

func isInternalGroup(name string) bool {
	return internalGroups[name]
}

func canCreateGroup(role string) bool {
	return role == RoleOwner || role == RoleAdmin
}

func isInternalAttributeSchema(name string) bool {
	return internalAttributeSchema[name]
}

func getCreatorFromAttributes(attributes []lgenerated.GetGroupDetailsByNameGroupByNameGroupAttributesAttributeValue) string {
	for _, attr := range attributes {
		if attr.Name == "creator" && len(attr.Value) > 0 {
			return attr.Value[0]
		}
	}
	return ""
}

// canModifyGroup checks if the user has permission to modify the group
func canModifyGroup(userRole, username, groupCreator string) bool {
	if userRole == RoleOwner {
		return true
	}
	if userRole == RoleAdmin || userRole == RoleNormal {
		return username == groupCreator
	}
	return false
}

func checkGroupModifyPermission(lldapProvider *authentication.LLDAPUserProvider, userSession session.UserSession, groupName string) (bool, error) {
	group, err := lldapProvider.GetGroup(userSession.AccessToken, groupName)
	if err != nil {
		return false, err
	}

	groupCreator := getCreatorFromAttributes(group.Attributes)
	if !canModifyGroup(userSession.OwnerRole, userSession.Username, groupCreator) {
		return false, errors.New("no permission to modify group")
	}

	return true, nil
}
