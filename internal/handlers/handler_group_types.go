package handlers

import lgenerated "github.com/beclab/lldap-client/pkg/generated"

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleNormal = "normal"
)

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
