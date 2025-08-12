package handlers

import (
	"errors"
	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/session"
	lgenerated "github.com/beclab/lldap-client/pkg/generated"
)

func isInternalGroup(name string) bool {
	return authentication.InternalGroups[name]
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
