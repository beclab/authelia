package authentication

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/authelia/authelia/v4/generated"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/beclab/lldap-client/pkg/cache"
	"github.com/beclab/lldap-client/pkg/cache/memory"
	"github.com/beclab/lldap-client/pkg/client"
	"github.com/beclab/lldap-client/pkg/config"
	lgenerated "github.com/beclab/lldap-client/pkg/generated"
	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

var InternalGroups = map[string]bool{
	"lldap_admin":           true,
	"lldap_password_manage": true,
	"lldap_strict_readonly": true,
	"lldap_regular":         true,
}

type LLDAPUserProvider struct {
	*LDAPUserProvider
	config     schema.LLDAPAuthenticationBackend
	restClient *resty.Client
	tokenCache cache.TokenCacheInterface
}

func NewLLDAPUserProvider(conf schema.AuthenticationBackend, certPool *x509.CertPool) *LLDAPUserProvider {
	lldapAdminUsername, lldapAdminPassword, err := getLldapCredentials()
	if err != nil {
		klog.Errorf("Failed to get LLDAP credentials: %v", err)
		return nil
	}

	conf.LDAP = &conf.LLDAP.LDAPAuthenticationBackend
	conf.LDAP.User = lldapAdminUsername
	conf.LDAP.Password = lldapAdminPassword

	ldap := NewLDAPUserProvider(conf, certPool)

	p := &LLDAPUserProvider{config: *conf.LLDAP, LDAPUserProvider: ldap, tokenCache: memory.New()}

	p.restClient = resty.New().SetTimeout(5 * time.Second).SetCookieJar(nil)

	return p
}

// CheckUserPassword implements UserProvider.
func (l *LLDAPUserProvider) CheckUserPassword(username string, password string) (valid bool, result *ValidResult, err error) {
	port := 80
	if l.config.Port != nil && *l.config.Port != 0 {
		port = *l.config.Port
	}

	url := fmt.Sprintf("http://%s:%d/auth/user/%s", l.config.Server, port, username)
	userResp, err := l.restClient.R().
		SetHeader(restful.HEADER_ContentType, restful.MIME_JSON).
		Get(url)
	if err != nil {
		return false, nil, errors.Wrapf(ErrSendRequest, "request to lldap user failed %v", err)
	}
	if userResp.StatusCode() != http.StatusOK {
		if userResp.StatusCode() == http.StatusNotFound {
			return false, nil, ErrLLDAPUserNotFound
		}
		return false, nil, errors.Wrapf(ErrLLDAPAuthFailed, "fetch user failed %v", string(userResp.Body()))
	}

	url = fmt.Sprintf("http://%s:%d/auth/simple/login", l.config.Server, port)
	reqBody := LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := l.restClient.R().
		SetHeader(restful.HEADER_ContentType, restful.MIME_JSON).
		SetBody(reqBody).
		SetResult(&LoginResponse{}).
		Post(url)

	if err != nil {
		return false, nil, errors.Wrapf(ErrSendRequest, "request to lldap login failed %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return false, nil, errors.Wrapf(ErrLLDAPAuthFailed, "login failed %v", string(resp.Body()))
	}

	responseData := resp.Result().(*LoginResponse)
	klog.Infof("responseData: %#v", responseData)

	result = &ValidResult{
		AccessToken:  responseData.Token,
		RefreshToken: responseData.RefreshToken,
	}
	return true, result, nil

}

// GetDetails implements UserProvider.
func (l *LLDAPUserProvider) GetDetails(username, token string) (details *UserDetails, err error) {
	info, err := utils.GetUserInfoFromBFL(l.restClient, username)
	if err != nil {
		return nil, err
	}

	if token != "" {
		klog.Info("get user detail from LLDAP")
		url := fmt.Sprintf("http://%s:%d", l.config.Server, *l.config.Port)
		klog.Infof("getDetails:url:%s", url)
		graphqlClient := createGraphClient(url, token)
		var viewerResp *generated.GetUserDetailsResponse
		viewerResp, err = generated.GetUserDetails(context.Background(), graphqlClient, username)
		if err != nil {
			klog.Info("get user detail from lldap error, ", err, ", ", username)
			if strings.Contains(err.Error(), "401 Unauthorized") {
				return nil, ErrUserTokenInvalid
			}
			return nil, err
		}

		groups := []string{info.OwnerRole}
		for _, g := range viewerResp.User.Groups {
			groups = append(groups, g.DisplayName)
		}

		details = &UserDetails{
			Username:    username,
			DisplayName: viewerResp.User.DisplayName,
			Groups:      groups,
			Emails:      []string{viewerResp.User.Email},
			OwnerRole:   info.OwnerRole,
		}

		return details, nil
	} else {
		klog.Info("get user detail from bfl")
		domain := strings.TrimLeft(info.Zone, username+".")

		details = &UserDetails{
			Username:    username,
			DisplayName: username,
			Groups:      []string{info.OwnerRole},
			Emails:      []string{username + "@" + domain}, // FIXME:
			OwnerRole:   info.OwnerRole,
		}

		return details, nil

	}
}

// Refresh implements UserProvider.
func (l *LLDAPUserProvider) Refresh(username string, token, refreshToken string) (*ValidResult, error) {
	port := 80
	if l.config.Port != nil && *l.config.Port != 0 {
		port = *l.config.Port
	}

	url := fmt.Sprintf("http://%s:%d/auth/refresh", l.config.Server, port)

	resp, err := l.restClient.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+token).
		SetHeader("refresh-token", ""+refreshToken).
		SetResult(&RefreshTokenResponse{}).
		Get(url)
	if err != nil {
		klog.Errorf("Error sending POST request: %v", err)
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		klog.Errorf("Error response from server: %s", resp.Body())
		return nil, errors.New(string(resp.Body()))
	}

	if resp.Result() == nil {
		klog.Error("Response result is nil")
		return nil, errors.New("response result is nil")
	}

	refreshTokenResp := resp.Result().(*RefreshTokenResponse)

	return &ValidResult{
		AccessToken:  refreshTokenResp.Token,
		RefreshToken: refreshTokenResp.RefreshToken,
	}, nil
}

func (l *LLDAPUserProvider) ResetPassword(username, oldPassword, newPassword, token string, isAdmin bool) error {
	port := 80
	if l.config.Port != nil && *l.config.Port != 0 {
		port = *l.config.Port
	}
	if !isAdmin {
		valid, err := l.CheckUserPasswordWithoutLogin(username, oldPassword)
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("reset password: verfiy password hash err %v", err)
		}
	}

	url := fmt.Sprintf("http://%s:%d/auth/simple/register", l.config.Server, port)
	resp, err := l.restClient.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+token).
		SetBody(&ResetPasswordRequest{
			Username: username,
			Password: newPassword,
		}).Post(url)
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		klog.Errorf("reset password: response from server: %s", resp.Body())
		return errors.New(string(resp.Body()))
	}
	err = l.RevokeUserToken(username, token)
	if err != nil {
		klog.Errorf("revoke user: %s token failed: %v", username, err)
	}

	return nil
}

func (l *LLDAPUserProvider) RevokeUserToken(username, token string) error {
	port := 80
	if l.config.Port != nil && *l.config.Port != 0 {
		port = *l.config.Port
	}
	url := fmt.Sprintf("http://%s:%d/auth/revoke/%s/token", l.config.Server, port, username)
	resp, err := l.restClient.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+token).Post(url)
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		klog.Errorf("revoke user: response from server: %s", resp.Body())
		return errors.New(string(resp.Body()))
	}
	return nil
}

func (l *LLDAPUserProvider) StartupCheck() (err error) {
	return nil
}

// backend api, list user wuth lldap admin user.
func (l *LLDAPUserProvider) ListUser(ctx context.Context) ([]*UserDetails, error) {
	var users []*UserDetails

	url := fmt.Sprintf("http://%s:%d", l.config.Server, *l.config.Port)
	graphqlClient, err := l.createGraphClientWithUser(url, l.config.User, l.config.Password)
	if err != nil {
		klog.Errorf("Failed to create GraphQL client: %v", err)
		return nil, err
	}

	list, err := generated.ListUsersQuery(ctx, graphqlClient, generated.RequestFilter{})
	if err != nil {
		klog.Errorf("Failed to list users: %v", err)
		return nil, err
	}

	for _, user := range list.GetUsers() {
		users = append(users, &UserDetails{
			Username:    user.DisplayName,
			DisplayName: user.DisplayName,
			Emails:      []string{user.Email},
		})
	}

	return users, nil
}

// CheckUserPasswordWithoutLogin implements UserProvider.
func (l *LLDAPUserProvider) CheckUserPasswordWithoutLogin(username string, password string) (valid bool, err error) {
	port := 80
	if l.config.Port != nil && *l.config.Port != 0 {
		port = *l.config.Port
	}

	url := fmt.Sprintf("http://%s:%d/auth/credentials/verify", l.config.Server, port)
	reqBody := LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := l.restClient.R().
		SetHeader(restful.HEADER_ContentType, restful.MIME_JSON).
		SetBody(reqBody).
		SetResult(&CredentialVerifyResponse{}).
		Post(url)

	if err != nil {
		return false, err
	}

	if resp.StatusCode() != http.StatusOK {
		return false, errors.New(string(resp.Body()))
	}

	responseData := resp.Result().(*CredentialVerifyResponse)
	klog.Infof("responseData: %#v", responseData)

	return responseData.Valid, nil

}

func (l *LLDAPUserProvider) SignToken(token string) (*ValidResult, error) {
	port := 80
	if l.config.Port != nil && *l.config.Port != 0 {
		port = *l.config.Port
	}

	url := fmt.Sprintf("http://%s:%d/auth/sign/token", l.config.Server, port)

	resp, err := l.restClient.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+token).
		SetResult(&RefreshTokenResponse{}).
		Post(url)
	if err != nil {
		klog.Errorf("Error sending POST request: %v", err)
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		klog.Errorf("Error response from server: %s", resp.Body())
		return nil, errors.New(string(resp.Body()))
	}

	if resp.Result() == nil {
		klog.Error("Response result is nil")
		return nil, errors.New("response result is nil")
	}

	refreshTokenResp := resp.Result().(*RefreshTokenResponse)

	return &ValidResult{
		AccessToken:  refreshTokenResp.Token,
		RefreshToken: refreshTokenResp.RefreshToken,
	}, nil
}

var _ UserProvider = &LLDAPUserProvider{}

func createGraphClient(base_url, token string) graphql.Client {
	httpClient := http.Client{
		Transport: &authedTransport{
			key:     token,
			wrapped: http.DefaultTransport,
		},
	}
	return graphql.NewClient(base_url+"/api/graphql", &httpClient)
}

func (l *LLDAPUserProvider) createGraphClientWithUser(base_url, user, password string) (graphql.Client, error) {
	lldapClient, err := client.New(&config.Config{
		Host:       base_url,
		Username:   user,
		Password:   password,
		TokenCache: l.tokenCache,
	})
	if err != nil {
		return nil, err
	}
	return lldapClient, nil
}

func getLldapCredentials() (username, password string, err error) {
	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		klog.Errorf("Failed to get kube config: %v", err)
		return "", "", err
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		klog.Errorf("Failed to create kubernetes client: %v", err)
		return "", "", err
	}

	secret, err := clientSet.CoreV1().Secrets("os-platform").Get(context.TODO(), "lldap-credentials", metav1.GetOptions{})
	if err != nil {
		klog.Errorf("Failed to get lldap credentials: %v", err)
		return "", "", err
	}

	bindUsername, err := getCredentialVal(secret, "lldap-ldap-user-dn")
	if err != nil {
		klog.Errorf("Failed to get bind username: %v", err)
		return "", "", err
	}
	bindPassword, err := getCredentialVal(secret, "lldap-ldap-user-pass")
	if err != nil {
		klog.Errorf("Failed to get bind password: %v", err)
		return "", "", err
	}

	return bindUsername, bindPassword, nil
}

func getCredentialVal(secret *corev1.Secret, key string) (string, error) {
	if value, ok := secret.Data[key]; ok {
		return string(value), nil
	}
	return "", fmt.Errorf("can not find credentialval for key %s", key)
}

type GroupListOptions struct {
	Username  string
	OwnerRole string
}

func (glo *GroupListOptions) filterGroup(groups []lgenerated.GetGroupListGroupsGroup) []lgenerated.GetGroupListGroupsGroup {
	filtered := make([]lgenerated.GetGroupListGroupsGroup, 0)
	for _, group := range groups {
		if !InternalGroups[group.DisplayName] {
			filtered = append(filtered, group)
		}
	}
	if glo.OwnerRole == "owner" {
		return filtered
	}
	if glo.Username == "" {
		return []lgenerated.GetGroupListGroupsGroup{}
	}
	fGroups := make([]lgenerated.GetGroupListGroupsGroup, 0)
	for _, group := range filtered {
		if getCreatorFromAttributes(group.Attributes) == glo.Username {
			fGroups = append(fGroups, group)
			continue
		}
		for _, user := range group.Users {
			if glo.Username == user.Id {
				fGroups = append(fGroups, group)
				break
			}
		}
	}
	return fGroups

}

func (l *LLDAPUserProvider) GroupList(token string, opts *GroupListOptions) ([]lgenerated.GetGroupListGroupsGroup, error) {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return nil, err
	}
	g, err := qClient.Groups().List(context.TODO())
	if err != nil {
		return nil, err
	}
	if opts == nil {
		return g, nil
	}
	groups := opts.filterGroup(g)
	return groups, nil

}

func (l *LLDAPUserProvider) CreateGroup(token, groupName, creator string) error {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return err
	}
	_, err = qClient.Groups().Create(context.TODO(), groupName, creator)
	if err != nil {
		return err
	}
	return nil
}

func (l *LLDAPUserProvider) GetGroup(token, groupName string) (*lgenerated.GetGroupDetailsByNameGroupByNameGroup, error) {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return nil, err
	}
	resp, err := qClient.Groups().GetByName(context.TODO(), groupName)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (l *LLDAPUserProvider) AddUserToGroup(token, username, groupName string) error {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return err
	}
	group, err := qClient.Groups().GetByName(context.TODO(), groupName)
	if err != nil {
		return err
	}
	err = qClient.Groups().AddUser(context.TODO(), username, group.Id)
	if err != nil {
		return err
	}
	return nil
}

func (l *LLDAPUserProvider) RemoveUserFromGroup(token, username, groupName string) error {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return err
	}
	group, err := qClient.Groups().GetByName(context.TODO(), groupName)
	if err != nil {
		return err
	}
	err = qClient.Groups().RemoveUser(context.TODO(), username, group.Id)
	if err != nil {
		return err
	}
	return nil
}

func (l *LLDAPUserProvider) DeleteGroup(token, groupName string) error {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return err
	}
	group, err := qClient.Groups().GetByName(context.TODO(), groupName)
	if err != nil {
		return err
	}

	_, err = qClient.Groups().Delete(context.TODO(), group.Id)
	if err != nil {
		return err
	}
	return nil
}

func (l *LLDAPUserProvider) UpdateGroup(token, groupName string, removeAttributes []string, insertAttributes []lgenerated.AttributeValueInput) error {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return err
	}
	group, err := qClient.Groups().GetByName(context.TODO(), groupName)
	if err != nil {
		return err
	}
	updateInput := lgenerated.UpdateGroupInput{
		Id:               group.Id,
		DisplayName:      groupName,
		RemoveAttributes: removeAttributes,
		InsertAttributes: insertAttributes,
	}
	err = qClient.Groups().Update(context.TODO(), updateInput)
	if err != nil {
		klog.Errorf("failed to update group %v", err)
		return err
	}
	return nil
}
func (l *LLDAPUserProvider) CreateGroupAttribute(token, name string, attributeType lgenerated.AttributeType, isList, isVisible bool) error {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return err
	}

	err = qClient.Groups().CreateAttribute(context.TODO(), name, attributeType, isList, isVisible)
	if err != nil {
		return err
	}
	return nil
}

func (l *LLDAPUserProvider) GetGroupAttributeSchema(token string) (*lgenerated.GetGroupAttributesSchemaResponse, error) {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return nil, err
	}

	resp, err := qClient.Groups().GetAttributeSchema(context.TODO())
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (l *LLDAPUserProvider) DeleteGroupAttributeSchema(token string, name string) error {
	qClient, err := l.createGraphqlClient(token)
	if err != nil {
		return err
	}

	err = qClient.Groups().DeleteAttribute(context.TODO(), name)
	if err != nil {
		return err
	}
	return nil
}

func (l *LLDAPUserProvider) createGraphqlClient(token string) (*client.Client, error) {
	if token == "" {
		return nil, errors.New("create graphql client invalid token")
	}
	host := fmt.Sprintf("http://%s:%d", l.config.Server, *l.config.Port)
	cfg := config.Config{
		Host:        host,
		BearerToken: token,
	}
	qClient, err := client.New(&cfg)
	if err != nil {
		return nil, err
	}
	return qClient, nil
}

func getCreatorFromAttributes(attributes []lgenerated.GetGroupListGroupsGroupAttributesAttributeValue) string {
	for _, attr := range attributes {
		if attr.Name == "creator" && len(attr.Value) > 0 {
			return attr.Value[0]
		}
	}
	return ""
}
