package authentication

import (
	"context"
	"crypto/x509"
	"errors"
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
	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

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

	url := fmt.Sprintf("http://%s:%d/auth/simple/login", l.config.Server, port)
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
		return false, nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return false, nil, errors.New(string(resp.Body()))
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
		valid, _, err := l.CheckUserPassword(username, oldPassword)
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
