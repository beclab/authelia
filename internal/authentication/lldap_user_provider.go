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
	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
	"k8s.io/klog/v2"
)

type LLDAPUserProvider struct {
	*LDAPUserProvider
	config     schema.LLDAPAuthenticationBackend
	restClient *resty.Client
}

func NewLLDAPUserProvider(conf schema.AuthenticationBackend, certPool *x509.CertPool) *LLDAPUserProvider {
	conf.LDAP = &conf.LLDAP.LDAPAuthenticationBackend
	ldap := NewLDAPUserProvider(conf, certPool)

	p := &LLDAPUserProvider{config: *conf.LLDAP, LDAPUserProvider: ldap}

	p.restClient = resty.New().SetTimeout(5 * time.Second)

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
		SetBody(&RefreshTokenResponse{}).
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

func (l *LLDAPUserProvider) StartupCheck() (err error) {
	return nil
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
