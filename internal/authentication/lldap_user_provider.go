package authentication

import (
	"context"
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
	config     schema.LLDAPAuthenticationBackend
	restClient *resty.Client
}

func NewLLDAPUserProvider(conf schema.LLDAPAuthenticationBackend) *LLDAPUserProvider {
	p := &LLDAPUserProvider{config: conf}

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
		SetResult(&utils.Response{Data: &utils.TokenResponse{}}).
		Post(url)

	if err != nil {
		return false, nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return false, nil, errors.New(string(resp.Body()))
	}

	responseData := resp.Result().(*utils.Response)

	if responseData.Code != 0 {
		switch responseData.Code {
		case http.StatusBadRequest:
			return false, nil, ErrInvalidUserPwd
		case http.StatusTooManyRequests:
			return false, nil, ErrTooManyRetries
		}
		return false, nil, errors.New(responseData.Message)
	}

	tokens := responseData.Data.(*LoginResponse)
	result = &ValidResult{
		AccessToken:  tokens.Token,
		RefreshToken: tokens.RefreshToken,
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
		graphqlClient := createGraphClient(l.config.Server, token)
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
func (l *LLDAPUserProvider) Refresh(username string, token string) (*ValidResult, error) {
	panic("unimplemented")
}

// StartupCheck implements UserProvider.
func (l *LLDAPUserProvider) StartupCheck() (err error) {
	panic("unimplemented")
}

// UpdatePassword implements UserProvider.
func (l *LLDAPUserProvider) UpdatePassword(username string, accessToken string, newPassword string) (err error) {
	panic("unimplemented")
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
