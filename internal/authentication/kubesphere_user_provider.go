// Copyright 2023 bytetrade
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authentication

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
	"github.com/jellydator/ttlcache/v3"
)

var (
	BFL = "bfl"
)

const (
	TokenCacheTTL      = 2 * time.Hour
	TokenCacheCapacity = 1000
)

func init() {
	envBfl := os.Getenv("BFL")
	if envBfl != "" {
		BFL = envBfl
	}
}

// BFL user types.
type UserPassword struct {
	UserName string `json:"username,omitempty"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
}

type UserInfo struct {
	Name        string `json:"name"`
	OwnerRole   string `json:"owner_role"`
	DID         string `json:"did"`
	IsEphemeral bool   `json:"is_ephemeral"`
	Zone        string `json:"zone"`
}

type UserDetail struct {
	UID               string `json:"uid"`
	Name              string `json:"name"`
	DisplayName       string `json:"display_name"`
	Description       string `json:"description"`
	Email             string `json:"email"`
	State             string `json:"state"`
	LastLoginTime     *int64 `json:"last_login_time"`
	CreationTimestamp int64  `json:"creation_timestamp"`

	DID            string `json:"did"`
	WizardComplete bool   `json:"wizard_complete"`

	Roles []string `json:"roles"`
}

type PasswordReset struct {
	CurrentPassword string `json:"current_password"`
	Password        string `json:"password"`
}

// BFL http types.
type Header struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Header

	Data any `json:"data,omitempty"` // data field, optional, object or list.
}

type UserCache struct {
	token string
	pwd   string
}

type KubesphereUserProvider struct {
	client *resty.Client
	cache  *ttlcache.Cache[string, UserCache]
}

func NewKubesphereUserProvider() *KubesphereUserProvider {
	return &KubesphereUserProvider{
		client: resty.New().SetTimeout(2 * time.Second),
		cache: ttlcache.New(
			ttlcache.WithTTL[string, UserCache](TokenCacheTTL),
			ttlcache.WithCapacity[string, UserCache](TokenCacheCapacity), // max online client 1000.
		),
	}
}

func (p *KubesphereUserProvider) CheckUserPassword(username string, password string) (match bool, res *ValidResult, err error) {
	loginUrl := fmt.Sprintf("http://%s/bfl/iam/v1alpha1/login", BFL)

	reqBody := UserPassword{
		UserName: username,
		Password: password,
	}

	resp, err := p.client.R().
		SetHeader(restful.HEADER_ContentType, restful.MIME_JSON).
		SetBody(reqBody).
		SetResult(&Response{Data: &TokenResponse{}}).
		Post(loginUrl)

	if err != nil {
		return false, nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return false, nil, errors.New(string(resp.Body()))
	}

	responseData := resp.Result().(*Response)

	if responseData.Code != 0 {
		return false, nil, errors.New(responseData.Message)
	}

	tokens := responseData.Data.(*TokenResponse)
	res = &ValidResult{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}

	p.cache.Set(username, UserCache{tokens.AccessToken, password}, TokenCacheTTL)

	return true, res, nil
}

func (p *KubesphereUserProvider) GetDetails(username string) (details *UserDetails, err error) {
	token := p.cache.Get(username)
	if token == nil {
		userUrl := fmt.Sprintf("http://%s/bfl/backend/v1/user-info", BFL)
		resp, err := p.client.R().
			SetHeader(restful.HEADER_Accept, restful.MIME_JSON).
			SetResult(&Response{Data: &UserInfo{}}).
			Get(userUrl)

		if err != nil {
			return nil, err
		}

		if resp.StatusCode() != http.StatusOK {
			return nil, errors.New(string(resp.Body()))
		}

		responseData := resp.Result().(*Response)

		if responseData.Code != 0 {
			return nil, errors.New(responseData.Message)
		}

		info := responseData.Data.(*UserInfo)

		details := &UserDetails{
			Username:    username,
			DisplayName: username,
			Groups:      []string{info.OwnerRole},
		}

		return details, nil
	} else {
		userUrl := fmt.Sprintf("http://%s/bfl/iam/v1alpha1/users/%s", BFL, username)

		resp, err := p.client.R().
			SetHeader(restful.HEADER_Accept, restful.MIME_JSON).
			SetHeader("X-Authorization", token.Value().token).
			SetResult(&Response{Data: &UserDetail{}}).
			Get(userUrl)

		if err != nil {
			return nil, err
		}

		if resp.StatusCode() != http.StatusOK {
			return nil, errors.New(string(resp.Body()))
		}

		responseData := resp.Result().(*Response)

		if responseData.Code != 0 {
			return nil, errors.New(responseData.Message)
		}

		d := responseData.Data.(*UserDetail)

		details := &UserDetails{
			Username:    username,
			DisplayName: username,
			Emails:      []string{d.Email},
			Groups:      d.Roles,
		}

		return details, nil
	}
}

// UpdatePassword update the password of the given user.
func (p *KubesphereUserProvider) UpdatePassword(username string, newPassword string) (err error) {
	cache := p.cache.Get(username)
	if cache == nil {
		return ErrUserNotFound
	}

	userUrl := fmt.Sprintf("http://%s/bfl/iam/v1alpha1/users/%s/password", BFL, username)
	reset := PasswordReset{
		CurrentPassword: cache.Value().pwd,
		Password:        newPassword,
	}

	resp, err := p.client.R().
		SetHeader(restful.HEADER_Accept, restful.MIME_JSON).
		SetHeader("X-Authorization", cache.Value().token).
		SetResult(&Response{}).
		SetBody(reset).
		Put(userUrl)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		return errors.New(string(resp.Body()))
	}

	responseData := resp.Result().(*Response)

	if responseData.Code != 0 {
		return errors.New(responseData.Message)
	}

	return nil
}

func (p *KubesphereUserProvider) StartupCheck() (err error) {
	return nil
}
