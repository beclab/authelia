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
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
	"github.com/jellydator/ttlcache/v3"

	"github.com/authelia/authelia/v4/internal/utils"
)

const (
	TokenCacheTTL      = 2 * time.Hour
	TokenCacheCapacity = 1000
)

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
	loginUrl := fmt.Sprintf("http://%s/bfl/iam/v1alpha1/login", utils.BFL)

	reqBody := utils.UserPassword{
		UserName: username,
		Password: password,
	}

	resp, err := p.client.R().
		SetHeader(restful.HEADER_ContentType, restful.MIME_JSON).
		SetBody(reqBody).
		SetResult(&utils.Response{Data: &utils.TokenResponse{}}).
		Post(loginUrl)

	if err != nil {
		return false, nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return false, nil, errors.New(string(resp.Body()))
	}

	responseData := resp.Result().(*utils.Response)

	if responseData.Code != 0 {
		return false, nil, errors.New(responseData.Message)
	}

	tokens := responseData.Data.(*utils.TokenResponse)
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
		info, err := utils.GetUserInfoFromBFL(p.client)
		if err != nil {
			return nil, err
		}

		details := &UserDetails{
			Username:    username,
			DisplayName: username,
			Groups:      []string{info.OwnerRole},
		}

		return details, nil
	} else {
		userUrl := fmt.Sprintf("http://%s/bfl/iam/v1alpha1/users/%s", utils.BFL, username)

		resp, err := p.client.R().
			SetHeader(restful.HEADER_Accept, restful.MIME_JSON).
			SetHeader("X-Authorization", token.Value().token).
			SetResult(&utils.Response{Data: &utils.UserDetail{}}).
			Get(userUrl)

		if err != nil {
			return nil, err
		}

		if resp.StatusCode() != http.StatusOK {
			return nil, errors.New(string(resp.Body()))
		}

		responseData := resp.Result().(*utils.Response)

		if responseData.Code != 0 {
			return nil, errors.New(responseData.Message)
		}

		d := responseData.Data.(*utils.UserDetail)

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

	userUrl := fmt.Sprintf("http://%s/bfl/iam/v1alpha1/users/%s/password", utils.BFL, username)
	reset := utils.PasswordReset{
		CurrentPassword: cache.Value().pwd,
		Password:        newPassword,
	}

	resp, err := p.client.R().
		SetHeader(restful.HEADER_Accept, restful.MIME_JSON).
		SetHeader("X-Authorization", cache.Value().token).
		SetResult(&utils.Response{}).
		SetBody(reset).
		Put(userUrl)
	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		return errors.New(string(resp.Body()))
	}

	responseData := resp.Result().(*utils.Response)

	if responseData.Code != 0 {
		return errors.New(responseData.Message)
	}

	return nil
}

func (p *KubesphereUserProvider) StartupCheck() (err error) {
	return nil
}

func (p *KubesphereUserProvider) Logout(token string) (err error) {
	logoutUrl := fmt.Sprintf("http://%s/bfl/iam/v1alpha1/logout", utils.BFL)
	resp, err := p.client.R().
		SetHeader(restful.HEADER_Accept, restful.MIME_JSON).
		SetHeader("X-Authorization", token).
		SetResult(&utils.Response{}).
		Post(logoutUrl)

	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusOK {
		return errors.New(string(resp.Body()))
	}

	responseData := resp.Result().(*utils.Response)

	if responseData.Code != 0 {
		return errors.New(responseData.Message)
	}

	return nil
}
