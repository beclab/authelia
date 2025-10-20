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

package utils

// BFL user types.
type UserPassword struct {
	UserName string `json:"username,omitempty"`
	Password string `json:"password"`
}

type UserToken struct {
	Token string `json:"token"`
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
	CreatedUser string `json:"created_user"`
	LocalZone   string `json:"-"`
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
