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

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"github.com/go-resty/resty/v2"
)

func GetUserInfoFromBFL(client *resty.Client) (*UserInfo, error) {
	userUrl := fmt.Sprintf("http://%s/bfl/backend/v1/user-info", BFL)
	resp, err := client.R().
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

	return responseData.Data.(*UserInfo), nil
}
