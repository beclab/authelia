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

package terminus

import (
	"time"

	"github.com/pquerna/otp/hotp"
	"k8s.io/klog/v2"
)

func NewOTPConfig(username, email string) (*TPOTPConfig, error) {
	key, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      username,
		AccountName: email,
	})

	if err != nil {
		return nil, err
	}

	return &TPOTPConfig{
		key:        key,
		expireTime: time.Now(), // initialized, no exists valid code.
		counter:    0,
	}, nil
}

func (c *TPOTPConfig) GenerateCode() (string, error) {
	code, err := hotp.GenerateCode(c.key.Secret(), c.counter+1)
	if err != nil {
		klog.Errorf("generate 2fa code for user % error, %s", c.key.Issuer(), err)
		return "", err
	}

	c.expireTime = time.Now().Add(DefaultOtpTTL)
	c.counter++

	return code, nil
}

func (c *TPOTPConfig) ValidateCode(code string) bool {
	if c.expireTime.Before(time.Now()) {
		return false
	}

	return hotp.Validate(code, c.counter, c.key.Secret())
}

func SendCodeToNnotification(code string) error {
	klog.Info("valid code: ", code)
	return nil
}
