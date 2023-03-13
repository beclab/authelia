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
	"crypto/rand"
	"encoding/base32"
	"testing"

	"github.com/test-go/testify/assert"
)

func TestGenerate(t *testing.T) {
	config, err := NewOTPConfig("liuyu", "l@l.com")
	assert.NoError(t, err)

	code, err := config.GenerateCode()
	assert.NoError(t, err)

	t.Log(code)
	t.Log(config.key.Secret())
}

func TestRand(t *testing.T) {
	secret := make([]byte, 10)
	_, err := rand.Reader.Read(secret)
	assert.NoError(t, err)

	var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

	t.Log(b32NoPadding.EncodeToString(secret))
	_, err = rand.Reader.Read(secret)
	assert.NoError(t, err)

	t.Log(b32NoPadding.EncodeToString(secret))
}
