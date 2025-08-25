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

package application

type ApplicationSettingsSubPolicy struct {
	URI      string `json:"uri"`
	Policy   string `json:"policy"`
	OneTime  bool   `json:"one_time"`
	Duration int32  `json:"valid_duration"`
}

type ApplicationSettingsPolicy struct {
	DefaultPolicy string                          `json:"default_policy"`
	SubPolicies   []*ApplicationSettingsSubPolicy `json:"sub_policies"`
	OneTime       bool                            `json:"one_time"`
	Duration      int32                           `json:"valid_duration"`
}

//	'{
//		"a":
//			{"cert":"certa","key":"keya","ssl_config":"firefox-a-domain-ssl-config",
//				"third_level_domain":"aa","third_party_domain":"adomain"},
//		"b":
//			{"cert":"","key":"","third_level_domain":"","third_party_domain":""}
//	}'
type ApplicationCustomDomain struct {
	Cert             string `json:"cert,omitempty"`
	Key              string `json:"key,omitempty"`
	SSLConfig        string `json:"ssl_config,omitempty"`
	ThirdLevelDomain string `json:"third_level_domain,omitempty"`
	ThirdPartyDomain string `json:"third_party_domain,omitempty"`
}

const ApplicationSettingsPolicyKey = "policy"
const ApplicationSettingsCustomDomainKey = "customDomain"
const ApplicationSettingsDefaultThirdLevelDomainConfigKey = "defaultThirdLevelDomainConfig"

type DefaultThirdLevelDomainConfig struct {
	AppName          string `json:"appName"`
	EntranceName     string `json:"entranceName"`
	ThirdLevelDomain string `json:"thirdLevelDomain"`
}
