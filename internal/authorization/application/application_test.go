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

import (
	"encoding/json"
	"testing"

	"k8s.io/klog/v2"
)

func TestJson(t *testing.T) {
	v := `{"default_policy":"","one_time":false,"sub_policies":[{"one_time":false,"policy":"public","uri":"/resources/Home/Pictures/Upload/8de9868667034b6e906597404806d0f6.jpg","valid_duration":0},{"one_time":false,"policy":"public","uri":"/resources/Home/Pictures/Upload/175d434d182744b69a65cc79e1549e81.jpg","valid_duration":0}],"valid_duration":0}`
	var p ApplicationSettingsPolicy
	err := json.Unmarshal([]byte(v), &p)
	if err != nil {
		klog.Error(err)
		t.Fail()
		return
	}

}
