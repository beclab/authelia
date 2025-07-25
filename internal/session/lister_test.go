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

package session

import (
	"encoding/json"
	"testing"

	"github.com/fasthttp/session/v2"
	"k8s.io/klog/v2"
)

func TestDecode(t *testing.T) {
	s := NewEncryptingSerializer("KLOSduGr3S4RobhU")

	var sess session.Dict
	err := s.Decode(&sess, []byte("\x0f?\xda\xc6@\x99\xca\x86@\xc5I\xa9\x14\xa8=\x8dZy4\xeb\x99\xa3I\xa7\x0b\x7f\x81\xc7hC\"\xf0\xb6f\x18\n\xe5\x01\xfaI\"\x9fA\x16C\x84`\xbcl\x14'o-^\xdf\xd5\xa02TH\x1ev\nT\xcek\xfe\xb8\x92\x83j\xee\xa8V_=\xc7\xbb\x0c\x9d\xcf\xbc\x8a\x9e\xda\xd2\x1c\x99\x18\xdffz\x1f\xc0\xd69\x96\xd25z\x1b\xfaL\x9d\xd7o\x12H\x1e\xd9\xa7\x05\xcb\xa1\x94k\xe0\xb7\xc1\x14y#q\xb6#\xbdzvmZ\xd9\x1dW\xb7rD'\xf1\\0\xb4\xeama ;\x83\xc0}\x0fb\"\xceV\xe0\x1a\xa9\xee\x90\xef\xd70j\xf8\xdf%eA*\xe59\x9f\xeabO\xed-\x90$\x0cA-\x8f.\xbc\x1f/\xe4\xf6\xfbY~\x82\xa7\xe0kY\xdb\x05\xb7\xc0v\x01s\xbe\xe5\xe2J\xdb\xe4\xc3\x1cqn`\xf8j<\x05A\xd7v\xe3~J\xaf\x10\xe9\xe5XA\x88\xb6\xb7@\x8b\xedZB\xd3\xf2\xce\xfdi\xd3E\x87<\x1b\xb0K\x8b\xa6\xf8V\xfd\xe5\xd1\xdf\x99\x1e\x18\x7f\xc8\x8a<\xc4\x91\"\xf7\xab@\xe3\x8a\\\xe5\x0c\x9b\xe3\xd5\xb6f\x83\xe4\x0cn\x83\xc8wG\x1dM5\rOQ\xe18\x9a\xb9\n1\xdc\xe08\xb1\xc1\x1eX\xa9\xc0\x0bw\x8a<1\x0e\x8fK\x1a\x95\xb8\xf0w\x16\xf6/\x93#\x99\xa6\xbe\xaf8\xf0m9@Q\xe2\xad5\x89\xae6\x11\xe3\x93,S\xaf\xd0\x0bj\x1aW\xd2\xb1\xac|{\xcc\x1fn5\xaa<\x9a\xfa,\xb3\xd8\xd1y\xb57vbO\xfd D(v\xb66\xd8\x9aG\rP\n\x10\x0b\xa9\xf8p\xb6\xb3e\xd6\xb6\a\xb7Z~\x89\n\xde\xe6\x03\\\x89D\x8e\xfbf\x89\xc3\x16\xe5b\xd7\xda\xdf\\\x85.\xa5\xcb\xdf\x0cl*\x86:\x93\xdeG\xd6\xea\xa8\xa9F\xd0\xbf>%\xee\x85\xbd|\xaay\x06\xb3\xc87+a\xef\xa03\x86E\xae]p\x05\x8bx\xd2\xc9\x8c}\xd9\xc5\x87\xc0\xb0X\xb0L\xe7i\x92\xcd=.; \xc5\xdb\xa4&\x8eJ\xc2\xbb\xb5Dx\t\xfe\xc9l\xad\x9b\x16p\xe2\x0c\xd9\xc8A\x94W\xef\xe1\xc6\xefN\xb0\xc7pPW\xd0Zv\aS\x12U\xb2\xf0KJ\xe1\xb5Mz\xe2l\xad\x99\xe6\x15U\xc8\xe6,\x16\xb0\x0f\xe0\x1c\xe3\xe0\x88\xf9\xa17\x0f\xaa\xac=\xfc- \xd5~\x1c\xd8A\x14j\xf6\xc0\x9eX1\x1a\xee\xd3\xdf2J#J!\xf8,oR6\xb9\xa7\xdc\x8e\xdb0\xe0\xf6\xd0\xf3e\xd1^_\x17NT\xc2\x9c]\xa3\x19\xc4\xea]\xab\xc9\xb3\xcf\xe8\xeb\xc3K\xa5\x9aK\xa0\x14\xbe\xb4\xcd%\xa7\xbe*\x96\x11\x8d\xdbS1\x8a\x02'\xbe\xb0\xf2\xff\x90"))

	if err != nil {
		klog.Error(err)
		t.Fail()
	}

	var us UserSession
	_ = json.Unmarshal(sess.KV["UserSession"].([]byte), &us)

	d, _ := json.Marshal(us)
	klog.Info(string(d))
}
