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

package authorization

import (
	appv1alpha1 "github.com/beclab/api/api/app.bytetrade.io/v1alpha1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientScheme "k8s.io/client-go/kubernetes/scheme"
)

// Upstream package only registers Application / ApplicationList with its
// own SchemeBuilder. Register them with the client-go default scheme so
// controller-runtime's client.New() can build typed clients without an
// explicit scheme.
func init() {
	utilruntime.Must(appv1alpha1.AddToScheme(clientScheme.Scheme))
}
