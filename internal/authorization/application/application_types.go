/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package application

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientScheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "app.bytetrade.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// ApplicationSpec defines the desired state of Application.
type ApplicationSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file.

	// the entrance of the application.
	Index string `json:"index,omitempty"`

	// description from app's description or frontend.
	Description string `json:"description,omitempty"`

	// The url of the icon.
	Icon string `json:"icon,omitempty"`

	// the name of the application.
	Name string `json:"name"`

	// the unique id of the application
	// for sys application appid equal name otherwise appid equal md5(name)[:8]
	Appid string `json:"appid"`

	IsSysApp bool `json:"isSysApp"`

	// the namespace of the application.
	Namespace string `json:"namespace,omitempty"`

	// the deployment of the application.
	DeploymentName string `json:"deployment,omitempty"`

	// the owner of the application.
	Owner string `json:"owner,omitempty"`

	// the service address of the application.
	ServiceAddr string `json:"service,omitempty"`

	// the extend settings of the application.
	Settings map[string]string `json:"settings,omitempty"`
}

// ApplicationStatus defines the observed state of Application.
type ApplicationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file.

	// the state of the application: draft, submitted, passed, rejected, suspended, active.
	State      string       `json:"state,omitempty"`
	UpdateTime *metav1.Time `json:"updateTime"`
	StatusTime *metav1.Time `json:"statusTime"`
}

//+genclient
//+genclient:nonNamespaced
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster, shortName={app}, categories={all}
//+kubebuilder:printcolumn:JSONPath=.spec.name, name=application name, type=string
//+kubebuilder:printcolumn:JSONPath=.spec.namespace, name=namespace, type=string
//+kubebuilder:printcolumn:JSONPath=.status.state, name=state, type=string
//+kubebuilder:printcolumn:JSONPath=.metadata.creationTimestamp, name=age, type=date
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Application is the Schema for the applications API.
type Application struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApplicationSpec   `json:"spec,omitempty"`
	Status ApplicationStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ApplicationList contains a list of Application.
type ApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Application `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Application{}, &ApplicationList{})
	utilruntime.Must(AddToScheme(clientScheme.Scheme))
}
