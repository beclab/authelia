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
	"context"
	"sync"
	"time"

	"github.com/beclab/api/pkg/generated/clientset/versioned"
	"github.com/beclab/api/pkg/generated/informers/externalversions"
	sysv1alpha1lister "github.com/beclab/api/pkg/generated/listers/sys.bytetrade.io/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

const terminusCacheSyncTimeout = 10 * time.Second

var (
	terminusOnce     sync.Once
	terminusLister   sysv1alpha1lister.TerminusLister
	terminusInformer cache.SharedIndexInformer
)

func initTerminusInformer() {
	config, err := ctrl.GetConfig()
	if err != nil {
		klog.Error("get kube config for terminus informer error, ", err)
		return
	}

	clientset, err := versioned.NewForConfig(config)
	if err != nil {
		klog.Error("create terminus clientset error, ", err)
		return
	}

	factory := externalversions.NewSharedInformerFactory(clientset, 0)
	informer := factory.Sys().V1alpha1().Terminus()
	terminusInformer = informer.Informer()
	terminusLister = informer.Lister()

	factory.Start(wait.NeverStop)

	ctx, cancel := context.WithTimeout(context.Background(), terminusCacheSyncTimeout)
	defer cancel()

	if !cache.WaitForCacheSync(ctx.Done(), terminusInformer.HasSynced) {
		klog.Error("wait for terminus informer cache sync timeout")
	}
}

// GetTerminusLocalName returns spec.localName of the cluster Terminus from the informer cache,
// or an empty string if it is not available.
func GetTerminusLocalName() string {
	terminusOnce.Do(initTerminusInformer)

	if terminusLister == nil || !terminusInformer.HasSynced() {
		return ""
	}

	terminuses, err := terminusLister.List(labels.Everything())
	if err != nil {
		klog.Error("list terminus from cache error, ", err)
		return ""
	}

	if len(terminuses) == 0 {
		klog.Warning("terminus not found in cache")
		return ""
	}

	return terminuses[0].Spec.LocalName
}
