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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/authelia/authelia/v4/internal/authorization/application"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/utils"
)

// Terminus app service access control.
type TsAuthorizer struct {
	client        client.Client
	httpClient    *resty.Client
	kubeConfig    *rest.Config
	rules         []*AccessControlRule
	defaultPolicy Level
	initialized   bool
	mutex         sync.Mutex
	log           *logrus.Logger
	desktopPolicy Level
	exitCh        chan struct{}
}

func NewTsAuthorizer() Authorizer {
	kubeconfig := ctrl.GetConfigOrDie()
	k8sClient, err := client.New(kubeconfig, client.Options{Scheme: scheme.Scheme})

	if err != nil {
		panic(err)
	}

	authorizer := &TsAuthorizer{
		kubeConfig:    kubeconfig,
		client:        k8sClient,
		defaultPolicy: Denied,
		httpClient:    resty.New().SetTimeout(2 * time.Second),
		log:           logging.Logger(),
		desktopPolicy: OneFactor,
		exitCh:        make(chan struct{}),
	}

	authorizer.reloadRules()
	go authorizer.autoRefreshRules()

	return authorizer
}

func (t *TsAuthorizer) Stop() {
	close(t.exitCh)
}

func (t *TsAuthorizer) IsSecondFactorEnabled() bool {
	switch {
	case !t.initialized:
		return false
	case t.defaultPolicy == Bypass:
		return false
	}

	return true
}

func (t *TsAuthorizer) GetRequiredLevel(subject Subject, object Object) (hasSubjects bool, level Level) {
	t.log.Debugf("Check user app process authorization of subject %s and object %s (method %s).",
		subject.String(), object.String(), object.Method)

	if !t.initialized {
		return false, t.defaultPolicy
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, rule := range t.rules {
		if rule.IsMatch(subject, object) {
			t.log.Tracef(traceFmtACLHitMiss, "HIT", rule.Position, subject, object, object.Method)

			return rule.HasSubjects, rule.Policy
		}

		t.log.Tracef(traceFmtACLHitMiss, "MISS", rule.Position, subject, object, object.Method)
	}

	t.log.Debugf("No matching rule for subject %s and url %s (method %s) applying default policy", subject, object, object.Method)

	return false, t.defaultPolicy
}

func (t *TsAuthorizer) GetRuleMatchResults(subject Subject, object Object) (results []RuleMatchResult) {
	skipped := false

	results = make([]RuleMatchResult, len(t.rules))
	if !t.initialized {
		return results
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	for i, rule := range t.rules {
		results[i] = RuleMatchResult{
			Rule:    rule,
			Skipped: skipped,

			MatchDomain:        rule.MatchesDomains(subject, object),
			MatchResources:     rule.MatchesResources(subject, object),
			MatchQuery:         rule.MatchesQuery(object),
			MatchMethods:       rule.MatchesMethods(object),
			MatchNetworks:      rule.MatchesNetworks(subject),
			MatchSubjects:      rule.MatchesSubjects(subject),
			MatchSubjectsExact: rule.MatchesSubjectExact(subject),
		}

		skipped = skipped || results[i].IsMatch()
	}

	return results
}

func (t *TsAuthorizer) getRules(ctx context.Context, userInfo *utils.UserInfo) ([]*AccessControlRule, error) {
	if userInfo.IsEphemeral {
		// Found the new user without DID binding, set the default policy to all.
		klog.Info("new user: ", userInfo.Name, "force default one_factor policy ")

		s, rule := NewAccessControlDomain("*." + defaultDomain)

		rules := []*AccessControlRule{
			{
				Position:    0,
				HasSubjects: s,
				Domains: []AccessControlDomain{
					rule,
				},
				Policy: t.desktopPolicy,
			},
		}

		return rules, nil
	}

	var appList application.ApplicationList
	if err := t.client.List(context.Background(), &appList, client.InNamespace("")); err != nil {
		return nil, err
	}

	var rules []*AccessControlRule

	// desktop rule.
	rules = t.addDesktopRules(ctx, userInfo.Name, userInfo.Zone)

	// applications rule.
	for _, a := range appList.Items {
		if a.Spec.Owner == userInfo.Name {
			appRules, err := t.getAppRules(len(rules), a.DeepCopy(), userInfo)
			if err != nil {
				return nil, err
			}

			rules = append(rules, appRules...)
		}
	}

	return rules, nil
}

func (t *TsAuthorizer) addDesktopRules(ctx context.Context, username, domain string) (rules []*AccessControlRule) {
	domains := []string{
		domain,
		"local." + domain,
	}

	var desktopPolicy = t.desktopPolicy

	if policy, err := t.getUserAccessPolicy(ctx, username); err != nil {
		klog.Error("get user access policy error, ", username, " ", err)
	} else {
		desktopPolicy = NewLevel(policy)
	}

	desktopRule := &AccessControlRule{
		Position: 1,
		Policy:   desktopPolicy,
	}
	ruleAddDomain(domains, desktopRule)

	rules = append(rules, desktopRule)

	return rules
}

/*
app settings:

		app.settings["policy"] = {
			"default_policy": "public / one_factor / two_factor",
			"sub_policies": [
				{
				"uri": "/api/pay",
				"policy": "deny / one_factor / two_factor",
				}
			}
		}
	}.
*/
func (t *TsAuthorizer) getAppRules(position int, app *application.Application, userInfo *utils.UserInfo) (rules []*AccessControlRule, err error) {
	policyData, ok := app.Spec.Settings[application.ApplicationSettingsPolicyKey]
	domains := []string{
		fmt.Sprintf("%s.%s", app.Spec.Name, userInfo.Zone),
		fmt.Sprintf("%s.local.%s", app.Spec.Name, userInfo.Zone),
	}

	if !ok {
		t.log.Debugf("app %s has not policy", app.Spec.Name)

		rule := &AccessControlRule{
			Position: position,
			Policy:   t.desktopPolicy,
		}
		ruleAddDomain(domains, rule)

		rules = append(rules, rule)

		return rules, nil
	}

	var policy application.ApplicationSettingsPolicy
	err = json.Unmarshal([]byte(policyData), &policy)

	if err != nil {
		return nil, err
	}

	if policy.SubPolicies != nil {
		for _, sp := range policy.SubPolicies {
			t.log.Debugf("add app %s rules %s on resource %s", app.Spec.Name, sp.Policy, sp.URI)

			resExp, err := regexp.Compile(sp.URI)
			if err != nil {
				t.log.Error("invalid resource sub policy uri ", app.Spec.Name, " ", sp.URI)
				return nil, err
			}

			resources := []regexp.Regexp{*resExp}

			rule := &AccessControlRule{
				Position: position,
				Policy:   NewLevel(sp.Policy),
			}
			ruleAddResources(resources, rule)
			ruleAddDomain(domains, rule)

			rules = append(rules, rule)

			position++
		} // end for policy.SubPolicies.
	} // end if.

	// add app others resource to default policy.
	ruleOthers := &AccessControlRule{
		Position: position,
		Policy:   NewLevel(policy.DefaultPolicy),
	}
	ruleAddDomain(domains, ruleOthers)

	rules = append(rules, ruleOthers)

	return rules, nil
}

func (t *TsAuthorizer) reloadRules() {
	info, err := utils.GetUserInfoFromBFL(t.httpClient)
	if err != nil {
		klog.Error("reload user info error, ", err)
		return
	}

	rules, err := t.getRules(context.Background(), info)
	if err != nil {
		klog.Error("reload apps auth rules error, ", err)
		return
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.initialized = true
	t.defaultPolicy = Denied
	t.rules = rules
}

func (t *TsAuthorizer) autoRefreshRules() {
	ticker := *time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.reloadRules()
		case <-t.exitCh:
			return
		}
	}
}

func (t *TsAuthorizer) getUserAccessPolicy(ctx context.Context, username string) (string, error) {
	gvr := schema.GroupVersionResource{
		Group:    "iam.kubesphere.io",
		Version:  "v1alpha2",
		Resource: "users",
	}
	client, err := dynamic.NewForConfig(t.kubeConfig)

	if err != nil {
		return "", err
	}

	data, err := client.Resource(gvr).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	policy, ok := data.GetAnnotations()[UserLauncherAuthPolicy]

	if !ok {
		return "", errors.New("user access policy not found")
	}

	return policy, nil
}
