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
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/asaskevich/govalidator"
	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/authelia/authelia/v4/internal/authorization/application"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/utils"
)

var TerminusNonce string

// Terminus app service access control.
type TsAuthorizer struct {
	client           client.Client
	httpClient       *resty.Client
	kubeConfig       *rest.Config
	rules            []*AccessControlRule
	defaultPolicy    Level
	initialized      bool
	mutex            sync.Mutex
	log              *logrus.Logger
	desktopPolicy    Level
	exitCh           chan struct{}
	userIsIniting    bool
	appDefaultPolicy Level

	LoginPortal string
}

func NewTsAuthorizer() Authorizer {
	kubeconfig := ctrl.GetConfigOrDie()
	k8sClient, err := client.New(kubeconfig, client.Options{Scheme: scheme.Scheme})

	if err != nil {
		panic(err)
	}

	authorizer := &TsAuthorizer{
		kubeConfig:       kubeconfig,
		client:           k8sClient,
		defaultPolicy:    Denied,
		httpClient:       resty.New().SetTimeout(2 * time.Second),
		log:              logging.Logger(),
		desktopPolicy:    TwoFactor,
		exitCh:           make(chan struct{}),
		appDefaultPolicy: OneFactor,
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

func (t *TsAuthorizer) GetRequiredLevel(subject Subject, object Object) (hasSubjects bool, level Level, r *AccessControlRule) {
	t.log.Debugf("Check user app process authorization of subject %s and object %s (method %s).",
		subject.String(), object.String(), object.Method)

	if !t.initialized {
		return false, t.defaultPolicy, nil
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, rule := range t.rules {
		if rule.IsMatch(subject, object) {
			t.log.Debugf(traceFmtACLHitMiss, "HIT", rule.Position, subject, object, (object.Method + " " + rule.Policy.String()))

			return rule.HasSubjects, rule.Policy, rule
		}

		t.log.Tracef(traceFmtACLHitMiss, "MISS", rule.Position, subject, object, object.Method)
	}

	t.log.Debugf("No matching rule for subject %s and url %s (method %s) applying default policy", subject, object, object.Method)

	pathToken := strings.Split(object.Path, "/")

	// FIXME:.
	if govalidator.IsIP(object.Domain) && pathToken[len(pathToken)-1] == "task-state" {
		return false, Bypass, nil
	}

	// TESTING:.
	if strings.HasPrefix(object.Path, "/bfl/backend") {
		return false, Bypass, nil
	}

	return false, t.defaultPolicy, nil
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
		klog.Info("new user: ", userInfo.Name, " just bypass launcher ")

		rule := &AccessControlRule{
			Position: 0,
			Policy:   Bypass,
		}
		ruleAddDomain(
			[]string{
				fmt.Sprintf("desktop-%s.%s", userInfo.Name, userInfo.Zone),
				fmt.Sprintf("desktop-%s.local.%s", userInfo.Name, userInfo.Zone),
			},
			rule,
		)

		rules := []*AccessControlRule{rule}

		return rules, nil
	}

	var appList application.ApplicationList
	if err := t.client.List(context.Background(), &appList, client.InNamespace("")); err != nil {
		return nil, err
	}

	var rules []*AccessControlRule

	// portal rule.
	rules = t.addPortalRules(userInfo.Zone, rules)

	// desktop rule.
	rules = t.addDesktopRules(ctx, userInfo.Name, userInfo.Zone, rules)

	// auth app rule.
	rules = t.addAuthDomainRules(userInfo.Zone, rules)

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

func (t *TsAuthorizer) addDomainBypassRules(subdomain, domain string, rules []*AccessControlRule) []*AccessControlRule {
	return t.addDomainSpecialRules(subdomain, domain, Bypass, rules)
}

func (t *TsAuthorizer) addDomainSpecialRules(subdomain, domain string, level Level, rules []*AccessControlRule) []*AccessControlRule {
	domains := []string{
		subdomain + "local." + domain,
		subdomain + domain,
	}

	rule := &AccessControlRule{
		Position: len(rules),
		Policy:   level,
	}
	ruleAddDomain(domains, rule)

	rules = append(rules, rule)

	return rules
}

func (t *TsAuthorizer) addPortalRules(domain string, rules []*AccessControlRule) []*AccessControlRule {
	return t.addDomainBypassRules("", domain, rules)
}

func (t *TsAuthorizer) addDesktopRules(ctx context.Context, username, domain string, rules []*AccessControlRule) []*AccessControlRule {
	domains := []string{
		"desktop.local." + domain,
		"desktop." + domain,
	}

	if policy, err := t.getUserAccessPolicy(ctx, username); err != nil {
		klog.Error("get user access policy error, ", username, " ", err)
	} else {
		t.desktopPolicy = NewLevel(policy)
	}

	position := len(rules)

	if !t.userIsIniting {
		// add loginn portal to bypass.
		resources := t.getResourceExps([]string{
			"^/login",
			"^/assets/.*",
			"^/avatar/.*",
			"^/icons/.*",
			"^/bfl/backend/.*",
			"^/api/.*",
		})

		loginPortalRule := &AccessControlRule{
			Position: position,
			Policy:   Bypass,
		}
		ruleAddDomain(domains, loginPortalRule)
		ruleAddResources(resources, loginPortalRule)

		rules = append(rules, loginPortalRule)
		position++
	}

	desktopRule := &AccessControlRule{
		Position: position,
		Policy:   t.desktopPolicy,
	}
	ruleAddDomain(domains, desktopRule)

	rules = append(rules, desktopRule)

	return rules
}

func (t *TsAuthorizer) addAuthDomainRules(domain string, rules []*AccessControlRule) []*AccessControlRule {
	return t.addDomainBypassRules("auth.", domain, rules)
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
		fmt.Sprintf("%s.local.%s", app.Spec.Name, userInfo.Zone),
		fmt.Sprintf("%s.%s", app.Spec.Name, userInfo.Zone),
	}

	if !ok {
		rule := &AccessControlRule{
			Position: position,
			Policy:   t.appDefaultPolicy,
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
				Position:      position,
				Policy:        NewLevel(sp.Policy),
				OneTimeValid:  sp.OneTime,
				ValidDuration: time.Duration(sp.Duration) * time.Second,
			}
			ruleAddResources(resources, rule)
			ruleAddDomain(domains, rule)

			rules = append(rules, rule)

			position++
		} // end for policy.SubPolicies.
	} // end if.

	// add app others resource to default policy.
	othersExp := regexp.MustCompile("^/.+")
	othersResources := []regexp.Regexp{*othersExp}

	ruleOthers := &AccessControlRule{
		Position:    position,
		Policy:      t.desktopPolicy,
		DefaultRule: true,
	}
	ruleAddResources(othersResources, ruleOthers)
	ruleAddDomain(domains, ruleOthers)

	rules = append(rules, ruleOthers)

	position++

	// add app root path to default policy with options.
	ruleRoot := &AccessControlRule{
		Position:      position,
		Policy:        NewLevel(policy.DefaultPolicy),
		OneTimeValid:  policy.OneTime,
		ValidDuration: time.Duration(policy.Duration) * time.Second,
	}
	ruleAddDomain(domains, ruleRoot)

	rules = append(rules, ruleRoot)

	return rules, nil
}

func (t *TsAuthorizer) reloadRules() {
	info, err := utils.GetUserInfoFromBFL(t.httpClient)
	if err != nil {
		klog.Error("reload user info error, ", err)
		return
	}

	ctx := context.Background()

	rules, err := t.getRules(ctx, info)
	if err != nil {
		klog.Error("reload apps auth rules error, ", err)
		return
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.userIsIniting = info.Zone == ""
	t.initialized = true
	t.rules = rules

	if info.IsEphemeral {
		t.LoginPortal = fmt.Sprintf("https://auth-%s.%s/", info.Name, info.Zone)
	} else {
		t.LoginPortal = fmt.Sprintf("https://auth.%s/", info.Zone)
	}

	if t.userIsIniting {
		t.defaultPolicy = Bypass
	} else {
		t.defaultPolicy = Denied
	}

	t.getNonce()
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
	data, err := t.getUserData(ctx, username)

	if err != nil {
		return "", nil
	}

	policy, ok := data.GetAnnotations()[UserLauncherAuthPolicy]

	if !ok {
		return "", errors.New("user access policy not found")
	}

	return policy, nil
}

func (t *TsAuthorizer) getUserData(ctx context.Context, username string) (*unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{
		Group:    "iam.kubesphere.io",
		Version:  "v1alpha2",
		Resource: "users",
	}
	client, err := dynamic.NewForConfig(t.kubeConfig)

	if err != nil {
		return nil, err
	}

	data, err := client.Resource(gvr).Get(ctx, username, metav1.GetOptions{})

	if err != nil {
		return nil, err
	}

	return data, nil
}

// func (t *TsAuthorizer) getUserZone(ctx context.Context, username string) (string, error) {
// 	data, err := t.getUserData(ctx, username)

// 	if err != nil {
// 		return "", nil
// 	}

// 	zone, ok := data.GetAnnotations()[UserAnnotationZoneKey]

// 	if !ok {
// 		return "", errors.New("user zone not found")
// 	}

//		return zone, nil
//	}.
func (t *TsAuthorizer) getResourceExps(res []string) []regexp.Regexp {
	var ret []regexp.Regexp

	for _, r := range res {
		e, err := regexp.Compile(r)
		if err != nil {
			t.log.Error("resource compile error: ", err)
		} else {
			ret = append(ret, *e)
		}
	}

	return ret
}

func (t *TsAuthorizer) getNonce() {
	nonceUrl := fmt.Sprintf("http://%s/permission/v1alpha1/nonce", utils.SYSTEM_SERVER)

	resp, err := t.httpClient.R().Get(nonceUrl)

	if err != nil {
		klog.Error("get nonce error, ", err)
		return
	}

	if resp.StatusCode() != http.StatusOK {
		klog.Error("response error, code: ", resp.StatusCode(), " ", string(resp.Body()))
		return
	}

	TerminusNonce = string(resp.Body())
	klog.Info("get terminus backend nonce with prefix: ", TerminusNonce[:8])
}
