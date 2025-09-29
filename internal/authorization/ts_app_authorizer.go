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
	"strconv"
	"strings"
	"sync"
	"time"

	conf_schema "github.com/authelia/authelia/v4/internal/configuration/schema"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/authelia/authelia/v4/internal/authorization/application"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/utils"
)

var (
	TerminusUserHeader                 = []byte("X-BFL-USER")
	AdminUser                          = ""
	UserAnnotationLocalDomainDNSRecord = "bytetrade.io/local-domain-dns-record"

	tmpUserCustomDomain map[string]map[string]string
	UserCustomDomain    map[string]map[string]string
)

// Terminus app service access control.
type TsAuthorizer struct {
	client     client.Client
	httpClient *resty.Client
	kubeConfig *rest.Config
	mutex      sync.Mutex
	log        *logrus.Logger
	exitCh     chan struct{}

	userAuthorizers map[string]*userAuthorizer

	updateOIDCClients func(config *conf_schema.OpenIDConnectConfiguration)
	oidcConfig        *conf_schema.OpenIDConnectConfiguration
}

type userAuthorizer struct {
	rules         []*AccessControlRule
	defaultPolicy Level
	initialized   bool

	desktopPolicy    Level
	userIsIniting    bool
	appDefaultPolicy Level

	LoginPortal string

	UserTerminusNonce string
	UserZone          string

	localDomainIpDnsRecord string
}

func NewTsAuthorizer(updateOIDCClients func(config *conf_schema.OpenIDConnectConfiguration)) Authorizer {
	kubeconfig := ctrl.GetConfigOrDie()
	k8sClient, err := client.New(kubeconfig, client.Options{Scheme: scheme.Scheme})

	if err != nil {
		panic(err)
	}

	authorizer := &TsAuthorizer{
		kubeConfig:        kubeconfig,
		client:            k8sClient,
		httpClient:        resty.New().SetTimeout(2 * time.Second),
		log:               logging.Logger(),
		exitCh:            make(chan struct{}),
		userAuthorizers:   make(map[string]*userAuthorizer),
		updateOIDCClients: updateOIDCClients,
		oidcConfig:        &conf_schema.DefaultOpenIDConnectConfiguration,
	}

	authorizer.reloadRules()
	go authorizer.autoRefreshRules()

	return authorizer
}

func (t *TsAuthorizer) Stop() {
	close(t.exitCh)
}

func (t *TsAuthorizer) GetUserBackendNonce(user string) string {
	a, ok := t.userAuthorizers[user]
	if !ok {
		return ""
	}

	return a.UserTerminusNonce
}

func (t *TsAuthorizer) GetUserZone(user string) string {
	a, ok := t.userAuthorizers[user]
	if !ok {
		return ""
	}

	return a.UserZone
}

func (t *TsAuthorizer) IsSecondFactorEnabled() bool {
	// switch {
	// case !t.initialized:
	// 	return false
	// case t.defaultPolicy == Bypass:
	// 	return false
	// }

	return true
}

func (t *TsAuthorizer) GetRequiredLevel(subject Subject, object Object) (hasSubjects bool, level Level, r *AccessControlRule) {
	t.log.Debugf("Check user app process authorization of subject %s and object %s (method %s).",
		subject.String(), object.String(), object.Method)

	t.mutex.Lock()
	defer t.mutex.Unlock()

	auth, ok := t.userAuthorizers[subject.Username]
	if ok {
		if !auth.initialized {
			return false, auth.defaultPolicy, nil
		}

		for _, rule := range auth.rules {
			if rule.IsMatch(subject, object) {
				t.log.Debugf(traceFmtACLHitMiss, "HIT", rule.Position, subject, object, (object.Method + " " + rule.Policy.String()))

				if rule.Internal && object.ViaVPN() && object.FromClusterPod() {
					t.log.Debug("internal policy rule matched, set policy public")
					return rule.HasSubjects, Bypass, rule
				}

				return rule.HasSubjects, rule.Policy, rule
			}

			t.log.Tracef(traceFmtACLHitMiss, "MISS", rule.Position, subject, object, object.Method)
		}
	} else {
		klog.Error("user not found in terminus authorizer, ", subject.Username)
	}

	t.log.Debugf("No matching rule for subject %s and url %s (method %s) applying default policy", subject, object, object.Method)

	pathToken := strings.Split(object.Path, "/")

	// FIXME:.
	if utils.IsIP(object.Domain) {
		switch {
		case pathToken[len(pathToken)-1] == "task-state":
			return false, OneFactor, nil
		case len(object.String()) == 0:
			return false, OneFactor, nil
		default:
			return false, TwoFactor, nil
		}
	}

	if ok {
		return false, auth.defaultPolicy, nil
	} else {
		return false, Denied, nil
	}
}

func (t *TsAuthorizer) GetRuleMatchResults(subject Subject, object Object) (results []RuleMatchResult) {
	skipped := false

	t.mutex.Lock()
	defer t.mutex.Unlock()

	auth, ok := t.userAuthorizers[subject.Username]
	if !ok {
		klog.Error("user not found in terminus authorizer, ", subject.Username)
		return nil
	}

	results = make([]RuleMatchResult, len(auth.rules))
	if !auth.initialized {
		return results
	}

	for i, rule := range auth.rules {
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

func (t *TsAuthorizer) getRules(ctx context.Context, userInfo *utils.UserInfo,
	userData *unstructured.Unstructured, userAuth *userAuthorizer) ([]*AccessControlRule, error) {
	if userInfo.IsEphemeral {
		// Found the new user without DID binding, set the default policy to all.
		klog.Info("new user: ", userInfo.Name, " just bypass launcher ")

		rule := &AccessControlRule{
			Position: 0,
			Policy:   Bypass,
		}
		ruleAddDomain(
			[]string{
				fmt.Sprintf("wizard-%s.%s", userInfo.Name, userInfo.Zone),
			},
			rule,
		)

		rules := []*AccessControlRule{rule}

		// CORS rules.
		rules = t.addCORSRules(userInfo.Zone, rules)

		return rules, nil
	}

	var appList application.ApplicationList
	if err := t.client.List(context.Background(), &appList, client.InNamespace("")); err != nil {
		return nil, err
	}

	var rules []*AccessControlRule

	// portal rule.
	rules = t.addPortalRules(userInfo.Zone, rules)

	// CORS rules.
	rules = t.addCORSRules(userInfo.Zone, rules)

	// desktop rule.
	rules = t.addDesktopRules(ctx, userInfo.Name, userInfo.Zone, rules, userData, userAuth)

	// auth app rule.
	rules = t.addAuthDomainRules(userInfo.Zone, rules)

	// applications rule.
	for _, a := range appList.Items {
		if a.Spec.Owner == userInfo.Name {
			appRules, err := t.getAppRules(len(rules), a.DeepCopy(), userInfo, userAuth)
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

func (t *TsAuthorizer) addCORSRules(domain string, rules []*AccessControlRule) []*AccessControlRule {
	// apply the `bypass` policy to `OPTIONS` CORS preflight requests.
	domains := []string{
		"*." + domain,
	}

	rule := &AccessControlRule{
		Position: len(rules),
		Policy:   Bypass,
		Methods:  []string{http.MethodOptions},
	}

	ruleAddDomain(domains, rule)

	rules = append(rules, rule)

	return rules
}

func (t *TsAuthorizer) addDesktopRules(ctx context.Context, username, domain string,
	rules []*AccessControlRule, userData *unstructured.Unstructured, userAuth *userAuthorizer) []*AccessControlRule {
	domains := []string{
		"desktop." + domain,
	}

	if policy, err := t.getUserAccessPolicy(ctx, userData); err != nil {
		klog.Error("get user access policy error, ", username, " ", err)
	} else {
		userAuth.desktopPolicy = NewLevel(policy)
	}

	// apps follow system level
	userAuth.appDefaultPolicy = userAuth.desktopPolicy

	position := len(rules)

	desktopRule := &AccessControlRule{
		Position: position,
		Policy:   userAuth.desktopPolicy,
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

type DefaultThirdLevelDomainConfig struct {
	AppName          string `json:"appName"`
	EntranceName     string `json:"entranceName"`
	ThirdLevelDomain string `json:"thirdLevelDomain"`
}

func (t *TsAuthorizer) getAppRules(position int, app *application.Application,
	userInfo *utils.UserInfo, userAuth *userAuthorizer) (rules []*AccessControlRule, err error) {
	policyData, policyExists := app.Spec.Settings[application.ApplicationSettingsPolicyKey]
	policies := make(map[string]*application.ApplicationSettingsPolicy)
	if policyExists {
		err = json.Unmarshal([]byte(policyData), &policies)

		if err != nil {
			return nil, err
		}
	}

	// default third level domain
	defaultThirdLevelDomains := make(map[string]string)
	if thirdLevelDomainConfig, ok := app.Spec.Settings[application.ApplicationSettingsDefaultThirdLevelDomainConfigKey]; ok {
		var allDomainConfigs []application.DefaultThirdLevelDomainConfig
		err = json.Unmarshal([]byte(thirdLevelDomainConfig), &allDomainConfigs)
		if err != nil {
			klog.Error("get default third level domain config error, ", app.Spec.Name, " ", err)
			return nil, err
		}

		for _, config := range allDomainConfigs {
			if config.ThirdLevelDomain != "" {
				defaultThirdLevelDomains[config.EntranceName] = config.ThirdLevelDomain
			}
		}
	}

	customDomainData, customDomainExists := app.Spec.Settings[application.ApplicationSettingsCustomDomainKey]
	customDomain := make(map[string]*application.ApplicationCustomDomain)
	if customDomainExists {
		err = json.Unmarshal([]byte(customDomainData), &customDomain)

		if err != nil {
			return nil, err
		}
	}
	var appDomainConfigs []DefaultThirdLevelDomainConfig
	if len(app.Spec.Settings["defaultThirdLevelDomainConfig"]) > 0 {
		err := json.Unmarshal([]byte(app.Spec.Settings["defaultThirdLevelDomainConfig"]), &appDomainConfigs)
		if err != nil {
			klog.Errorf("unmarshal defaultThirdLevelDomainConfig error %v", err)
		}
	}

	for index, entrance := range app.Spec.Entrances {
		entranceId := app.Spec.Appid
		if len(app.Spec.Entrances) > 1 {
			entranceId += strconv.Itoa(index)
		}
		for _, adc := range appDomainConfigs {
			if adc.AppName == app.Spec.Name && adc.EntranceName == entrance.Name && len(adc.ThirdLevelDomain) > 0 {
				entranceId = adc.ThirdLevelDomain
			}
		}

		domains := []string{
			fmt.Sprintf("%s.%s", entranceId, userInfo.Zone),
		}
		if entranceDefaultThirdDomain, ok := defaultThirdLevelDomains[entrance.Name]; ok {
			domains = append(domains, fmt.Sprintf("%s.%s", entranceDefaultThirdDomain, userInfo.Zone))
			// hardcode vault /server policy
			if entranceDefaultThirdDomain == "vault" {
				if policy, ok := policies["vault"]; !ok {
					policies["vault"] = &application.ApplicationSettingsPolicy{
						DefaultPolicy: userAuth.appDefaultPolicy.String(),
						SubPolicies: []*application.ApplicationSettingsSubPolicy{
							{
								URI:    "/server",
								Policy: OneFactor.String(),
							},
						},
						OneTime:  false,
						Duration: -1,
					}
				} else {
					found := false
					for _, sp := range policy.SubPolicies {
						if sp.URI == "/server" {
							sp.Policy = OneFactor.String()
							found = true
						}
					}

					// force replace policy
					if !found {
						policy.SubPolicies = append(policy.SubPolicies, &application.ApplicationSettingsSubPolicy{
							URI:    "/server",
							Policy: OneFactor.String(),
						})
					}
				}

			} // end if vault
		} // end for if add default third level domain

		if customDomainExists {
			entranceCustomDomain, ok := customDomain[entrance.Name]
			if ok {
				if entranceCustomDomain.ThirdLevelDomain != "" {
					domains = append(domains, fmt.Sprintf("%s.%s", entranceCustomDomain.ThirdLevelDomain, userInfo.Zone))
				}

				if entranceCustomDomain.ThirdPartyDomain != "" {
					domains = append(domains, entranceCustomDomain.ThirdPartyDomain)

					// add domain to user domain, for session bridge
					if _, ok = tmpUserCustomDomain[userInfo.Name]; !ok {
						tmpUserCustomDomain[userInfo.Name] = make(map[string]string)
					}

					tmpUserCustomDomain[userInfo.Name][entranceCustomDomain.ThirdPartyDomain] = entrance.Name
				}
			}
		}

		newRule := func(r *AccessControlRule) *AccessControlRule {
			return r
		}

		nonPolicy := func(p Level, domains []string) {
			rule := newRule(&AccessControlRule{
				Position: position,
				Policy:   p,
			})
			ruleAddDomain(domains, rule)
			rules = append(rules, rule)
			position++
		}

		defaultPolicy := userAuth.appDefaultPolicy
		if entrance.AuthLevel != "" && entrance.AuthLevel == public {
			defaultPolicy = NewLevel(entrance.AuthLevel)
		}
		if entrance.AuthLevel != "" && entrance.AuthLevel == internal {
			oldRule := newRule
			newRule = func(r *AccessControlRule) *AccessControlRule {
				newR := oldRule(r)
				newR.Internal = true
				return newR
			}
		}

		if !policyExists {
			nonPolicy(defaultPolicy, domains)
			continue
		}

		policy, ok := policies[entrance.Name]
		if !ok {
			nonPolicy(defaultPolicy, domains)
			continue
		}

		getLevel := func(policy string) Level {
			switch policy {
			case system:
				return userAuth.appDefaultPolicy
			default:
				return NewLevel(policy)
			}
		}

		appendRule := func(rule *AccessControlRule) {
			rules = append(rules, rule)
			position++
		}

		if policy.SubPolicies != nil {
			for _, sp := range policy.SubPolicies {
				// t.log.Debugf("add app %s rules %s on resource %s", app.Spec.Name, sp.Policy, sp.URI)

				resExp, err := regexp.Compile(sp.URI)
				if err != nil {
					t.log.Error("invalid resource sub policy uri ", app.Spec.Name, " ", sp.URI)
					return nil, err
				}

				resources := []regexp.Regexp{*resExp}

				rule := newRule(&AccessControlRule{
					Position:      position,
					Policy:        getLevel(sp.Policy),
					OneTimeValid:  sp.OneTime,
					ValidDuration: time.Duration(sp.Duration) * time.Second,
				})
				ruleAddResources(resources, rule)
				ruleAddDomain(domains, rule)

				appendRule(rule)
			} // end for policy.SubPolicies.
		} // end if.

		// add app others resource to default policy.
		othersExp := regexp.MustCompile("^/.+")
		othersResources := []regexp.Regexp{*othersExp}

		if entrance.AuthLevel != public {
			defaultPolicy = getLevel(policy.DefaultPolicy)
		}

		ruleOthers := newRule(&AccessControlRule{
			Position:    position,
			Policy:      defaultPolicy,
			DefaultRule: true,
		})
		ruleAddResources(othersResources, ruleOthers)
		ruleAddDomain(domains, ruleOthers)

		appendRule(ruleOthers)

		// add app root path to default policy with options.
		ruleRoot := newRule(&AccessControlRule{
			Position:      position,
			Policy:        defaultPolicy,
			OneTimeValid:  policy.OneTime,
			ValidDuration: time.Duration(policy.Duration) * time.Second,
			DefaultRule:   true,
		})
		ruleAddDomain(domains, ruleRoot)

		appendRule(ruleRoot)
	}

	return rules, nil
}

func (t *TsAuthorizer) newUserAuthorizer(_ string) *userAuthorizer {
	return &userAuthorizer{
		defaultPolicy:    Denied,
		desktopPolicy:    TwoFactor,
		appDefaultPolicy: TwoFactor,
	}
}

func (t *TsAuthorizer) reloadRules() {
	ctx := context.Background()

	users, err := t.listUserData(ctx)
	if err != nil {
		klog.Error("list user error, ", err)
		return
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	// FIXME: check the user's role
	AdminUser = users[0].GetName()

	tmpUserCustomDomain = make(map[string]map[string]string)
	for _, user := range users {
		username := user.GetName()

		info, err := utils.GetUserInfoFromBFL(t.httpClient, username)
		if err != nil {
			klog.Error("reload user info error, ", err, ", ", username)
			continue
		}

		userAuth := t.newUserAuthorizer(username)

		userAuth.userIsIniting = info.Zone == ""
		userAuth.initialized = true
		userAuth.localDomainIpDnsRecord = user.GetAnnotations()[UserAnnotationLocalDomainDNSRecord]

		if info.IsEphemeral {
			userAuth.LoginPortal = fmt.Sprintf("https://auth-%s.%s/", info.Name, info.Zone)
		} else {
			userAuth.LoginPortal = fmt.Sprintf("https://auth.%s/", info.Zone)
		}

		if userAuth.userIsIniting {
			userAuth.defaultPolicy = Bypass
		} else {
			userAuth.defaultPolicy = Denied
		}

		rules, err := t.getRules(ctx, info, &user, userAuth)
		if err != nil {
			klog.Error("reload user apps auth rules error, ", err, ", ", username)
			continue
		}

		userAuth.rules = rules

		nonce, err := t.getNonce(username)
		if err != nil {
			klog.Error("get user backend service nonce error, ", err, ", ", username)
			continue
		}

		userAuth.UserTerminusNonce = nonce
		userAuth.UserZone = info.Zone

		t.userAuthorizers[username] = userAuth

	}

	if err = t.getOIDCClients(); err != nil {
		klog.Error("get oidc clients error, ", err)
	}

	UserCustomDomain = tmpUserCustomDomain
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

func (t *TsAuthorizer) getUserAccessPolicy(_ context.Context, userData *unstructured.Unstructured) (string, error) {
	policy, ok := userData.GetAnnotations()[UserLauncherAuthPolicy]

	if !ok {
		return "", errors.New("user access policy not found")
	}

	return policy, nil
}

func (t *TsAuthorizer) listUserData(ctx context.Context) ([]unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{
		Group:    "iam.kubesphere.io",
		Version:  "v1alpha2",
		Resource: "users",
	}
	client, err := dynamic.NewForConfig(t.kubeConfig)

	if err != nil {
		return nil, err
	}

	data, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})

	if err != nil {
		return nil, err
	}

	return data.Items, nil
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
//	}

// func (t *TsAuthorizer) getResourceExps(res []string) []regexp.Regexp {
// 	var ret []regexp.Regexp

// 	for _, r := range res {
// 		e, err := regexp.Compile(r)
// 		if err != nil {
// 			t.log.Error("resource compile error: ", err)
// 		} else {
// 			ret = append(ret, *e)
// 		}
// 	}

// 	return ret
// }

func (t *TsAuthorizer) getNonce(user string) (string, error) {
	nonceUrl := fmt.Sprintf("http://%s.user-system-%s/permission/v1alpha1/nonce", utils.SYSTEM_SERVER_NAME, user)

	resp, err := t.httpClient.R().Get(nonceUrl)

	if err != nil {
		klog.Error("get nonce error, ", err)
		return "", err
	}

	if resp.StatusCode() != http.StatusOK {
		klog.Error("response error, code: ", resp.StatusCode(), " ", string(resp.Body()))
		return "", err
	}

	nonce := string(resp.Body())
	// klog.Info("get terminus backend nonce with prefix: ", nonce[:8])

	return nonce, nil
}

func (t *TsAuthorizer) ValidBackendRequest(ctx *fasthttp.RequestCtx, nonce string) bool {
	user := ctx.Request.Header.PeekBytes(TerminusUserHeader)
	if user == nil {
		for _, u := range t.userAuthorizers {
			if u.UserTerminusNonce == nonce {
				return true
			}
		}
		return false
	}

	userAuth, ok := t.userAuthorizers[string(user)]
	if !ok {
		klog.Error("user not found in authorizer, ", string(user))
		return false
	}

	return userAuth.UserTerminusNonce == nonce
}

func (t *TsAuthorizer) LoginPortal(ctx *fasthttp.RequestCtx) string {
	user := ctx.UserValueBytes(TerminusUserHeader)

	if user == nil {
		user = ctx.Request.Header.PeekBytes(TerminusUserHeader)
	}

	if user == nil {
		// try to gen the user's login portal from request url
		klog.Info("user header not found, gen login url from request")
		uri := ctx.Request.URI()
		host := string(uri.Host())
		hostToken := strings.Split(host, ".")
		hostToken[0] = "auth"

		return "https://" + strings.Join(hostToken, ".") + "/"
	}

	userAuth, ok := t.userAuthorizers[string(user.([]byte))]
	if !ok {
		klog.Error("user not found in authorizer, ", string(user.([]byte)))
		return ""
	}

	loginPortal := userAuth.LoginPortal

	return loginPortal
}

// clients config example
// ## The other portions of the mandatory OpenID Connect 1.0 configuration go here.
// ## See: https://www.authelia.com/c/oidc
// clients:
//   - client_id: 'Express.js'
//     client_name: 'Express.js App'
//     client_secret: '$pbkdf2-sha512$310000$c8p78n7pUMln0jzvd4aK4Q$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1wJn5KGiHrD0YKtZaR/nCb2CJPOsKaPK0hjf.9yHxzQGZziziccp6Yng'  # The digest of 'insecure_secret'.
//     public: false
//     authorization_policy: 'two_factor'
//     require_pkce: true
//     require_pushed_authorization_requests: true
//     redirect_uris:
//   - 'https://express.example.com/callback'
//     scopes:
//   - 'openid'
//   - 'profile'
//   - 'email'
//   - 'groups'
//     userinfo_signed_response_alg: 'none'
//     token_endpoint_auth_method: 'client_secret_basic'
func (t *TsAuthorizer) getOIDCClients() error {
	var clients []conf_schema.OpenIDConnectClientConfiguration

	var appList application.ApplicationList
	if err := t.client.List(context.Background(), &appList, client.InNamespace("")); err != nil {
		return err
	}

	for _, app := range appList.Items {
		conf := conf_schema.OpenIDConnectClientConfiguration{
			Public:                   false,
			Policy:                   "two_factor",
			EnforcePKCE:              false,
			Scopes:                   []string{"openid", "profile", "email", "groups"},
			UserinfoSigningAlgorithm: "none",
			ConsentMode:              "implicit",
			GrantTypes:               []string{"refresh_token", "authorization_code"},
			ResponseTypes:            []string{"code"},
			ResponseModes:            []string{"form_post", "query", "fragment"},
		}

		var (
			ok bool
		)

		if conf.ID, ok = app.Spec.Settings["oidc.client.id"]; !ok {
			// klog.Errorf("%s oidc client id not found", app.Name)
			continue
		}

		if secret, ok := app.Spec.Settings["oidc.client.secret"]; !ok {
			klog.Errorf("%s oidc client secret not found", app.Name)
			continue
		} else {
			var err error
			conf.Secret, err = conf_schema.DecodePasswordDigest(secret)
			if err != nil {
				klog.Error("decode secret error, ", err, ", ", app.Name)
				continue
			}
		}

		if redirect_uri, ok := app.Spec.Settings["oidc.client.redirect_uri"]; !ok {
			klog.Errorf("%s oidc client redirect uri not found", app.Name)
			continue
		} else {
			conf.RedirectURIs = []string{redirect_uri}
		}

		clients = append(clients, conf)
	}

	t.oidcConfig.Clients = clients
	t.updateOIDCClients(t.oidcConfig)
	return nil
}
