package session

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jellydator/ttlcache/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/utils"
)

// Provider contains a list of domain sessions.
type Provider struct {
	sessions          map[string]SessionProvider
	sessionCreator    func(domain, targetDomain string) (SessionProvider, error)
	lock              sync.Mutex
	Config            schema.SessionConfiguration
	providerWithToken *ttlcache.Cache[string, SessionProvider]

	lldapServer string
}

type Type string

type Claims struct {
	jwt.StandardClaims
	// Private Claim Names
	// Username user identity, deprecated field
	Username string `json:"username,omitempty"`

	Groups []string `json:"groups,omitempty"`
	Mfa    int64    `json:"mfa,omitempty"`
}

type SessionTokenInfo struct {
	Token                 string `json:"token"`
	Username              string `json:"userName"`
	AuthLevel             string `json:"authLevel"`
	FirstFactorTimestamp  int64  `json:"firstFactorTimestamp"`
	SecondFactorTimestamp int64  `json:"secondFactorTimestamp"`
}

// NewProvider instantiate a session provider given a configuration.
func NewProvider(config *schema.Configuration, certPool *x509.CertPool) *Provider {
	// log := logging.Logger()
	lldapServer := fmt.Sprintf("http://%s:%d", config.AuthenticationBackend.LLDAP.Server, *config.AuthenticationBackend.LLDAP.Port)

	provider := &Provider{
		sessions: map[string]SessionProvider{},
		Config:   config.Session,
		providerWithToken: ttlcache.New(
			ttlcache.WithTTL[string, SessionProvider](config.Session.Expiration),
			ttlcache.WithCapacity[string, SessionProvider](1000),
		),
		lldapServer: lldapServer,
	}

	// if config.Session.Redis != nil {
	// 	// reload token from redis.
	// 	lister, err := NewLister(provider.Config, certPool)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	provider.reloadLister = lister
	// }

	creator := func(domain, targetDomain string) (SessionProvider, error) {
		for _, dconfig := range provider.Config.Cookies {
			klog.Info("try to create session holder for domain, ", dconfig.Domain, " ", domain)

			// name, p, s, err := NewSessionProvider(provider.Config, certPool)

			// if err != nil {
			// 	log.Fatal(err)
			// }

			if dconfig.Domain == domain {
				// _, holder, err := NewProviderConfigAndSession(dconfig, name, s, p)

				// if err != nil {
				// 	return nil, err
				// }
				//
				// provider.sessions[domain] = &internelSession{
				// 	Config:        dconfig,
				// 	sessionHolder: holder,
				// 	sessionWithToken: ttlcache.New(
				// 		ttlcache.WithTTL[string, string](dconfig.Expiration),
				// 		ttlcache.WithCapacity[string, string](1000),
				// 	),
				// 	TargetDomain: targetDomain,
				// }

				provider.sessions[domain] = &lldapSession{
					TargetDomain: targetDomain,
					Config:       &dconfig,
					tokenCache: ttlcache.New(
						ttlcache.WithTTL[string, *UserSession](dconfig.Expiration),
						ttlcache.WithCapacity[string, *UserSession](1000),
					),
					lldapAddr:     lldapServer,
					parseToken:    parseToken,
					revokingToken: make(map[string]string),
				}

				return provider.sessions[domain], nil
			} // end if.
		} // end for.

		return nil, fmt.Errorf("no session config found by domain, %s", domain)
	}

	provider.sessionCreator = creator

	// if sesssion provider is lldap session
	provider.reloadTokenToCache(lldapServer)

	return provider
}

// Get returns session information for specified domain.
func (p *Provider) Get(domain, targetDomain, token string, backend bool) (SessionProvider, error) {
	log := logging.Logger()

	if domain == "" && !backend {
		return nil, fmt.Errorf("can not get session from an undefined domain")
	}

	log.Debugf("find session provider by token %s, current domain %s, and target domain %s", token, domain, targetDomain)

	var (
		s     SessionProvider
		found bool
		err   error
	)

	if domain != "" {
		s, found = p.sessions[domain]
	}

	if found {
		log.Debugf("found session provider by domain %s", domain)
		return s, nil
	}

	if s = p.GetByToken(token); s != nil && (p.findDomain(s.GetTargetDomain()) == domain || backend) { // TODO: install wizard.
		return s, nil
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	if domain != "" {
		s, found = p.sessions[domain]
	} else {
		log.Error("domain is empty and is not a backend request")
		return nil, fmt.Errorf("can not get session from an undefined domain")
	}

	if !found {
		if s, err = p.sessionCreator(domain, targetDomain); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Get returns session information for specified token.
func (p *Provider) GetByToken(token string) SessionProvider {
	if token == "" {
		klog.Errorf("can not get session from an undefined token")
		return nil
	}

	s := p.providerWithToken.Get(token)

	if s == nil {
		return nil
	}

	return s.Value()
}

// Get returns session information for specified token.
func (p *Provider) SetByToken(token string, session SessionProvider) {
	if token == "" {
		klog.Warning("token is empty")
		return
	}

	s := p.providerWithToken.Get(token)

	if s == nil {
		p.providerWithToken.Set(token, session, p.Config.Expiration)
	}
}

func (p *Provider) RevokeByToken(token string) {
	if token != "" {
		p.providerWithToken.Delete(token)
	}
}

func (p *Provider) GetUserTokens(user string) ([]*SessionTokenInfo, error) {
	dataList, err := p.tokenList(p.lldapServer)

	if err != nil {
		klog.Error("get token list error, ", err)
		return nil, err
	}

	var infos []*SessionTokenInfo
	for _, data := range dataList {
		if data.IsBlacklisted {
			klog.Warning("token is blacklisted, ", data.AccessToken)
			continue
		}

		claims, err := parseToken(data.AccessToken)
		if err != nil {
			klog.Error("parse token error, ", err, ", token: ", data.AccessToken)
			continue
		}

		if claims.Username == user {
			token := strings.Split(data.AccessToken, ".")
			if len(token) != 3 {
				klog.Error("invalid access token in session data, ", data.AccessToken)
				continue
			}

			authenticationLevel := authentication.OneFactor
			if claims.Mfa > 0 {
				authenticationLevel = authentication.TwoFactor
			}

			info := &SessionTokenInfo{
				Token:                 data.AccessToken,
				Username:              claims.Username,
				AuthLevel:             authenticationLevel.String(),
				FirstFactorTimestamp:  claims.IssuedAt,
				SecondFactorTimestamp: claims.IssuedAt,
			}

			infos = append(infos, info)
		}

	}

	return infos, nil
}

func (p *Provider) findDomain(hostname string) string {
	for _, domain := range p.Config.Cookies {
		if utils.HasDomainSuffix(hostname, domain.Domain) {
			return domain.Domain
		}
	}

	return hostname
}

func (p *Provider) reloadTokenToCache(server string) {
	klog.Info("start to reload token from session redis storage")

	users, err := p.listUserData()
	if err != nil {
		panic(err)
	}

	dataList, err := p.tokenList(server)

	if err != nil {
		klog.Error("reload token list error, ", err)
		panic(err)
	}

	for _, data := range dataList {
		claims, err := parseToken(data.AccessToken)
		if err != nil {
			klog.Error("parse token error, ", err, ", token: ", data.AccessToken)
			continue
		}

		var user *unstructured.Unstructured
		if user = func() *unstructured.Unstructured {
			for _, u := range users {
				if u.GetName() == claims.Username {
					return &u
				}
			}

			return nil
		}(); user == nil {
			klog.Info("clear unknown user, ", claims.Username)
			continue
		}

		userZone, ok := user.GetAnnotations()[authorization.UserAnnotationZoneKey]
		if !ok {
			klog.Error("user zone not found in user annotations, ", claims.Username)
			continue
		}

		// create provider.
		if func() bool {
			for _, c := range p.Config.Cookies {
				if c.Domain == userZone {
					return false
				}
			}

			return true
		}() {
			if len(p.Config.Cookies) > 0 {
				c := p.Config.Cookies[0]
				c.Domain = userZone
				p.Config.Cookies = append(p.Config.Cookies, c)
			}
		}

		s, err := p.Get(userZone, userZone, data.AccessToken, false)

		if err != nil {
			klog.Error("create provider error")
			continue
		}

		s.SaveSessionID(data.AccessToken, data.IsBlacklisted)

		p.SetByToken(data.AccessToken, s)
	}
}

func (p *Provider) listUserData() ([]unstructured.Unstructured, error) {
	kubeConfig := ctrl.GetConfigOrDie()

	gvr := k8sschema.GroupVersionResource{
		Group:    "iam.kubesphere.io",
		Version:  "v1alpha2",
		Resource: "users",
	}
	client, err := dynamic.NewForConfig(kubeConfig)

	if err != nil {
		return nil, err
	}

	data, err := client.Resource(gvr).List(context.Background(), metav1.ListOptions{})

	if err != nil {
		return nil, err
	}

	return data.Items, nil
}

type tokenInfo struct {
	AccessToken   string `json:"access_token"`
	IsBlacklisted bool   `json:"is_blacklisted"`
}

func (p *Provider) tokenList(baseURL string) ([]tokenInfo, error) {
	url := fmt.Sprintf("%s/auth/token/list", baseURL)
	client := resty.New()

	resp, err := client.SetTimeout(30*time.Second).R().
		SetHeader("Content-Type", "application/json").
		Get(url)
	if err != nil {
		klog.Infof("send request failed: %v", err)
		return nil, err
	}
	if resp.StatusCode() != http.StatusOK {
		klog.Infof("not 200, %v, body: %v", resp.StatusCode(), string(resp.Body()))
		return nil, errors.New(resp.String())
	}
	var response []tokenInfo
	err = json.Unmarshal(resp.Body(), &response)
	if err != nil {
		klog.Infof("unmarshal failed: %v", err)
		return nil, err
	}
	klog.Infof("tokenList res: %v", response)
	return response, nil
}

func parseToken(token string) (*Claims, error) {
	if len(token) == 0 {
		return nil, errors.New("token is empty")
	}

	// Parse the JWT token with claims and without claims validation
	parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, nil, jwt.WithoutClaimsValidation())

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			switch {
			case ve.Errors&jwt.ValidationErrorMalformed != 0:
				return nil, fmt.Errorf("malformed token: %w", err)
			case ve.Errors&jwt.ValidationErrorExpired != 0:
				return nil, fmt.Errorf("token expired: %w", err)
			case ve.Errors&jwt.ValidationErrorSignatureInvalid != 0:
				return nil, fmt.Errorf("invalid token signature: %w", err)
			case ve.Errors&jwt.ValidationErrorUnverifiable != 0:
				// do not need verify the token signature
			default:
				return nil, fmt.Errorf("token validation error: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}
	}

	claims, ok := parsedToken.Claims.(*Claims)
	if !ok {
		return nil, errors.New("failed to extract claims from token")
	}

	return claims, nil
}
