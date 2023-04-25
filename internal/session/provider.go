package session

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/fasthttp/session/v2"
	"github.com/go-resty/resty/v2"
	"github.com/jellydator/ttlcache/v3"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	kubesphere "github.com/authelia/authelia/v4/internal/session/kubesphere/v3.3"
	"github.com/authelia/authelia/v4/internal/utils"
)

// Provider contains a list of domain sessions.
type Provider struct {
	sessions          map[string]*Session
	sessionCreator    func(domain, targetDomain string) (*Session, error)
	lock              sync.Mutex
	Config            schema.SessionConfiguration
	providerWithToken *ttlcache.Cache[string, *Session]

	reloadLister *Lister
}

// NewProvider instantiate a session provider given a configuration.
func NewProvider(config schema.SessionConfiguration, certPool *x509.CertPool) *Provider {
	log := logging.Logger()

	provider := &Provider{
		sessions: map[string]*Session{},
		Config:   config,
		providerWithToken: ttlcache.New(
			ttlcache.WithTTL[string, *Session](config.Expiration),
			ttlcache.WithCapacity[string, *Session](1000),
		),
	}

	if config.Redis != nil {
		// reload token from redis.
		lister, err := NewLister(provider.Config, certPool)
		if err != nil {
			panic(err)
		}

		provider.reloadLister = lister
	}

	creator := func(domain, targetDomain string) (*Session, error) {
		for _, dconfig := range provider.Config.Cookies {
			klog.Info("try to create session holder for domain, ", dconfig.Domain, " ", domain)

			name, p, s, err := NewSessionProvider(provider.Config, certPool)

			if err != nil {
				log.Fatal(err)
			}

			if dconfig.Domain == domain {
				_, holder, err := NewProviderConfigAndSession(dconfig, name, s, p)

				if err != nil {
					return nil, err
				}

				provider.sessions[domain] = &Session{
					Config:        dconfig,
					sessionHolder: holder,
					sessionWithToken: ttlcache.New(
						ttlcache.WithTTL[string, string](dconfig.Expiration),
						ttlcache.WithCapacity[string, string](1000),
					),
					TargetDomain: targetDomain,
				}

				return provider.sessions[domain], nil
			} // end if.
		} // end for.

		return nil, fmt.Errorf("no session config found by domain, %s", domain)
	}

	provider.sessionCreator = creator

	if provider.reloadLister != nil {
		provider.reloadTokenToCache()
	}

	return provider
}

// Get returns session information for specified domain.
func (p *Provider) Get(domain, targetDomain, token string, backend bool) (*Session, error) {
	log := logging.Logger()

	if domain == "" {
		return nil, fmt.Errorf("can not get session from an undefined domain")
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	log.Debugf("find session provider by token %s, current domain %s, and target domain %s", token, domain, targetDomain)

	var (
		s     *Session
		found bool
		err   error
	)

	if s = p.GetByToken(token); s != nil && (p.findDomain(s.TargetDomain) == domain || backend) { // TODO: install wizard.
		return s, nil
	} else {
		s, found = p.sessions[domain]
	}

	if !found {
		if s, err = p.sessionCreator(domain, targetDomain); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Get returns session information for specified token.
func (p *Provider) GetByToken(token string) *Session {
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
func (p *Provider) SetByToken(token string, session *Session) {
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

func (p *Provider) findDomain(hostname string) string {
	for _, domain := range p.Config.Cookies {
		if utils.HasDomainSuffix(hostname, domain.Domain) {
			return domain.Domain
		}
	}

	return hostname
}

func (p *Provider) reloadTokenToCache() {
	klog.Info("start to reload token from session redis storage")

	info, err := utils.GetUserInfoFromBFL(resty.New().SetTimeout(2 * time.Second))

	if err != nil {
		klog.Error("reload user info error, ", err)
		panic(err)
	}

	// force target domain equals user's zone.
	targetDomain := info.Zone

	serializer := NewEncryptingSerializer(p.Config.Secret)

	dataList, err := p.reloadLister.List()

	if err != nil {
		klog.Error("reload token list error, ", err)
		panic(err)
	}

	ksTokenOperator, err := kubesphere.NewTokenOperator()

	if err != nil {
		klog.Error("connect to kubesphere token cache error, ", err)
	}

	for sid, data := range dataList {
		var sess session.Dict
		err := serializer.Decode(&sess, data)

		if err != nil {
			klog.Error("decode session data error, ", err)
			continue
		}

		var us UserSession
		err = json.Unmarshal(sess.KV[userSessionStorerKey].([]byte), &us)

		if err != nil {
			klog.Error("json unmarshal session data error, ", err)
			continue
		}

		token := us.AccessToken
		domain := us.CookieDomain

		if token == "" {
			klog.Info("ignore unauthorized session, ", sid)
			continue
		}

		if ksTokenOperator != nil {
			ksTokenOperator.RestoreToken(us.Username, token, p.Config.Expiration)
		}

		// create provider.
		if func() bool {
			for _, c := range p.Config.Cookies {
				if c.Domain == domain {
					return false
				}
			}

			return true
		}() {
			if len(p.Config.Cookies) > 0 {
				c := p.Config.Cookies[0]
				c.Domain = domain
				p.Config.Cookies = append(p.Config.Cookies, c)
			}
		}

		s, err := p.Get(domain, targetDomain, token, false)

		if err != nil {
			klog.Error("create provider error")
			continue
		}

		s.SaveSessionID(token, sid)
		p.SetByToken(token, s)
	}

	if ksTokenOperator != nil {
		ksTokenOperator.Close()
	}
}
