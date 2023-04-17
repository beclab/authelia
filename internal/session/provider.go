package session

import (
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/jellydator/ttlcache/v3"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
)

// Provider contains a list of domain sessions.
type Provider struct {
	sessions          map[string]*Session
	sessionCreator    func(domain, targetDomain string) (*Session, error)
	lock              sync.Mutex
	Config            schema.SessionConfiguration
	providerWithToken *ttlcache.Cache[string, *Session]
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
					targetDomain: targetDomain,
				}

				return provider.sessions[domain], nil
			} // end if.
		} // end for.

		return nil, fmt.Errorf("no session config found by domain, %s", domain)
	}

	provider.sessionCreator = creator

	return provider
}

// Get returns session information for specified domain.
func (p *Provider) Get(domain, targetDomain, token string) (*Session, error) {
	log := logging.Logger()

	if domain == "" {
		return nil, fmt.Errorf("can not get session from an undefined domain")
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	s, found := p.sessions[domain]

	if !found {
		log.Debugf("find session provider by token %s, and target domain %s", token, targetDomain)

		if s, err := p.GetByToken(token); err != nil {
			return nil, err
		} else if s != nil && s.targetDomain == targetDomain {
			return s, nil
		}

		if s, err := p.sessionCreator(domain, targetDomain); err != nil {
			return nil, err
		} else {
			p.SetByToken(token, s)
			return s, nil
		}
	}

	return s, nil
}

// Get returns session information for specified token.
func (p *Provider) GetByToken(token string) (*Session, error) {
	if token == "" {
		klog.Errorf("can not get session from an undefined token")
		return nil, nil
	}

	s := p.providerWithToken.Get(token)

	if s == nil {
		return nil, nil
	}

	return s.Value(), nil
}

// Get returns session information for specified token.
func (p *Provider) SetByToken(token string, session *Session) {
	if token == "" {
		klog.Warning("token is empty")
		return
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	s := p.providerWithToken.Get(token)

	if s == nil {
		p.providerWithToken.Set(token, session, p.Config.Expiration)
	}
}
