package middlewares

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/valyala/fasthttp"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/jellydator/ttlcache/v3"
)

// NewBridgeBuilder creates a new BridgeBuilder.
func NewBridgeBuilder(config *schema.Configuration, providers *Providers) *BridgeBuilder {
	b := &BridgeBuilder{
		config:     config,
		providers:  providers,
		httpClient: resty.New().SetTimeout(2 * time.Second),
		userCache: ttlcache.New(
			ttlcache.WithTTL[string, *utils.UserInfo](time.Minute),
			ttlcache.WithCapacity[string, *utils.UserInfo](1000),
			ttlcache.WithDisableTouchOnHit[string, *utils.UserInfo](),
		),
	}

	return b
}

// WithConfig sets the schema.Configuration used with this BridgeBuilder.
func (b *BridgeBuilder) WithConfig(config *schema.Configuration) *BridgeBuilder {
	b.config = config

	return b
}

// WithProviders sets the Providers used with this BridgeBuilder.
func (b *BridgeBuilder) WithProviders(providers *Providers) *BridgeBuilder {
	b.providers = providers

	return b
}

// WithPreMiddlewares sets the Middleware's used with this BridgeBuilder which are applied before the actual Bridge.
func (b *BridgeBuilder) WithPreMiddlewares(middlewares ...Middleware) *BridgeBuilder {
	b.preMiddlewares = middlewares

	return b
}

// WithPostMiddlewares sets the AutheliaMiddleware's used with this BridgeBuilder which are applied after the actual
// Bridge.
func (b *BridgeBuilder) WithPostMiddlewares(middlewares ...AutheliaMiddleware) *BridgeBuilder {
	b.postMiddlewares = middlewares

	return b
}

// Build and return the Bridge configured by this BridgeBuilder.
func (b *BridgeBuilder) Build() Bridge {
	return func(next RequestHandler) fasthttp.RequestHandler {
		for i := len(b.postMiddlewares) - 1; i >= 0; i-- {
			next = b.postMiddlewares[i](next)
		}

		bridge := func(requestCtx *fasthttp.RequestCtx) {
			var domain string

			var host *url.URL

			hostStr := string(requestCtx.Host())

			host, err := url.Parse(string(requestCtx.URI().Scheme()) + "://" + hostStr + "/")
			if err != nil {
				klog.Error("cannot parse request host, ", host)
				requestCtx.Error("cannot parse request host", http.StatusBadRequest)
				return
			}

			domain = strings.Split(hostStr, ":")[0]
			// validate domain, if not valid, check if it's a custom domain from user
			if zone, ok := authorization.ValidDomain[domain]; ok {
				domain = zone
			} else {
				_, ok := authorization.UserCustomDomain[domain]
				if !ok {
					// FIXME: request from a local ip, should be validated too
					if !utils.IsIP(domain) {
						klog.Error("cannot find domain from user and request: ", domain)
						requestCtx.Error("cannot find domain from user and request", http.StatusBadRequest)
						return
					}
				}
			}

			klog.Info("find domain from user and request: ", domain)

			var cconfig *schema.SessionCookieConfiguration

			b.cookieMu.RLock()
			for i, c := range b.config.Session.Cookies {
				if c.Domain == domain {
					cconfig = &b.config.Session.Cookies[i]
					break
				}
			}
			b.cookieMu.RUnlock()

			if cconfig == nil {
				b.cookieMu.Lock()
				// must have a placeholder cookie config
				klog.Info("add new cookie domain: ", domain)
				c := b.config.Session.Cookies[0]
				c.Domain = domain
				c.AutheliaURL = host
				b.config.Session.Cookies = append(b.config.Session.Cookies, c)
				b.providers.SessionProvider.Config = b.config.Session
				b.cookieMu.Unlock()
			}

			ctxConfig := *b.config
			ctxConfig.DefaultRedirectionURL = string(requestCtx.URI().Scheme()) + "://" + domain + "/"
			ctx := NewAutheliaCtx(requestCtx, ctxConfig, *b.providers)
			next(ctx)
		}

		for i := len(b.preMiddlewares) - 1; i >= 0; i-- {
			bridge = b.preMiddlewares[i](bridge)
		}

		return bridge
	}
}
