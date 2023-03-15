package middlewares

import (
	"net/url"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/valyala/fasthttp"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
)

// NewBridgeBuilder creates a new BridgeBuilder.
func NewBridgeBuilder(config schema.Configuration, providers Providers) *BridgeBuilder {
	return &BridgeBuilder{
		config:     config,
		providers:  providers,
		httpClient: resty.New().SetTimeout(2 * time.Second),
	}
}

// WithConfig sets the schema.Configuration used with this BridgeBuilder.
func (b *BridgeBuilder) WithConfig(config schema.Configuration) *BridgeBuilder {
	b.config = config

	return b
}

// WithProviders sets the Providers used with this BridgeBuilder.
func (b *BridgeBuilder) WithProviders(providers Providers) *BridgeBuilder {
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
			info, err := utils.GetUserInfoFromBFL(b.httpClient)
			if err != nil {
				klog.Error("reload user info error, ", err)
				return
			}

			var domain string

			var host *url.URL

			parentDomain := func(host string) string {
				hostSub := strings.Split(host, ".")
				return strings.Join(hostSub[1:], ".")
			}

			if info.Zone == "" { // admin user.
				hostStr := string(requestCtx.Host())
				domain = strings.Split(hostStr, ":")[0]

				if info.IsEphemeral {
					domain = parentDomain(domain)
				}

				host, err := url.Parse(string(requestCtx.URI().Scheme()) + "://" + hostStr + "/")

				if err != nil {
					klog.Error("cannot parse request host, ", host)
					return
				}
			} else {
				domain = info.Zone
			}

			klog.Info("find domain from user and request: ", domain)

			for i := range b.config.Session.Cookies {
				b.config.Session.Cookies[i].AutheliaURL = host
				b.config.Session.Cookies[i].Domain = domain
			}

			next(NewAutheliaCtx(requestCtx, b.config, b.providers))
		}

		for i := len(b.preMiddlewares) - 1; i >= 0; i-- {
			bridge = b.preMiddlewares[i](bridge)
		}

		return bridge
	}
}
