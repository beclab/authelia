package middlewares

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-resty/resty/v2"
	"github.com/valyala/fasthttp"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
)

// NewBridgeBuilder creates a new BridgeBuilder.
func NewBridgeBuilder(config schema.Configuration, providers Providers) *BridgeBuilder {
	b := &BridgeBuilder{
		config:     config,
		providers:  providers,
		httpClient: resty.New().SetTimeout(2 * time.Second),
	}

	return b
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
			user := requestCtx.Request.Header.PeekBytes(authorization.TerminusUserHeader)
			if user == nil {
				klog.Error("cannot get user name from header")

				host := string(requestCtx.Host())
				host = strings.Split(host, ":")[0]
				if govalidator.IsIP(host) && authorization.AdminUser != "" {
					// only admin user will access the os via ip and port
					user = []byte(authorization.AdminUser)
					klog.Info("set the default admin user, ", authorization.AdminUser)
				} else {
					// FIXME:
					hostToken := strings.Split(host, ".")
					for _, t := range hostToken {
						klog.Info("try to find user space")
						if strings.HasPrefix(t, "user-space-") {
							user = []byte(strings.Replace(t, "user-space-", "", 1))
						}
					}

					if user == nil {
						requestCtx.Error("cannot get user name from header", http.StatusBadRequest)
						return
					}
				}
			}

			info, err := utils.GetUserInfoFromBFL(b.httpClient, string(user))
			if err != nil {
				klog.Error("reload user info error, ", err)
				requestCtx.Error(err.Error(), http.StatusBadRequest)
				return
			}

			var domain string

			var host *url.URL

			hostStr := string(requestCtx.Host())

			parentDomain := func(host string) string {
				hostSub := strings.Split(host, ".")
				return strings.Join(hostSub[1:], ".")
			}

			host, err = url.Parse(string(requestCtx.URI().Scheme()) + "://" + hostStr + "/")

			if err != nil {
				klog.Error("cannot parse request host, ", host)
				requestCtx.Error("cannot parse request host", http.StatusBadRequest)
				return
			}

			if info.Zone == "" { // admin user.
				domain = strings.Split(hostStr, ":")[0]

				if info.IsEphemeral {
					domain = parentDomain(domain)
				}
			} else {
				domain = info.Zone
			}

			klog.Info("find domain from user and request: ", domain)

			var cconfig *schema.SessionCookieConfiguration

			for i, c := range b.config.Session.Cookies {
				if c.Domain == domain {
					cconfig = &b.config.Session.Cookies[i]
					break
				}
			}

			if cconfig == nil && len(b.config.Session.Cookies) > 0 {
				c := b.config.Session.Cookies[0]
				c.Domain = domain
				c.AutheliaURL = host
				b.config.Session.Cookies = append(b.config.Session.Cookies, c)
			}

			b.providers.SessionProvider.Config = b.config.Session
			b.config.DefaultRedirectionURL = string(requestCtx.URI().Scheme()) + "://" + domain + "/"
			next(NewAutheliaCtx(requestCtx, b.config, b.providers))
		}

		for i := len(b.preMiddlewares) - 1; i >= 0; i-- {
			bridge = b.preMiddlewares[i](bridge)
		}

		return bridge
	}
}
