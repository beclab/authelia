package middlewares

import (
	"net/url"

	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/valyala/fasthttp"
	"k8s.io/klog/v2"
)

// ProbeValidate is a middleware that validates probe requests using a secret.
func ProbeValidate(next fasthttp.RequestHandler, probeSecret string) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		requestURI, err := url.Parse(string(ctx.URI().FullURI()))
		if err != nil {
			klog.Errorf("failed to parse request URI: %v", err)
			next(ctx)
			return
		}

		object := authorization.NewObject(requestURI, string(ctx.Method()), string(ctx.UserAgent()))
		if object.IsPodIp() && object.IsProbeUA(probeSecret) {
			klog.Infof("Probe request detected from UA: %s, responding with 200 OK", object.UA)
			ctx.SetStatusCode(fasthttp.StatusOK)
			return
		}
		next(ctx)
	}
}
