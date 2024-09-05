package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/fosite"
	"k8s.io/klog/v2"
)

type terminusAuthorizeRequester struct {
	*fosite.AuthorizeRequest
	httpRequest *http.Request
}

// override
func (r *terminusAuthorizeRequester) GetRedirectURI() *url.URL {
	u := r.AuthorizeRequest.GetRedirectURI()

	refer := getCookie(r.httpRequest, "prev-host")
	klog.Info("try to find refer for requets, ", u.String())
	if refer != "" {
		klog.Info("found refer for redirect url, ", u.String(), ", ", refer)
		referToken := strings.Split(refer, ".")

		if len(referToken) > 1 && referToken[1] == "local" {
			klog.Info("force change redirect url host ", u.Host, " to local")
			hostToken := strings.Split(u.Host, ".")
			if hostToken[1] != "local" {
				var newHostToken []string
				newHostToken = append(newHostToken, hostToken[0])
				newHostToken = append(newHostToken, "local")
				newHostToken = append(newHostToken, hostToken[1:]...)
				u.Host = strings.Join(newHostToken, ".")
			}
		}
	}

	return u
}

func getCookie(r *http.Request, cookieName string) string {
	for _, c := range r.Cookies() {
		if c.Name == cookieName {
			return c.Value
		}
	}

	return ""
}
