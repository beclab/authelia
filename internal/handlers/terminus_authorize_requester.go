package handlers

import (
	"net/http"
	"net/url"

	"github.com/ory/fosite"
)

type terminusAuthorizeRequester struct {
	*fosite.AuthorizeRequest
	httpRequest *http.Request
}

// override
func (r *terminusAuthorizeRequester) GetRedirectURI() *url.URL {
	u := r.AuthorizeRequest.GetRedirectURI()
	return u
}
