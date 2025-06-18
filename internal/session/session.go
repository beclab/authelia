package session

import (
	"encoding/json"
	"time"

	"github.com/fasthttp/session/v2"
	"github.com/jellydator/ttlcache/v3"
	"github.com/valyala/fasthttp"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

var _ SessionProvider = (*internelSession)(nil)

// Session a session provider.
type internelSession struct {
	Config schema.SessionCookieConfiguration

	sessionHolder *session.Session

	sessionWithToken *ttlcache.Cache[string, string]

	TargetDomain string
}

// NewDefaultUserSession returns a new default UserSession for this session provider.
func (p *internelSession) NewDefaultUserSession() (userSession UserSession) {
	userSession = NewDefaultUserSession()

	userSession.CookieDomain = p.Config.Domain

	return userSession
}

// GetSession return the user session from a request.
func (p *internelSession) GetSession(ctx *fasthttp.RequestCtx) (userSession UserSession, err error) {
	var store *session.Store

	klog.Info("get ctx session cookie, ", string(ctx.Request.Header.Cookie("authelia_session")), " config domain: ", p.Config.Domain)

	if store, err = p.sessionHolder.Get(ctx); err != nil {
		return p.NewDefaultUserSession(), err
	}

	userSessionJSON, ok := store.Get(userSessionStorerKey).([]byte)

	// If userSession is not yet defined we create the new session with default values
	// and save it in the store.
	if !ok {
		klog.Info("user session not found in store, create new session")

		userSession = p.NewDefaultUserSession()

		store.Set(userSessionStorerKey, userSession)

		return userSession, nil
	}

	if err = json.Unmarshal(userSessionJSON, &userSession); err != nil {
		return p.NewDefaultUserSession(), err
	}

	return userSession, nil
}

// SaveSession save the user session.
func (p *internelSession) SaveSession(ctx *fasthttp.RequestCtx, userSession UserSession) (err error) {
	var (
		store           *session.Store
		userSessionJSON []byte
	)

	if store, err = p.sessionHolder.Get(ctx); err != nil {
		return err
	}

	if userSessionJSON, err = json.Marshal(userSession); err != nil {
		return err
	}

	store.Set(userSessionStorerKey, userSessionJSON)
	// anonymous session default expiration 5 minutes
	if userSession.Username == "" {
		store.SetExpiration(5 * time.Minute)
	} else {
		store.SetExpiration(p.Config.Expiration)
	}

	if err = p.sessionHolder.Save(ctx, store); err != nil {
		return err
	}

	// force remove session cookie
	cookie := ctx.UserValueBytes(authentication.AuthnAcceptCookeKey)
	if cookie != nil && !*cookie.(*bool) {
		ctx.Response.Header.DelCookie(p.Config.SessionCookieCommonConfiguration.Name)
	}

	return nil
}

// RegenerateSession regenerate a session ID.
func (p *internelSession) RegenerateSession(ctx *fasthttp.RequestCtx) error {
	return p.sessionHolder.Regenerate(ctx)
}

// DestroySession destroy a session ID and delete the cookie.
func (p *internelSession) DestroySession(ctx *fasthttp.RequestCtx) error {
	klog.Warning("destroy session cookie, ", string(ctx.Request.Header.Cookie(p.Config.SessionCookieCommonConfiguration.Name)))
	return p.sessionHolder.Destroy(ctx)
}

// UpdateExpiration update the expiration of the cookie and session.
func (p *internelSession) UpdateExpiration(ctx *fasthttp.RequestCtx, expiration time.Duration) (err error) {
	var store *session.Store

	if store, err = p.sessionHolder.Get(ctx); err != nil {
		return err
	}

	err = store.SetExpiration(expiration)

	if err != nil {
		return err
	}

	return p.sessionHolder.Save(ctx, store)
}

// GetExpiration get the expiration of the current session.
func (p *internelSession) GetExpiration(ctx *fasthttp.RequestCtx) (time.Duration, error) {
	store, err := p.sessionHolder.Get(ctx)

	if err != nil {
		return time.Duration(0), err
	}

	return store.GetExpiration(), nil
}

func (p *internelSession) GetSessionID(token string) string {
	item := p.sessionWithToken.Get(token)
	if item == nil {
		klog.Warning("cannot get cookie with token, ", token)
		return ""
	}

	return item.Value()
}

func (p *internelSession) SaveSessionID(token string, sessionId any) {
	p.sessionWithToken.Set(token, sessionId.(string), p.Config.Expiration)
}

func (p *internelSession) RemoveSessionID(token string) {
	p.sessionWithToken.Delete(token)
}

func (p *internelSession) GetTargetDomain() string {
	return p.TargetDomain
}

func (p *internelSession) GetConfig() *schema.SessionCookieConfiguration {
	return &p.Config
}

func (p *internelSession) SetTargetDomain(domain string) {
	p.TargetDomain = domain
}
