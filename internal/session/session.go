package session

import (
	"encoding/json"
	"time"

	"github.com/fasthttp/session/v2"
	"github.com/jellydator/ttlcache/v3"
	"github.com/valyala/fasthttp"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

// Session a session provider.
type Session struct {
	Config schema.SessionCookieConfiguration

	sessionHolder *session.Session

	sessionWithToken *ttlcache.Cache[string, string]

	TargetDomain string
}

// NewDefaultUserSession returns a new default UserSession for this session provider.
func (p *Session) NewDefaultUserSession() (userSession UserSession) {
	userSession = NewDefaultUserSession()

	userSession.CookieDomain = p.Config.Domain

	return userSession
}

// GetSession return the user session from a request.
func (p *Session) GetSession(ctx *fasthttp.RequestCtx) (userSession UserSession, err error) {
	var store *session.Store

	klog.Info("get ctx session cookie, ", string(ctx.Request.Header.Cookie("authelia_session")), " config domain: ", p.Config.Domain)

	if store, err = p.sessionHolder.Get(ctx); err != nil {
		return p.NewDefaultUserSession(), err
	}

	userSessionJSON, ok := store.Get(userSessionStorerKey).([]byte)

	// If userSession is not yet defined we create the new session with default values
	// and save it in the store.
	if !ok {
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
func (p *Session) SaveSession(ctx *fasthttp.RequestCtx, userSession UserSession) (err error) {
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

	if err = p.sessionHolder.Save(ctx, store); err != nil {
		return err
	}

	return nil
}

// RegenerateSession regenerate a session ID.
func (p *Session) RegenerateSession(ctx *fasthttp.RequestCtx) error {
	return p.sessionHolder.Regenerate(ctx)
}

// DestroySession destroy a session ID and delete the cookie.
func (p *Session) DestroySession(ctx *fasthttp.RequestCtx) error {
	return p.sessionHolder.Destroy(ctx)
}

// UpdateExpiration update the expiration of the cookie and session.
func (p *Session) UpdateExpiration(ctx *fasthttp.RequestCtx, expiration time.Duration) (err error) {
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
func (p *Session) GetExpiration(ctx *fasthttp.RequestCtx) (time.Duration, error) {
	store, err := p.sessionHolder.Get(ctx)

	if err != nil {
		return time.Duration(0), err
	}

	return store.GetExpiration(), nil
}

func (p *Session) GetSessionID(token string) string {
	item := p.sessionWithToken.Get(token)
	if item == nil {
		klog.Warning("cannot get cookie with token, ", token)
		return ""
	}

	return item.Value()
}

func (p *Session) SaveSessionID(token, sessionId string) {
	p.sessionWithToken.Set(token, sessionId, p.Config.Expiration)
}

func (p *Session) RemoveSessionID(token string) {
	p.sessionWithToken.Delete(token)
}
