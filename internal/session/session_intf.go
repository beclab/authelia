package session

import (
	"time"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/valyala/fasthttp"
)

type SessionProvider interface {
	NewDefaultUserSession() (userSession UserSession)
	GetSession(ctx *fasthttp.RequestCtx) (userSession UserSession, err error)
	SaveSession(ctx *fasthttp.RequestCtx, userSession UserSession) (err error)
	RegenerateSession(ctx *fasthttp.RequestCtx) error
	DestroySession(ctx *fasthttp.RequestCtx) error
	UpdateExpiration(ctx *fasthttp.RequestCtx, expiration time.Duration) (err error)
	GetExpiration(ctx *fasthttp.RequestCtx) (time.Duration, error)
	GetSessionID(token string) string
	SaveSessionID(token string, param any)
	RemoveSessionID(token string)
	GetTargetDomain() string
	SetTargetDomain(domain string)
	GetConfig() *schema.SessionCookieConfiguration
	ClearUserTokenCache(username string)
	// SearchSession searches for a session by token, if not found, it will search the revoking token.
	SearchSession(ctx *fasthttp.RequestCtx) (userSession UserSession, err error)
}

const AUTH_TOKEN = "auth_token"
