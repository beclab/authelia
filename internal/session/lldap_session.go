package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jellydator/ttlcache/v3"
	"github.com/savsgio/gotils/strconv"
	"github.com/valyala/fasthttp"
	"k8s.io/klog/v2"
)

var _ SessionProvider = (*lldapSession)(nil)

type lldapSession struct {
	TargetDomain string
	Config       *schema.SessionCookieConfiguration
	tokenCache   *ttlcache.Cache[string, *UserSession]
}

// DestroySession implements SessionProvider.
func (l *lldapSession) DestroySession(ctx *fasthttp.RequestCtx) error {
	token := l.getToken(ctx)
	if len(token) == 0 {
		klog.Error("no session token found in request context, nothing to destroy")
		return nil
	}

	klog.Infof("destroying session with token %s", token)

	// Remove the session from the cache.
	if l.tokenCache != nil {
		l.tokenCache.Delete(token)
	}

	// Delete the token from the lldap

	return nil
}

// GetConfig implements SessionProvider.
func (l *lldapSession) GetConfig() *schema.SessionCookieConfiguration {
	return l.Config
}

// GetExpiration implements SessionProvider.
func (l *lldapSession) GetExpiration(ctx *fasthttp.RequestCtx) (time.Duration, error) {
	panic("unimplemented")
}

// GetSession implements SessionProvider.
func (l *lldapSession) GetSession(ctx *fasthttp.RequestCtx) (userSession UserSession, err error) {
	token := l.getToken(ctx)
	if len(token) == 0 {
		klog.Error("no session token found in request context")
		return l.NewDefaultUserSession(), errors.New("no session token found in request context")
	}

	// validate token
	if l.tokenCache == nil {
		klog.Error("token cache is not initialized")
		return l.NewDefaultUserSession(), errors.New("token cache is not initialized")
	}

	if item := l.tokenCache.Get(token); item != nil {
		klog.Infof("session found in cache for token %s", token)
		session := item.Value()
		return *session, nil
	}

	// Token not found in cache, parse and validate the JWT token
	claims, err := l.parseToken(token)
	if err != nil {
		klog.Errorf("failed to parse token: %v", err)
		return l.NewDefaultUserSession(), fmt.Errorf("invalid token: %w", err)
	}

	// Create user session from claims
	userSession = l.NewDefaultUserSession()
	userSession.Username = claims.Username
	userSession.DisplayName = claims.PreferredUsername
	userSession.Emails = []string{claims.Email}
	userSession.CookieDomain = l.Config.Domain

	// Store in cache for future requests
	l.tokenCache.Set(token, &userSession, time.Until(time.Unix(claims.ExpiresAt, 0))) // Cache for 1 hour

	return userSession, nil
}

// GetSessionID implements SessionProvider.
func (l *lldapSession) GetSessionID(token string) string {
	return token
}

// GetTargetDomain implements SessionProvider.
func (l *lldapSession) GetTargetDomain() string {
	return l.TargetDomain
}

// NewDefaultUserSession implements SessionProvider.
func (l *lldapSession) NewDefaultUserSession() (userSession UserSession) {
	userSession = NewDefaultUserSession()

	userSession.CookieDomain = l.Config.Domain

	return userSession
}

// RegenerateSession implements SessionProvider.
func (l *lldapSession) RegenerateSession(ctx *fasthttp.RequestCtx) error {
	panic("unimplemented")
}

// RemoveSessionID implements SessionProvider.
func (l *lldapSession) RemoveSessionID(token string) {
	panic("unimplemented")
}

// SaveSession implements SessionProvider.
func (l *lldapSession) SaveSession(ctx *fasthttp.RequestCtx, userSession UserSession) (err error) {
	// For LLDAP session, we don't need to save session data as it's JWT-based
	// The token itself contains all the necessary information
	// We could optionally cache the session if needed
	token := l.getToken(ctx)
	if token != "" && l.tokenCache != nil {
		l.tokenCache.Set(token, &userSession, time.Hour)
	}
	return nil
}

// SaveSessionID implements SessionProvider.
func (l *lldapSession) SaveSessionID(token string, sessionId string) {
	// do nothing, lldapSession does not use session ID
}

// SetTargetDomain implements SessionProvider.
func (l *lldapSession) SetTargetDomain(domain string) {
	l.TargetDomain = domain
}

// UpdateExpiration implements SessionProvider.
func (l *lldapSession) UpdateExpiration(ctx *fasthttp.RequestCtx, expiration time.Duration) (err error) {
	klog.Error("UpdateExpiration is not implemented for lldapSession, as it uses JWT tokens which do not require session expiration management")
	return nil
}

func (l *lldapSession) getToken(ctx *fasthttp.RequestCtx) string {
	val := ctx.Request.Header.Cookie(AUTH_TOKEN)
	if len(val) > 0 {
		return strconv.B2S(val)
	}

	if token := ctx.Request.Header.PeekBytes(utils.TerminusAuthTokenHeader); len(token) > 0 {
		return strconv.B2S(token)
	}

	return ""
}

func (l *lldapSession) parseToken(token string) (*Claims, error) {
	if len(token) == 0 {
		return nil, errors.New("token is empty")
	}

	// Parse the JWT token with claims and without claims validation
	parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, nil, jwt.WithoutClaimsValidation())

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			switch {
			case ve.Errors&jwt.ValidationErrorMalformed != 0:
				return nil, fmt.Errorf("malformed token: %w", err)
			case ve.Errors&jwt.ValidationErrorExpired != 0:
				return nil, fmt.Errorf("token expired: %w", err)
			case ve.Errors&jwt.ValidationErrorNotValidYet != 0:
				return nil, fmt.Errorf("token not valid yet: %w", err)
			case ve.Errors&jwt.ValidationErrorSignatureInvalid != 0:
				return nil, fmt.Errorf("invalid token signature: %w", err)
			default:
				return nil, fmt.Errorf("token validation error: %w", err)
			}
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if token is valid and extract claims
	if !parsedToken.Valid {
		return nil, errors.New("token is invalid")
	}

	claims, ok := parsedToken.Claims.(*Claims)
	if !ok {
		return nil, errors.New("failed to extract claims from token")
	}

	return claims, nil
}
