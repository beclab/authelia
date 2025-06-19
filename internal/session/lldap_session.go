package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/go-resty/resty/v2"
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
	lldapAddr    string

	parseToken func(token string) (*Claims, error)
}

// DestroySession implements SessionProvider.
func (l *lldapSession) DestroySession(ctx *fasthttp.RequestCtx) error {
	token := l.getToken(ctx)
	if len(token) == 0 {
		klog.Error("no session token found in request context, nothing to destroy")
		return nil
	}

	klog.Infof("destroying session with token %s", token)

	// Delete the token from the lldap
	err := TokenInvalidate(l.lldapAddr, token, token)
	if err != nil {
		klog.Errorf("failed to invalidate token %s: %v", token, err)
		return fmt.Errorf("failed to invalidate token: %w", err)
	}

	// Remove the session from the cache.
	if l.tokenCache != nil {
		l.tokenCache.Delete(token)
	}

	return nil
}

// GetConfig implements SessionProvider.
func (l *lldapSession) GetConfig() *schema.SessionCookieConfiguration {
	return l.Config
}

// GetExpiration implements SessionProvider.
func (l *lldapSession) GetExpiration(ctx *fasthttp.RequestCtx) (time.Duration, error) {
	token := l.getToken(ctx)
	if len(token) == 0 {
		klog.Error("no session token found in request context")
		return 0, errors.New("no session token found in request context")
	}

	return l.getExpiration(token)
}

func (l *lldapSession) getExpiration(token string) (time.Duration, error) {
	claims, err := l.parseToken(token)
	if err != nil {
		klog.Errorf("failed to parse token: %v", err)
		return 0, fmt.Errorf("invalid token: %w", err)
	}

	return time.Until(time.Unix(claims.ExpiresAt, 0)), nil
}

// GetSession implements SessionProvider.
func (l *lldapSession) GetSession(ctx *fasthttp.RequestCtx) (userSession UserSession, err error) {
	token := l.getToken(ctx)
	if len(token) == 0 {
		klog.Warning("no session token found in request context for lldapSession, returning default session")
		return l.NewDefaultUserSession(), nil
	}

	// validate token
	if l.tokenCache == nil {
		klog.Error("token cache is not initialized")
		return l.NewDefaultUserSession(), errors.New("token cache is not initialized")
	}

	if item := l.tokenCache.Get(token); item != nil {
		klog.Infof("session found in cache for token %s", token)
		session := item.Value()
		if session.InBlacklist {
			klog.Infof("session for token %s is blacklisted, returning default session", token)
			return l.NewDefaultUserSession(), nil
		}

		return *session, nil
	}

	klog.Infof("session not found in cache for token %s, verifing token", token)
	_, err = TokenVerify(l.lldapAddr, token, token)
	if err != nil {
		klog.Errorf("failed to verify token %s: %v", token, err)
		return l.NewDefaultUserSession(), nil
	}

	// Token not found in cache, parse and validate the JWT token
	claims, err := l.parseToken(token)
	if err != nil {
		klog.Errorf("failed to parse token: %v", err)
		return l.NewDefaultUserSession(), err
	}

	// Create user session from claims
	userSession = l.createSessionFromTokenClaims(token, claims)

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
	return nil
}

// RemoveSessionID implements SessionProvider.
func (l *lldapSession) RemoveSessionID(token string) {
	l.tokenCache.Delete(token)
	klog.Infof("removed session ID for token %s", token)
}

// SaveSession implements SessionProvider.
func (l *lldapSession) SaveSession(ctx *fasthttp.RequestCtx, userSession UserSession) (err error) {
	// For LLDAP session, we don't need to save session data as it's JWT-based
	// The token itself contains all the necessary information
	// We could optionally cache the session if needed
	token := l.getToken(ctx)
	if token == "" {
		if userSession.AccessToken != "" {
			c, err := l.parseToken(userSession.AccessToken)
			if err != nil {
				klog.Errorf("failed to parse user session access token: %v", err)
				return fmt.Errorf("failed to parse user session access token: %w", err)
			}

			userSession = l.createSessionFromTokenClaims(userSession.AccessToken, c)
		}

		token = userSession.AccessToken
	}

	if token != "" && l.tokenCache != nil {
		if userSession.AccessToken != token {
			klog.Infof("updating session token from %s to %s", token, userSession.AccessToken)

			token = userSession.AccessToken
			l.tokenCache.Delete(token) // Remove old token if it exists
		}

		exp, err := l.getExpiration(token)
		if err != nil {
			klog.Errorf("failed to get expiration for token %s: %v", token, err)
			return fmt.Errorf("failed to get expiration for token %s: %w", token, err)
		}

		l.tokenCache.Set(token, &userSession, exp)
	}
	return nil
}

// SaveSessionID implements SessionProvider.
func (l *lldapSession) SaveSessionID(token string, InBlacklist any) {
	if token != "" {
		claims, err := l.parseToken(token)
		if err != nil {
			klog.Errorf("failed to parse token: %v", err)
			return
		}

		session := l.createSessionFromTokenClaims(token, claims)

		session.InBlacklist = InBlacklist.(bool)

		exp := time.Until(time.Unix(claims.ExpiresAt, 0))
		l.tokenCache.Set(token, &session, exp)
	}
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

func (l *lldapSession) createSessionFromTokenClaims(token string, claims *Claims) UserSession {
	userSession := l.NewDefaultUserSession()
	userSession.Username = claims.Username
	userSession.DisplayName = claims.Username
	userSession.Emails = []string{claims.Username + "@olares.com"}
	userSession.CookieDomain = l.Config.Domain
	userSession.AuthenticationLevel = authentication.OneFactor
	userSession.Groups = claims.Groups
	userSession.AccessToken = token
	userSession.KeepMeLoggedIn = true // Assuming we want to keep the session alive
	userSession.LastActivity = time.Now().Unix()

	if claims.Mfa > 0 {
		userSession.AuthenticationLevel = authentication.TwoFactor
	}

	return userSession
}

func TokenVerify(baseURL, accessToken, validToken string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/auth/token/verify", baseURL)
	client := resty.New()

	resp, err := client.SetTimeout(10*time.Second).R().
		SetHeader("Content-Type", "application/json").SetAuthToken(accessToken).
		SetBody(map[string]string{
			"access_token": validToken,
		}).Post(url)
	if err != nil {
		klog.Infof("send request failed: %v", err)
		return nil, err
	}
	if resp.StatusCode() != http.StatusOK {
		klog.Infof("not 200, %v, body: %v", resp.StatusCode(), string(resp.Body()))
		return nil, errors.New(resp.String())
	}
	var response map[string]interface{}
	err = json.Unmarshal(resp.Body(), &response)
	if err != nil {
		klog.Infof("unmarshal failed: %v", err)
		return nil, err
	}
	klog.Infof("token verify res: %v", response)

	if status, ok := response["status"]; ok && status == "invalid token" {
		klog.Infof("token verify failed, status: %s", status)
		return nil, errors.New("token verification failed")
	}
	return response, nil
}

func TokenInvalidate(baseURL, accessToken, revokeToken string) error {
	url := fmt.Sprintf("%s/auth/token/invalidate", baseURL)
	client := resty.New()

	resp, err := client.SetTimeout(10*time.Second).R().
		SetHeader("Content-Type", "application/json").SetAuthToken(accessToken).
		SetBody(map[string]string{
			"access_token": revokeToken,
		}).Post(url)
	if err != nil {
		klog.Infof("send request failed: %v", err)
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		klog.Infof("not 200, %v, body: %v", resp.StatusCode(), string(resp.Body()))
		return errors.New(resp.String())
	}
	return nil
}
