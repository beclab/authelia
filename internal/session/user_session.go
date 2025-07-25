package session

import (
	"errors"
	"time"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
)

// NewDefaultUserSession create a default user session.
func NewDefaultUserSession() UserSession {
	return UserSession{
		KeepMeLoggedIn:               false,
		AuthenticationLevel:          authentication.NotAuthenticated,
		LastActivity:                 0,
		ResourceAuthenticationLevels: []*ResourceAuthenticationLevel{},
	}
}

// IsAnonymous returns true if the username is empty or the AuthenticationLevel is authentication.NotAuthenticated.
func (s *UserSession) IsAnonymous() bool {
	return s.Username == "" || s.AuthenticationLevel == authentication.NotAuthenticated
}

// SetOneFactor sets the 1FA AMR's and expected property values for one factor authentication.
func (s *UserSession) SetOneFactor(now time.Time, details *authentication.UserDetails, keepMeLoggedIn bool) {
	s.FirstFactorAuthnTimestamp = now.Unix()
	s.LastActivity = now.Unix()
	s.AuthenticationLevel = authentication.OneFactor

	s.KeepMeLoggedIn = keepMeLoggedIn

	s.Username = details.Username
	s.DisplayName = details.DisplayName
	s.Groups = details.Groups
	s.Emails = details.Emails

	s.AuthenticationMethodRefs.UsernameAndPassword = true
}

func (s *UserSession) setTwoFactor(now time.Time) {
	s.SecondFactorAuthnTimestamp = now.Unix()
	s.LastActivity = now.Unix()
	s.AuthenticationLevel = authentication.TwoFactor
}

// SetTwoFactorTOTP sets the relevant TOTP AMR's and sets the factor to 2FA.
func (s *UserSession) SetTwoFactorTOTP(now time.Time) {
	s.setTwoFactor(now)
	s.AuthenticationMethodRefs.TOTP = true
	s.Prev1FaAccessToken = s.AccessToken // Store the previous 1FA access token.
}

// SetTwoFactorDuo sets the relevant Duo AMR's and sets the factor to 2FA.
func (s *UserSession) SetTwoFactorDuo(now time.Time) {
	s.setTwoFactor(now)
	s.AuthenticationMethodRefs.Duo = true
}

// SetTwoFactorWebauthn sets the relevant Webauthn AMR's and sets the factor to 2FA.
func (s *UserSession) SetTwoFactorWebauthn(now time.Time, userPresence, userVerified bool) {
	s.setTwoFactor(now)
	s.AuthenticationMethodRefs.Webauthn = true
	s.AuthenticationMethodRefs.WebauthnUserPresence, s.AuthenticationMethodRefs.WebauthnUserVerified = userPresence, userVerified

	s.Webauthn = nil
}

// SetTwoFactorTerminusPass sets the relevant terminus pass AMR's and sets the factor to 2FA.
func (s *UserSession) SetTwoFactorTerminusPass(now time.Time) {
	s.setTwoFactor(now)
	s.AuthenticationMethodRefs.TerminusPass = true
	s.Prev1FaAccessToken = s.AccessToken // Store the previous 1FA access token.
}

// AuthenticatedTime returns the unix timestamp this session authenticated successfully at the given level.
func (s *UserSession) AuthenticatedTime(level authorization.Level) (authenticatedTime time.Time, err error) {
	switch level {
	case authorization.OneFactor:
		return time.Unix(s.FirstFactorAuthnTimestamp, 0), nil
	case authorization.TwoFactor:
		return time.Unix(s.SecondFactorAuthnTimestamp, 0), nil
	default:
		return time.Unix(0, 0), errors.New("invalid authorization level")
	}
}
