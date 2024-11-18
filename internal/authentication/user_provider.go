package authentication

import (
	"errors"

	"github.com/authelia/authelia/v4/internal/model"
)

type ValidResult struct {
	AccessToken  string
	RefreshToken string
}

var (
	ErrInvalidUserPwd = errors.New("invalid username / password")
	ErrInvalidToken   = errors.New("invalid refresh token")
	ErrTooManyRetries = errors.New("too many failed login attempts, retry again later after 5 minutes")
)

// UserProvider is the interface for checking user password and
// gathering user details.
type UserProvider interface {
	model.StartupCheck

	CheckUserPassword(username string, password string) (valid bool, result *ValidResult, err error)
	GetDetails(username string, token string) (details *UserDetails, err error)
	UpdatePassword(username, accessToken string, newPassword string) (err error)
	Refresh(username, token, refreshToken string) (*ValidResult, error)
}
