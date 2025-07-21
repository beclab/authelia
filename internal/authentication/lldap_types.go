package authentication

import "net/http"

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

type RefreshTokenResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type ResetPasswordRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ResetPasswordResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type CredentialVerifyResponse struct {
	Username string `json:"username"`
	Valid    bool   `json:"valid"`
	Message  string `json:"message"`
}

type authedTransport struct {
	key     string
	wrapped http.RoundTripper
}

func (t *authedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.key)
	return t.wrapped.RoundTrip(req)
}
