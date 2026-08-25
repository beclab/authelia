package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
)

func bareAuthzCtx() *middlewares.AutheliaCtx {
	return &middlewares.AutheliaCtx{RequestCtx: &fasthttp.RequestCtx{}}
}

func assertOutboundIdentityEmpty(t *testing.T, ctx *middlewares.AutheliaCtx) {
	t.Helper()
	assert.Empty(t, ctx.Response.Header.PeekBytes(headerRemoteUser))
	assert.Empty(t, ctx.Response.Header.PeekBytes(headerRemoteGroups))
	assert.Empty(t, ctx.Response.Header.PeekBytes(headerRemoteName))
	assert.Empty(t, ctx.Response.Header.PeekBytes(headerRemoteEmail))
	assert.Empty(t, ctx.Response.Header.PeekBytes(headerXBFLUser))
	assert.Empty(t, ctx.Response.Header.PeekBytes(headerRemoteAccessToken))
}

func TestHandleAuthzAuthorizedStandardIdentityHeaders(t *testing.T) {
	t.Parallel()

	mkAuthn := func(username, accessToken string) *Authn {
		return &Authn{
			Username: username,
			Details: authentication.UserDetails{
				Username:    username,
				DisplayName: "Display",
				Emails:      []string{"u@example.com"},
				Groups:      []string{"owner"},
			},
			Level: authentication.OneFactor,
			Token: authentication.ValidResult{
				AccessToken: accessToken,
			},
		}
	}

	t.Run("SessionOnPrivateWritesIdentityAndXBFLUser", func(t *testing.T) {
		ctx := bareAuthzCtx()
		rule := &authorization.AccessControlRule{Policy: authorization.OneFactor}
		// Empty AccessToken: setTokenToCookie needs SessionProvider; identity
		// headers alone prove the write path.
		handleAuthzAuthorizedStandard(ctx, mkAuthn("alice", ""), rule)

		assert.Equal(t, 200, ctx.Response.StatusCode())
		assert.Equal(t, "alice", string(ctx.Response.Header.PeekBytes(headerRemoteUser)))
		assert.Equal(t, "owner", string(ctx.Response.Header.PeekBytes(headerRemoteGroups)))
		assert.Equal(t, "Display", string(ctx.Response.Header.PeekBytes(headerRemoteName)))
		assert.Equal(t, "u@example.com", string(ctx.Response.Header.PeekBytes(headerRemoteEmail)))
		assert.Equal(t, "alice", string(ctx.Response.Header.PeekBytes(headerXBFLUser)))
	})

	// Internal LAN / probe may force required==Bypass while rule.Policy stays
	// OneFactor (or stronger). Session identity must still be written.
	t.Run("NonBypassRulePolicyWithSessionWritesIdentity", func(t *testing.T) {
		ctx := bareAuthzCtx()
		rule := &authorization.AccessControlRule{Policy: authorization.OneFactor}
		require.NotEqual(t, authorization.Bypass, rule.Policy)

		handleAuthzAuthorizedStandard(ctx, mkAuthn("carol", ""), rule)

		assert.Equal(t, 200, ctx.Response.StatusCode())
		assert.Equal(t, "carol", string(ctx.Response.Header.PeekBytes(headerRemoteUser)))
		assert.Equal(t, "owner", string(ctx.Response.Header.PeekBytes(headerRemoteGroups)))
		assert.Equal(t, "Display", string(ctx.Response.Header.PeekBytes(headerRemoteName)))
		assert.Equal(t, "u@example.com", string(ctx.Response.Header.PeekBytes(headerRemoteEmail)))
		assert.Equal(t, "carol", string(ctx.Response.Header.PeekBytes(headerXBFLUser)))
	})

	// SESSHDR: public (Policy Bypass) with a session must still emit identity.
	// Empty AccessToken avoids setTokenToCookie SessionProvider dependency.
	t.Run("PublicPolicyWithSessionWritesIdentity", func(t *testing.T) {
		ctx := bareAuthzCtx()
		rule := &authorization.AccessControlRule{Policy: authorization.Bypass}
		handleAuthzAuthorizedStandard(ctx, mkAuthn("alice", ""), rule)

		assert.Equal(t, 200, ctx.Response.StatusCode())
		assert.Equal(t, "alice", string(ctx.Response.Header.PeekBytes(headerRemoteUser)))
		assert.Equal(t, "owner", string(ctx.Response.Header.PeekBytes(headerRemoteGroups)))
		assert.Equal(t, "Display", string(ctx.Response.Header.PeekBytes(headerRemoteName)))
		assert.Equal(t, "u@example.com", string(ctx.Response.Header.PeekBytes(headerRemoteEmail)))
		assert.Equal(t, "alice", string(ctx.Response.Header.PeekBytes(headerXBFLUser)))
	})

	t.Run("EmptyUsernameOmitsIdentity", func(t *testing.T) {
		ctx := bareAuthzCtx()
		rule := &authorization.AccessControlRule{Policy: authorization.OneFactor}
		handleAuthzAuthorizedStandard(ctx, mkAuthn("", "tok-anon"), rule)

		require.Equal(t, 200, ctx.Response.StatusCode())
		assertOutboundIdentityEmpty(t, ctx)
	})

	t.Run("EmptyUsernameOnPublicOmitsIdentity", func(t *testing.T) {
		ctx := bareAuthzCtx()
		rule := &authorization.AccessControlRule{Policy: authorization.Bypass}
		handleAuthzAuthorizedStandard(ctx, mkAuthn("", "tok-anon"), rule)

		require.Equal(t, 200, ctx.Response.StatusCode())
		assertOutboundIdentityEmpty(t, ctx)
	})

	t.Run("NilRuleWithSessionWritesIdentity", func(t *testing.T) {
		ctx := bareAuthzCtx()
		handleAuthzAuthorizedStandard(ctx, mkAuthn("bob", ""), nil)

		assert.Equal(t, "bob", string(ctx.Response.Header.PeekBytes(headerRemoteUser)))
		assert.Equal(t, "bob", string(ctx.Response.Header.PeekBytes(headerXBFLUser)))
	})
}
