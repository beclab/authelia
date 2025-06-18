package handlers

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/session"
)

func TestRunAuthRequestAuthzSuite(t *testing.T) {
	suite.Run(t, NewAuthRequestAuthzSuite())
}

func NewAuthRequestAuthzSuite() *AuthRequestAuthzSuite {
	return &AuthRequestAuthzSuite{
		AuthzSuite: &AuthzSuite{
			implementation: AuthzImplAuthRequest,
			setRequest:     setRequestAuthRequest,
		},
	}
}

type AuthRequestAuthzSuite struct {
	*AuthzSuite
}

func (s *AuthRequestAuthzSuite) TestShouldHandleAllMethodsDeny() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("OriginalMethod%s", method), func(t *testing.T) {
			for _, targetURI := range []*url.URL{
				s.RequireParseRequestURI("https://one-factor.example.com"),
				s.RequireParseRequestURI("https://one-factor.example.com/subpath"),
				s.RequireParseRequestURI("https://one-factor.example2.com"),
				s.RequireParseRequestURI("https://one-factor.example2.com/subpath"),
			} {
				t.Run(targetURI.String(), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					s.setRequest(mock.Ctx, method, targetURI, true, false)

					authz.Handler(mock.Ctx)

					assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
					assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldHandleInvalidMethodCharsDeny() {
	for _, method := range testRequestMethods {
		method += "z"

		s.T().Run(fmt.Sprintf("OriginalMethod%s", method), func(t *testing.T) {
			for _, targetURI := range []*url.URL{
				s.RequireParseRequestURI("https://bypass.example.com"),
				s.RequireParseRequestURI("https://bypass.example.com/subpath"),
				s.RequireParseRequestURI("https://bypass.example2.com"),
				s.RequireParseRequestURI("https://bypass.example2.com/subpath"),
			} {
				t.Run(targetURI.String(), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					s.setRequest(mock.Ctx, method, targetURI, true, false)

					authz.Handler(mock.Ctx)

					assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
					assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldHandleMissingXOriginalMethodDeny() {
	for _, targetURI := range []*url.URL{
		s.RequireParseRequestURI("https://bypass.example.com"),
		s.RequireParseRequestURI("https://bypass.example.com/subpath"),
		s.RequireParseRequestURI("https://bypass.example2.com"),
		s.RequireParseRequestURI("https://bypass.example2.com/subpath"),
	} {
		s.T().Run(targetURI.String(), func(t *testing.T) {
			authz := s.Builder().Build()

			mock := mocks.NewMockAutheliaCtx(t)

			defer mock.Close()

			s.setRequest(mock.Ctx, "", targetURI, true, false)

			authz.Handler(mock.Ctx)

			assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
			assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldHandleMissingXOriginalURLDeny() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("OriginalMethod%s", method), func(t *testing.T) {
			authz := s.Builder().Build()

			mock := mocks.NewMockAutheliaCtx(t)

			defer mock.Close()

			s.setRequest(mock.Ctx, method, nil, true, false)

			authz.Handler(mock.Ctx)

			assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
			assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldHandleAllMethodsAllow() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("OriginalMethod%s", method), func(t *testing.T) {
			for _, targetURI := range []*url.URL{
				s.RequireParseRequestURI("https://bypass.example.com"),
				s.RequireParseRequestURI("https://bypass.example.com/subpath"),
				s.RequireParseRequestURI("https://bypass.example2.com"),
				s.RequireParseRequestURI("https://bypass.example2.com/subpath"),
			} {
				t.Run(targetURI.String(), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					s.setRequest(mock.Ctx, method, targetURI, true, false)

					authz.Handler(mock.Ctx)

					assert.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())
					assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldHandleAllMethodsWithMethodsACL() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("Method%s", method), func(t *testing.T) {
			for _, methodACL := range testRequestMethods {
				targetURI := s.RequireParseRequestURI(fmt.Sprintf("https://bypass-%s.example.com", strings.ToLower(methodACL)))
				t.Run(targetURI.String(), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					for i, cookie := range mock.Ctx.Configuration.Session.Cookies {
						mock.Ctx.Configuration.Session.Cookies[i].AutheliaURL = s.RequireParseRequestURI(fmt.Sprintf("https://auth.%s", cookie.Domain))
					}

					mock.Ctx.Providers.SessionProvider = session.NewProvider(&mock.Ctx.Configuration, nil)

					s.setRequest(mock.Ctx, method, targetURI, true, false)

					authz.Handler(mock.Ctx)

					if method == methodACL {
						assert.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())
						assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
					} else {
						assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
						assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
					}
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldHandleInvalidURLForCVE202132637() {
	testCases := []struct {
		name     string
		uri      []byte
		expected int
	}{
		{"Should401UnauthorizedWithNullByte",
			[]byte{104, 116, 116, 112, 115, 58, 47, 47, 0, 110, 111, 116, 45, 111, 110, 101, 45, 102, 97, 99, 116, 111, 114, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109},
			fasthttp.StatusUnauthorized,
		},
		{"Should200OkWithoutNullByte",
			[]byte{104, 116, 116, 112, 115, 58, 47, 47, 110, 111, 116, 45, 111, 110, 101, 45, 102, 97, 99, 116, 111, 114, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109},
			fasthttp.StatusOK,
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.name, func(t *testing.T) {
			for _, method := range testRequestMethods {
				t.Run(fmt.Sprintf("OriginalMethod%s", method), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					mock.Ctx.Configuration.AccessControl.DefaultPolicy = testBypass
					mock.Ctx.Providers.Authorizer = authorization.NewFileAuthorizer(&mock.Ctx.Configuration)

					mock.Ctx.Request.Header.Set(testXOriginalMethod, method)
					mock.Ctx.Request.Header.SetBytesKV([]byte(testXOriginalUrl), tc.uri)

					authz.Handler(mock.Ctx)

					assert.Equal(t, tc.expected, mock.Ctx.Response.StatusCode())
					assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldNotHandleExtAuthzAllMethodsAllow() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("Method%s", method), func(t *testing.T) {
			for _, targetURI := range []*url.URL{
				s.RequireParseRequestURI("https://bypass.example.com"),
				s.RequireParseRequestURI("https://bypass.example.com/subpath"),
				s.RequireParseRequestURI("https://bypass.example2.com"),
				s.RequireParseRequestURI("https://bypass.example2.com/subpath"),
			} {
				t.Run(targetURI.String(), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					for i, cookie := range mock.Ctx.Configuration.Session.Cookies {
						mock.Ctx.Configuration.Session.Cookies[i].AutheliaURL = s.RequireParseRequestURI(fmt.Sprintf("https://auth.%s", cookie.Domain))
					}

					mock.Ctx.Providers.SessionProvider = session.NewProvider(&mock.Ctx.Configuration, nil)

					setRequestExtAuthz(mock.Ctx, method, targetURI, true, false)

					authz.Handler(mock.Ctx)

					assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
					assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldNotHandleExtAuthzAllMethodsAllowXHR() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("Method%s", method), func(t *testing.T) {
			for xname, x := range testXHR {
				t.Run(xname, func(t *testing.T) {
					for _, targetURI := range []*url.URL{
						s.RequireParseRequestURI("https://bypass.example.com"),
						s.RequireParseRequestURI("https://bypass.example.com/subpath"),
						s.RequireParseRequestURI("https://bypass.example2.com"),
						s.RequireParseRequestURI("https://bypass.example2.com/subpath"),
					} {
						t.Run(targetURI.String(), func(t *testing.T) {
							authz := s.Builder().Build()

							mock := mocks.NewMockAutheliaCtx(t)

							defer mock.Close()

							for i, cookie := range mock.Ctx.Configuration.Session.Cookies {
								mock.Ctx.Configuration.Session.Cookies[i].AutheliaURL = s.RequireParseRequestURI(fmt.Sprintf("https://auth.%s", cookie.Domain))
							}

							mock.Ctx.Providers.SessionProvider = session.NewProvider(&mock.Ctx.Configuration, nil)

							setRequestExtAuthz(mock.Ctx, method, targetURI, x, x)

							authz.Handler(mock.Ctx)

							assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
							assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
						})
					}
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldNotHandleExtAuthzAllMethodsWithMethodsACL() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("Method%s", method), func(t *testing.T) {
			for _, methodACL := range testRequestMethods {
				targetURI := s.RequireParseRequestURI(fmt.Sprintf("https://bypass-%s.example.com", strings.ToLower(methodACL)))
				t.Run(targetURI.String(), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					for i, cookie := range mock.Ctx.Configuration.Session.Cookies {
						mock.Ctx.Configuration.Session.Cookies[i].AutheliaURL = s.RequireParseRequestURI(fmt.Sprintf("https://auth.%s", cookie.Domain))
					}

					mock.Ctx.Providers.SessionProvider = session.NewProvider(&mock.Ctx.Configuration, nil)

					setRequestExtAuthz(mock.Ctx, method, targetURI, true, false)

					authz.Handler(mock.Ctx)

					assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
					assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldNotHandleForwardAuthAllMethodsAllow() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("Method%s", method), func(t *testing.T) {
			for _, targetURI := range []*url.URL{
				s.RequireParseRequestURI("https://bypass.example.com"),
				s.RequireParseRequestURI("https://bypass.example.com/subpath"),
				s.RequireParseRequestURI("https://bypass.example2.com"),
				s.RequireParseRequestURI("https://bypass.example2.com/subpath"),
			} {
				t.Run(targetURI.String(), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					for i, cookie := range mock.Ctx.Configuration.Session.Cookies {
						mock.Ctx.Configuration.Session.Cookies[i].AutheliaURL = s.RequireParseRequestURI(fmt.Sprintf("https://auth.%s", cookie.Domain))
					}

					mock.Ctx.Providers.SessionProvider = session.NewProvider(&mock.Ctx.Configuration, nil)

					setRequestForwardAuth(mock.Ctx, method, targetURI, true, false)

					authz.Handler(mock.Ctx)

					assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
					assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldNotHandleForwardAuthAllMethodsAllowXHR() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("Method%s", method), func(t *testing.T) {
			for xname, x := range testXHR {
				t.Run(xname, func(t *testing.T) {
					for _, targetURI := range []*url.URL{
						s.RequireParseRequestURI("https://bypass.example.com"),
						s.RequireParseRequestURI("https://bypass.example.com/subpath"),
						s.RequireParseRequestURI("https://bypass.example2.com"),
						s.RequireParseRequestURI("https://bypass.example2.com/subpath"),
					} {
						t.Run(targetURI.String(), func(t *testing.T) {
							authz := s.Builder().Build()

							mock := mocks.NewMockAutheliaCtx(t)

							defer mock.Close()

							for i, cookie := range mock.Ctx.Configuration.Session.Cookies {
								mock.Ctx.Configuration.Session.Cookies[i].AutheliaURL = s.RequireParseRequestURI(fmt.Sprintf("https://auth.%s", cookie.Domain))
							}

							mock.Ctx.Providers.SessionProvider = session.NewProvider(&mock.Ctx.Configuration, nil)

							setRequestForwardAuth(mock.Ctx, method, targetURI, x, x)

							authz.Handler(mock.Ctx)

							assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
							assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
						})
					}
				})
			}
		})
	}
}

func (s *AuthRequestAuthzSuite) TestShouldNotHandleForwardAuthAllMethodsWithMethodsACL() {
	for _, method := range testRequestMethods {
		s.T().Run(fmt.Sprintf("Method%s", method), func(t *testing.T) {
			for _, methodACL := range testRequestMethods {
				targetURI := s.RequireParseRequestURI(fmt.Sprintf("https://bypass-%s.example.com", strings.ToLower(methodACL)))
				t.Run(targetURI.String(), func(t *testing.T) {
					authz := s.Builder().Build()

					mock := mocks.NewMockAutheliaCtx(t)

					defer mock.Close()

					for i, cookie := range mock.Ctx.Configuration.Session.Cookies {
						mock.Ctx.Configuration.Session.Cookies[i].AutheliaURL = s.RequireParseRequestURI(fmt.Sprintf("https://auth.%s", cookie.Domain))
					}

					mock.Ctx.Providers.SessionProvider = session.NewProvider(&mock.Ctx.Configuration, nil)

					setRequestForwardAuth(mock.Ctx, method, targetURI, true, false)

					authz.Handler(mock.Ctx)

					assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
					assert.Equal(t, []byte(nil), mock.Ctx.Response.Header.Peek(fasthttp.HeaderLocation))
				})
			}
		})
	}
}

func setRequestAuthRequest(ctx *middlewares.AutheliaCtx, method string, targetURI *url.URL, accept, xhr bool) {
	if method != "" {
		ctx.Request.Header.Set(testXOriginalMethod, method)
	}

	if targetURI != nil {
		ctx.Request.Header.Set(testXOriginalUrl, targetURI.String())
	}

	setRequestXHRValues(ctx, accept, xhr)
}
