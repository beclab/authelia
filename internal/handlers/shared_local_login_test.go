package handlers

import (
	"errors"
	"testing"

	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestAllowSharedLocalLogin(t *testing.T) {
	for _, tt := range []struct {
		name, host, username, localName string
		info                            *utils.UserInfo
		lookupErr                       error
		want, wantLookup                bool
	}{
		{name: "member on shared dotted Auth", host: "auth.owner.olares.local", want: true, wantLookup: true},
		{name: "shared hyphen alias", host: "auth-owner.olares.local", want: true, wantLookup: true},
		{name: "port", host: "auth.owner.olares.local:80", want: true, wantLookup: true},
		{name: "public domain", host: "auth.owner.olares.com"},
		{name: "another device", host: "auth.other.olares.local"},
		{name: "suffix is insufficient", host: "auth.evil.owner.olares.local"},
		{name: "non Auth host", host: "vault.owner.olares.local"},
		{name: "missing device identity", host: "auth.owner.olares.local", localName: "-"},
		{name: "namespace injection", host: "auth.owner.olares.local", username: "member/../../other"},
		{name: "cloud account", host: "auth.owner.olares.local", info: &utils.UserInfo{Name: "member", Zone: "member.olares.com", LocalZone: "owner.olares.local"}, wantLookup: true},
		{name: "ephemeral account", host: "auth.owner.olares.local", info: &utils.UserInfo{Name: "member", IsEphemeral: true, LocalZone: "owner.olares.local"}, wantLookup: true},
		{name: "different local zone", host: "auth.owner.olares.local", info: &utils.UserInfo{Name: "member", LocalZone: "other.olares.local"}, wantLookup: true},
		{name: "wrong returned user", host: "auth.owner.olares.local", info: &utils.UserInfo{Name: "owner", LocalZone: "owner.olares.local"}, wantLookup: true},
		{name: "BFL unavailable", host: "auth.owner.olares.local", lookupErr: errors.New("unavailable"), wantLookup: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			username, localName := tt.username, tt.localName
			if username == "" {
				username = "member"
			}
			if localName == "" {
				localName = "owner"
			}
			called := false
			lookup := func(user string) (*utils.UserInfo, error) {
				called = true
				require.Equal(t, "member", user)
				if tt.info != nil || tt.lookupErr != nil {
					return tt.info, tt.lookupErr
				}
				return &utils.UserInfo{Name: "member", LocalZone: "owner.olares.local"}, nil
			}
			require.Equal(t, tt.want, allowSharedLocalLogin(tt.host, username, localName, lookup))
			require.Equal(t, tt.wantLookup, called)
		})
	}
}
