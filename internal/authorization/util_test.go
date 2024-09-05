package authorization

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization/application"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestLevelToString(t *testing.T) {
	testCases := []struct {
		have     Level
		expected string
	}{
		{Bypass, "bypass"},
		{OneFactor, "one_factor"},
		{TwoFactor, "two_factor"},
		{Denied, "deny"},
		{99, "deny"},
	}

	for _, tc := range testCases {
		t.Run("Expected_"+tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.String())
		})
	}
}

func TestShouldNotParseInvalidSubjects(t *testing.T) {
	subjectsSchema := [][]string{{"groups:z"}, {"group:z", "users:b"}}
	subjectsACL := schemaSubjectsToACL(subjectsSchema)

	require.Len(t, subjectsACL, 1)

	require.Len(t, subjectsACL[0].Subjects, 1)

	assert.True(t, subjectsACL[0].IsMatch(Subject{Username: "a", Groups: []string{"z"}}))
}

func TestShouldSplitDomainCorrectly(t *testing.T) {
	prefix, suffix := domainToPrefixSuffix("apple.example.com")

	assert.Equal(t, "apple", prefix)
	assert.Equal(t, "example.com", suffix)

	prefix, suffix = domainToPrefixSuffix("example")

	assert.Equal(t, "", prefix)
	assert.Equal(t, "example", suffix)

	prefix, suffix = domainToPrefixSuffix("example.com")

	assert.Equal(t, "example", prefix)
	assert.Equal(t, "com", suffix)
}

func TestShouldParseRuleNetworks(t *testing.T) {
	schemaNetworks := []schema.ACLNetwork{
		{
			Name: "desktop",
			Networks: []string{
				"10.0.0.1",
			},
		},
		{
			Name: "lan",
			Networks: []string{
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
		},
	}

	_, firstNetwork, err := net.ParseCIDR("192.168.1.20/32")
	require.NoError(t, err)

	networksMap, networksCacheMap := parseSchemaNetworks(schemaNetworks)

	assert.Len(t, networksCacheMap, 5)

	networks := []string{"192.168.1.20", "lan"}

	acl := schemaNetworksToACL(networks, networksMap, networksCacheMap)

	assert.Len(t, networksCacheMap, 7)

	require.Len(t, acl, 4)
	assert.Equal(t, firstNetwork, acl[0])
	assert.Equal(t, networksMap["lan"][0], acl[1])
	assert.Equal(t, networksMap["lan"][1], acl[2])
	assert.Equal(t, networksMap["lan"][2], acl[3])

	// Check they are the same memory address.
	assert.True(t, networksMap["lan"][0] == acl[1])
	assert.True(t, networksMap["lan"][1] == acl[2])
	assert.True(t, networksMap["lan"][2] == acl[3])

	assert.False(t, firstNetwork == acl[0])
}

func TestShouldParseACLNetworks(t *testing.T) {
	schemaNetworks := []schema.ACLNetwork{
		{
			Name: "test",
			Networks: []string{
				"10.0.0.1",
			},
		},
		{
			Name: "second",
			Networks: []string{
				"10.0.0.1",
			},
		},
		{
			Name: "duplicate",
			Networks: []string{
				"10.0.0.1",
			},
		},
		{
			Name: "duplicate",
			Networks: []string{
				"10.0.0.1",
			},
		},
		{
			Name: "ipv6",
			Networks: []string{
				"fec0::1",
			},
		},
		{
			Name: "ipv6net",
			Networks: []string{
				"fec0::1/64",
			},
		},
		{
			Name: "net",
			Networks: []string{
				"10.0.0.0/8",
			},
		},
		{
			Name: "badnet",
			Networks: []string{
				"bad/8",
			},
		},
	}

	_, firstNetwork, err := net.ParseCIDR("10.0.0.1/32")
	require.NoError(t, err)

	_, secondNetwork, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	_, thirdNetwork, err := net.ParseCIDR("fec0::1/64")
	require.NoError(t, err)

	_, fourthNetwork, err := net.ParseCIDR("fec0::1/128")
	require.NoError(t, err)

	networksMap, networksCacheMap := parseSchemaNetworks(schemaNetworks)

	require.Len(t, networksMap, 6)
	require.Contains(t, networksMap, "test")
	require.Contains(t, networksMap, "second")
	require.Contains(t, networksMap, "duplicate")
	require.Contains(t, networksMap, "ipv6")
	require.Contains(t, networksMap, "ipv6net")
	require.Contains(t, networksMap, "net")
	require.Len(t, networksMap["test"], 1)

	require.Len(t, networksCacheMap, 7)
	require.Contains(t, networksCacheMap, "10.0.0.1")
	require.Contains(t, networksCacheMap, "10.0.0.1/32")
	require.Contains(t, networksCacheMap, "10.0.0.1/32")
	require.Contains(t, networksCacheMap, "10.0.0.0/8")
	require.Contains(t, networksCacheMap, "fec0::1")
	require.Contains(t, networksCacheMap, "fec0::1/128")
	require.Contains(t, networksCacheMap, "fec0::1/64")

	assert.Equal(t, firstNetwork, networksMap["test"][0])
	assert.Equal(t, secondNetwork, networksMap["net"][0])
	assert.Equal(t, thirdNetwork, networksMap["ipv6net"][0])
	assert.Equal(t, fourthNetwork, networksMap["ipv6"][0])

	assert.Equal(t, firstNetwork, networksCacheMap["10.0.0.1"])
	assert.Equal(t, firstNetwork, networksCacheMap["10.0.0.1/32"])

	assert.Equal(t, secondNetwork, networksCacheMap["10.0.0.0/8"])

	assert.Equal(t, thirdNetwork, networksCacheMap["fec0::1/64"])

	assert.Equal(t, fourthNetwork, networksCacheMap["fec0::1"])
	assert.Equal(t, fourthNetwork, networksCacheMap["fec0::1/128"])
}

func TestIsAuthLevelSufficient(t *testing.T) {
	assert.False(t, IsAuthLevelSufficient(authentication.NotAuthenticated, Denied))
	assert.False(t, IsAuthLevelSufficient(authentication.OneFactor, Denied))
	assert.False(t, IsAuthLevelSufficient(authentication.TwoFactor, Denied))
	assert.True(t, IsAuthLevelSufficient(authentication.NotAuthenticated, Bypass))
	assert.True(t, IsAuthLevelSufficient(authentication.OneFactor, Bypass))
	assert.True(t, IsAuthLevelSufficient(authentication.TwoFactor, Bypass))
	assert.False(t, IsAuthLevelSufficient(authentication.NotAuthenticated, OneFactor))
	assert.True(t, IsAuthLevelSufficient(authentication.OneFactor, OneFactor))
	assert.True(t, IsAuthLevelSufficient(authentication.TwoFactor, OneFactor))
	assert.False(t, IsAuthLevelSufficient(authentication.NotAuthenticated, TwoFactor))
	assert.False(t, IsAuthLevelSufficient(authentication.OneFactor, TwoFactor))
	assert.True(t, IsAuthLevelSufficient(authentication.TwoFactor, TwoFactor))
}

func TestPolicy(t *testing.T) {
	p := []byte(`{"vault":{"default_policy":"one_factor","sub_policies":null,"one_time":false,"valid_duration":0}}`)
	policies := make(map[string]*application.ApplicationSettingsPolicy)
	err := json.Unmarshal(p, &policies)

	if err != nil {
		t.Log(err)
		t.Fail()

		return
	}

	fmt.Printf("%v", policies)
}

func TestAddLocal(t *testing.T) {
	redirect_uri := "https://222fd105.xuejingjie8.myterminus.com/auth/login"
	url, err := url.Parse(redirect_uri)
	if err != nil {
		klog.Errorf("%s oidc client redirect uri invalid, %s, %v", "test", redirect_uri, err)
		return
	}
	hostToken := strings.Split(url.Host, ".")
	if len(hostToken) < 2 {
		klog.Errorf("%s oidc client redirect uri host invalid, %s", "test", redirect_uri)
		return
	}

	var newHostToken []string
	newHostToken = append(newHostToken, hostToken[0], "local")
	newHostToken = append(newHostToken, hostToken[1:]...)

	url.Host = strings.Join(newHostToken, ".")
	local_redirect_uri := url.String()

	t.Log(local_redirect_uri)

}
