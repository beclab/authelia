package handlers

import (
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/authelia/authelia/v4/internal/utils"
	"github.com/go-resty/resty/v2"
)

var (
	sharedLocalLoginName   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	sharedLocalLoginClient = resty.New().SetTimeout(2 * time.Second)
)

// allowSharedLocalLogin only relaxes the old zone-owner equality check on this
// device's local Auth entrance. It does not authenticate the requested user:
// FirstFactorPOST must still verify that user's password and establish their
// own session, followed by the normal second-factor checks.
func allowSharedLocalLogin(host, username, localName string, lookup func(string) (*utils.UserInfo, error)) bool {
	if !sharedLocalLoginName.MatchString(username) || !sharedLocalLoginName.MatchString(localName) {
		return false
	}

	endpoint, err := url.Parse("http://" + host)
	if err != nil || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return false
	}

	zone := localName + ".olares.local"
	hostname := strings.ToLower(strings.TrimSuffix(endpoint.Hostname(), "."))
	if hostname != "auth."+zone && hostname != "auth-"+localName+".olares.local" {
		return false
	}

	// BFL is addressed by a validated namespace label, never a client URL.
	// Require a local, persistent account on this device; public Olares ID and
	// ephemeral accounts retain the existing owner equality requirement.
	info, err := lookup(username)
	return err == nil && info != nil && info.Name == username &&
		!info.IsEphemeral && info.Zone == "" && info.LocalZone == zone
}
