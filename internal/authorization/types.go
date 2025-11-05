package authorization

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/authelia/authelia/v4/internal/utils"
	"k8s.io/klog/v2"
)

// SubjectMatcher is a matcher that takes a subject.
type SubjectMatcher interface {
	IsMatch(subject Subject) (match bool)
}

// StringSubjectMatcher is a matcher that takes an input string and subject.
type StringSubjectMatcher interface {
	IsMatch(input string, subject Subject) (match bool)
}

// SubjectObjectMatcher is a matcher that takes both a subject and an object.
type SubjectObjectMatcher interface {
	IsMatch(subject Subject, object Object) (match bool)
}

// ObjectMatcher is a matcher that takes an object.
type ObjectMatcher interface {
	IsMatch(object Object) (match bool)
}

// Subject represents the identity of a user for the purposes of ACL matching.
type Subject struct {
	Username string
	Groups   []string
	IP       net.IP
}

// String returns a string representation of the Subject.
func (s Subject) String() string {
	return fmt.Sprintf("username=%s groups=%s ip=%s", s.Username, strings.Join(s.Groups, ","), s.IP.String())
}

// IsAnonymous returns true if the Subject username and groups are empty.
func (s Subject) IsAnonymous() bool {
	return s.Username == "" && len(s.Groups) == 0
}

// Object represents a protected object for the purposes of ACL matching.
type Object struct {
	URL *url.URL

	Domain   string
	Path     string
	Method   string
	RealIP   string
	RemoteIP []string
}

// String is a string representation of the Object.
func (o Object) String() string {
	return o.URL.String()
}

func (o Object) ViaVPN() bool {
	cidr := "100.64.0.0/16"
	return o.validateCidr(cidr)
}

func (o Object) FromClusterPod() bool {
	cidr := "10.233.0.0/16"
	return o.validateCidr(cidr)
}

func (o Object) FromNodeInternalNetwork(internalCidr string) bool {
	if internalCidr == "" {
		return false
	}
	return o.validateCidr(internalCidr)
}

func (o Object) validateCidr(cidr string) bool {
	if len(o.RemoteIP) > 0 {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			klog.Errorf("failed to parse CIDR %s: %v", cidr, err)
			return false
		}

		// in cloud environments, the X-Forwarded-For header may contain multiple IPs
		for _, remoteIP := range o.RemoteIP {
			if govalidator.IsIPv4(remoteIP) {
				ip := net.ParseIP(remoteIP)
				if ipnet.Contains(ip) {
					return true
				}
			}
		}
	}

	return false
}

func (o Object) VaildInternalNetwork(internalCidr string) bool {
	getIpnet := func(cidr string) *net.IPNet {
		if cidr == "" {
			return nil
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			klog.Errorf("failed to parse CIDR %s: %v", cidr, err)
			return nil
		}
		return ipnet
	}

	vpnNet := getIpnet("100.64.0.0/16")
	clusterNet := getIpnet("10.233.0.0/16")
	internalNet := getIpnet(internalCidr)

	validate := func(ipStr string, ipnet *net.IPNet) bool {
		if ipnet == nil {
			return false
		}
		if govalidator.IsIPv4(ipStr) {
			ip := net.ParseIP(ipStr)
			if ipnet.Contains(ip) {
				return true
			}
		}
		return false
	}

	for _, remoteIP := range o.RemoteIP {
		if !validate(remoteIP, vpnNet) &&
			!validate(remoteIP, clusterNet) &&
			!validate(remoteIP, internalNet) {
			return false
		}
	}
	return true
}

// NewObjectRaw creates a new Object type from a URL and a method header.
func NewObjectRaw(targetURL *url.URL, method []byte) (object Object) {
	return NewObject(targetURL, string(method))
}

// NewObject creates a new Object type from a URL and a method header.
func NewObject(targetURL *url.URL, method string) (object Object) {
	return Object{
		URL:    targetURL,
		Domain: targetURL.Hostname(),
		Path:   utils.URLPathFullClean(targetURL),
		Method: method,
	}
}

// RuleMatchResult describes how well a rule matched a subject/object combo.
type RuleMatchResult struct {
	Rule *AccessControlRule

	Skipped bool

	MatchDomain        bool
	MatchResources     bool
	MatchQuery         bool
	MatchMethods       bool
	MatchNetworks      bool
	MatchSubjects      bool
	MatchSubjectsExact bool
}

// IsMatch returns true if all the criteria matched.
func (r RuleMatchResult) IsMatch() (match bool) {
	return r.MatchDomain && r.MatchResources && r.MatchMethods && r.MatchNetworks && r.MatchSubjectsExact
}

// IsPotentialMatch returns true if the rule is potentially a match.
func (r RuleMatchResult) IsPotentialMatch() (match bool) {
	return r.MatchDomain && r.MatchResources && r.MatchMethods && r.MatchNetworks && r.MatchSubjects && !r.MatchSubjectsExact
}
