package authorization

import (
	"fmt"
)

// Level is the type representing an authorization level.
type Level int

const (
	// Bypass bypass level.
	Bypass Level = iota

	// OneFactor one factor level.
	OneFactor

	// TwoFactor two factor level.
	TwoFactor

	// Denied denied level.
	Denied

	// System follow system's level
	System
)

const (
	prefixUser  = "user:"
	prefixGroup = "group:"
)

const (
	bypass    = "bypass"
	oneFactor = "one_factor"
	twoFactor = "two_factor"
	deny      = "deny"
	public    = "public"
	system    = "system"
	internal  = "internal"
)

const (
	operatorPresent    = "present"
	operatorAbsent     = "absent"
	operatorEqual      = "equal"
	operatorNotEqual   = "not equal"
	operatorPattern    = "pattern"
	operatorNotPattern = "not pattern"
)

const (
	subexpNameUser  = "User"
	subexpNameGroup = "Group"
)

var (
	// IdentitySubexpNames is a list of valid regex subexp names.
	IdentitySubexpNames = []string{subexpNameUser, subexpNameGroup}

	AnnotationGroup        = "bytetrade.io"
	UserLauncherAuthPolicy = fmt.Sprintf("%s/launcher-auth-policy", AnnotationGroup)
	UserAnnotationZoneKey  = fmt.Sprintf("%s/zone", AnnotationGroup)
)

const traceFmtACLHitMiss = "ACL %s Position %d for subject %s and object %s (method %s)"

// var defaultDomain = "snowinning.com".

// func init() {
// 	envDomain := os.Getenv("DOMAIN")
// 	if envDomain != "" {
// 		defaultDomain = envDomain
// 	}
// }.
