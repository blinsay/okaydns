package okaydns

import (
	"github.com/miekg/dns"
)

// A RequestResponseValidator is a function that checks the answers returned by
// a set of nameservers, given the original DNS request message as context.
//
// Every RequestResponseValidator returns a set of failures caused by individual
// nameservers and failures caused by considering the resopnses as a group.
type RequestResponseValidator func(*dns.Msg, map[Nameserver]*dns.Msg) []Failure

// A MessageValidator is a function that examines a single DNS message and
// returns any problems it's configured to spot.
type MessageValidator func(*dns.Msg) []Failure

// A Check is a check to run. Checks are responsible for building their own
// DNS Request from an FQDN and validating the response.
//
// Checks may optionally alter the list of Nameservers that the check will be
// performed on.
type Check struct {
	Name                 string
	ConfigureNameservers func(nameservers []Nameserver) []Nameserver
	Question             func(fqdn string) *dns.Msg
	Validators           []RequestResponseValidator
}

// A CheckResult is the result of running a CheckConfig. It includes the name
// of the check that was run, the nameservers it was run on, the complete dns
// request and response for every nameserver.
//
// Failures are returned per-nameserver and also as a general, global failure.
type CheckResult struct {
	Name        string
	Nameservers []Nameserver
	Question    *dns.Msg
	Answers     map[Nameserver]*dns.Msg
	Errors      map[Nameserver]error
	Failures    []Failure
}

// IsFailed returns true if the check failed in any way.
func (c *CheckResult) IsFailed() bool {
	return len(c.Failures) > 0
}

// A Failure is a reason that a check fails. They optionally include the
// nameserver that a failure is associated with. If a failure isn't associated
// with a specific Nameserver it can be assumed to be applied to the group as
// a whole.
type Failure struct {
	// Message is a string explaining this failure.
	Message string

	// Nameserver is the (optional) Nameserver that failed this check.
	Nameserver Nameserver
}
