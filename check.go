package okaydns

import (
	"net"

	"github.com/miekg/dns"
)

// A Checker runs a check and produces a result
type Checker interface {
	Check(*Check, string, []Nameserver) *CheckResult
}

var _defaultChecker = defaultChecker{}

// DoCheck runs the given check with the default Checker. Every request is made
// with a new client, and is made in the calling goroutine.
func DoCheck(c *Check, fqdn string, nss []Nameserver) *CheckResult {
	return _defaultChecker.Check(c, fqdn, nss)
}

// the default checker does all checks in the calling goroutine and creates a
// new client for every request.
//
// TODO(benl): run checks in a new goroutine per nameserver. this might require
// some throttling per-nameserver to do while being polite.
type defaultChecker struct{}

func (d *defaultChecker) Check(config *Check, fqdn string, nameservers []Nameserver) *CheckResult {
	// FIXME(benl): it sucks to do this here, boo
	if config.ConfigureNameservers != nil {
		nameservers = config.ConfigureNameservers(nameservers)
	}

	check := &CheckResult{
		Name:        config.Name,
		Nameservers: nameservers,
		Question:    config.Question(fqdn),
	}

	check.Answers, check.Errors = queryAll(check.Question, check.Nameservers)

	for _, validator := range config.Validators {
		check.Failures = append(check.Failures, validator(check.Question, check.Answers)...)
	}

	return check
}

func queryAll(query *dns.Msg, nameservers []Nameserver) (map[Nameserver]*dns.Msg, map[Nameserver]error) {
	replies := make(map[Nameserver]*dns.Msg)
	errors := make(map[Nameserver]error)

	for _, nameserver := range nameservers {
		client := dns.Client{
			Net: nameserver.Proto.String(),
		}
		addr := net.JoinHostPort(nameserver.Hostname, nameserver.Port)
		reply, _, err := client.Exchange(query, addr)

		if err != nil {
			errors[nameserver] = err
			continue
		}
		replies[nameserver] = reply
	}

	return replies, errors
}
