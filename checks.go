package okaydns

import (
	"github.com/miekg/dns"
)

// TODO(benl): it might be worth adding net.Context and timeouts. the dialers
// should still time out connections but there's no way to enforce a deadline on
// a check as a whole.

// CheckA checks that a resolver has at least one valid A record for the given
// domain.
func CheckA(resolver *Resolver, fqdn string) []Failure {
	reply, _, err := resolver.Exchange(checkAQuestion(fqdn))
	if failures, err := CheckError(nil, resolver, err); err != nil {
		return failures
	}
	return checkA(nil, resolver, reply)
}

func checkAQuestion(fqdn string) *dns.Msg {
	return NonRecursiveQuestion(fqdn, dns.TypeA)
}

func checkA(failures []Failure, resolver *Resolver, response *dns.Msg) []Failure {
	failures = CheckResponseCode(failures, resolver, response.Rcode, dns.RcodeSuccess)

	var foundA bool
	for _, answer := range response.Answer {
		if _, ok := answer.(*dns.A); ok {
			foundA = true
		}
	}
	if !foundA {
		failures = FailCheck(failures, resolver, "no A records returned")
	}
	return failures
}

// CheckAWithRandomization checks that a request for an A record with
// character case randomized returns records with the same name capitalization.
//
// This check may be run whether or not CheckA fails, so it does not assume A
// records are configured correctly.
func CheckAWithRandomization(resolver *Resolver, fqdn string) (failures []Failure) {
	query := check0x20Question(fqdn)
	reply, _, err := resolver.Exchange(query)
	if failures, err := CheckError(failures, resolver, err); err != nil {
		return failures
	}
	return check0x20(failures, resolver, query, reply)
}

func check0x20Question(fqdn string) *dns.Msg {
	return NonRecursiveQuestion(RandomizeCase(fqdn), dns.TypeA)
}

func check0x20(failures []Failure, resolver *Resolver, request, response *dns.Msg) []Failure {
	failures = CheckResponseCode(failures, resolver, response.Rcode, dns.RcodeSuccess)

	// NOTE: since the question is supposed to be created in the check, this
	// would be a programmer error or the DNS lib doing something EXTREMELY
	// fishy by modifying the request. panic is appropraite.
	if len(request.Question) < 1 {
		panic("expected a valid dns question")
	}
	question := request.Question[0]

	var foundA bool
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			foundA = true

			if questionName, responseName := question.Name, a.Hdr.Name; questionName != responseName {
				failures = FailCheck(failures, resolver, "answer did not match question: question=%q answer=%q", question.Name, a.Hdr.Name)
			}
		}
	}

	if !foundA {
		failures = FailCheck(failures, resolver, "no A records returned")
	}

	return failures
}

// CheckUnknownQuestion sends an invalid question type to a resolver and ensures
// that the response is successful.
func CheckUnknownQuestion(resolver *Resolver, fqdn string) (failures []Failure) {
	reply, _, err := resolver.Exchange(makeUnknownQuestion(fqdn))
	if failures, err := CheckError(failures, resolver, err); err != nil {
		return failures
	}
	return checkUnknownQuestion(failures, resolver, reply)
}

const typeUnknownQuestion uint16 = 666

func makeUnknownQuestion(fqdn string) *dns.Msg {
	return NonRecursiveQuestion(fqdn, typeUnknownQuestion)
}

func checkUnknownQuestion(failures []Failure, resolver *Resolver, response *dns.Msg) []Failure {
	if len(response.Answer) > 0 {
		failures = FailCheck(failures, resolver, "should not include an answer to an unknown question type")
	}
	return CheckResponseCode(failures, resolver, response.Rcode, dns.RcodeSuccess)
}

// CheckSOA checks that every resolver returns an authoritative response to an
// SOA query and that the serials of the SOA responses are all the same.
func CheckSOA(resolvers []*Resolver, fqdn string) (failures []Failure) {
	query := makeSOAQuery(fqdn)

	var replies []*dns.Msg
	for _, resolver := range resolvers {
		reply, _, err := resolver.Exchange(query)
		if failures, err := CheckError(failures, resolver, err); err != nil {
			return failures
		}
		replies = append(replies, reply)
	}

	return checkSOAMatchingSerials(failures, resolvers, replies)
}

func makeSOAQuery(fqdn string) *dns.Msg {
	return NonRecursiveQuestion(fqdn, dns.TypeSOA)
}

func checkSOAMatchingSerials(failures []Failure, resolvers []*Resolver, replies []*dns.Msg) []Failure {
	if len(resolvers) > len(replies) {
		return FailGroupCheck(failures, resolvers, "not all resolvers replied")
	}
	// there should be exactly one response for a resolver. this probably means
	// that someone wrote a bug.
	if len(resolvers) < len(replies) {
		panic("too many replies for resolvers")
	}

	serials := make(map[uint32]struct{})
	for i, reply := range replies {
		resolver := resolvers[i]
		failures = CheckResponseCode(failures, resolver, reply.Rcode, dns.RcodeSuccess)

		var found bool
		for _, answer := range reply.Answer {
			if soa, ok := answer.(*dns.SOA); ok {
				serials[soa.Serial] = struct{}{}
				found = true
				break
			}
		}

		if !found {
			failures = FailCheck(failures, resolver, "resolver did not return an SOA record")
		}
	}

	// TODO(benl): should this failure inlclude all of the serials?
	if len(serials) > 1 {
		failures = FailGroupCheck(failures, resolvers, "SOA serials are out of sync")
	}

	return failures
}
