package main

import (
	"github.com/blinsay/okaydns"
	"github.com/blinsay/okaydns/okaycheck"
	"github.com/miekg/dns"
)

var defaultChecks = []okaydns.Check{
	checkA,
	checkAOverTCP,
	checkNoCNAMEAtRoot,
	check0x20,
	checkUnknownQuestion,
	checkSOA,
}

// Checks that there is an A record and no CNAME at the given domain. This is a
// basic sanity check.
var checkA = okaydns.Check{
	Name: "A record",
	Question: func(fqdn string) *dns.Msg {
		return okaydns.NonRecursiveQuestion(fqdn, dns.TypeA)
	},
	Validators: []okaydns.RequestResponseValidator{
		okaycheck.EachNameserver(
			okaycheck.AuthoritativeResponse,
			okaycheck.ResponseCode(dns.RcodeSuccess),
			okaycheck.AnswerContains(dns.TypeA),
		),
	},
}

// Validates that an A query succeeds over TCP. Uses the same validations as
// the CheckA check.
var checkAOverTCP = okaydns.Check{
	Name: "A record (TCP)",
	Question: func(fqdn string) *dns.Msg {
		return okaydns.NonRecursiveQuestion(fqdn, dns.TypeA)
	},
	ConfigureNameservers: func(nameservers []okaydns.Nameserver) []okaydns.Nameserver {
		tcpns := make([]okaydns.Nameserver, len(nameservers))
		for i, ns := range nameservers {
			tcpns[i] = ns
			tcpns[i].Proto = okaydns.ProtoTCP
		}
		return tcpns
	},
	Validators: []okaydns.RequestResponseValidator{
		okaycheck.EachNameserver(
			okaycheck.AuthoritativeResponse,
			okaycheck.ResponseCode(dns.RcodeSuccess),
		),
	},
}

var checkNoCNAMEAtRoot = okaydns.Check{
	Name: "Not a CNAME",
	Question: func(fqdn string) *dns.Msg {
		return okaydns.NonRecursiveQuestion(fqdn, dns.TypeCNAME)
	},
	Validators: []okaydns.RequestResponseValidator{
		okaycheck.EachNameserver(
			okaycheck.AuthoritativeResponse,
			okaycheck.ResponseCode(dns.RcodeSuccess),
			okaycheck.AnswerIsEmpty,
		),
	},
}

// Checks that nameservers respond to queries with the same capitalization of
// domains as the question.
//
// See:
// - https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00
var check0x20 = okaydns.Check{
	Name: "Handles 0x20 randomization",
	Question: func(fqdn string) *dns.Msg {
		return okaydns.NonRecursiveQuestion(okaydns.RandomizeCase(fqdn), dns.TypeA)
	},
	Validators: []okaydns.RequestResponseValidator{
		okaycheck.EachNameserver(
			okaycheck.AuthoritativeResponse,
			okaycheck.ResponseCode(dns.RcodeSuccess),
			okaycheck.AnswerContains(dns.TypeA),
		),
		validateCaseMatches,
	},
}

func validateCaseMatches(q *dns.Msg, replies map[okaydns.Nameserver]*dns.Msg) (failures []okaydns.Failure) {
	if len(q.Question) != 1 {
		return []okaydns.Failure{{Message: "missing a question"}}
	}

	target := q.Question[0].Name

	for nameserver, reply := range replies {
		for _, answer := range reply.Answer {
			if answer.Header().Name != target {
				failures = append(failures, okaydns.Failure{
					Nameserver: nameserver,
					Message:    "case does not match",
				})
			}
		}
	}

	return
}

// Validates that nameservers respond to a question with an unknown query syntax
// by returning an empty answer with an okay response code.
var checkUnknownQuestion = okaydns.Check{
	Name: "Handles unknown question types",
	Question: func(fqdn string) *dns.Msg {
		return okaydns.NonRecursiveQuestion(fqdn, typeUnknownQuestion)
	},
	Validators: []okaydns.RequestResponseValidator{
		okaycheck.EachNameserver(
			okaycheck.AuthoritativeResponse,
			okaycheck.ResponseCode(dns.RcodeSuccess),
			okaycheck.AnswerIsEmpty,
		),
	},
}

const typeUnknownQuestion uint16 = 666

// Validates that nameservers all return authoritative SOA records for this
// domain and that their serials match.
var checkSOA = okaydns.Check{
	Name: "SOA serials match",
	Question: func(fqdn string) *dns.Msg {
		return okaydns.NonRecursiveQuestion(fqdn, dns.TypeSOA)
	},
	Validators: []okaydns.RequestResponseValidator{
		okaycheck.EachNameserver(
			okaycheck.AuthoritativeResponse,
			okaycheck.ResponseCode(dns.RcodeSuccess),
			okaycheck.AnswerContains(dns.TypeSOA),
		),
		validateSerialsMatch,
	},
}

func validateSerialsMatch(_ *dns.Msg, replies map[okaydns.Nameserver]*dns.Msg) (failures []okaydns.Failure) {
	serials := make(map[uint32]struct{})

	for _, reply := range replies {
		for _, answer := range reply.Answer {
			if soa, ok := answer.(*dns.SOA); ok {
				serials[soa.Serial] = struct{}{}
			}
		}
	}

	if len(serials) > 1 {
		failures = append(failures, okaydns.Failure{Message: "SOA queries return more than one serial"})
	}
	return
}
