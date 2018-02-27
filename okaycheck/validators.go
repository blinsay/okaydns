package okaycheck

import (
	"fmt"

	"github.com/blinsay/okaydns"
	"github.com/miekg/dns"
)

// EachNameserver builds a RequestResponseValidator that runs the given
// MessageValidators for each request-response pair. Failures are grouped by
// nameserver.
func EachNameserver(vs ...okaydns.MessageValidator) okaydns.RequestResponseValidator {
	return func(_ *dns.Msg, answers map[okaydns.Nameserver]*dns.Msg) (map[okaydns.Nameserver][]okaydns.Failure, []okaydns.Failure) {
		failures := make(map[okaydns.Nameserver][]okaydns.Failure)

		for nameserver, answer := range answers {
			for _, validator := range vs {
				if failure := validator(answer); failure != nil {
					failures[nameserver] = append(failures[nameserver], failure...)
				}
			}
		}

		return failures, nil
	}
}

// ResponseCode builds a MessageValidator that asserts the response
// code of a message is the expected rcode.
func ResponseCode(rcode int) okaydns.MessageValidator {
	return func(m *dns.Msg) []okaydns.Failure {
		if m.Rcode != rcode {
			return []okaydns.Failure{{
				Message: fmt.Sprintf("invalid response code: %s", dns.RcodeToString[m.Rcode]),
			}}
		}
		return nil
	}
}

// AuthoritativeResponse is a MessageValidator that asserts a response is
// Authoritative.
func AuthoritativeResponse(m *dns.Msg) []okaydns.Failure {
	if !m.Authoritative {
		return []okaydns.Failure{{Message: "response was not authoritative"}}
	}
	return nil
}

// AnswerIsEmpty is a MessageValidator that asserts a message contains
// no RRs in the Answer section.
func AnswerIsEmpty(m *dns.Msg) []okaydns.Failure {
	if len(m.Answer) > 0 {
		return []okaydns.Failure{{
			Message: fmt.Sprintf("expected no Answers but got %d", len(m.Answer)),
		}}
	}
	return nil
}

// AnswerContains builds a MessageValidator that asserts a response's Answer
// section contains an RR of the given rtype.
func AnswerContains(rtype uint16) okaydns.MessageValidator {
	return func(m *dns.Msg) []okaydns.Failure {
		for _, answer := range m.Answer {
			if answer.Header().Rrtype == rtype {
				return nil
			}
		}
		return []okaydns.Failure{{
			Message: fmt.Sprintf("response does not contain a %s record", dns.TypeToString[rtype]),
		}}
	}
}

// AnswerDoesNotContain builds a MessageValidator that asserts a response's
// Answer section does not contain an RR of the given rtype.
func AnswerDoesNotContain(rtype uint16) okaydns.MessageValidator {
	return func(m *dns.Msg) []okaydns.Failure {
		for _, answer := range m.Answer {
			if answer.Header().Rrtype == rtype {
				return []okaydns.Failure{{
					Message: fmt.Sprintf("response contains a %s record", dns.TypeToString[rtype]),
				}}
			}
		}
		return nil
	}
}
