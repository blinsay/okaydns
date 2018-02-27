package okaycheck

import (
	"net"
	"testing"

	"github.com/blinsay/okaydns"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

type validatorTestCase struct {
	name       string
	v          okaydns.MessageValidator
	msg        *dns.Msg
	shouldFail bool
}

func validatorTests(t *testing.T, tcs []validatorTestCase) {
	for _, tc := range tcs {
		runValidatorTest(t, tc)
	}
}

func runValidatorTest(t *testing.T, tc validatorTestCase) {
	t.Helper()

	t.Run(tc.name, func(t *testing.T) {
		t.Parallel()

		failures := tc.v(tc.msg)
		if tc.shouldFail {
			assert.NotEmpty(t, failures, "expected at least one failure")
		} else {
			assert.Empty(t, failures, "expected message to be valid")
		}
	})
}

func TestResponseCode(t *testing.T) {
	validatorTests(t, []validatorTestCase{
		{
			"response code does not match",
			ResponseCode(dns.RcodeSuccess),
			&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeBadAlg}},
			true,
		},
		{
			"response code matches",
			ResponseCode(dns.RcodeSuccess),
			&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}},
			false,
		},
	})
}

func TestAuthoritativeResponse(t *testing.T) {
	validatorTests(t, []validatorTestCase{
		{
			"fails non-authoritative response",
			AuthoritativeResponse,
			&dns.Msg{},
			true,
		},
		{
			"passes authoritative response",
			AuthoritativeResponse,
			&dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}},
			false,
		},
	})
}

func TestAnswerEmpty(t *testing.T) {
	validatorTests(t, []validatorTestCase{
		{
			"ok on empty",
			AnswerIsEmpty,
			&dns.Msg{},
			false,
		},
		{
			"ok on records in authority and extra",
			AnswerIsEmpty,
			&dns.Msg{
				Ns:    []dns.RR{&dns.NS{Ns: "dns1.foo.bar.baz"}},
				Extra: []dns.RR{&dns.A{A: net.IPv4zero}},
			},
			false,
		},
		{
			"fail on records in answers",
			AnswerIsEmpty,
			&dns.Msg{
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.IPv4zero},
				},
			},
			true,
		},
	})
}

func TestAnswerContains(t *testing.T) {
	validatorTests(t, []validatorTestCase{
		{
			"fails on empty",
			AnswerContains(dns.TypeAAAA),
			&dns.Msg{},
			true,
		},
		{
			"fails on the wrong type",
			AnswerContains(dns.TypeAAAA),
			&dns.Msg{
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.IPv4zero},
				},
			},
			true,
		},
		{
			"succeeds on single type",
			AnswerContains(dns.TypeAAAA),
			&dns.Msg{
				Answer: []dns.RR{
					&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}, AAAA: net.IPv6zero},
				},
			},
			false,
		},
		{
			"succeeds with mixed RR sets",
			AnswerContains(dns.TypeAAAA),
			&dns.Msg{
				Answer: []dns.RR{
					&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}, AAAA: net.IPv6zero},
					&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.IPv4zero},
				},
			},
			false,
		},
	})
}

func TestAnswerDoesNotContain(t *testing.T) {
	validatorTests(t, []validatorTestCase{
		{
			"succeeds on empty",
			AnswerDoesNotContain(dns.TypeAAAA),
			&dns.Msg{},
			false,
		},
		{
			"succeds when type is not included",
			AnswerDoesNotContain(dns.TypeAAAA),
			&dns.Msg{
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.IPv4zero},
				},
			},
			false,
		},
		{
			"fails when type is included",
			AnswerDoesNotContain(dns.TypeAAAA),
			&dns.Msg{
				Answer: []dns.RR{
					&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}, AAAA: net.IPv6zero},
				},
			},
			true,
		},
		{
			"fails when type is included in mixed RR set",
			AnswerDoesNotContain(dns.TypeAAAA),
			&dns.Msg{
				Answer: []dns.RR{
					&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}, AAAA: net.IPv6zero},
					&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.IPv4zero},
				},
			},
			true,
		},
	})
}
