package okaydns

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// compile time tests that checks satisfy the check interface

func TestCheckA(t *testing.T) {
	// Compile-time test that CheckA is a Check
	var _ Check = CheckA

	t.Run("question", func(t *testing.T) {
		question := checkAQuestion(dns.Fqdn("foo.bar.baz"))

		assert.False(t, question.RecursionDesired)
		assert.Equal(t,
			[]dns.Question{{Name: "foo.bar.baz.", Qclass: dns.ClassINET, Qtype: dns.TypeA}},
			question.Question)
	})

	t.Run("check", func(t *testing.T) {
		query := checkAQuestion(dns.Fqdn("foo.bar.baz"))

		t.Run("no answers", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)

			assert.NotEmpty(t, checkA(nil, nil, m))
		})

		t.Run("no A records", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Answer = []dns.RR{&dns.AAAA{AAAA: net.IPv6zero}}

			assert.NotEmpty(t, checkA(nil, nil, m))
		})

		t.Run("invalid status", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Answer = []dns.RR{&dns.A{A: net.IPv4zero}}
			m.Rcode = dns.RcodeServerFailure // what if servfail but also ok

			assert.NotEmpty(t, checkA(nil, nil, m))
		})

		t.Run("ok", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Answer = []dns.RR{&dns.A{A: net.IPv4zero}}

			assert.Empty(t, checkA(nil, nil, m))
		})
	})
}

func TestCheckAWithRandomization(t *testing.T) {
	// Compile-time test that CheckAWithRandomization is a Check
	var _ Check = CheckAWithRandomization

	t.Run("question", func(t *testing.T) {
		question := check0x20Question(dns.Fqdn("foo.bar.baz"))

		assert.False(t, question.RecursionDesired)
		assert.Equal(t, dns.TypeA, question.Question[0].Qclass, "should be an A query")
		assert.Equal(t, dns.Fqdn("foo.bar.baz"), strings.ToLower(question.Question[0].Name), "lowercased name should be the same as the query")
	})

	t.Run("check", func(t *testing.T) {
		query := check0x20Question(dns.Fqdn("foo.bar.baz"))

		t.Run("fail if no answers are returned", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)

			assert.NotEmpty(t, check0x20(nil, nil, query, m))
		})

		t.Run("fail if no A records are returned", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Answer = []dns.RR{&dns.AAAA{AAAA: net.IPv6zero}}

			assert.NotEmpty(t, check0x20(nil, nil, query, m))
		})

		t.Run("fail if the response has an invalid status", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Rcode = dns.RcodeServerFailure
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name: query.Question[0].Name,
				},
				A: net.IPv4zero,
			}}

			assert.NotEmpty(t, check0x20(nil, nil, query, m))
		})

		t.Run("fail if the answer changes the case of the name", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name: strings.ToUpper(query.Question[0].Name),
				},
				A: net.IPv4zero,
			}}
			assert.NotEmpty(t, check0x20(nil, nil, query, m))
		})

		t.Run("ok", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name: query.Question[0].Name,
				},
				A: net.IPv4zero,
			}}

			assert.Empty(t, check0x20(nil, nil, query, m))
		})
	})
}

func TestUnknownQuestion(t *testing.T) {
	// Compile-time test that CheckAWithRandomization is a Check
	var _ Check = CheckUnknownQuestion

	t.Run("question", func(t *testing.T) {
		query := makeUnknownQuestion("foo.bar.baz")
		assert.False(t, query.RecursionDesired, "should not be a recursive question")
		assert.Empty(t, dns.TypeToString[query.Question[0].Qtype], "should not be a known question type")
	})

	t.Run("check", func(t *testing.T) {
		query := makeUnknownQuestion("foo.bar.baz")

		t.Run("fail if the response includes answers", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Answer = []dns.RR{&dns.A{A: net.IPv4zero}}

			assert.NotEmpty(t, checkUnknownQuestion(nil, nil, m))
		})

		t.Run("fail if the response status code is servfail", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)
			m.Rcode = dns.RcodeServerFailure

			assert.NotEmpty(t, checkUnknownQuestion(nil, nil, m))
		})

		t.Run("ok", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetReply(query)

			assert.Empty(t, checkUnknownQuestion(nil, nil, m))
		})
	})
}

func TestCheckSOA(t *testing.T) {
	// Compile-time test that CheckSOA is a GroupCheck
	var _ GroupCheck = CheckSOA

	t.Run("question", func(t *testing.T) {
		query := makeSOAQuery(dns.Fqdn("foo.bar.baz"))

		assert.False(t, query.RecursionDesired, "should not be a recursive question")
		assert.Equal(t, []dns.Question{{Name: "foo.bar.baz.", Qclass: dns.ClassINET, Qtype: dns.TypeSOA}}, query.Question)
	})

	t.Run("check", func(t *testing.T) {
		assert.FailNow(t, "implement me")
	})
}
