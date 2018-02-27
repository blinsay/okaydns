package okaydns

import (
	"math/rand"
	"strings"
	"unicode"

	"github.com/miekg/dns"
)

// RandomizeCase copies a string and randomizes the case of all unicode
// characters it contains. Useful for doing 0x20 randomization.
//
// See https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00
func RandomizeCase(s string) string {
	s = strings.ToLower(s)

	var runes []rune
	for _, runeVal := range s {
		if rand.Float32() > 0.5 {
			runeVal = unicode.ToUpper(runeVal)
		} else {
			runeVal = unicode.ToLower(runeVal)
		}
		runes = append(runes, runeVal)
	}
	return string(runes)
}

// NonRecursiveQuestion is a util function for constructing a non-recursive
// DNS query.
//
// This is equivalent to:
//
//   q := new(dns.Msg)
//   q.SetQuestion(fqdn, qtype)
//   q.RecursionDesired = false
//
func NonRecursiveQuestion(fqdn string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(fqdn, qtype)
	q.RecursionDesired = false
	return q
}
