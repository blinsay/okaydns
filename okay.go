package okaydns

import (
	"fmt"
	"math/rand"
	"strings"
	"unicode"

	"github.com/miekg/dns"
)

// TODO
type Failure interface {
	Message() string
}

// TODO
type Check func(*Resolver, string) []Failure

// TODO
type GroupCheck func([]*Resolver, string) []Failure

// TODO
func FailCheck(failures []Failure, resolver *Resolver, message string, args ...interface{}) []Failure {
	return append(failures, &ResolverFailure{
		Resolver: resolver,
		Msg:      fmt.Sprintf(message, args...),
	})
}

// TODO
func FailGroupCheck(failures []Failure, resolvers []*Resolver, message string, args ...interface{}) []Failure {
	return append(failures, &GroupFailure{
		Resolvers: resolvers,
		Msg:       fmt.Sprintf(message, args...),
	})
}

// CheckError adds a failure to failures if the error is non-nil.
//
// Returns true if the error was nil and false otherwise.
func CheckError(failures []Failure, resolver *Resolver, err error) ([]Failure, error) {
	if err != nil {
		failures = append(failures, &ErrorFailure{Resolver: resolver, Err: err})
		return failures, err
	}
	return failures, nil
}

// CheckResponseCode adds a failure to failures if rtype is not in allowedTypes.
//
// Returns true if the response code was found in allowedTypes.
func CheckResponseCode(failures []Failure, resolver *Resolver, rtype int, allowedTypes ...int) []Failure {
	for _, allowedType := range allowedTypes {
		if allowedType == rtype {
			return failures
		}
	}

	return append(failures, &ResponseCodeFailure{
		Resolver: resolver,
		Code:     rtype,
	})
}

// Randomize the case of all ASCII characters in the given string.
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
