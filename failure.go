package okaydns

import "fmt"
import "github.com/miekg/dns"

// A ResolverFailure is a generic failure for a single resolver.
type ResolverFailure struct {
	Resolver *Resolver
	Msg      string
}

func (r *ResolverFailure) Message() string { return r.Msg }

// A GroupFailure is a failure based on the behavior of multiple resolvers.
type GroupFailure struct {
	Resolvers []*Resolver
	Msg       string
}

func (g *GroupFailure) Message() string { return g.Msg }

// An ErrorFailure is a failure cause by an error during a check.
type ErrorFailure struct {
	Resolver *Resolver
	Err      error
}

func (e *ErrorFailure) Message() string {
	return fmt.Sprintf("unexpected error: %s", e.Err)
}

// A ResponseCodeFailure is a failure caused by a Resolver returning an
// unexpected response code for a query.
type ResponseCodeFailure struct {
	Resolver *Resolver
	Code     int
}

func (r *ResponseCodeFailure) Message() string {
	return fmt.Sprintf("invalid response code: %s (%x)", dns.RcodeToString[r.Code], r.Code)
}
