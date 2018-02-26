package okaydns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

// A Resolver is a dns.Client configured to point at a specific host/port.
type Resolver struct {
	dns.Client
	Name string
	Host string
	Port string

	// TODO(benl): include a throttle
	// TODO(benl): include an RTT summary statistic?
	// TODO(benl): retry temporary net errors?
}

func (r *Resolver) String() string {
	return fmt.Sprintf("%s (%s)", r.Host, r.Client.Net)
}

func ResolverFor(nameserver, port, netType string) *Resolver {
	return nil
}

// ResolversFromFile parses a resolv.conf(5) like file and returns a resolver
// for every server listed. If more than one netType is specified multiple
// resolvers are created with the given network types. netTypes defaults to
// udp only.
func ResolversFromFile(file string, netTypes ...string) ([]*Resolver, error) {
	clientConfig, err := dns.ClientConfigFromFile(file)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create resolvers")
	}

	if len(netTypes) == 0 {
		netTypes = []string{"udp"}
	}

	resolvers := make([]*Resolver, 0, len(netTypes)*len(clientConfig.Servers))
	for _, server := range clientConfig.Servers {
		for _, netType := range netTypes {
			resolver := &Resolver{
				Client: dns.Client{
					Net: netType,
				},
				Name: server,
				Host: server,
				Port: clientConfig.Port,
			}
			resolvers = append(resolvers, resolver)
		}
	}

	return resolvers, nil
}

// TODO
func (r *Resolver) Exchange(m *dns.Msg) (*dns.Msg, time.Duration, error) {
	return r.Client.Exchange(m, net.JoinHostPort(r.Host, r.Port))
}

// Nameservers returns a map ip addresses for every nameserver listed for the
// given fqdn.
//
// NS records for the given fqdn are looked up with a recursive query to
// resolver, and then the same resolver is recursively queried again for A
// (and optionally AAAA) records for each nameserver.
func Nameservers(resolver *Resolver, fqdn string, v6 bool) (map[string][]net.IP, error) {
	nameservers, err := ns(resolver, fqdn)
	if err != nil {
		return nil, err
	}

	amap := make(map[string][]net.IP)
	for _, nameserver := range nameservers {
		ips, err := ips(resolver, nameserver, v6)
		if err != nil {
			return nil, err
		}
		amap[nameserver] = ips
	}
	return amap, nil
}

// ns issues a recursive ns query for the given fqdn against a resolver. returns
// all of the namservers listed in any NS answers received.
func ns(resolver *Resolver, fqdn string) ([]string, error) {
	m := &dns.Msg{}
	m.SetQuestion(fqdn, dns.TypeNS)

	reply, _, err := resolver.Exchange(m)
	if err != nil {
		return nil, errors.Wrap(err, "NS query failed")
	}
	if reply.Rcode != dns.RcodeSuccess {
		return nil, errors.Errorf("%s: invalid error code: %s", resolver, dns.RcodeToString[reply.Rcode])
	}

	nservers := make([]string, 0, len(reply.Answer))
	for _, answer := range reply.Answer {
		if ns, ok := answer.(*dns.NS); ok {
			nservers = append(nservers, ns.Ns)
		}
	}
	return nservers, nil
}

// ips runs recurse A and AAAA queries against a given resolver and returns all
// of the ip addresses returned in the answer sections of both queries
func ips(resolver *Resolver, fqdn string, v6 bool) ([]net.IP, error) {
	aReply, _, err := resolver.Exchange(new(dns.Msg).SetQuestion(fqdn, dns.TypeA))
	if err != nil {
		return nil, errors.Wrap(err, "A query failed")
	}
	if aReply.Rcode != dns.RcodeSuccess {
		return nil, errors.Errorf("%s: invalid error code: %s", resolver, dns.RcodeToString[aReply.Rcode])
	}

	addrs := make([]net.IP, 0, 2)
	for _, answer := range aReply.Answer {
		if a, ok := answer.(*dns.A); ok {
			addrs = append(addrs, a.A)
		}
	}

	if v6 {
		aaaaReply, _, err := resolver.Exchange(new(dns.Msg).SetQuestion(fqdn, dns.TypeAAAA))
		if err != nil {
			return nil, errors.Wrap(err, "AAAA query failed")
		}
		if aaaaReply.Rcode != dns.RcodeSuccess {
			return nil, errors.Errorf("%s: invalid error code: %s", resolver, dns.RcodeToString[aaaaReply.Rcode])
		}
		for _, answer := range aaaaReply.Answer {
			if aaaa, ok := answer.(*dns.AAAA); ok {
				addrs = append(addrs, aaaa.AAAA)
			}
		}
	}

	return addrs, nil
}
