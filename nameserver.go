package okaydns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

// Proto is an enum for the protocol used by a Nameserver. This defines
// the allowed values for the Net strings used in miekg/dns.Client.
type Proto uint8

const (
	// ProtoUDP is DNS over UDP
	ProtoUDP Proto = iota

	// ProtoTCP is DNS over TCP
	ProtoTCP

	// ProtoTCPTLS is DNS over TCP with TLS
	ProtoTCPTLS
)

func (p Proto) String() string {
	switch p {
	case ProtoUDP:
		return "udp"
	case ProtoTCP:
		return "tcp"
	case ProtoTCPTLS:
		return "tcp-tls"
	default:
		panic("unknown protocol")
	}
}

// A Nameserver is the protocol and address infotuple used to connect to an
// existing nameserver. Also includes the hostname of the nameserver for human
// readability.
type Nameserver struct {
	Hostname string `json:"hostname"`
	Proto    Proto  `json:"proto"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
}

// IsZero returns true if the given Nameserver is the zero-valued struct.
func (n *Nameserver) IsZero() bool {
	return n.Port == "" && n.Hostname != "" && n.IP != ""
}

func (n *Nameserver) String() string {
	if n.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s://%s", n.Proto, net.JoinHostPort(n.IP, n.Port))
}

// Address returns an ip:port string used to connect to this nameserver.
func (n *Nameserver) Address() string {
	if n.IsZero() {
		return ""
	}
	return net.JoinHostPort(n.Hostname, n.Port)
}

// AuthoritativeNameservers issues recursive NS and A queries to the given
// nameserver ns to look up the authoritative nameserver for fqdn. The nameservers
// returned from this func always use UDP on port 53.
func AuthoritativeNameservers(fqdn string, ns Nameserver, includeIPv6 bool) (found []Nameserver, _ error) {
	nsHostnames, err := lookupNs(ns, fqdn)
	if err != nil {
		return nil, err
	}

	for _, hostname := range nsHostnames {
		ips, err := lookupIps(ns, hostname, includeIPv6)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			found = append(found, Nameserver{
				Hostname: hostname,
				IP:       ip.String(),
				Port:     "53",
			})
		}
	}

	return
}

// ns issues a recursive ns query for the given fqdn against a resolver. returns
// all of the namservers listed in any NS answers received.
func lookupNs(localNameserver Nameserver, fqdn string) ([]string, error) {
	client := &dns.Client{Net: localNameserver.Proto.String()}

	m := &dns.Msg{}
	m.SetQuestion(fqdn, dns.TypeNS)

	reply, _, err := client.Exchange(m, localNameserver.Address())
	if err != nil {
		return nil, errors.Wrap(err, "NS query failed")
	}
	if reply.Rcode != dns.RcodeSuccess {
		return nil, errors.Errorf("%s: invalid response code: %s", localNameserver.Hostname, dns.RcodeToString[reply.Rcode])
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
func lookupIps(localNameserver Nameserver, fqdn string, v6 bool) ([]net.IP, error) {
	client := &dns.Client{Net: localNameserver.Proto.String()}

	aReply, _, err := client.Exchange(new(dns.Msg).SetQuestion(fqdn, dns.TypeA), localNameserver.Address())
	if err != nil {
		return nil, errors.Wrap(err, "A query failed")
	}
	if aReply.Rcode != dns.RcodeSuccess {
		return nil, errors.Errorf("%s: invalid response code: %s", localNameserver.Hostname, dns.RcodeToString[aReply.Rcode])
	}

	addrs := make([]net.IP, 0, 2)
	for _, answer := range aReply.Answer {
		if a, ok := answer.(*dns.A); ok {
			addrs = append(addrs, a.A)
		}
	}

	if v6 {
		aaaaReply, _, err := client.Exchange(new(dns.Msg).SetQuestion(fqdn, dns.TypeAAAA), localNameserver.Address())
		if err != nil {
			return nil, errors.Wrap(err, "AAAA query failed")
		}
		if aaaaReply.Rcode != dns.RcodeSuccess {
			return nil, errors.Errorf("%s: invalid response code: %s", localNameserver.Hostname, dns.RcodeToString[aaaaReply.Rcode])
		}
		for _, answer := range aaaaReply.Answer {
			if aaaa, ok := answer.(*dns.AAAA); ok {
				addrs = append(addrs, aaaa.AAAA)
			}
		}
	}

	return addrs, nil
}
