package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/blinsay/okaydns"
	"github.com/miekg/dns"
)

var (
	checkPort int  = 53
	v6        bool = false
)

// TODO(benl): maybe check should be a type that has the name, the question to
// send (a func(string) *dns.Msg that takes the fqdn) , and a response checking
// func (*dns.Msg) []Failure????? that would make this all easier to test and
// maybe also add to/format?

var checks = []struct {
	Name  string
	Check okaydns.GroupCheck
}{
	{"A", checkAll(okaydns.CheckA)},
	{"A with 0x20 Randomization", checkAll(okaydns.CheckAWithRandomization)},
	{"Invalid types", checkAll(okaydns.CheckUnknownQuestion)},
	{"SOA", okaydns.CheckSOA},
}

func init() {
	log.SetFlags(0)

	flag.Parse()
}

func main() {
	localResolvers, err := okaydns.ResolversFromFile("/etc/resolv.conf")
	if err != nil {
		log.Fatalln(err)
	}
	if len(localResolvers) == 0 {
		log.Fatalln("couldn't find a configured local resolver")
	}
	localResolver := localResolvers[0]

	for _, target := range flag.Args() {
		nameservers, err := okaydns.Nameservers(localResolver, dns.Fqdn(target), v6)
		if err != nil {
			log.Fatalf("failed to find nameservers for %s: %s", target, err)
		}

		if len(nameservers) == 0 {
			log.Fatalf("no nameservers found for %s. is your domain an apex domain?", target)
		}

		resolvers := resolversForNameservers(nameservers)
		fmt.Println("checking", target, "using the following nameservers:")
		for _, resolver := range resolvers {
			fmt.Println("\t", resolver.Name, resolver.Host)
		}

		for _, check := range checks {
			fmt.Print(check.Name, "...")

			failures := check.Check(resolvers, dns.Fqdn(target))
			if len(failures) == 0 {
				fmt.Println("ok")
			} else {
				fmt.Println(len(failures), "checks failed")
				for _, failure := range failures {
					fmt.Printf("\t%s\n", failure.Message())
				}
			}
		}
	}
}

func resolversForNameservers(nameservers map[string][]net.IP) []*okaydns.Resolver {
	var resolvers []*okaydns.Resolver

	for nameserver, ips := range nameservers {
		for _, ip := range ips {
			resolvers = append(resolvers, &okaydns.Resolver{
				Name: nameserver,
				Host: ip.String(),
				Port: strconv.Itoa(checkPort),
			})
		}
	}

	return resolvers
}

func checkAll(c okaydns.Check) okaydns.GroupCheck {
	return func(resolvers []*okaydns.Resolver, fqdn string) []okaydns.Failure {
		var failures []okaydns.Failure
		for _, resolver := range resolvers {
			failures = append(failures, c(resolver, fqdn)...)
		}
		return failures
	}
}
