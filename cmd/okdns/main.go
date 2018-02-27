package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/blinsay/okaydns"
	"github.com/miekg/dns"
)

var (
	verbose = false
)

func init() {
	// logging
	log.SetFlags(0)

	// cli flags
	flag.BoolVar(&verbose, "verbose", false, "include verbose check output")
	flag.Parse()
}

// TODO(benl): optionally configure the local resolver from the CLI
// TODO(benl): non-json output
// TODO(benl): include IPv6 support

func main() {
	seedns, err := configuredNameserver("/etc/resolv.conf")
	if err != nil {
		log.Fatalf("failed to start: %s", err)
	}

	for _, domain := range flag.Args() {
		fqdn := dns.Fqdn(domain)
		nameservers, err := okaydns.AuthoritativeNameservers(fqdn, seedns, false)
		if err != nil {
			log.Printf("failed to look up authoritative nameservers for %s: %s", domain, err)
			continue
		}

		var results []*okaydns.CheckResult
		for _, check := range defaultChecks {
			results = append(results, okaydns.DoCheck(&check, fqdn, nameservers))
		}

		for _, result := range results {
			bs, err := json.MarshalIndent(asJSONOutput(result, verbose), " ", " ")
			if err != nil {
				panic(err)
			}
			log.Println(string(bs))
		}
	}
}

// return the first nameserver listed in filename, which must be a resolv.conf(5)
// style file.
func configuredNameserver(filename string) (okaydns.Nameserver, error) {
	config, err := dns.ClientConfigFromFile(filename)
	if err != nil {
		return okaydns.Nameserver{}, err
	}

	if len(config.Servers) < 1 {
		return okaydns.Nameserver{}, fmt.Errorf("no resolvers found in file: %s", filename)
	}

	configns := okaydns.Nameserver{
		Hostname: config.Servers[0],
		Port:     config.Port,
	}
	return configns, nil
}
