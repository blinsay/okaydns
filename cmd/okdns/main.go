package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/blinsay/okaydns"
	"github.com/fatih/color"
	"github.com/miekg/dns"
)

var (
	verbose    = false
	outputJSON = false
)

var (
	text = textFormatter{
		ok:      color.New(color.FgGreen).SprintFunc(),
		failure: color.New(color.FgRed).SprintFunc(),
	}

	formatter checkFormatter = &text
)

func init() {
	// logging
	log.SetFlags(0)

	// cli flags
	flag.BoolVar(&outputJSON, "json", false, "output check results as JSON")
	flag.BoolVar(&verbose, "verbose", false, "include verbose check output")
	flag.Parse()

	if outputJSON {
		formatter = &jsonFormatter{}
	}
	formatter.SetVerbose(verbose)
}

// TODO(benl): enable/disable checks with a flag. only run checks that match a pattern?
// TODO(benl): search parent domains if there are no nameservers found for a target
// TODO(benl): optionally configure the local resolver from the CLI
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

		if len(nameservers) == 0 {
			log.Printf("no nameservers found for %s", domain)
			continue
		}

		bs, err := formatter.FormatHeader(fqdn, nameservers)
		if err != nil {
			panic(err)
		}
		if bs != nil {
			log.Print(string(bs))
		}

		var results []*okaydns.CheckResult
		for _, check := range defaultChecks {
			results = append(results, okaydns.DoCheck(&check, fqdn, nameservers))
		}

		for _, result := range results {
			bs, err := formatter.FormatCheck(result)
			if err != nil {
				panic(err)
			}
			log.Print(string(bs))
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
