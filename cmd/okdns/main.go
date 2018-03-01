package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/blinsay/okaydns"
	"github.com/fatih/color"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

var (
	verbose    = false
	outputJSON = false
)

type nameserverList []string

func (n *nameserverList) String() string     { return strings.Join(*n, ",") }
func (n *nameserverList) Set(v string) error { *n = append(*n, v); return nil }

var (
	filterPattern = ""
	filterRe      *regexp.Regexp

	targetNameservers nameserverList

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
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [output flags] [domains]\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "okdns is a tool for checking to see if your dns is ok. checks are run\n")
		fmt.Fprintf(flag.CommandLine.Output(), "against every domain listed. unless otherwise specified with the -ns\n")
		fmt.Fprintf(flag.CommandLine.Output(), "option, the local resolver is queried for the authoritative nameservers\n")
		fmt.Fprintf(flag.CommandLine.Output(), "for the domains specified, and checks are run against those.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "available options:\n")
		flag.PrintDefaults()
	}

	flag.BoolVar(&outputJSON, "json", false, "output check results as JSON")
	flag.BoolVar(&verbose, "verbose", false, "include verbose check output")
	flag.StringVar(&filterPattern, "check", "", "only run checks that match the given `pattern`")
	flag.Var(&targetNameservers, "ns", "a `nameserver` to check explicitly. may be specified multiple times.")
	flag.Parse()

	if filterPattern != "" {
		re, err := regexp.Compile(filterPattern)
		if err != nil {
			log.Fatalf("error: illegal check pattern")
		}
		filterRe = re
	}

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
		log.Fatalln("error loading local nameserver info from /etc/resolv.conf:", err)
	}

	var checks []okaydns.Check
	for _, check := range defaultChecks {
		if filterRe == nil || filterRe.MatchString(check.Name) {
			checks = append(checks, check)
		}
	}

	for _, domain := range flag.Args() {
		fqdn := dns.Fqdn(domain)

		nameservers, err := findNameservers(seedns, fqdn, targetNameservers)
		if err != nil {
			log.Fatalln(err)
		}

		bs, err := formatter.FormatHeader(fqdn, checks, nameservers)
		if err != nil {
			panic(err)
		}
		if bs != nil {
			log.Print(string(bs))
		}

		var results []*okaydns.CheckResult
		for _, check := range checks {
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

func findNameservers(seedns okaydns.Nameserver, fqdn string, configured []string) ([]okaydns.Nameserver, error) {
	if len(configured) > 0 {
		return explicitNameservers(seedns, configured)
	}
	return authoritativeNameservers(seedns, fqdn)
}

func explicitNameservers(seedns okaydns.Nameserver, configured []string) ([]okaydns.Nameserver, error) {
	var nameservers []okaydns.Nameserver

	for _, s := range configured {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			return nil, errors.Wrap(err, "invalid nameserver specified")
		}

		ips, err := okaydns.LookupIPs(seedns, dns.Fqdn(host), false)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error looking up ip for %s", host))
		}

		for _, ip := range ips {
			nameservers = append(nameservers, okaydns.Nameserver{
				Hostname: host,
				IP:       ip.String(),
				Port:     port,
				Proto:    okaydns.ProtoTCP,
			})
		}

	}

	return nameservers, nil
}

// do an NS lookup on the fqdn and return the hostnames and IPs of those
// nameservers.
func authoritativeNameservers(seedns okaydns.Nameserver, fqdn string) ([]okaydns.Nameserver, error) {
	nameservers, err := okaydns.AuthoritativeNameservers(fqdn, seedns, false)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("looking up authoritative nameservers for %s", fqdn))
	}
	if len(nameservers) == 0 {
		return nil, fmt.Errorf("no nameservers found for %s", fqdn)
	}
	return nameservers, nil
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
