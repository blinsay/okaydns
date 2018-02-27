## OK

`okdns` is a command-line tool that runs some standard checks against the
authoritative nameservers for a domain.

When given a domain as a target, it runs a recursive query against your local
resolver to find the authoritative nameservers for that domain, and then runs
some checks against them.

```
$ okdns blinsay.com
Running checks for blinsay.com. using 2 nameservers:
	dns1.registrar-servers.com. (udp://216.87.155.33:53)
	dns2.registrar-servers.com. (udp://216.87.152.33:53)
A:                             ok
A (with 0x20 Randomization):   ok
Unknown question type:         ok
SOA:                           ok
```

#### Installing

Download the repo to your $GOPATH with `go get` and run `make install`.


## OKAY

`okaydns` is a library used to write checks to see if your DNS is okay. `okaydns`
represents checks as functions that validate a set of DNS requests and
responses, and provides some standard tools for making that easier.

Check out [the docs](https://godoc.org/github.com/blinsay/okaydns) for more details.

#### Examples

A check that makes sure your domain has an A record at the root, has no CNAME
at the root, and that all of the nameservers give an authoritative response.

```go
var CheckA = okaydns.Check{
	Name: "A",
	Question: func(fqdn string) *dns.Msg {
		return okaydns.NonRecursiveQuestion(fqdn, dns.TypeA)
	},
	Validators: []okaydns.RequestResponseValidator{
		okaycheck.EachNameserver(
			okaycheck.AuthoritativeResponse,
			okaycheck.ResponseCode(dns.RcodeSuccess),
			okaycheck.AnswerContains(dns.TypeA),
			okaycheck.AnswerDoesNotContain(dns.TypeCNAME),
		),
	},
}
```

A check that makes sure the nameservers return an authoritative response for
SOA records and that every SOA record has the same serial.

```go
var CheckSOASerials = okaydns.Check{
	Name: "SOA",
	Question: func(fqdn string) *dns.Msg {
		return okaydns.NonRecursiveQuestion(fqdn, dns.TypeSOA)
	},
	Validators: []okaydns.RequestResponseValidator{
		okaycheck.EachNameserver(
			okaycheck.AuthoritativeResponse,
			okaycheck.ResponseCode(dns.RcodeSuccess),
			okaycheck.AnswerContains(dns.TypeSOA),
		),
		validateSerialsMatch,
	},
}

func validateSerialsMatch(_ *dns.Msg, replies map[okaydns.Nameserver]*dns.Msg) (failures []okaydns.Failure) {
	serials := make(map[uint32]struct{})

	for _, reply := range replies {
		for _, answer := range reply.Answer {
			if soa, ok := answer.(*dns.SOA); ok {
				serials[soa.Serial] = struct{}{}
			}
		}
	}

	if len(serials) > 1 {
		failures = append(failures, okaydns.Failure{Message: "SOA queries return more than one serial"})
	}
	return
}
```
