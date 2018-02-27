package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/blinsay/okaydns"
)

type checkFormatter interface {
	SetVerbose(bool)
	FormatHeader(fqdn string, nameservers []okaydns.Nameserver) ([]byte, error)
	FormatCheck(cr *okaydns.CheckResult) ([]byte, error)
}

// text output

type textFormatter struct {
	verbose bool
	ok      func(...interface{}) string
	failure func(...interface{}) string
}

func (t *textFormatter) SetVerbose(v bool) {
	t.verbose = v
}

func (t *textFormatter) FormatHeader(fqdn string, nameservers []okaydns.Nameserver) ([]byte, error) {
	var bs bytes.Buffer

	fmt.Fprintf(&bs, "Running checks for %s using %d nameservers:\n", fqdn, len(nameservers))

	for _, nameserver := range nameservers {
		fmt.Fprintf(&bs, "\t%s (%s)\n", nameserver.Hostname, nameserver.String())
	}

	return bs.Bytes(), nil
}

func (t *textFormatter) FormatCheck(cr *okaydns.CheckResult) ([]byte, error) {
	var bs bytes.Buffer

	status := t.ok("ok")
	if cr.IsFailed() {
		status = t.failure("failed")
	}
	fmt.Fprintf(&bs, "%-30s %s\n", cr.Name+":", status)

	for _, failure := range cr.Failures {
		if failure.Nameserver.IsZero() {
			fmt.Fprintf(&bs, "\t%s\n", failure.Message)
		} else {
			fmt.Fprintf(&bs, "\t%s (%s): %s\n", failure.Nameserver.Hostname, failure.Nameserver.String(), failure.Message)
		}
	}

	if t.verbose {
		fmt.Fprintf(&bs, "<<>> Request <<>>\n%s\n", cr.Question)

		for nameserver, response := range cr.Answers {
			fmt.Fprintf(&bs, "<<>> Response from (%s) %s <<>>\n%s\n", nameserver.Hostname, nameserver.String(), response)
		}
	}

	return bs.Bytes(), nil
}

// json output

type jsonFormatter struct {
	verbose bool
}

func (j *jsonFormatter) SetVerbose(v bool) {
	j.verbose = v
}

func (j *jsonFormatter) FormatHeader(fqdn string, nameservers []okaydns.Nameserver) ([]byte, error) {
	// returns nil, since json checks are meant to be parsed individually and don't
	// need a header
	return nil, nil
}

func (j *jsonFormatter) FormatCheck(cr *okaydns.CheckResult) ([]byte, error) {
	output := jsonOutput{
		Name: cr.Name,
	}

	// nameservers
	output.Nameservers = make([]nameserverInfo, len(cr.Nameservers))
	for i, ns := range cr.Nameservers {
		output.Nameservers[i] = nameserverInfo{
			Name:    ns.Hostname,
			Address: ns.String(),
		}
	}

	// errors
	output.Errors = make(map[string]error)
	for ns, err := range cr.Errors {
		output.Errors[ns.String()] = err
	}

	// ns failures
	output.Failures = make([]failureInfo, len(cr.Failures))
	for i, failure := range cr.Failures {
		output.Failures[i].Message = failure.Message
		if failure.Nameserver.Hostname != "" || failure.Nameserver.IP != "" {
			nsString := failure.Nameserver.String()
			output.Failures[i].Nameserver = &nsString
		}
	}

	if j.verbose {
		// question
		output.Question = cr.Question.String()

		// answers
		output.Answers = make(map[string]string, len(cr.Answers))
		for ns, answer := range cr.Answers {
			output.Answers[ns.String()] = answer.String()
		}
	}

	return json.Marshal(&output)
}

type jsonOutput struct {
	Name        string            `json:"name"`
	Nameservers []nameserverInfo  `json:"nameservers"`
	Question    string            `json:"question,omitempty"`
	Answers     map[string]string `json:"answers,omitempty"`
	Errors      map[string]error  `json:"errors,omitempty"`
	Failures    []failureInfo     `json:"check_failures,omitempty"`
}

type nameserverInfo struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type failureInfo struct {
	Nameserver *string `json:"nameserver,omitempty"`
	Message    string  `json:"message"`
}
