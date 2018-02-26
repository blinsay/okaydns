package okaydns

import (
	"strings"
	"testing"
)

func TestRandomizeCase(t *testing.T) {
	tcs := []string{
		"baz.com",
		"foo",
		"bar",
		"ba!z!!!!",
		"BAAZ",
		"www.corp.net.hp.com.blergh",
	}

	for _, tc := range tcs {
		randomized := RandomizeCase(tc)
		t.Logf("tc=%q randomized=%q", tc, randomized)
		if strings.ToLower(tc) != strings.ToLower(randomized) {
			t.Fatalf("RandomizeCase should not alter the string: before=%q after=%q", tc, randomized)
		}
	}
}
