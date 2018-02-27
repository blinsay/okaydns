package okaydns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
		assert.NotEqual(t, tc, randomized, "RandomizeCase should never return the input string unaltered")
		assert.Equal(t, strings.ToLower(tc), strings.ToLower(randomized), "RandomizeCase should not alter the input string")
	}
}
