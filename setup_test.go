package coredyndns

import (
	"testing"

	"github.com/coredns/caddy"
	"github.com/google/go-cmp/cmp"
)

func TestParse(t *testing.T) {
	tests := []struct {
		inputFileRules string
		shouldErr      bool

		expectedZones       []string
		expectedListen      string
		expectedUseTls      bool
		expectedInsecureTls bool
		expectedTlsCert     []byte
		expectedTlsKey      []byte
		expectedUsername    string
		expectedPassword    string
	}{
		{
			`coredyndns`,
			false,
			[]string{}, ":9080", false, false, nil, nil, "", "",
		},
		{
			` coredyndns example.com`,
			false,
			[]string{"example.com."}, ":9080", false, false, nil, nil, "", "",
		},
		{
			`coredyndns example.com example2.com {
				listen :88
				username user
				password passw0rd
			}`,
			false,
			[]string{"example.com.", "example2.com."}, ":88", false, false, nil, nil, "user", "passw0rd",
		},
		{
			`coredyndns example.com example2.com {
				listen :88 tls
				username user
				password passw0rd
			}`,
			true,
			[]string{"example.com.", "example2.com."}, ":88", true, false, nil, nil, "user", "passw0rd",
		},
		{
			`coredyndns {
				listen :88
				username user
			}`,
			true,
			[]string{}, ":88", false, false, nil, nil, "user", "",
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("coredyndns", test.inputFileRules)
		d, err := parse(c)

		if err == nil && test.shouldErr {
			t.Fatalf("Test %d expected errors, but got no error", i)
		} else if err != nil && !test.shouldErr {
			t.Fatalf("Test %d expected no errors, but got '%v'", i, err)
		} else if !test.shouldErr {
			if !cmp.Equal(d.zones, test.expectedZones) {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedZones, d.zones)
			}
			if d.listen != test.expectedListen {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedListen, d.listen)
			}
			if d.useTls != test.expectedUseTls {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedUseTls, d.useTls)
			}
			if d.insecureTls != test.expectedInsecureTls {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedInsecureTls, d.insecureTls)
			}
			if !cmp.Equal(d.tlsCert, test.expectedTlsCert) {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedTlsCert, d.tlsCert)
			}
			if !cmp.Equal(d.tlsKey, test.expectedTlsKey) {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedTlsKey, d.tlsKey)
			}
			if d.username != test.expectedUsername {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedUsername, d.username)
			}
			if d.password != test.expectedPassword {
				t.Fatalf("Test %d expected %v, got %v", i, test.expectedPassword, d.password)
			}
		}
	}
}
