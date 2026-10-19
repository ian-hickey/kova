package redact

import (
	"strings"
	"testing"
)

func TestRedactsCommonSecretShapes(t *testing.T) {
	cases := map[string]string{
		"STRIPE_KEY=sk_live_51Hxyzabcdefghijklmnop":                                                          "STRIPE_KEY=" + Mask,
		`"api_key": "a1b2c3d4e5f6g7h8"`:                                                                      `"api_key": "` + Mask,
		"export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789":                                       "export GITHUB_TOKEN=" + Mask,
		"curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'":                                         "Authorization: Bearer " + Mask,
		"aws: AKIAIOSFODNN7EXAMPLE":                                                                          "aws: " + Mask,
		"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U": "token " + Mask,
		"https://user:hunter2@internal.example.com/x":                                                        "https://user:" + Mask + "@internal.example.com/x",
		"KEY=$(grep '^JEV=' .env.development | cut -d= -f2-)":                                                "KEY=$(grep '^JEV=' .env.development | cut -d= -f2-)", // a reference, not a value
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----":                            "-----BEGIN PRIVATE KEY----- " + Mask + " -----END PRIVATE KEY-----",
	}
	for in, want := range cases {
		got := Text(in)
		if !strings.Contains(got, want) {
			t.Errorf("Text(%q) = %q, want it to contain %q", in, got, want)
		}
	}
}

func TestLeavesOrdinaryTextAndURLsAlone(t *testing.T) {
	benign := []string{
		"Run `go test ./...` before pushing.",
		"curl -fsSL https://kovaverified.io/install.sh | sh",
		"TOKEN=${GITHUB_TOKEN}",
		"The secret of good tests is small fixtures.",
		"password: <ask the user>",
	}
	for _, s := range benign {
		if Changed(s) {
			t.Errorf("should be unchanged: %q -> %q", s, Text(s))
		}
	}
}
