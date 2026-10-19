// Package redact masks credential-shaped text before kova lets anything leave the machine: the
// diffs and commands sent to the triage classifier, and the diff excerpts attached to events.
// People put tokens in CLAUDE.md and in shell commands; the classifier does not need their value,
// and the dashboard should not become a second place a secret is stored.
//
// It is deliberately pattern-based and conservative: it keeps the shape ("STRIPE_KEY=[REDACTED]")
// so a reviewer and the model still see that a secret was involved. It does not touch URLs or
// hostnames, which are signal for the classifier.
package redact

import (
	"regexp"
	"strings"
)

const Mask = "[REDACTED]"

var (
	// Vendor-prefixed tokens with distinctive shapes.
	prefixed = regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk_(?:live|test)_[0-9A-Za-z]{10,}|rk_(?:live|test)_[0-9A-Za-z]{10,}|whsec_[0-9A-Za-z]{10,}|kv_(?:live|dev)_[0-9a-f]{20,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|ghu_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|sk-[A-Za-z0-9_-]{20,}|apikey_[A-Za-z0-9]{10,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{30,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b`)
	// JSON Web Tokens.
	jwt = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	// PEM private keys (whole block).
	pem = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)
	// Authorization headers / bearer tokens.
	bearer = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*["']?\s*(?:bearer|basic|token)\s+|bearer\s+)([A-Za-z0-9._~+/=-]{12,})`)
	// Generic KEY=value / "key": "value" where the key name says secret.
	assign = regexp.MustCompile(`(?i)\b((?:[A-Z0-9_]*?(?:API[_-]?KEY|APIKEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET|AUTH)[A-Z0-9_]*)\s*["']?\s*[:=]\s*["']?)([^\s"'` + "`" + `,;&|)]{6,})`)
	// user:password@ in URLs.
	userinfo = regexp.MustCompile(`(://[^/\s:@]+):([^/\s@]+)@`)
)

// Text returns s with credential-shaped substrings masked.
func Text(s string) string {
	if s == "" {
		return s
	}
	s = pem.ReplaceAllString(s, "-----BEGIN PRIVATE KEY----- "+Mask+" -----END PRIVATE KEY-----")
	s = jwt.ReplaceAllString(s, Mask)
	s = prefixed.ReplaceAllString(s, Mask)
	s = bearer.ReplaceAllString(s, "${1}"+Mask)
	s = assign.ReplaceAllStringFunc(s, func(m string) string {
		sub := assign.FindStringSubmatch(m)
		val := sub[2]
		// Leave placeholders and references alone: ${VAR}, <token>, "..." , env lookups.
		if strings.HasPrefix(val, "$") || strings.HasPrefix(val, "<") || strings.HasPrefix(val, "...") || val == Mask || strings.EqualFold(val, "bearer") || strings.EqualFold(val, "basic") || strings.EqualFold(val, "token") || strings.EqualFold(val, "null") || strings.EqualFold(val, "none") || strings.EqualFold(val, "true") || strings.EqualFold(val, "false") {
			return m
		}
		return sub[1] + Mask
	})
	s = userinfo.ReplaceAllString(s, "${1}:"+Mask+"@")
	return s
}

// Changed reports whether Text would alter s (handy for tests and for noting redaction in events).
func Changed(s string) bool { return Text(s) != s }
