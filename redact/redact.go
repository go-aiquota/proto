// Package redact removes credential-shaped text from strings that are about
// to be shown or logged.
//
// It is the second line of defense, not the first: anything that is a
// credential from the moment it exists should be a [secret.Secret], which
// structurally cannot be printed. This package is for raw text that might
// contain one incidentally — a plugin subprocess's stderr, a panic value, an
// upstream error message quoting a request — where nothing already stripped
// it out. Modeled on tools/gitsafe/redact ("a secret that CAN reach an
// output stream eventually does"), generalized past GitHub token shapes to
// session-cookie-style credentials.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Mask is what replaces a secret. It matches secret.Mask so a redacted
// transcript reads consistently regardless of which layer caught the value.
const Mask = "«SECRET»"

// shapes are credential formats recognized even when the exact value is
// unknown. Kept deliberately narrow (a shape that's too eager masks ordinary
// text): a JWT (three dot-separated base64url segments, as claude.ai and
// most session systems use for bearer-style tokens) and an explicit
// "sess_"/"sk-" prefixed high-entropy token, the common shape for a session
// or API key. Extend this list once a real provider's actual cookie/token
// shape is confirmed (see go-aiquota/plugin-claude) rather than guessing
// further here.
var shapes = []*regexp.Regexp{
	regexp.MustCompile(`\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	regexp.MustCompile(`\b(?:sess|sk|sid)[_-][A-Za-z0-9_-]{16,}\b`),
}

// Redactor removes both the secrets it was told about and anything shaped
// like one.
type Redactor struct{ literals []string }

// New returns a Redactor that also removes these exact values, longest
// first so a secret containing another is not left half-masked.
func New(secrets ...string) *Redactor {
	var lits []string
	for _, s := range secrets {
		// A short "secret" would mask ordinary text everywhere. Anything
		// this short is not a credential, and masking it would do more harm
		// than the leak it prevents.
		if len(strings.TrimSpace(s)) >= 8 {
			lits = append(lits, strings.TrimSpace(s))
		}
	}
	sort.Slice(lits, func(i, j int) bool { return len(lits[i]) > len(lits[j]) })
	return &Redactor{literals: lits}
}

// String returns s with every known and every plausible secret removed.
func (r *Redactor) String(s string) string {
	for _, lit := range r.literals {
		s = strings.ReplaceAll(s, lit, Mask)
	}
	for _, re := range shapes {
		s = re.ReplaceAllString(s, Mask)
	}
	return s
}

// Bytes is String for a byte slice.
func (r *Redactor) Bytes(b []byte) []byte { return []byte(r.String(string(b))) }

// Clean reports whether s is free of anything shaped like a credential. Use
// it to refuse writing a line rather than to describe one after the fact —
// e.g. a config file that must hold no secrets is rejected, not sanitized.
func Clean(s string) bool {
	for _, re := range shapes {
		if re.MatchString(s) {
			return false
		}
	}
	return true
}
