// Package secret wraps a credential value so that the ordinary ways a Go
// program accidentally prints something — fmt's %v/%+v, an error wrapped
// with %w, a JSON-encoded struct, a debugger's variable dump reaching a log
// — cannot show it.
//
// It exists because a leak does not need a careless author: a value that
// CAN reach an output stream eventually does (the same lesson
// tools/gitsafe/redact was built from, after a token was pasted into a
// command line and git echoed it back twice). That package removes secrets
// from text after the fact, by shape; this one stops the value from ever
// becoming ordinary text in the first place. Use both: Secret for anything
// that is a credential from the moment it exists, redact for raw text (a
// subprocess's stderr, say) that might contain one incidentally.
package secret

import (
	"encoding/json"
	"fmt"
)

// Mask is what a Secret prints as, everywhere. It is deliberately
// unmistakable so a redacted transcript reads as redacted, not truncated.
const Mask = "«SECRET»"

// Secret holds a credential value. Its zero value holds no value and
// behaves like an empty Secret (Reveal never calls its function).
//
// There is deliberately no way to read the value back out except through
// [Secret.Reveal]: no accessor, no exported field. That keeps every read
// site a single, greppable line instead of a plain string variable that
// could be logged, formatted, or returned three lines after it was needed.
type Secret struct {
	v string
	// set distinguishes an empty secret from a zero-value Secret; both
	// behave the same today (Reveal skips), but a future String-vs-not-set
	// affordance can key off it without a breaking change.
	set bool
}

// New wraps v as a Secret.
func New(v string) Secret { return Secret{v: v, set: true} }

// Reveal calls fn with the underlying value if one was set. Keep the body of
// fn to the single use that needs the raw value (e.g. setting one gRPC
// request field) — do not assign the argument to a variable that outlives
// the call.
func (s Secret) Reveal(fn func(v string)) {
	if s.set && fn != nil {
		fn(s.v)
	}
}

// IsSet reports whether a value was wrapped (vs. a zero-value Secret).
func (s Secret) IsSet() bool { return s.set }

// String implements fmt.Stringer. It always returns [Mask], never the value.
func (s Secret) String() string { return Mask }

// GoString implements fmt.GoStringer, covering %#v.
func (s Secret) GoString() string { return Mask }

// Format implements fmt.Formatter, covering every fmt verb (%v, %+v, %q, %x,
// …) so there is no verb that bypasses String/GoString.
func (s Secret) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte(Mask))
}

// MarshalJSON refuses to serialize the value: a Secret can never land in a
// JSON config file, log record, or API response by accident. Encoding a
// struct that embeds a Secret field fails loudly instead of writing the
// credential to disk.
func (s Secret) MarshalJSON() ([]byte, error) {
	return nil, errNotSerializable
}

// UnmarshalJSON always fails, for the same reason: nothing should be reading
// a Secret's value out of a JSON document (accounts.json holds only
// non-secret metadata; the credential itself lives in the OS keyring).
func (s *Secret) UnmarshalJSON([]byte) error {
	return errNotSerializable
}

var errNotSerializable = secretError("secret: value is not JSON-serializable by design")

type secretError string

func (e secretError) Error() string { return string(e) }

var (
	_ json.Marshaler   = Secret{}
	_ json.Unmarshaler = (*Secret)(nil)
	_ fmt.Stringer     = Secret{}
	_ fmt.GoStringer   = Secret{}
	_ fmt.Formatter    = Secret{}
)
