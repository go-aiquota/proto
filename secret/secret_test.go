package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// poison is a realistically-shaped fake session cookie: long, base64-like,
// distinctive enough that strings.Contains would catch it appearing
// anywhere it shouldn't.
const poison = "sk-ses-aiquota-poison-QANT8bV3z9mR7wKp2LxYcH0dJfN6tGqE4sWo1uIrPy"

func TestNeverLeaksThroughFmtVerbs(t *testing.T) {
	s := New(poison)
	for _, out := range []string{
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%#v", s),
		fmt.Sprintf("%s", s),
		fmt.Sprintf("%q", s),
		s.String(),
		s.GoString(),
	} {
		if strings.Contains(out, poison) {
			t.Fatalf("poison value leaked through a fmt verb: %q", out)
		}
		if !strings.Contains(out, Mask) {
			t.Errorf("expected the mask %q in output, got %q", Mask, out)
		}
	}
}

func TestNeverLeaksThroughWrappedError(t *testing.T) {
	s := New(poison)
	err := fmt.Errorf("dialing provider failed, credential was %v: %w", s, errors.New("boom"))
	if strings.Contains(err.Error(), poison) {
		t.Fatalf("poison value leaked through a wrapped error: %q", err.Error())
	}
}

func TestNeverLeaksThroughJSON(t *testing.T) {
	type config struct {
		Label string `json:"label"`
		Cred  Secret `json:"cred"`
	}
	_, err := json.Marshal(config{Label: "acct-1", Cred: New(poison)})
	if err == nil {
		t.Fatal("expected MarshalJSON to refuse a Secret field, got nil error")
	}
	if strings.Contains(err.Error(), poison) {
		t.Fatalf("poison value leaked through the marshal error: %q", err.Error())
	}
}

func TestRevealIsTheOnlyWayOut(t *testing.T) {
	s := New(poison)
	got := ""
	s.Reveal(func(v string) { got = v })
	if got != poison {
		t.Fatalf("Reveal did not hand back the wrapped value: got %q", got)
	}
}

func TestZeroValueRevealIsNoop(t *testing.T) {
	var s Secret
	called := false
	s.Reveal(func(string) { called = true })
	if called {
		t.Fatal("Reveal called fn on an unset Secret")
	}
	if s.IsSet() {
		t.Fatal("zero-value Secret reports IsSet")
	}
}
