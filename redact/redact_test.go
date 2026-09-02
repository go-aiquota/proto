package redact

import "testing"

const fakeJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY2NvdW50LTEyMyJ9.dGhpc19pc19ub3RfYV9yZWFsX3NpZ25hdHVyZQ"

func TestStringMasksKnownLiteral(t *testing.T) {
	r := New("sess-abc123456789xyz")
	got := r.String("cookie: sess-abc123456789xyz; other=fine")
	if got != "cookie: "+Mask+"; other=fine" {
		t.Fatalf("literal not masked: %q", got)
	}
}

func TestStringMasksJWTShape(t *testing.T) {
	r := New()
	got := r.String("Authorization: Bearer " + fakeJWT)
	if got != "Authorization: Bearer "+Mask {
		t.Fatalf("JWT shape not masked: %q", got)
	}
}

func TestStringMasksSessPrefixShape(t *testing.T) {
	r := New()
	got := r.String("set-cookie: sess_QANT8bV3z9mR7wKp2LxYcH0dJfN6tGqE4sWo1uIr")
	if got != "set-cookie: "+Mask {
		t.Fatalf("sess_ shape not masked: %q", got)
	}
}

func TestShortLiteralNotMasked(t *testing.T) {
	r := New("abc")
	got := r.String("abc is not a secret")
	if got != "abc is not a secret" {
		t.Fatalf("a too-short literal was masked anyway: %q", got)
	}
}

func TestCleanReportsCredentialShapedText(t *testing.T) {
	if Clean("Authorization: Bearer " + fakeJWT) {
		t.Fatal("Clean reported a JWT-shaped string as clean")
	}
	if !Clean("hello world, nothing secret here") {
		t.Fatal("Clean reported ordinary text as unclean")
	}
}

func TestLongestLiteralWinsWhenOverlapping(t *testing.T) {
	r := New("token1234", "token1234-extended-suffix-value")
	got := r.String("value=token1234-extended-suffix-value")
	if got != "value="+Mask {
		t.Fatalf("overlapping literals left a fragment: %q", got)
	}
}
