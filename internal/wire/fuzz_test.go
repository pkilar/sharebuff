package wire

import (
	"strings"
	"testing"
)

// The three parsers below all consume bytes an attacker controls. None may
// panic, and none may return a value alongside an error.

func FuzzDecodeEnvelope(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 'x'})
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	env, err := EncodeEnvelope(Header{T: "text"}, []byte("seed"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(env)

	f.Fuzz(func(t *testing.T, b []byte) {
		h, payload, err := DecodeEnvelope(b)
		if err != nil {
			return
		}
		if h.T != "text" && h.T != "file" {
			t.Fatalf("accepted envelope with type %q", h.T)
		}
		if len(payload) > len(b) {
			t.Fatalf("payload %d longer than input %d", len(payload), len(b))
		}
	})
}

func FuzzDecodeCode(f *testing.F) {
	f.Add("")
	f.Add("AAAAA")
	f.Add("o1i-l 2ab")
	f.Add(EncodeCode("AB3DE", NewKey(KeyLenTiny)))
	f.Add(EncodeCode("AB3DE", NewKey(KeyLenFull)))

	f.Fuzz(func(t *testing.T, s string) {
		locator, key, err := DecodeCode(s)
		if err != nil {
			return
		}
		// Anything that decodes must be canonical and re-encode to itself.
		if !ValidLocator(locator) {
			t.Fatalf("accepted invalid locator %q", locator)
		}
		if !ValidKeyLen(len(key)) {
			t.Fatalf("accepted key length %d", len(key))
		}
		if got := NormalizeCode(EncodeCode(locator, key)); got != NormalizeCode(s) {
			t.Fatalf("re-encode mismatch: %q vs %q", got, NormalizeCode(s))
		}
	})
}

func FuzzNormalizeCode(f *testing.F) {
	f.Add("o1i-l 2ab")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		once := NormalizeCode(s)
		// Normalization must be idempotent: the retrieve page normalizes what
		// the user types, the sender normalizes what it generated, and the two
		// must agree no matter how often either is applied.
		if twice := NormalizeCode(once); twice != once {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, once, twice)
		}
		if strings.ContainsAny(once, " -OIL") {
			t.Fatalf("normalized output still contains a mapped character: %q", once)
		}
	})
}

func FuzzOpen(f *testing.F) {
	loc := "AB3DE"
	encKey, _, err := Derive(NewKey(KeyLenTiny), "0123AB", loc)
	if err != nil {
		f.Fatal(err)
	}
	blob, err := Seal(encKey, loc, []byte("seed"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(blob)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := Open(encKey, loc, b)
		if err == nil && got == nil {
			t.Fatal("Open returned nil plaintext and nil error")
		}
		if err != nil && got != nil {
			t.Fatalf("Open returned %d bytes alongside an error", len(got))
		}
	})
}
