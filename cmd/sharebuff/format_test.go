package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestPreview(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "empty input",
			in:   []byte{},
			want: `""`,
		},
		{
			name: "short ascii, no truncation",
			in:   []byte("hello world"),
			want: `"hello world"`,
		},
		{
			name: "exactly 40 runes: no ellipsis",
			in:   []byte(strings.Repeat("x", 40)),
			want: fmt.Sprintf(`"%s"`, strings.Repeat("x", 40)),
		},
		{
			name: "41 runes: truncated to 40 plus ellipsis suffix",
			in:   []byte(strings.Repeat("x", 41)),
			want: fmt.Sprintf(`"%s…"`, strings.Repeat("x", 40)),
		},
		{
			name: "truncation counts runes, not bytes, for multi-byte UTF-8",
			in:   []byte(strings.Repeat("é", 41)), // 'é' is 2 bytes in UTF-8
			want: fmt.Sprintf(`"%s…"`, strings.Repeat("é", 40)),
		},
		{
			name: "control characters collapse to single spaces",
			in:   []byte("a\tb\x01c\x7fd"), // tab, SOH, DEL
			want: `"a b c d"`,
		},
		{
			name: "leading/trailing control chars vanish after collapsing+trim",
			in:   []byte("\x01hello\x02"),
			want: `"hello"`,
		},
		{
			name: "invalid UTF-8 byte becomes a single replacement rune",
			in:   []byte{'a', 0xff, 'b'},
			want: `"a�b"`,
		},
		{
			name: "a run of invalid UTF-8 bytes collapses to one replacement rune",
			in:   []byte{'a', 0xff, 0xff, 'b'},
			want: `"a�b"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := preview(c.in); got != c.want {
				t.Errorf("preview(%q) = %s, want %s", c.in, got, c.want)
			}
		})
	}
}

func TestHumanSize(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want string
	}{
		{name: "zero bytes", in: 0, want: "0 B"},
		{name: "just below the KiB boundary", in: 1023, want: "1023 B"},
		{name: "at the KiB boundary", in: 1024, want: "1.0 KiB"},
		{name: "mid KiB range", in: 1536, want: "1.5 KiB"},
		// (1<<20)-1 is still the KiB branch; 1048575/1024 = 1023.999023...,
		// which %.1f rounds up to 1024.0 -- that rounding is the actual,
		// observable behavior of humanSize at this boundary.
		{name: "just below the MiB boundary", in: 1<<20 - 1, want: "1024.0 KiB"},
		{name: "at the MiB boundary", in: 1 << 20, want: "1.0 MiB"},
		{name: "mid MiB range", in: 1572864, want: "1.5 MiB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := humanSize(c.in); got != c.want {
				t.Errorf("humanSize(%d) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestEscalatedReason(t *testing.T) {
	cases := []struct {
		name   string
		isFile bool
		want   string
	}{
		{name: "file payload", isFile: true, want: "files always get it"},
		{name: "text payload", isFile: false, want: fmt.Sprintf("text over %d bytes", AutoEscalateBytes)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := escalatedReason(c.isFile); got != c.want {
				t.Errorf("escalatedReason(%v) = %q, want %q", c.isFile, got, c.want)
			}
		})
	}
}
