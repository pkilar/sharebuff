package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sourcefrenchy/sharebuff/internal/wire"
)

func testEnvelope(t *testing.T) []byte {
	t.Helper()
	env, err := wire.EncodeEnvelope(wire.Header{T: "text"}, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestUploadKeepsCredentialsOnBadReply: the server stores the ciphertext before
// it answers 201, so a reply that fails to decode must still yield a locator.
// Failing here would strand a secret that exists and nobody can reach.
func TestUploadKeepsCredentialsOnBadReply(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantExpiry int64
		wantWarn   bool
	}{
		{"empty body", "", 0, true},
		{"truncated json", `{"expires_at":17`, 0, true},
		{"not json at all", "<html>502 Bad Gateway</html>", 0, true},
		{"valid, no expiry reported", `{}`, 0, false},
		{"valid", `{"expires_at":1789000000}`, 1789000000, false},
	}
	env, key := testEnvelope(t), wire.NewKey(wire.KeyLenTiny)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(c.body))
			}))
			defer ts.Close()

			var warn bytes.Buffer
			got, err := upload(ts.Client(), ts.URL, env, key, "ABCDEF", 3600, &warn)
			if err != nil {
				t.Fatalf("upload returned an error on a 201, stranding the secret: %v", err)
			}
			if !wire.ValidLocator(got.Locator) {
				t.Errorf("locator = %q, want a valid one", got.Locator)
			}
			if got.ExpiresAt != c.wantExpiry {
				t.Errorf("ExpiresAt = %d, want %d", got.ExpiresAt, c.wantExpiry)
			}
			if warned := warn.Len() > 0; warned != c.wantWarn {
				t.Errorf("warned = %v, want %v (warning was %q)", warned, c.wantWarn, warn.String())
			}
		})
	}
}

// TestUploadRetriesLocatorCollision: 409 means the random locator was already
// taken, so a fresh one must be drawn rather than the same one re-sent.
func TestUploadRetriesLocatorCollision(t *testing.T) {
	var attempts atomic.Int32
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req createReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		seen = append(seen, req.ID)
		mu.Unlock()
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"id already exists"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"expires_at":1789000000}`))
	}))
	defer ts.Close()

	got, err := upload(ts.Client(), ts.URL, testEnvelope(t), wire.NewKey(wire.KeyLenTiny), "ABCDEF", 3600, io.Discard)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if n := attempts.Load(); n != 2 {
		t.Fatalf("attempts = %d, want 2", n)
	}
	if len(seen) != 2 {
		t.Fatalf("saw %d requests, want 2", len(seen))
	}
	if seen[0] == seen[1] {
		t.Errorf("retry reused the colliding locator %q", seen[0])
	}
	if got.Locator != seen[1] {
		t.Errorf("returned locator %q, want the accepted one %q", got.Locator, seen[1])
	}
}

func TestUploadErrors(t *testing.T) {
	env, key := testEnvelope(t), wire.NewKey(wire.KeyLenTiny)
	cases := []struct {
		name    string
		status  int
		body    string
		wantSub string
	}{
		{"corporate refusal surfaces the reasons", http.StatusForbidden,
			`{"error":"sharing is disabled on this network","reasons":["proxy header via"]}`, "proxy header via"},
		{"server error", http.StatusInternalServerError, `{"error":"boom"}`, "500"},
		{"persistent collision gives up", http.StatusConflict, `{"error":"id already exists"}`, "409"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer ts.Close()

			got, err := upload(ts.Client(), ts.URL, env, key, "ABCDEF", 3600, io.Discard)
			if err == nil {
				t.Fatalf("want an error, got %+v", got)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("error %q does not mention %q", err, c.wantSub)
			}
			if got.Locator != "" {
				t.Errorf("returned locator %q alongside an error", got.Locator)
			}
		})
	}
}
