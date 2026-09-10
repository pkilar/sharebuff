package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sourcefrenchy/sharebuff/internal/wire"
	"github.com/sourcefrenchy/sharebuff/web"
)

type secret struct {
	id, pin  string
	authHex  string
	verifier string
	ct       string
}

func makeSecret(t *testing.T) secret {
	return makeSecretPayload(t, []byte("payload"))
}

func makeSecretPayload(t *testing.T, payload []byte) secret {
	t.Helper()
	key := wire.NewKey(wire.KeyLenTiny)
	pin := wire.NewPIN(6)
	id := wire.NewLocator()
	encKey, authKey, err := wire.Derive(key, pin, id)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.EncodeEnvelope(wire.Header{T: "file", N: "test.bin", M: "application/octet-stream"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := wire.Seal(encKey, id, env)
	if err != nil {
		t.Fatal(err)
	}
	return secret{
		id:       id,
		pin:      pin,
		authHex:  fmt.Sprintf("%x", authKey),
		verifier: wire.VerifierHex(authKey),
		ct:       base64.StdEncoding.EncodeToString(blob),
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Now()}
	s := &store{m: make(map[string]*record), maxTTL: 168 * time.Hour, now: clk.Now, allowShare: true, enforce: true, rl: make(map[string]*window), statsSalt: []byte("test")}
	ts := httptest.NewServer(newMux(s))
	t.Cleanup(ts.Close)
	return ts, clk
}

func post(t *testing.T, url string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decoding %s response (%d): %v; body=%q", url, resp.StatusCode, err, raw)
		}
	}
	return resp.StatusCode, out
}

// numField and friends fail the test cleanly instead of panicking when the
// server answers with an unexpected shape.
func numField(t *testing.T, body map[string]any, key string) int {
	t.Helper()
	v, ok := body[key].(float64)
	if !ok {
		t.Fatalf("%q missing or not a number in %v", key, body)
	}
	return int(v)
}

func strField(t *testing.T, body map[string]any, key string) string {
	t.Helper()
	v, ok := body[key].(string)
	if !ok {
		t.Fatalf("%q missing or not a string in %v", key, body)
	}
	return v
}

func boolField(t *testing.T, body map[string]any, key string) bool {
	t.Helper()
	v, ok := body[key].(bool)
	if !ok {
		t.Fatalf("%q missing or not a bool in %v", key, body)
	}
	return v
}

func sliceField(t *testing.T, body map[string]any, key string) []any {
	t.Helper()
	v, ok := body[key].([]any)
	if !ok {
		t.Fatalf("%q missing or not an array in %v", key, body)
	}
	return v
}

func create(t *testing.T, ts *httptest.Server, sec secret) {
	t.Helper()
	code, _ := post(t, ts.URL+"/api/secrets", map[string]any{
		"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600,
	})
	if code != 201 {
		t.Fatalf("create: got %d", code)
	}
}

func TestClaimLifecycle(t *testing.T) {
	ts, clk := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)

	// Duplicate id rejected.
	if code, _ := post(t, ts.URL+"/api/secrets", map[string]any{
		"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600,
	}); code != 409 {
		t.Fatalf("duplicate create: got %d", code)
	}

	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	badAuth := "00" + sec.authHex[2:]

	// Wrong proofs do NOT burn; attempts_left counts down (clock advanced
	// past each cooldown so the attempts are counted).
	for i := 1; i <= 2; i++ {
		code, body := post(t, ts.URL+"/api/secrets/"+sec.id+"/claim", map[string]string{"auth": badAuth})
		if code != 403 || numField(t, body, "attempts_left") != wire.MaxAttempts-i {
			t.Fatalf("bad claim %d: code=%d body=%v", i, code, body)
		}
		clk.Advance(time.Duration(wire.CooldownMaxSeconds+1) * time.Second)
	}

	// Valid claim returns the ciphertext and destroys the record.
	code, body := post(t, claimURL, map[string]string{"auth": sec.authHex})
	if code != 200 || strField(t, body, "ct") != sec.ct {
		t.Fatalf("valid claim: code=%d", code)
	}

	// Second claim (even valid) hits the tombstone.
	if code, body := post(t, claimURL, map[string]string{"auth": sec.authHex}); code != 410 || body["reason"] != "claimed" {
		t.Fatalf("post-claim: code=%d body=%v", code, body)
	}
	// Unknown id is 404.
	if code, _ := post(t, ts.URL+"/api/secrets/ZZZZZ/claim", map[string]string{"auth": sec.authHex}); code != 404 {
		t.Fatalf("unknown id: code=%d", code)
	}
}

func TestBurnAfterMaxAttempts(t *testing.T) {
	ts, clk := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	badAuth := "00" + sec.authHex[2:]

	for i := 1; i < wire.MaxAttempts; i++ {
		if code, _ := post(t, claimURL, map[string]string{"auth": badAuth}); code != 403 {
			t.Fatalf("attempt %d: code=%d", i, code)
		}
		clk.Advance(time.Duration(wire.CooldownMaxSeconds+1) * time.Second)
	}
	if code, body := post(t, claimURL, map[string]string{"auth": badAuth}); code != 410 || body["reason"] != "burned" {
		t.Fatalf("burning attempt: code=%d body=%v", code, body)
	}
	// The real PIN is now useless: the ciphertext is gone.
	if code, body := post(t, claimURL, map[string]string{"auth": sec.authHex}); code != 410 || body["reason"] != "burned" {
		t.Fatalf("post-burn valid claim: code=%d body=%v", code, body)
	}
}

// TestCooldown: attempts inside the cooldown window are rejected with 429 and
// do NOT count toward the burn limit — spam can neither brute-force nor burn.
func TestCooldown(t *testing.T) {
	ts, clk := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	badAuth := "00" + sec.authHex[2:]

	// First wrong attempt is counted (attempts_left 9) and starts a 2s cooldown.
	code, body := post(t, claimURL, map[string]string{"auth": badAuth})
	if code != 403 || numField(t, body, "attempts_left") != wire.MaxAttempts-1 {
		t.Fatalf("first wrong: code=%d body=%v", code, body)
	}
	// Hammering during the cooldown: all 429, none counted — even with the
	// correct proof, which is not examined during cooldown.
	for i := 0; i < 50; i++ {
		auth := badAuth
		if i%2 == 0 {
			auth = sec.authHex
		}
		code, body := post(t, claimURL, map[string]string{"auth": auth})
		if code != 429 || body["retry_after_seconds"] == nil {
			t.Fatalf("spam %d: code=%d body=%v", i, code, body)
		}
	}
	// After the window: the counter did not move (still 8 left after this one)...
	clk.Advance(3 * time.Second)
	if code, body := post(t, claimURL, map[string]string{"auth": badAuth}); code != 403 ||
		numField(t, body, "attempts_left") != wire.MaxAttempts-2 {
		t.Fatalf("post-cooldown wrong: code=%d body=%v", code, body)
	}
	// ...and the correct PIN still works once its cooldown (4s) passes.
	clk.Advance(5 * time.Second)
	if code, _ := post(t, claimURL, map[string]string{"auth": sec.authHex}); code != 200 {
		t.Fatalf("post-cooldown valid claim: code=%d", code)
	}
}

// TestConcurrentClaims verifies exactly one winner under parallel valid claims.
func TestConcurrentClaims(t *testing.T) {
	ts, _ := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"

	const n = 16
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _ = post(t, claimURL, map[string]string{"auth": sec.authHex})
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, c := range codes {
		switch c {
		case 200:
			wins++
		case 410:
		default:
			t.Fatalf("unexpected code %d", c)
		}
	}
	if wins != 1 {
		t.Fatalf("expected exactly 1 successful claim, got %d", wins)
	}
}

func TestValidation(t *testing.T) {
	ts, _ := newTestServer(t)
	sec := makeSecret(t)
	// Oversized ciphertext (one byte past the blob cap).
	big := base64.StdEncoding.EncodeToString(make([]byte, wire.MaxBlob+1))
	if code, _ := post(t, ts.URL+"/api/secrets", map[string]any{
		"id": sec.id, "ct": big, "verifier": sec.verifier, "ttl_seconds": 3600,
	}); code != 413 {
		t.Fatalf("oversize: code=%d", code)
	}
	// Bad ttl / id / verifier.
	for _, req := range []map[string]any{
		{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 5},
		{"id": "bad!id", "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600},
		{"id": sec.id, "ct": sec.ct, "verifier": "xyz", "ttl_seconds": 3600},
	} {
		if code, _ := post(t, ts.URL+"/api/secrets", req); code != 400 {
			t.Fatalf("expected 400 for %v, got %d", req, code)
		}
	}
}

// TestLargePayloadRoundtrip pushes a 3 MiB binary through create+claim and
// verifies the ciphertext comes back byte-identical and decryptable.
func TestLargePayloadRoundtrip(t *testing.T) {
	ts, _ := newTestServer(t)
	payload := bytes.Repeat([]byte{0xC3, 0x28, 0x00, 0xFF}, 3<<20/4) // 3 MiB, non-UTF8
	sec := makeSecretPayload(t, payload)
	create(t, ts, sec)
	code, body := post(t, ts.URL+"/api/secrets/"+sec.id+"/claim", map[string]string{"auth": sec.authHex})
	if code != 200 {
		t.Fatalf("claim: %d", code)
	}
	if strField(t, body, "ct") != sec.ct {
		t.Fatal("large ciphertext corrupted in transit")
	}
}

func TestEnvironmentSignals(t *testing.T) {
	ts, _ := newTestServer(t)
	get := func(hdr map[string]string) (bool, []any) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/env", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return boolField(t, out, "share"), sliceField(t, out, "reasons")
	}
	if share, reasons := get(nil); !share || len(reasons) != 0 {
		t.Fatalf("clean request: share=%v reasons=%v", share, reasons)
	}
	for _, h := range []map[string]string{
		{"X-Sharebuff-Policy": "retrieve-only"},
		{"Via": "1.1 zscaler.net"},
		{"X-Forwarded-For": "10.0.0.5, 203.0.113.9"},
		{"X-Netskope-User": "alice"},
	} {
		if share, reasons := get(h); share || len(reasons) == 0 {
			t.Fatalf("headers %v should disable share: share=%v reasons=%v", h, share, reasons)
		}
	}
}

// TestCreateEnforcement: the API itself refuses creation on corporate signals,
// so patching the page's JavaScript (or using curl) gains nothing.
func TestCreateEnforcement(t *testing.T) {
	ts, _ := newTestServer(t)
	sec := makeSecret(t)
	body, _ := json.Marshal(map[string]any{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600})
	try := func(hdr map[string]string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", ts.URL+"/api/secrets", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	for _, hdr := range []map[string]string{
		{"Via": "1.1 zscaler.net"},
		{"X-Forwarded-For": "10.0.0.5, 203.0.113.9"},
		// httptest speaks HTTP/1.1: a modern browser UA over it is the middlebox tell.
		{"User-Agent": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"},
		{"User-Agent": "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"},
	} {
		if code, out := try(hdr); code != 403 || out["reasons"] == nil {
			t.Fatalf("headers %v: expected 403 with reasons, got %d %v", hdr, code, out)
		}
	}
	// Old / non-browser user agents over HTTP/1.1 are fine (curl, the CLI).
	if code, _ := try(map[string]string{"User-Agent": "curl/8.4.0"}); code != 201 {
		t.Fatalf("plain create refused: %d", code)
	}
	// Advise-only mode reports but does not refuse.
	adv := &store{m: make(map[string]*record), maxTTL: time.Hour, now: time.Now, allowShare: true, enforce: false, rl: make(map[string]*window)}
	ts2 := httptest.NewServer(newMux(adv))
	defer ts2.Close()
	req, _ := http.NewRequest("POST", ts2.URL+"/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Via", "1.1 zscaler.net")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("advise mode should accept: %d", resp.StatusCode)
	}
}

func TestShareDisabledByOperator(t *testing.T) {
	s := &store{m: make(map[string]*record), maxTTL: time.Hour, now: time.Now, allowShare: false, rl: make(map[string]*window)}
	ts := httptest.NewServer(newMux(s))
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/env")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if boolField(t, out, "share") {
		t.Fatal("operator -share=false not honoured")
	}
}

// TestRateLimit: per-IP fixed windows on create and claim, 429 with
// Retry-After, and the window resets with the clock.
func TestRateLimit(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	s := &store{m: make(map[string]*record), maxTTL: 168 * time.Hour, now: clk.Now, allowShare: true, enforce: false,
		createRPM: 3, claimRPM: 2, rl: make(map[string]*window)}
	ts := httptest.NewServer(newMux(s))
	defer ts.Close()

	codes := []int{}
	for i := 0; i < 4; i++ {
		sec := makeSecret(t)
		code, _ := post(t, ts.URL+"/api/secrets", map[string]any{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600})
		codes = append(codes, code)
	}
	if codes[0] != 201 || codes[1] != 201 || codes[2] != 201 || codes[3] != 429 {
		t.Fatalf("create burst codes = %v, want 201 201 201 429", codes)
	}
	clk.Advance(61 * time.Second)
	sec := makeSecret(t)
	if code, _ := post(t, ts.URL+"/api/secrets", map[string]any{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600}); code != 201 {
		t.Fatalf("after window reset: %d", code)
	}
	// Claims: 2 per minute, the third is limited regardless of proof validity.
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	bad := "00" + sec.authHex[2:]
	post(t, claimURL, map[string]string{"auth": bad})
	clk.Advance(3 * time.Second) // past the per-record cooldown
	post(t, claimURL, map[string]string{"auth": bad})
	clk.Advance(5 * time.Second)
	if code, body := post(t, claimURL, map[string]string{"auth": sec.authHex}); code != 429 || body["retry_after_seconds"] == nil {
		t.Fatalf("third claim in window: code=%d body=%v", code, body)
	}
}

// TestVolumeCaps: hourly per-IP create count and upload-byte caps (bulk
// dead-drop guard) answer 429 and reset with the clock.
func TestVolumeCaps(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	s := &store{m: make(map[string]*record), maxTTL: 168 * time.Hour, now: clk.Now, allowShare: true, enforce: false,
		createRPM: 0, claimRPM: 0, createPerHour: 3, createBytesHour: 0, rl: make(map[string]*window)}
	ts := httptest.NewServer(newMux(s))
	defer ts.Close()
	mk := func() (int, map[string]any) {
		sec := makeSecret(t)
		return post(t, ts.URL+"/api/secrets", map[string]any{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600})
	}
	for i := 0; i < 3; i++ {
		if code, _ := mk(); code != 201 {
			t.Fatalf("create %d: %d", i, code)
		}
	}
	if code, body := mk(); code != 429 || body["retry_after_seconds"] == nil {
		t.Fatalf("4th create in the hour: %d %v", code, body)
	}
	clk.Advance(61 * time.Minute)
	if code, _ := mk(); code != 201 {
		t.Fatal("hour window did not reset")
	}
	// Byte cap: size it from a real request body so two fit and the third does not.
	secs := []secret{makeSecret(t), makeSecret(t), makeSecret(t)}
	bodyLen := func(sec secret) int64 {
		b, _ := json.Marshal(map[string]any{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600})
		return int64(len(b))
	}
	cap := bodyLen(secs[0]) + bodyLen(secs[1]) + bodyLen(secs[2])/2
	s2 := &store{m: make(map[string]*record), maxTTL: 168 * time.Hour, now: clk.Now, allowShare: true, enforce: false,
		createPerHour: 0, createBytesHour: cap, rl: make(map[string]*window)}
	ts2 := httptest.NewServer(newMux(s2))
	defer ts2.Close()
	codes := []int{}
	for _, sec := range secs {
		code, _ := post(t, ts2.URL+"/api/secrets", map[string]any{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600})
		codes = append(codes, code)
	}
	if codes[0] != 201 || codes[1] != 201 || codes[2] != 429 {
		t.Fatalf("byte cap codes = %v, want 201 201 429", codes)
	}
}

// TestNoPushChannels guards the "poor C2" property: the protocol must stay
// one-shot with no server→client push, poll or subscribe surface.
func TestNoPushChannels(t *testing.T) {
	re := regexp.MustCompile(`(?i)websocket|eventsource|text/event-stream|/subscribe|long-?poll`)
	roots := []string{"../../worker/src", "../../web", "."}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".go" && ext != ".ts" && ext != ".js" {
				return nil
			}
			b, _ := os.ReadFile(path)
			if loc := re.FindIndex(b); loc != nil {
				t.Errorf("%s contains a push/poll primitive (%q); the protocol must stay one-shot", path, string(b[loc[0]:loc[1]]))
			}
			return nil
		})
	}
}

// TestIntegrityFresh: web/integrity.json must match the embedded page files,
// so the footer hash and the published values never go stale.
func TestIntegrityFresh(t *testing.T) {
	raw, err := web.FS.ReadFile("integrity.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SHA map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for name, want := range doc.SHA {
		b, err := web.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("%s listed in integrity.json but not embedded: %v", name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
			t.Fatalf("%s hash is stale — run: make integrity", name)
		}
	}
}

// TestAlertWebhook: refused creates and burns POST a JSON event (no payload,
// no IP) to the configured webhook.
func TestAlertWebhook(t *testing.T) {
	events := make(chan map[string]any, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		_ = json.NewDecoder(r.Body).Decode(&ev)
		events <- ev
	}))
	defer hook.Close()
	s := &store{m: make(map[string]*record), maxTTL: time.Hour, now: time.Now, allowShare: true, enforce: true,
		rl: make(map[string]*window), alertWebhook: hook.URL}
	ts := httptest.NewServer(newMux(s))
	defer ts.Close()
	sec := makeSecret(t)
	body, _ := json.Marshal(map[string]any{"id": sec.id, "ct": sec.ct, "verifier": sec.verifier, "ttl_seconds": 3600})
	req, _ := http.NewRequest("POST", ts.URL+"/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Via", "1.1 zscaler.net")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	select {
	case ev := <-events:
		if ev["event"] != "create_refused" || ev["reasons"] == nil {
			t.Fatalf("unexpected event %v", ev)
		}
		for _, forbidden := range []string{"ct", "auth", "ip"} {
			if _, ok := ev[forbidden]; ok {
				t.Fatalf("alert leaked %s", forbidden)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no webhook event received")
	}
}

// TestStats: events are tallied per day and per "CC|City|asntag"; the ASN tag
// is a keyed hash (stable for the same org, never the org itself), and the
// feed carries only abnormal events.
func TestStats(t *testing.T) {
	ts, _ := newTestServer(t)
	sec := makeSecret(t)
	create(t, ts, sec)
	claimURL := ts.URL + "/api/secrets/" + sec.id + "/claim"
	post(t, claimURL, map[string]string{"auth": "00" + sec.authHex[2:]}) // wrong → claim_wrong
	resp, err := http.Get(ts.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Totals map[string]int            `json:"totals"`
		ByGeo  map[string]map[string]int `json:"by_geo"`
		Feed   []map[string]any          `json:"feed"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Totals["create"] != 1 || out.Totals["claim_wrong"] != 1 {
		t.Fatalf("totals %v", out.Totals)
	}
	if len(out.Feed) != 1 || out.Feed[0]["event"] != "claim_wrong" {
		t.Fatalf("feed %v", out.Feed)
	}
	// ASN tag: keyed, stable across calls, never the org name.
	s := &store{now: time.Now, statsSalt: []byte("k"), trustProxy: true}
	r1, _ := http.NewRequest("POST", "/", nil)
	r1.Header.Set("X-ASN-Org", "Zscaler Inc")
	s.record(r1, "refused", "x")
	s.record(r1, "refused", "x")
	day := s.stats.days[time.Now().UTC().Format("2006-01-02")]
	if len(day.Geo) != 1 {
		t.Fatalf("same org should tally under one tag: %v", day.Geo)
	}
	for g := range day.Geo {
		tag := strings.Split(g, "|")[2]
		if len(tag) != 6 || strings.Contains(strings.ToUpper(g), "ZSCALER") {
			t.Fatalf("asn tag %q leaks or is malformed", g)
		}
	}
}

// TestSweep covers the janitor's work directly: it is what enforces the TTL
// and retires stale rate-limit windows.
func TestSweep(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	s := &store{m: make(map[string]*record), now: clk.Now, rl: make(map[string]*window)}
	s.m["LIVE1"] = &record{expiresAt: clk.Now().Add(time.Hour)}
	s.m["DEAD1"] = &record{expiresAt: clk.Now().Add(-time.Second)}
	s.rl["fresh"] = &window{start: clk.Now(), count: 1}
	s.rl["stale"] = &window{start: clk.Now().Add(-3 * time.Hour), count: 1}

	s.sweep(clk.Now())

	if _, ok := s.m["LIVE1"]; !ok {
		t.Error("sweep dropped a live record")
	}
	if _, ok := s.m["DEAD1"]; ok {
		t.Error("sweep kept an expired record")
	}
	if _, ok := s.rl["fresh"]; !ok {
		t.Error("sweep dropped a fresh rate-limit window")
	}
	if _, ok := s.rl["stale"]; ok {
		t.Error("sweep kept a stale rate-limit window")
	}
	clk.Advance(2 * time.Hour)
	s.sweep(clk.Now())
	if _, ok := s.m["LIVE1"]; ok {
		t.Error("sweep kept a record past its expiry")
	}
}

// TestTakeRejectsOversizedAndNegative: the byte cap is metered with amounts
// derived from the request, so one huge or negative addition must not be able
// to overflow the window or run the counter backwards.
func TestTakeRejectsOversizedAndNegative(t *testing.T) {
	s := &store{rl: make(map[string]*window), now: time.Now}
	now := time.Now()
	const limit = 1 << 20
	if ok, _ := s.take("k", limit, math.MaxInt64, time.Hour, now); ok {
		t.Fatal("accepted an addition larger than the whole window")
	}
	if ok, _ := s.take("k", limit, -1, time.Hour, now); ok {
		t.Fatal("accepted a negative addition")
	}
	if ok, _ := s.take("k", limit, limit, time.Hour, now); !ok {
		t.Fatal("rejected a legitimate full-window addition")
	}
	if ok, _ := s.take("k", limit, 1, time.Hour, now); ok {
		t.Fatal("cap not enforced once the window was full")
	}
}

func TestJanitorStopsOnContextCancel(t *testing.T) {
	s := &store{m: make(map[string]*record), now: time.Now, rl: make(map[string]*window)}
	// Background is the deliberate parent here: the test owns the cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.janitor(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("janitor did not stop when its context was cancelled")
	}
}

func TestClientIP(t *testing.T) {
	r, _ := http.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("X-Real-IP", "203.0.113.1")
	r.Header.Set("X-Forwarded-For", "203.0.113.2, 10.0.0.1")

	if got := (&store{}).clientIP(r); got != "192.0.2.10" {
		t.Errorf("untrusted: got %q, want the socket address 192.0.2.10", got)
	}
	if got := (&store{trustProxy: true}).clientIP(r); got != "203.0.113.1" {
		t.Errorf("trusted: got %q, want X-Real-IP 203.0.113.1", got)
	}
	r.Header.Del("X-Real-IP")
	if got := (&store{trustProxy: true}).clientIP(r); got != "203.0.113.2" {
		t.Errorf("trusted XFF: got %q, want the first hop 203.0.113.2", got)
	}
	r2, _ := http.NewRequest("POST", "/", nil)
	r2.RemoteAddr = "no-port-here"
	if got := (&store{}).clientIP(r2); got != "no-port-here" {
		t.Errorf("unparseable RemoteAddr: got %q, want it returned verbatim", got)
	}
}

func TestModernBrowser(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want bool
	}{
		{"chrome current", "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", true},
		{"chrome ancient", "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.0.0 Safari/537.36", false},
		{"firefox current", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", true},
		{"firefox ancient", "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0", false},
		{"safari current", "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", true},
		{"version overflows int", "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99999999999999999999 Safari/537.36", false},
		{"not a browser", "curl/8.5.0", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := modernBrowser(c.ua); got != c.want {
				t.Errorf("modernBrowser(%q) = %v, want %v", c.ua, got, c.want)
			}
		})
	}
}

func TestGoneEvent(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"claimed", "gone"},
		{"burned", "burned"},
		{"", "unknown"},
		{"some-future-state", "unknown"},
	} {
		if got := goneEvent(c.in); got != c.want {
			t.Errorf("goneEvent(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStaticPageHeaders(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /: %d", resp.StatusCode)
	}
	for _, h := range []string{"Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "Strict-Transport-Security", "Permissions-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Fatalf("missing header %s", h)
		}
	}
}
