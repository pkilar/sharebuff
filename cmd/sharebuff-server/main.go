// sharebuff-server is the self-hosted fallback: the same HTTP API as the
// Cloudflare Worker (docs/SPEC.md), backed by an in-memory store, serving the
// same embedded static retrieve page. Run it behind any TLS proxy.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sourcefrenchy/sharebuff/internal/wire"
	"github.com/sourcefrenchy/sharebuff/web"
)

var (
	idRe  = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{5}$`) // a v4 locator
	hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type record struct {
	ct            []byte
	verifier      [32]byte
	attempts      int
	expiresAt     time.Time
	nextAllowedAt time.Time
	gone          string // "", "claimed", "burned"
}

type store struct {
	mu         sync.Mutex
	m          map[string]*record
	maxTTL     time.Duration
	now        func() time.Time
	allowShare bool
	enforce    bool // refuse creation on corporate signals (not just report them)

	// Per-IP fixed-window rate limits (requests per minute); 0 disables.
	createRPM, claimRPM int
	// Per-IP hourly create caps (bulk dead-drop guard); 0 disables.
	createPerHour   int
	createBytesHour int64
	trustProxy      bool // honour X-Real-IP / X-Forwarded-For for the client IP
	rl              map[string]*window
	alertWebhook    string

	stats     *stats
	statsSalt []byte
}

// stats is the in-memory counterpart of the Worker's Stats object: per-day
// tallies by event and by "CC|City|asntag", plus a short recent-events feed.
// Country/city come from CF-IPCountry / CF-IPCity headers when a Cloudflare
// proxy fronts the server, otherwise "??"; the ASN tag is HMAC(salt, org)
// when an X-ASN-Org header is supplied, otherwise "—".
type stats struct {
	days map[string]*statDay
	feed []statEvent
}
type statDay struct {
	Totals map[string]int            `json:"totals"`
	Geo    map[string]map[string]int `json:"geo"`
}
type statEvent struct {
	T      string `json:"t"`
	Event  string `json:"event"`
	CC     string `json:"cc"`
	City   string `json:"city"`
	ASN    string `json:"asn"`
	Reason string `json:"reason,omitempty"`
}

const statsDays = 30

// record tallies an event. Caller must NOT hold s.mu (it locks itself).
func (s *store) record(r *http.Request, event, reason string) {
	// Geo/ASN headers only mean anything when a proxy we control sets them;
	// otherwise any client can poison the public /api/stats feed.
	cc, city, asn := "??", "—", "—"
	if s.trustProxy {
		if v := r.Header.Get("CF-IPCountry"); v != "" {
			cc = v
		}
		if v := r.Header.Get("CF-IPCity"); v != "" {
			city = v
		}
		if org := r.Header.Get("X-ASN-Org"); org != "" && len(s.statsSalt) > 0 {
			mac := hmac.New(sha256.New, s.statsSalt)
			mac.Write([]byte(strings.ToUpper(org)))
			asn = hex.EncodeToString(mac.Sum(nil)[:3])
		}
	}
	now := s.now().UTC()
	day := now.Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stats == nil {
		s.stats = &stats{days: map[string]*statDay{}}
	}
	d := s.stats.days[day]
	if d == nil {
		d = &statDay{Totals: map[string]int{}, Geo: map[string]map[string]int{}}
		s.stats.days[day] = d
	}
	d.Totals[event]++
	g := cc + "|" + city + "|" + asn
	if d.Geo[g] == nil {
		d.Geo[g] = map[string]int{}
	}
	d.Geo[g][event]++
	if event != "create" && event != "claim_ok" {
		s.stats.feed = append([]statEvent{{T: now.Format("2006-01-02T15:04Z"), Event: event, CC: cc, City: city, ASN: asn, Reason: reason}}, s.stats.feed...)
		if len(s.stats.feed) > 60 {
			s.stats.feed = s.stats.feed[:60]
		}
	}
	cutoff := now.AddDate(0, 0, -statsDays).Format("2006-01-02")
	for k := range s.stats.days {
		if k < cutoff {
			delete(s.stats.days, k)
		}
	}
}

func (s *store) statsHandler(w http.ResponseWriter, r *http.Request) {
	totals := map[string]int{}
	byDay := map[string]map[string]int{}
	byGeo := map[string]map[string]int{}
	feed := []statEvent{}
	// Copy every map out under the lock: the response is encoded after it is
	// released, and record/sweep keep mutating the originals.
	s.mu.Lock()
	if s.stats != nil {
		for day, d := range s.stats.days {
			dayTotals := make(map[string]int, len(d.Totals))
			for e, n := range d.Totals {
				dayTotals[e] = n
				totals[e] += n
			}
			byDay[day] = dayTotals
			for g, counts := range d.Geo {
				if byGeo[g] == nil {
					byGeo[g] = map[string]int{}
				}
				for e, n := range counts {
					byGeo[g][e] += n
				}
			}
		}
		feed = append(feed, s.stats.feed...)
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(map[string]any{"days": statsDays, "totals": totals, "by_day": byDay, "by_geo": byGeo, "feed": feed})
}

type window struct {
	start time.Time
	count int64
}

// clientIP returns the address used for rate limiting.
func (s *store) clientIP(r *http.Request) string {
	if s.trustProxy {
		if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// take applies a fixed window of max units per period for key, adding add
// units. Returns ok=false with the seconds to wait when the window is full.
// Caller must hold s.mu.
func (s *store) take(key string, max, add int64, period time.Duration, now time.Time) (ok bool, retryAfter int) {
	if max <= 0 {
		return true, 0
	}
	// One request must never exceed the whole window, and a negative addition
	// must never widen it: either would defeat the cap outright.
	if add < 0 || add > max {
		return false, int(period/time.Second) + 1
	}
	w := s.rl[key]
	if w == nil || now.Sub(w.start) >= period {
		s.rl[key] = &window{start: now, count: add}
		return true, 0
	}
	if w.count+add > max {
		return false, int((period-now.Sub(w.start))/time.Second) + 1
	}
	w.count += add
	return true, 0
}

// allow applies the per-minute request limit for a bucket.
func (s *store) allow(bucket, ip string, rpm int, now time.Time) (bool, int) {
	return s.take(bucket+"|"+ip, int64(rpm), 1, time.Minute, now)
}

// allowCount applies the hourly create-count cap. It is charged before the
// body is read, so an exhausted quota costs no ingress.
func (s *store) allowCount(ip string, now time.Time) (ok bool, retryAfter int, limit string) {
	if ok, retry := s.take("createh|"+ip, int64(s.createPerHour), 1, time.Hour, now); !ok {
		return false, retry, "per_hour"
	}
	return true, 0, ""
}

// allowBytes charges the hourly upload-byte cap. Only this one has to wait for
// the body, because only it needs the real length.
func (s *store) allowBytes(ip string, bytes int64, now time.Time) (ok bool, retryAfter int) {
	return s.take("createb|"+ip, s.createBytesHour, bytes, time.Hour, now)
}

// alertClient is shared: alerts fire exactly when the server is busiest, so
// that is the wrong moment to build a fresh client and connection pool.
var alertClient = &http.Client{Timeout: 5 * time.Second}

// alert emits a structured event to the log and, if configured, to the
// webhook. Never includes payloads, proofs, or client IPs.
func (s *store) alert(event string, fields map[string]any) {
	fields["event"] = event
	fields["ts"] = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(fields)
	log.Printf("alert %s", b)
	if s.alertWebhook != "" {
		go func() {
			resp, err := alertClient.Post(s.alertWebhook, "application/json", bytes.NewReader(b))
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
}

// proxyHeaders are added by corporate secure web gateways / TLS-intercepting
// proxies; their presence hides the browser Share tab (docs/SECURITY.md).
var proxyHeaders = []string{"Via", "X-Bluecoat-Via", "X-Zscaler-Ip", "X-Zscaler-User", "X-Netskope-User", "Proxy-Authorization"}

var (
	chromeRe  = regexp.MustCompile(`(?:Chrome|CriOS|Chromium)/(\d+)`)
	firefoxRe = regexp.MustCompile(`Firefox/(\d+)`)
	safariRe  = regexp.MustCompile(`Version/(\d+)[\d.]* .*Safari/`)
)

// modernBrowser reports whether ua is a current browser, which would normally
// speak HTTP/2+; seeing one over HTTP/1.x suggests a TLS-intercepting proxy.
func modernBrowser(ua string) bool {
	atLeast := func(re *regexp.Regexp, minVersion int) (bool, bool) {
		m := re.FindStringSubmatch(ua)
		if m == nil {
			return false, false
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return true, false
		}
		return true, v >= minVersion
	}
	if ok, modern := atLeast(chromeRe, 90); ok {
		return modern
	}
	if ok, modern := atLeast(firefoxRe, 90); ok {
		return modern
	}
	if ok, modern := atLeast(safariRe, 14); ok {
		return modern
	}
	return false
}

// signals lists the corporate-environment tells visible on this request.
func (s *store) signals(r *http.Request) []string {
	var reasons []string
	if !s.allowShare {
		reasons = append(reasons, "sharing disabled by the server operator")
	}
	if r.ProtoMajor == 1 && modernBrowser(r.UserAgent()) {
		reasons = append(reasons, "modern browser arriving over "+r.Proto+" (TLS-intercepting proxy suspected)")
	}
	if p := strings.ToLower(r.Header.Get("X-Sharebuff-Policy")); strings.Contains(p, "retrieve-only") || strings.Contains(p, "no-share") {
		reasons = append(reasons, "organization policy header")
	}
	for _, h := range proxyHeaders {
		if r.Header.Get(h) != "" {
			reasons = append(reasons, "proxy header "+strings.ToLower(h))
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); strings.Count(xff, ",") >= 1 {
		reasons = append(reasons, "forwarded through a proxy")
	}
	if reasons == nil {
		reasons = []string{}
	}
	return reasons
}

// environment reports whether the page may offer browser-side sharing.
func (s *store) environment(w http.ResponseWriter, r *http.Request) {
	reasons := s.signals(r)
	writeJSON(w, http.StatusOK, map[string]any{"share": len(reasons) == 0, "reasons": reasons})
}

// goneEvent maps a tombstone reason to its stats event suffix.
func goneEvent(gone string) string {
	switch gone {
	case "claimed":
		return "gone"
	case "burned":
		return "burned"
	default:
		return "unknown"
	}
}

// cooldown returns the wait imposed after the n-th counted wrong attempt.
func cooldown(attempts int) time.Duration {
	if attempts >= 30 || 1<<attempts > wire.CooldownMaxSeconds {
		return wire.CooldownMaxSeconds * time.Second
	}
	return time.Duration(1<<attempts) * time.Second
}

// sweep drops expired records and stale rate-limit windows.
func (s *store) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.m {
		if now.After(r.expiresAt) {
			delete(s.m, id)
		}
	}
	for k, w := range s.rl {
		if now.Sub(w.start) >= 2*time.Hour {
			delete(s.rl, k)
		}
	}
}

// janitor sweeps once a minute until ctx is cancelled.
func (s *store) janitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep(s.now())
		}
	}
}

// serve runs srv until ctx is cancelled, then waits for in-flight requests to
// drain. Shutdown makes Serve return ErrServerClosed immediately, so returning
// on that alone would exit while handlers are still writing -- and a claim is
// tombstoned before its ciphertext is sent, so a truncated response destroys
// the only copy.
func serve(ctx context.Context, srv *http.Server, ln net.Listener, grace time.Duration) error {
	drained := make(chan error, 1)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		drained <- srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return <-drained
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *store) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string `json:"id"`
		CT         string `json:"ct"`
		Verifier   string `json:"verifier"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	// Server-side enforcement: a patched page or curl gets the same answer.
	if s.enforce {
		if reasons := s.signals(r); len(reasons) > 0 {
			s.alert("create_refused", map[string]any{"reasons": reasons, "ua": r.UserAgent()})
			s.record(r, "refused", reasons[0])
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "sharing is disabled on this network", "reasons": reasons})
			return
		}
	}
	ip := s.clientIP(r)
	// Both of these are cheap and unspoofable, so they run before the body is
	// read: an IP that is already out of quota must not be able to make the
	// server buffer 32 MiB first.
	s.mu.Lock()
	ok, retry := s.allow("create", ip, s.createRPM, s.now())
	limit := "per_minute"
	if ok {
		ok, retry, limit = s.allowCount(ip, s.now())
	}
	s.mu.Unlock()
	if !ok {
		event := "rate_limited"
		if limit != "per_minute" {
			event = "volume_limited"
		}
		s.alert(event, map[string]any{"bucket": "create", "limit": limit})
		s.record(r, event, limit)
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many requests", "retry_after_seconds": retry})
		return
	}
	// Blob cap is ~20 MiB; base64 (+33%) plus JSON framing fits in 32 MiB.
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	// Charge the bytes that actually arrived, including on a truncated read --
	// an aborted upload still consumed the ingress, so leaving it uncharged
	// would make it a free channel. r.ContentLength is client-declared and is
	// never what gets metered.
	s.mu.Lock()
	volOK, volRetry := s.allowBytes(ip, int64(len(body)), s.now())
	s.mu.Unlock()
	if err != nil {
		errJSON(w, http.StatusBadRequest, "malformed body")
		return
	}
	if !volOK {
		s.alert("volume_limited", map[string]any{"bucket": "create", "limit": "bytes_per_hour"})
		s.record(r, "volume_limited", "bytes_per_hour")
		w.Header().Set("Retry-After", strconv.Itoa(volRetry))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many requests", "retry_after_seconds": volRetry})
		return
	}
	if json.Unmarshal(body, &req) != nil {
		errJSON(w, http.StatusBadRequest, "malformed body")
		return
	}
	if !idRe.MatchString(req.ID) || !hexRe.MatchString(req.Verifier) {
		errJSON(w, http.StatusBadRequest, "malformed id or verifier")
		return
	}
	if req.TTLSeconds == 0 {
		req.TTLSeconds = wire.DefaultTTLSeconds
	}
	if req.TTLSeconds < wire.MinTTLSeconds || req.TTLSeconds > int64(s.maxTTL.Seconds()) {
		errJSON(w, http.StatusBadRequest, "ttl out of range")
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.CT)
	if err != nil || len(ct) < wire.NonceLen+16 {
		errJSON(w, http.StatusBadRequest, "malformed ciphertext")
		return
	}
	if len(ct) > wire.MaxBlob {
		errJSON(w, http.StatusRequestEntityTooLarge, "ciphertext too large")
		return
	}
	verifier, _ := hex.DecodeString(req.Verifier)
	rec := &record{ct: ct, expiresAt: s.now().Add(time.Duration(req.TTLSeconds) * time.Second)}
	copy(rec.verifier[:], verifier)

	s.mu.Lock()
	_, exists := s.m[req.ID]
	if !exists {
		s.m[req.ID] = rec
	}
	s.mu.Unlock()
	if exists {
		errJSON(w, http.StatusConflict, "id already exists")
		return
	}
	s.record(r, "create", "")
	writeJSON(w, http.StatusCreated, map[string]int64{"expires_at": rec.expiresAt.Unix()})
}

func (s *store) claim(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Auth string `json:"auth"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil || json.Unmarshal(body, &req) != nil || !idRe.MatchString(id) || !hexRe.MatchString(req.Auth) {
		errJSON(w, http.StatusBadRequest, "malformed request")
		return
	}
	authBytes, _ := hex.DecodeString(req.Auth)
	sum := sha256.Sum256(authBytes)

	// Every branch below decides and mutates under the lock, then releases it
	// before alerting, recording or writing. s.mu guards every handler and the
	// janitor, so a slow reader must never be able to hold it across a Write.
	s.mu.Lock()
	now := s.now()
	if ok, retry := s.allow("claim", s.clientIP(r), s.claimRPM, now); !ok {
		s.mu.Unlock()
		s.alert("rate_limited", map[string]any{"bucket": "claim"})
		s.record(r, "rate_limited", "claim")
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many requests", "retry_after_seconds": retry})
		return
	}
	rec, ok := s.m[id]
	if !ok || now.After(rec.expiresAt) {
		delete(s.m, id)
		s.mu.Unlock()
		s.record(r, "claim_missing", "")
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	if rec.gone != "" {
		gone := rec.gone
		s.mu.Unlock()
		s.record(r, "claim_"+goneEvent(gone), "")
		writeJSON(w, http.StatusGone, map[string]string{"reason": gone})
		return
	}
	// Cooldown gate: rejected before the proof is examined, and NOT counted —
	// hammering can neither brute-force the PIN nor burn the secret.
	if now.Before(rec.nextAllowedAt) {
		retry := int64(rec.nextAllowedAt.Sub(now).Seconds()) + 1
		s.mu.Unlock()
		w.Header().Set("Retry-After", strconv.FormatInt(retry, 10))
		writeJSON(w, http.StatusTooManyRequests, map[string]int64{"retry_after_seconds": retry})
		return
	}
	if subtle.ConstantTimeCompare(sum[:], rec.verifier[:]) != 1 {
		rec.attempts++
		rec.nextAllowedAt = now.Add(cooldown(rec.attempts))
		attempts := rec.attempts
		if attempts >= wire.MaxAttempts {
			// Burn: keep only a tombstone until the original expiry.
			s.m[id] = &record{gone: "burned", expiresAt: rec.expiresAt}
			s.mu.Unlock()
			s.alert("secret_burned", map[string]any{"locator": id})
			s.record(r, "claim_burned", "")
			writeJSON(w, http.StatusGone, map[string]string{"reason": "burned"})
			return
		}
		s.mu.Unlock()
		s.record(r, "claim_wrong", "")
		writeJSON(w, http.StatusForbidden, map[string]int{"attempts_left": wire.MaxAttempts - attempts})
		return
	}
	// Valid claim: destroy before responding; exactly one caller can get here.
	ct := rec.ct
	s.m[id] = &record{gone: "claimed", expiresAt: rec.expiresAt}
	s.mu.Unlock()
	s.record(r, "claim_ok", "")
	writeJSON(w, http.StatusOK, map[string]string{"ct": base64.StdEncoding.EncodeToString(ct)})
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(web.FS, ".")
	if err != nil {
		log.Fatal(err)
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
}

func newMux(s *store) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/secrets", s.create)
	mux.HandleFunc("POST /api/secrets/{id}/claim", s.claim)
	mux.HandleFunc("GET /api/env", s.environment)
	mux.HandleFunc("GET /api/stats", s.statsHandler)
	mux.Handle("GET /", staticHandler())
	return mux
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8091", "listen address")
	maxTTL := flag.Duration("max-ttl", 168*time.Hour, "maximum secret TTL")
	share := flag.Bool("share", true, "allow creating secrets at all (false = retrieve-only server)")
	enforce := flag.Bool("enforce", true, "refuse creation on corporate-network signals (proxy headers, HTTP/1.x from a modern browser); false = report only via /api/env")
	createRPM := flag.Int("create-rpm", 10, "per-IP creates per minute (0 = unlimited)")
	claimRPM := flag.Int("claim-rpm", 30, "per-IP claims per minute (0 = unlimited)")
	createPerHour := flag.Int("create-per-hour", 60, "per-IP creates per hour (0 = unlimited)")
	mibPerHour := flag.Int("mib-per-hour", 256, "per-IP upload MiB per hour (0 = unlimited)")
	trustProxy := flag.Bool("trust-proxy-headers", false, "use X-Real-IP / X-Forwarded-For as the client IP (only behind a proxy you control)")
	alertWebhook := flag.String("alert-webhook", "", "POST JSON alert events (create_refused, secret_burned, rate_limited) to this URL")
	statsSalt := flag.String("stats-salt", "", "HMAC key for the ASN tag in /api/stats (random per process if empty)")
	flag.Parse()
	salt := []byte(*statsSalt)
	if len(salt) == 0 {
		salt = make([]byte, 32)
		_, _ = rand.Read(salt)
	}

	s := &store{m: make(map[string]*record), maxTTL: *maxTTL, now: time.Now, allowShare: *share, enforce: *enforce,
		createRPM: *createRPM, claimRPM: *claimRPM, createPerHour: *createPerHour, createBytesHour: int64(*mibPerHour) << 20,
		trustProxy: *trustProxy, rl: make(map[string]*window), alertWebhook: *alertWebhook, statsSalt: salt}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go s.janitor(ctx)
	mux := newMux(s)

	log.Printf("sharebuff-server listening on %s (max TTL %s)", *addr, *maxTTL)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Minute, // ~27 MB uploads on slow links
		WriteTimeout:      5 * time.Minute,
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	// A second signal kills immediately rather than waiting out the drain.
	go func() {
		<-ctx.Done()
		stop()
	}()
	if err := serve(ctx, srv, ln, 30*time.Second); err != nil {
		log.Fatal(err)
	}
}
