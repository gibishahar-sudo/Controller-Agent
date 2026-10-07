package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rmm/internal/ui"
)

// UI login gate (tablet/PWA prerequisite). The console HTTP UI had no
// password: anyone who could reach it controlled every agent. Everything
// here is server-side — the desktop console (index.html and its JS) is
// untouched; a browser just carries the session cookie after one login.
//
// Password source (first hit wins, no new CLI flags by design):
// RMM_UI_PASSWORD env → ui_password.txt beside the exe (or CWD, 0600)
// → generated once, persisted, logged (never the secret itself).
// The env is read live on every attempt (no boot-cache staleness), but the
// OS rule still applies: a process inherits its environment ONCE at spawn,
// so a new/changed user variable needs a controller restart to arrive.
// File/generated passwords use the cached hash.
// Sessions: 32-byte random tokens, 12h fixed TTL, server-side store.
// Brute force: 5 bad passwords per source IP → 5-minute block (429).
// Sessions: 32-byte random tokens, 12h fixed TTL, server-side store.
// Brute force: 5 bad passwords per source IP → 5-minute block (429).

const (
	uiSessionCookie = "rmm_ui"
	uiSessionTTL    = 12 * time.Hour
	uiPassFile      = "ui_password.txt"
	uiFailLimit     = 5
	uiFailBlock     = 5 * time.Minute
)

type uiFailRec struct {
	n     int
	until time.Time
}

// initUIAuth resolves the UI password and caches the login page. Called
// once from startHTTP; safe to call in tests on a bare &Server{}.
func (s *Server) initUIAuth() {
	s.uiSessMu.Lock()
	if s.uiSessions == nil {
		s.uiSessions = map[string]time.Time{}
	}
	s.uiSessMu.Unlock()
	s.uiFailMu.Lock()
	if s.uiFails == nil {
		s.uiFails = map[string]uiFailRec{}
	}
	s.uiFailMu.Unlock()
	pw, src := uiResolvePassword()
	sum := sha256.Sum256([]byte(pw))
	s.uiPassMu.Lock()
	s.uiPassHash = sum[:]
	s.uiPassMu.Unlock()
	if b, err := ui.FS.ReadFile("frontend/login.html"); err == nil {
		s.uiLoginPage = b
	} else {
		log.Printf("[http] login page missing from bundle: %v", err)
	}
	log.Printf("[http] UI login required (password from %s)", src)
}

// uiResolvePassword returns (password, source-description).
func uiResolvePassword() (string, string) {
	if pw := os.Getenv("RMM_UI_PASSWORD"); pw != "" {
		return pw, "RMM_UI_PASSWORD"
	}
	cands := []string{uiPassFile}
	if exe, err := os.Executable(); err == nil {
		cands = append([]string{filepath.Join(filepath.Dir(exe), uiPassFile)}, cands...)
	}
	for _, p := range cands {
		if b, err := os.ReadFile(p); err == nil {
			if pw := string(b); len(pw) > 0 {
				// Trim a single trailing newline; a password that IS a
				// newline is not a password anyone meant.
				for len(pw) > 0 && (pw[len(pw)-1] == '\n' || pw[len(pw)-1] == '\r') {
					pw = pw[:len(pw)-1]
				}
				if pw != "" {
					return pw, p
				}
			}
		}
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		// Practically unreachable; fall back to time-mixed bytes rather
		// than an empty password (which would lock everyone out — or
		// worse, read as "no password").
		sum := sha256.Sum256([]byte(time.Now().String()))
		raw = sum[:16]
	}
	pw := hex.EncodeToString(raw)
	save := cands[0]
	if err := os.WriteFile(save, []byte(pw+"\n"), 0600); err != nil {
		save = uiPassFile
		_ = os.WriteFile(save, []byte(pw+"\n"), 0600)
	}
	log.Printf("[http] generated UI password (saved to %s) — set RMM_UI_PASSWORD to override", save)
	return pw, "generated " + save
}

// uiActiveSource names the winning password source WITHOUT side effects
// (unlike uiResolvePassword, it never generates+saves). Local logs only —
// never sent to any client. Exists so the next "correct password rejected"
// is a one-line log read instead of an investigation.
func uiActiveSource() string {
	if os.Getenv("RMM_UI_PASSWORD") != "" {
		return "RMM_UI_PASSWORD"
	}
	cands := []string{uiPassFile}
	if exe, err := os.Executable(); err == nil {
		cands = append([]string{filepath.Join(filepath.Dir(exe), uiPassFile)}, cands...)
	}
	for _, p := range cands {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "none-yet (generated at boot)"
}

// uiVerifyPassword constant-time compares the candidate. The env password
// is read live (no boot-cache staleness); file/generated passwords use the
// cached hash. Process environment still arrives once at spawn — see header.
func (s *Server) uiVerifyPassword(candidate string) bool {
	if pw := os.Getenv("RMM_UI_PASSWORD"); pw != "" {
		a := sha256.Sum256([]byte(candidate))
		b := sha256.Sum256([]byte(pw))
		return subtle.ConstantTimeCompare(a[:], b[:]) == 1
	}
	sum := sha256.Sum256([]byte(candidate))
	s.uiPassMu.Lock()
	defer s.uiPassMu.Unlock()
	if len(s.uiPassHash) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(sum[:], s.uiPassHash) == 1
}

// uiAuthed reports whether the request carries a live session.
func (s *Server) uiAuthed(r *http.Request) bool {
	c, err := r.Cookie(uiSessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	now := time.Now()
	s.uiSessMu.Lock()
	defer s.uiSessMu.Unlock()
	exp, ok := s.uiSessions[c.Value]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(s.uiSessions, c.Value)
		return false
	}
	return true
}

// uiIssueSession mints a token valid for uiSessionTTL.
func (s *Server) uiIssueSession() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		sum := sha256.Sum256([]byte(time.Now().String()))
		copy(raw, sum[:])
	}
	tok := hex.EncodeToString(raw)
	s.uiSessMu.Lock()
	if s.uiSessions == nil {
		s.uiSessions = map[string]time.Time{}
	}
	// Opportunistic purge so the map cannot grow forever.
	now := time.Now()
	for k, exp := range s.uiSessions {
		if now.After(exp) {
			delete(s.uiSessions, k)
		}
	}
	s.uiSessions[tok] = now.Add(uiSessionTTL)
	s.uiSessMu.Unlock()
	return tok
}

// uiClientIP keys brute-force backoff (RemoteAddr as seen; behind a
// tunnel all clients may share it — backoff still slows guessing).
func uiClientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// uiBlocked reports whether ip is inside a backoff block.
func (s *Server) uiBlocked(ip string) bool {
	s.uiFailMu.Lock()
	defer s.uiFailMu.Unlock()
	rec, ok := s.uiFails[ip]
	if !ok {
		return false
	}
	if time.Now().Before(rec.until) {
		return true
	}
	if rec.n >= uiFailLimit {
		delete(s.uiFails, ip) // block served; the next streak counts fresh
	}
	return false
}

// uiFail records one bad password; resets on success via uiFailReset.
// The block start is logged (one line per block, not per attempt).
func (s *Server) uiFail(ip string) {
	s.uiFailMu.Lock()
	defer s.uiFailMu.Unlock()
	if s.uiFails == nil {
		s.uiFails = map[string]uiFailRec{}
	}
	rec := s.uiFails[ip]
	rec.n++
	blocked := false
	if rec.n >= uiFailLimit && time.Now().After(rec.until) {
		blocked = true
	}
	if rec.n >= uiFailLimit {
		rec.until = time.Now().Add(uiFailBlock)
	}
	s.uiFails[ip] = rec
	if blocked {
		log.Printf("[http] login blocked for %s (%d bad passwords, %s)", ip, rec.n, uiFailBlock)
	}
}

func (s *Server) uiFailReset(ip string) {
	s.uiFailMu.Lock()
	defer s.uiFailMu.Unlock()
	delete(s.uiFails, ip)
}

// handleUILogin exchanges the UI password for a session cookie.
func (s *Server) handleUILogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	ip := uiClientIP(r)
	if s.uiBlocked(ip) {
		http.Error(w, "too many attempts, try later", http.StatusTooManyRequests)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad json: need {\"password\":\"...\"}", http.StatusBadRequest)
		return
	}
	// Paste artifacts (stray spaces from password managers) fail an
	// otherwise-correct password; retry trimmed before counting a strike.
	// Intentional space-padded passwords still match on the first try.
	if !s.uiVerifyPassword(req.Password) {
		if trimmed := strings.TrimSpace(req.Password); trimmed != req.Password && s.uiVerifyPassword(trimmed) {
			s.uiFailReset(ip)
			s.uiIssueSessionCookie(w, r)
			return
		}
		s.uiFail(ip)
		log.Printf("[http] login failed for %s (password from %s)", ip, uiActiveSource())
		http.Error(w, "bad password", http.StatusUnauthorized)
		return
	}
	s.uiFailReset(ip)
	s.uiIssueSessionCookie(w, r)
}

// uiIssueSessionCookie mints a session and sets the cookie (shared by the
// exact and trimmed-space login paths).
func (s *Server) uiIssueSessionCookie(w http.ResponseWriter, r *http.Request) {
	tok := s.uiIssueSession()
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((uiSessionTTL).Seconds()),
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleUILogout drops the session.
func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(uiSessionCookie); err == nil && c.Value != "" {
		s.uiSessMu.Lock()
		delete(s.uiSessions, c.Value)
		s.uiSessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: uiSessionCookie, Value: "", Path: "/", MaxAge: -1})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// uiMaybeTLS wraps ln in TLS when both PEM paths are set. Unset pair →
// plain HTTP; set-but-broken → plain HTTP with a loud log (an explicit
// request that silently downgraded would be worse than refusing loudly
// into the log the operator already watches).
func uiMaybeTLS(ln net.Listener, certFile, keyFile string) (net.Listener, string) {
	if certFile == "" || keyFile == "" {
		return ln, "http"
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("[http] RMM_UI_TLS_CERT/KEY invalid (%v) — serving plain HTTP", err)
		return ln, "http"
	}
	return tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), "https"
}

// uiOriginOK rejects cross-site WebSocket hijacks. Empty Origin (native
// clients, curl) passes — only a *mismatching* browser Origin fails.
func uiOriginOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Host == r.Host
}

// uiPublic reports whether path is servable pre-login: the login
// endpoint + page, and the PWA shell (manifest, worker, icons —
// branding only, zero sensitivity). Everything else needs a session,
// notably /screens/ (remote pixels) and all of /api/.
func uiPublic(path string) bool {
	if path == "/api/login" || path == "/api/logout" || path == "/login.html" {
		return true
	}
	if path == "/manifest.webmanifest" || path == "/sw.js" {
		return true
	}
	return strings.HasPrefix(path, "/icons/")
}

// uiGuard fronts the whole console mux: login endpoint + login page stay
// public; everything else needs a live session. Unauthenticated page
// navigations get the login page itself (so the desktop browser and the
// future PWA just land on login), API/WS get 401.
func (s *Server) uiGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if uiPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if !s.uiAuthed(r) {
			if r.URL.Path == "/ws" || strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "login required", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(s.uiLoginPage)
			return
		}
		if r.URL.Path == "/ws" && !uiOriginOK(r) {
			http.Error(w, "bad origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
