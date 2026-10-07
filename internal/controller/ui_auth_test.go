package controller

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmm/internal/ui"
)

// testAuthServer builds a Server with a known UI password ("s3cret")
// without touching disk or env.
func testAuthServer(t *testing.T) *Server {
	t.Setenv("RMM_UI_PASSWORD", "") // hermetic: live-env branch must not fire
	s := &Server{}
	sum := sha256.Sum256([]byte("s3cret"))
	s.uiPassHash = sum[:]
	if b, err := ui.FS.ReadFile("frontend/login.html"); err == nil {
		s.uiLoginPage = b
	}
	return s
}

func TestUIVerifyPassword(t *testing.T) {
	s := testAuthServer(t)
	if !s.uiVerifyPassword("s3cret") {
		t.Fatal("correct password rejected")
	}
	if s.uiVerifyPassword("wrong") {
		t.Fatal("wrong password accepted")
	}
	if s.uiVerifyPassword("") {
		t.Fatal("empty password accepted")
	}
	// Uninitialized hash must never verify.
	if (&Server{}).uiVerifyPassword("s3cret") {
		t.Fatal("nil hash verified")
	}
}

func TestUISessionLifecycle(t *testing.T) {
	s := testAuthServer(t)
	tok := s.uiIssueSession()
	r := httptest.NewRequest("GET", "/", nil)
	if s.uiAuthed(r) {
		t.Fatal("no-cookie request authed")
	}
	r.AddCookie(&http.Cookie{Name: uiSessionCookie, Value: tok})
	if !s.uiAuthed(r) {
		t.Fatal("fresh session rejected")
	}
	// Expire it manually.
	s.uiSessMu.Lock()
	s.uiSessions[tok] = time.Now().Add(-time.Second)
	s.uiSessMu.Unlock()
	if s.uiAuthed(r) {
		t.Fatal("expired session accepted")
	}
	// Expired entries are purged on read.
	s.uiSessMu.Lock()
	_, still := s.uiSessions[tok]
	s.uiSessMu.Unlock()
	if still {
		t.Fatal("expired session not purged")
	}
}

func TestUILoginBackoff(t *testing.T) {
	s := testAuthServer(t)
	ip := "10.9.9.9"
	login := func(pw string) int {
		body := strings.NewReader(`{"password":"` + pw + `"}`)
		r := httptest.NewRequest("POST", "/api/login", body)
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		s.handleUILogin(w, r)
		return w.Code
	}
	for i := 0; i < uiFailLimit; i++ {
		if code := login("nope"); code != http.StatusUnauthorized {
			t.Fatalf("bad attempt %d: code %d want 401", i, code)
		}
	}
	if code := login("nope"); code != http.StatusTooManyRequests {
		t.Fatalf("6th bad attempt: code %d want 429", code)
	}
	// Correct password during a block still fails.
	if code := login("s3cret"); code != http.StatusTooManyRequests {
		t.Fatalf("good password during block: code %d want 429", code)
	}
	// Success path (fresh server): sets an HttpOnly cookie.
	s2 := testAuthServer(t)
	body := strings.NewReader(`{"password":"s3cret"}`)
	r := httptest.NewRequest("POST", "/api/login", body)
	r.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	s2.handleUILogin(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("good login: code %d want 200", w.Code)
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == uiSessionCookie && c.Value != "" && c.HttpOnly && c.Path == "/" {
			found = true
		}
	}
	if !found {
		t.Fatal("login did not set a proper session cookie")
	}
}

func TestUIGuardMatrix(t *testing.T) {
	s := testAuthServer(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("INNER"))
	})
	g := s.uiGuard(inner)
	doReq := func(method, path, cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: uiSessionCookie, Value: cookie})
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
			r.Host = "ctrl:8080"
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	// Public: login endpoint + login page.
	if w := doReq("POST", "/api/login", "", ""); w.Code == http.StatusUnauthorized && w.Body.String() == "login required\n" {
		t.Fatal("login endpoint gated itself")
	}
	if w := doReq("GET", "/login.html", "", ""); w.Code != http.StatusOK {
		t.Fatalf("login page: code %d want 200", w.Code)
	}
	// Unauthenticated: API/WS get 401, pages get the login document.
	if w := doReq("GET", "/api/files", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("api unauthed: code %d want 401", w.Code)
	}
	if w := doReq("GET", "/ws", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("ws unauthed: code %d want 401", w.Code)
	}
	if w := doReq("GET", "/", "", ""); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "RMM Console") {
		t.Fatalf("root unauthed: code %d, want 401 + login page", w.Code)
	}
	// Public PWA shell: manifest, worker, icons need no session.
	for _, p := range []string{"/manifest.webmanifest", "/sw.js", "/icons/icon-192.png"} {
		if w := doReq("GET", p, "", ""); w.Body.String() != "INNER" {
			t.Fatalf("public %s blocked pre-login", p)
		}
	}
	// Screens stay gated (remote pixels are sensitive).
	if w := doReq("GET", "/screens/x.png", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("screens unauthed: code %d want 401", w.Code)
	}
	// Authenticated: inner serves.
	tok := s.uiIssueSession()
	if w := doReq("GET", "/", tok, ""); w.Body.String() != "INNER" {
		t.Fatal("authed root did not reach inner handler")
	}
	if w := doReq("GET", "/ws", tok, ""); w.Body.String() != "INNER" {
		t.Fatal("authed ws with empty origin blocked (native clients send none)")
	}
	if w := doReq("GET", "/ws", tok, "http://ctrl:8080"); w.Body.String() != "INNER" {
		t.Fatal("authed ws with matching origin blocked")
	}
	if w := doReq("GET", "/ws", tok, "http://evil.test"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin ws: code %d want 403", w.Code)
	}
	// Security headers on every response.
	if w := doReq("GET", "/", "", ""); w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff header")
	}
	if w := doReq("GET", "/", tok, ""); w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatal("missing framing header")
	}
}

func TestUIOriginOK(t *testing.T) {	r := httptest.NewRequest("GET", "/ws", nil)
	r.Host = "ctrl:8080"
	if !uiOriginOK(r) {
		t.Fatal("empty origin rejected")
	}
	r.Header.Set("Origin", "http://ctrl:8080")
	if !uiOriginOK(r) {
		t.Fatal("matching origin rejected")
	}
	r.Header.Set("Origin", "http://evil.test")
	if uiOriginOK(r) {
		t.Fatal("mismatching origin accepted")
	}
	r.Header.Set("Origin", "http://[::1")
	if uiOriginOK(r) {
		t.Fatal("malformed origin accepted")
	}
}

func TestUILiveEnvPassword(t *testing.T) {
	s := &Server{}
	t.Setenv("RMM_UI_PASSWORD", "live-one")
	if !s.uiVerifyPassword("live-one") {
		t.Fatal("live env password rejected")
	}
	// Rotating the env takes effect with no restart and no cache use.
	t.Setenv("RMM_UI_PASSWORD", "live-two")
	if s.uiVerifyPassword("live-one") {
		t.Fatal("stale env password still accepted")
	}
	if !s.uiVerifyPassword("live-two") {
		t.Fatal("rotated env password rejected")
	}
	// End to end over the login handler (cookie set).
	body := strings.NewReader(`{"password":"live-two"}`)
	r := httptest.NewRequest("POST", "/api/login", body)
	r.RemoteAddr = "10.9.9.10:1234"
	w := httptest.NewRecorder()
	s.handleUILogin(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("live env login: code %d want 200", w.Code)
	}
}

func TestUITrimmedLogin(t *testing.T) {
	s := &Server{}
	t.Setenv("RMM_UI_PASSWORD", "s3cret leven")
	login := func(pw string) int {
		body := strings.NewReader(`{"password":"` + pw + `"}`)
		r := httptest.NewRequest("POST", "/api/login", body)
		r.RemoteAddr = "10.9.9.11:1234"
		w := httptest.NewRecorder()
		s.handleUILogin(w, r)
		return w.Code
	}
	// Exact first (intentional space-passwords keep working).
	if code := login("s3cret leven"); code != http.StatusOK {
		t.Fatalf("exact spaced password: code %d want 200", code)
	}
	// Paste artifacts (surrounding spaces) succeed without a strike.
	s2 := &Server{}
	t.Setenv("RMM_UI_PASSWORD", "s3cret")
	body := strings.NewReader(`{"password":"  s3cret  "}`)
	r := httptest.NewRequest("POST", "/api/login", body)
	r.RemoteAddr = "10.9.9.12:1234"
	w := httptest.NewRecorder()
	s2.handleUILogin(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("padded password: code %d want 200", w.Code)
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == uiSessionCookie && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("padded login set no session cookie")
	}
	// Genuinely wrong stays wrong.
	if code := login("nope"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: code %d want 401", code)
	}
}

func TestUIActiveSource(t *testing.T) {
	t.Setenv("RMM_UI_PASSWORD", "whatever")
	if got := uiActiveSource(); got != "RMM_UI_PASSWORD" {
		t.Fatalf("env set: source %q", got)
	}
	t.Setenv("RMM_UI_PASSWORD", "")
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()
	if got := uiActiveSource(); strings.Contains(got, "RMM_UI_PASSWORD") {
		t.Fatalf("env empty: source %q", got)
	}
	// No file anywhere: the none-yet branch (must not generate).
	before, _ := os.ReadDir(dir)
	if got := uiActiveSource(); got == "" || strings.Contains(got, "RMM_UI_PASSWORD") {
		t.Fatalf("nothing configured: source %q", got)
	}
	after, _ := os.ReadDir(dir)
	if len(before) != len(after) {
		t.Fatal("source probe must never generate a password file")
	}
	// A ui_password.txt in CWD wins when env is empty.
	if err := os.WriteFile(filepath.Join(dir, uiPassFile), []byte("f\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := uiActiveSource(); !strings.HasSuffix(got, uiPassFile) {
		t.Fatalf("file present: source %q", got)
	}
}
