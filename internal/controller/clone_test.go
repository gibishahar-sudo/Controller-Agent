package controller

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsPrivateV4(t *testing.T) {
	for ip, want := range map[string]bool{
		"192.168.1.5":   true,
		"10.0.0.9":      true,
		"172.16.0.1":    true,
		"172.31.255.1":  true,
		"127.0.0.1":     true,
		"8.8.8.8":       false,
		"176.229.98.54": false,
		"1.1.1.1":       false,
	} {
		if got := isPrivateV4(net.ParseIP(ip)); got != want {
			t.Fatalf("isPrivateV4(%s) = %v, want %v", ip, got, want)
		}
	}
	if isPrivateV4(net.ParseIP("::1")) {
		t.Fatal("ipv6 ::1 should not count as private v4")
	}
}

func TestHandleCloneRejectsBadIP(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/clone",
		strings.NewReader(`{"ip":"not-an-ip","username":"Administrator","password":"x"}`))
	rec := httptest.NewRecorder()
	s.handleClone(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad ip status = %d, want 400", rec.Code)
	}
}

func TestHandleCloneRejectsPublicIP(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/clone",
		strings.NewReader(`{"ip":"8.8.8.8","username":"Administrator","password":"x"}`))
	rec := httptest.NewRecorder()
	s.handleClone(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("public ip status = %d, want 403", rec.Code)
	}
}

func TestHandleCloneRequiresCreds(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/clone",
		strings.NewReader(`{"ip":"192.168.1.50","username":"","password":""}`))
	rec := httptest.NewRecorder()
	s.handleClone(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty creds status = %d, want 400", rec.Code)
	}
}
