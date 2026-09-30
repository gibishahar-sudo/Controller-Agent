package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUIMaybeTLSOff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback: " + err.Error())
	}
	defer ln.Close()
	if out, scheme := uiMaybeTLS(ln, "", ""); out != ln || scheme != "http" {
		t.Fatal("unset pair must pass through as http")
	}
	if out, scheme := uiMaybeTLS(ln, "/nope/cert", "/nope/key"); out != ln || scheme != "http" {
		t.Fatal("missing files must fall back to http")
	}
}

// TestUIMaybeTLSOn generates a throwaway CA-less server cert, wraps a
// listener, and completes a real HTTPS handshake against it.
func TestUIMaybeTLSOn(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rmm-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	kf.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback: " + err.Error())
	}
	wrapped, scheme := uiMaybeTLS(ln, certPath, keyPath)
	if scheme != "https" {
		t.Fatal("valid pair must yield https")
	}
	defer wrapped.Close()
	go func() {
		_ = http.Serve(wrapped, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Write([]byte("TLS-OK"))
		}))
	}()
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := cl.Get("https://" + wrapped.Addr().String() + "/")
	if err != nil {
		t.Fatalf("https handshake failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "TLS-OK" {
		t.Fatalf("unexpected body %q", body)
	}
}
