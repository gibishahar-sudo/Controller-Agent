package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	outDir := flag.String("out", "certs", "output directory for certs")
	cn := flag.String("cn", "localhost", "common name")
	days := flag.Int("days", 365, "validity in days")
	ipFlag := flag.String("ip", "", "extra IP SAN (e.g. public IP, repeatable via comma)")
	autoLAN := flag.Bool("lan", true, "auto-add local LAN IPv4 addresses as SANs")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   *cn,
			Organization: []string{"RMM"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", *cn},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	seenIP := map[string]bool{"127.0.0.1": true}
	addIP := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seenIP[s] {
			return
		}
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			seenIP[s] = true
		}
	}
	for _, s := range strings.Split(*ipFlag, ",") {
		addIP(s)
	}
	if *autoLAN {
		if ifaces, err := net.Interfaces(); err == nil {
			for _, iface := range ifaces {
				if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
					continue
				}
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}
				for _, a := range addrs {
					var ip net.IP
					switch v := a.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip == nil || ip.IsLoopback() || ip.To4() == nil {
						continue
					}
					addIP(ip.String())
				}
			}
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}

	certPath := filepath.Join(*outDir, "server.crt")
	keyPath := filepath.Join(*outDir, "server.key")

	certFile, err := os.Create(certPath)
	if err != nil {
		log.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		log.Fatalf("pem cert: %v", err)
	}
	certFile.Close()

	keyFile, err := os.Create(keyPath)
	if err != nil {
		log.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		log.Fatalf("pem key: %v", err)
	}
	keyFile.Close()

	fmt.Printf("Generated %s and %s\n", certPath, keyPath)
	fmt.Printf("  CN=%s  Valid %d days  SANs: %v %v\n", *cn, *days, tmpl.DNSNames, tmpl.IPAddresses)
	fmt.Printf("  Distribute server.crt to agents (RootCA). Keep server.key on controller only.\n")
}
