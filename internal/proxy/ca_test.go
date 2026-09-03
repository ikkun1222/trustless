package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateCA_CreatesCertAndKeyFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := CAConfig{
		CertPath: filepath.Join(dir, "ca.crt"),
		KeyPath:  filepath.Join(dir, "ca.key"),
	}

	ca, err := GenerateCA(cfg)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		t.Fatal("GenerateCA returned incomplete CA")
	}

	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("cert file contains no PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("cert PEM type = %q, want CERTIFICATE", block.Type)
	}

	keyPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("key file contains no PEM block")
	}

	fi, err := os.Stat(cfg.KeyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("CA key mode = %04o, want 0600 (private key must not be world-readable)", perm)
	}
}

func TestGenerateCA_CertIsRootCA(t *testing.T) {
	cfg := CAConfig{CertPath: filepath.Join(t.TempDir(), "ca.crt"), KeyPath: filepath.Join(t.TempDir(), "ca.key")}
	ca, err := GenerateCA(cfg)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	c := ca.Cert
	if !c.IsCA {
		t.Fatal("cert is not marked as CA")
	}
	if !c.BasicConstraintsValid {
		t.Fatal("basic constraints not valid")
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("cert lacks CertSign key usage")
	}
	if got := c.Subject.CommonName; got != "trustless MITM Proxy CA" {
		t.Fatalf("CN = %q, want %q", got, "trustless MITM Proxy CA")
	}
	if !c.NotAfter.After(c.NotBefore.Add(9 * 365 * 24 * time.Hour)) { // ~10y validity
		t.Fatalf("CA validity too short: %v -> %v", c.NotBefore, c.NotAfter)
	}
}

func TestLoadOrGenerateCA_LoadsExistingCA(t *testing.T) {
	dir := t.TempDir()
	cfg := CAConfig{CertPath: filepath.Join(dir, "ca.crt"), KeyPath: filepath.Join(dir, "ca.key")}

	first, err := GenerateCA(cfg)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Second call must reuse the on-disk CA, not regenerate a new one.
	second, err := LoadOrGenerateCA(cfg)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if string(first.Cert.Raw) != string(second.Cert.Raw) {
		t.Fatal("LoadOrGenerateCA regenerated a different CA instead of loading the existing one")
	}

	// The loaded CA must still be able to sign verifiable leaf certs.
	leaf, err := second.LeafCert("api.example.com")
	if err != nil {
		t.Fatalf("LeafCert from loaded CA: %v", err)
	}
	verifyLeaf(t, leaf, second.Cert, "api.example.com", true)
}

func TestLoadOrGenerateCA_RegeneratesWhenKeyMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := CAConfig{CertPath: filepath.Join(dir, "ca.crt"), KeyPath: filepath.Join(dir, "ca.key")}

	if _, err := GenerateCA(cfg); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := os.Remove(cfg.KeyPath); err != nil {
		t.Fatalf("remove key: %v", err)
	}

	ca, err := LoadOrGenerateCA(cfg)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA with missing key: %v", err)
	}
	if _, err := os.Stat(cfg.KeyPath); err != nil {
		t.Fatalf("key file not regenerated: %v", err)
	}
	if ca.Cert == nil {
		t.Fatal("regenerated CA has no cert")
	}
}

func TestLoadCA_RejectsCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Valid CA first, then corrupt one side at a time.
	if _, err := GenerateCA(CAConfig{CertPath: certPath, KeyPath: keyPath}); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if err := os.WriteFile(certPath, []byte("not a pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCA(CAConfig{CertPath: certPath, KeyPath: keyPath}); err == nil {
		t.Fatal("loadCA accepted corrupt cert PEM")
	}

	if _, err := GenerateCA(CAConfig{CertPath: certPath, KeyPath: keyPath}); err != nil {
		t.Fatalf("re-GenerateCA: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCA(CAConfig{CertPath: certPath, KeyPath: keyPath}); err == nil {
		t.Fatal("loadCA accepted corrupt key PEM")
	}
}

func TestLeafCert_ServesHostnameAndVerifies(t *testing.T) {
	cfg := CAConfig{CertPath: filepath.Join(t.TempDir(), "ca.crt"), KeyPath: filepath.Join(t.TempDir(), "ca.key")}
	ca, err := GenerateCA(cfg)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	leaf, err := ca.LeafCert("api.example.com")
	if err != nil {
		t.Fatalf("LeafCert: %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("leaf chain length = %d, want 2 (leaf + CA)", len(leaf.Certificate))
	}

	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leafCert.DNSNames) != 1 || leafCert.DNSNames[0] != "api.example.com" {
		t.Fatalf("leaf DNSNames = %v, want [api.example.com]", leafCert.DNSNames)
	}

	verifyLeaf(t, leaf, ca.Cert, "api.example.com", true)
	verifyLeaf(t, leaf, ca.Cert, "evil.example.com", false)
}

func TestLeafCert_RejectsEmptyHostname(t *testing.T) {
	cfg := CAConfig{CertPath: filepath.Join(t.TempDir(), "ca.crt"), KeyPath: filepath.Join(t.TempDir(), "ca.key")}
	ca, err := GenerateCA(cfg)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	leaf, err := ca.LeafCert("")
	if err != nil {
		t.Fatalf("LeafCert with empty hostname should not error: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := leafCert.Subject.CommonName; got != "" {
		t.Fatalf("CN = %q, want empty", got)
	}
}

func TestSavePEM_CorrectsExistingKeyMode(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.key")
	if err := os.WriteFile(keyPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := savePEM(keyPath, 0o600, "PRIVATE KEY", []byte("dummy-der")); err != nil {
		t.Fatalf("savePEM: %v", err)
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key mode = %04o, want 0600", perm)
	}
}

func TestDefaultCAPaths_UsesTrustlessConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	paths := DefaultCAPaths()
	if !strings.HasSuffix(paths.CertPath, caCertName) {
		t.Fatalf("cert path %q does not end with %q", paths.CertPath, caCertName)
	}
	if !strings.HasSuffix(paths.KeyPath, caKeyName) {
		t.Fatalf("key path %q does not end with %q", paths.KeyPath, caKeyName)
	}
}

// verifyLeaf verifies leaf against the CA cert for dnsName and asserts the
// result matches wantValid.
func verifyLeaf(t *testing.T, leaf tls.Certificate, caCert *x509.Certificate, dnsName string, wantValid bool) {
	t.Helper()
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = leafCert.Verify(x509.VerifyOptions{Roots: roots, DNSName: dnsName})
	if wantValid && err != nil {
		t.Fatalf("leaf for %q failed verification: %v", dnsName, err)
	}
	if !wantValid && err == nil {
		t.Fatalf("leaf unexpectedly verified for %q", dnsName)
	}
}
