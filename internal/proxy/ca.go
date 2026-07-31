package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caCertName = "trustless-ca.crt"
	caKeyName  = "trustless-ca.key"
)

type CA struct {
	Cert     *x509.Certificate
	Key      crypto.PrivateKey
	certPath string
	keyPath  string
}

type CAConfig struct {
	CertPath string
	KeyPath  string
}

func DefaultCAPaths() CAConfig {
	home, _ := os.UserHomeDir()
	return CAConfig{
		CertPath: filepath.Join(home, ".config", "trustless", caCertName),
		KeyPath:  filepath.Join(home, ".config", "trustless", caKeyName),
	}
}

func LoadOrGenerateCA(cfg CAConfig) (*CA, error) {
	if _, err := os.Stat(cfg.CertPath); err == nil {
		if _, err := os.Stat(cfg.KeyPath); err == nil {
			return loadCA(cfg)
		}
	}
	return GenerateCA(cfg)
}

func loadCA(cfg CAConfig) (*CA, error) {
	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode CA key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &CA{
		Cert:     cert,
		Key:      key,
		certPath: cfg.CertPath,
		keyPath:  cfg.KeyPath,
	}, nil
}

func GenerateCA(cfg CAConfig) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "trustless MITM Proxy CA",
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.CertPath), 0755); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}

	if err := savePEM(cfg.CertPath, 0644, "CERTIFICATE", certDER); err != nil {
		return nil, fmt.Errorf("save CA cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	if err := savePEM(cfg.KeyPath, 0600, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, fmt.Errorf("save CA key: %w", err)
	}

	return &CA{
		Cert:     cert,
		Key:      key,
		certPath: cfg.CertPath,
		keyPath:  cfg.KeyPath,
	}, nil
}

func (ca *CA) LeafCert(hostname string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:    []string{hostname},
		NotBefore:   now,
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create leaf cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER, ca.Cert.Raw},
		PrivateKey:  key,
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return serial, nil
}

func savePEM(path string, mode os.FileMode, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
