package config

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRPCConfig_NewTLSConfig_SetsBothCAPools regresses
// SECURITY-REPORT.md M-3. The Raft RPC TLS config used the same private
// CA pool to gate inbound (ClientCAs) but left RootCAs unset for the
// peer-dial path. tls.Dial then fell back to the host's system trust
// store, so any cert chained to a public CA (Let's Encrypt, DigiCert,
// …) with a matching SAN could impersonate a Raft peer. Both fields
// must point at the operator-supplied CA pool — and at the same one,
// since Raft peers authenticate symmetrically.
func TestRPCConfig_NewTLSConfig_SetsBothCAPools(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caPath := writeTestCertPEM(t, dir)

	cfg := RPCConfig{
		Enabled:       true,
		TLSCertFile:   certPath,
		TLSKeyFile:    keyPath,
		TLSCACertFile: caPath,
	}
	tlsCfg, err := cfg.NewTLSConfig()
	if err != nil {
		t.Fatalf("NewTLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("NewTLSConfig returned nil with Enabled=true")
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("ClientCAs is nil — inbound peer auth disabled")
	}
	if tlsCfg.RootCAs == nil {
		t.Error("RootCAs is nil — outbound peer dial falls back to system trust store (M-3 regression: peer impersonation)")
	}
	if tlsCfg.ClientCAs != tlsCfg.RootCAs {
		t.Error("ClientCAs and RootCAs should be the same private CA pool; Raft peer auth is symmetric")
	}
}

func TestRPCConfig_NewTLSConfig_RejectsOversizedCAFile(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := writeTestCertPEM(t, dir)
	caPath := filepath.Join(dir, "oversized-ca.crt")
	if err := os.WriteFile(caPath, bytes.Repeat([]byte{'x'}, maxRPCCACertFileSize+1), 0o600); err != nil {
		t.Fatalf("write oversized CA: %v", err)
	}

	cfg := RPCConfig{
		Enabled:       true,
		TLSCertFile:   certPath,
		TLSKeyFile:    keyPath,
		TLSCACertFile: caPath,
	}
	if _, err := cfg.NewTLSConfig(); err == nil {
		t.Fatal("NewTLSConfig should reject oversized CA file")
	}
}

// writeTestCertPEM generates a self-signed cert and writes it as both
// the server cert and the CA cert under dir. Returns cert, key, ca
// paths suitable for an RPCConfig.
func writeTestCertPEM(t *testing.T, dir string) (certPath, keyPath, caPath string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-raft-peer"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	certPath = filepath.Join(dir, "peer.crt")
	keyPath = filepath.Join(dir, "peer.key")
	caPath = filepath.Join(dir, "ca.crt")
	for _, write := range []struct {
		path string
		data []byte
	}{
		{certPath, certPEM},
		{keyPath, keyPEM},
		{caPath, certPEM}, // self-signed: cert == ca
	} {
		if err := os.WriteFile(write.path, write.data, 0o600); err != nil {
			t.Fatalf("write %s: %v", write.path, err)
		}
	}
	return certPath, keyPath, caPath
}
