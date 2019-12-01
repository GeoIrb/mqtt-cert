package generate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type CertificateAuthority struct {
	PrivKey     *rsa.PrivateKey
	certificate x509.Certificate
}

func NewCertificateAuthority() (ca CertificateAuthority, err error) {
	keyFile, crtFile := "ca.key", "ca.crt"

	ca.certificate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "An MQTT broker",
			Organization:       []string{"MyCompany.org"},
			OrganizationalUnit: []string{"generate-CA"},
		},
		EmailAddresses: []string{"nobody@example.net"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour * 24 * 180),

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	ca.PrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return CertificateAuthority{}, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &ca.certificate, &ca.certificate, &ca.PrivKey.PublicKey, ca.PrivKey)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("Failed to create certificate: %s", err)
	}

	file, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY, 0444)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("Create key file: %s", err)
	}
	pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.PrivKey)})
	file.Close()

	file, err = os.OpenFile(crtFile, os.O_CREATE|os.O_WRONLY, 0444)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("Create crt file: %s", err)
	}
	pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	file.Close()

	return ca, nil
}
