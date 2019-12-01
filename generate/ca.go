package generate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

type CertificateAuthority struct {
	key         *rsa.PrivateKey
	certificate x509.Certificate
}

func NewCertificateAuthority() (ca CertificateAuthority, err error) {

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

	ca.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return CertificateAuthority{}, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &ca.certificate, &ca.certificate, &ca.key.PublicKey, ca.key)
	if err != nil {
		return CertificateAuthority{}, fmt.Errorf("Failed to create certificate: %s", err)
	}

	if err := saveInFile("ca.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(ca.key)); err != nil {
		return CertificateAuthority{}, fmt.Errorf("Create ca crt file: %s", err)
	}

	if err := saveInFile("ca.crt", "CERTIFICATE", derBytes); err != nil {
		return CertificateAuthority{}, fmt.Errorf("Create ca crt file: %s", err)
	}

	return ca, nil
}
