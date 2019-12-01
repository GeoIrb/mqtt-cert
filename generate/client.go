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

func (ca CertificateAuthority) Client() error {

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "./client",
			Organization:       []string{"MyCompany.org"},
			OrganizationalUnit: []string{"generate-CA"},
		},
		EmailAddresses: []string{"nobody@example.net"},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		SubjectKeyId: []byte{1, 2, 3, 4, 7},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &ca.certificate, &key.PublicKey, ca.key)

	if err := saveInFile("client.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		return fmt.Errorf("Create server key file: %s", err)
	}

	if err := saveInFile("client.crt", "CERTIFICATE", derBytes); err != nil {
		return fmt.Errorf("Create server crt file: %s", err)
	}

	return nil
}
