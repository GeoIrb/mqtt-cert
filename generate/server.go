package generate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func (ca CertificateAuthority) Server() error {
	hostname, _ := os.Hostname()
	keyFile := fmt.Sprintf("%s.key", hostname)
	crtFile := fmt.Sprintf("%s.crt", hostname)

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY, 0444)
	if err != nil {
		return fmt.Errorf("Create server key file: %s", err)
	}
	pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey)})
	file.Close()

	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "An MQTT broker",
			Organization:       []string{"MyCompany.org"},
			OrganizationalUnit: []string{"generate-CA"},
		},
		EmailAddresses: []string{"nobody@example.net"},
		IPAddresses:    getAddresses().list,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour * 24 * 180),

		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature, // + x509.KeyUsageEncipherOnly,

		IsCA:                  false,
		BasicConstraintsValid: false,

		AuthorityKeyId: []byte{1, 2, 3, 4, 7},

		PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 3, 5, 8}},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &cert, &ca.certificate, &certPrivKey.PublicKey, ca.PrivKey)

	file, err = os.OpenFile(crtFile, os.O_CREATE|os.O_WRONLY, 0444)
	if err != nil {
		return fmt.Errorf("Create server crt file: %s", err)
	}
	pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	file.Close()

	return nil
}
