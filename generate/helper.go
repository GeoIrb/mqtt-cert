package generate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

var CertServer x509.Certificate = x509.Certificate{
	SerialNumber: big.NewInt(1),
	Subject: pkix.Name{
		CommonName:         "An MQTT broker",
		Organization:       []string{"MyCompany.org"},
		OrganizationalUnit: []string{"generate-CA"},
	},
	EmailAddresses: []string{"nobody@example.net"},
	IPAddresses:    getAddresses(),
	NotBefore:      time.Now(),
	NotAfter:       time.Now().Add(time.Hour * 24 * 180),

	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:     x509.KeyUsageDigitalSignature,

	IsCA:                  false,
	BasicConstraintsValid: false,

	AuthorityKeyId: []byte{1, 2, 3, 4, 7},

	PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 3, 5, 8}},
}

var CertClient x509.Certificate = x509.Certificate{
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

func saveInFile(fileName, t string, info []byte) error {
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0444)
	if err != nil {
		return fmt.Errorf("Create crt file: %s", err)
	}
	pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: info})
	file.Close()

	return nil
}

func getAddresses() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Printf("IP: %s", err)
		return nil
	}

	var ip []net.IP
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To16() != nil {
				ip = append(ip, ipnet.IP)
			}
		}
	}

	return ip
}
