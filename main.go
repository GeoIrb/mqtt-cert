package main

import (
	"log"
	"os"

	"github.com/GeoIrb/mqtt-cert/generate"
)

func main() {
	ca, err := generate.NewCertificateAuthority()
	if err != nil {
		log.Fatalf("Generate CA: %s", err)
	}
	log.Println("Generated CA cert and key")

	hostname, _ := os.Hostname()
	if err := ca.Generate(hostname, generate.CertServer); err != nil {
		log.Fatalf("Generate Server: %s", err)
	}
	log.Println("Generated server cert and key")

	if err := ca.Generate("client", generate.CertClient); err != nil {
		log.Fatalf("Generate Client: %s", err)
	}
	log.Println("Generated client cert and key")
}
