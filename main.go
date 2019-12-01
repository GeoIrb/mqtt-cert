package main

import (
	"log"

	"github.com/GeoIrb/mqtt-cert/generate"
)

func main() {
	ca, err := generate.NewCertificateAuthority()
	if err != nil {
		log.Fatalf("Generate CA: %s", err)
	}
	log.Println("Generated CA cert and key")

	if err := ca.Server(); err != nil {
		log.Fatalf("Generate Server: %s", err)
	}
	log.Println("Generated server cert and key")

	if err := ca.Client(); err != nil {
		log.Fatalf("Generate Client: %s", err)
	}
	log.Println("Generated client cert and key")
}
