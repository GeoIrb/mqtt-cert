package main

import (
	"fmt"

	"github.com/GeoIrb/mqtt-cert/generate"
)

func main() {
	ca, err := generate.NewCertificateAuthority()
	fmt.Println(err, ca.Server(), ca.Client())
}
