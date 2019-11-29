package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("openssl", "req", "-newkey", "rsa:2048", "-x509", "-nodes", "-sha512", "-days", "365", "-extensions", "v3_ca", "-keyout", "ca.key", "-out", "ca.crt", "-subj", `"/CN=An MQTT broker"`)
	fmt.Println(cmd.Run())

	cmd = exec.Command("openssl", "x509", "-in", "ca.crt", "-nameopt", "multiline", "-subject", "-noout")
	fmt.Println(cmd.Run())
}
