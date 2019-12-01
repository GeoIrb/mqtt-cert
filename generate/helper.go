package generate

import (
	"encoding/pem"
	"fmt"
	"os"
)

func saveInFile(fileName, t string, info []byte) error {
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0444)
	if err != nil {
		return fmt.Errorf("Create crt file: %s", err)
	}
	pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: info})
	file.Close()

	return nil
}
