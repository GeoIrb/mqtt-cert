package generate

import (
	"net"
	"os"
)

type Adress struct {
	list []net.IP
}

func getAddresses() Adress {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		os.Stderr.WriteString("Oops: " + err.Error() + "\n")
		return Adress{}
	}

	var ip Adress
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To16() != nil {
				ip.list = append(ip.list, ipnet.IP)
			}
		}
	}

	return ip
}
