package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

func cert_get(addr string) []*x509.Certificate {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", addr+":443", conf)
	if err != nil {
		log.Println("Dial error", err)
		return nil
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates
}

func main() {
	certs := cert_get(os.Args[1])

	fmt.Printf("%#v\n", certs)

	for _, c := range certs {
		fmt.Printf("%+v", c)
	}

}
