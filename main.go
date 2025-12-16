package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"encoding/pem"
)

func Get(fqdn string) []*x509.Certificate {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", fqdn+":443", conf)
	if err != nil {
		log.Println("Dial error", err)
		return nil
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates
}

func Pem(cert *x509.Certificate) []byte {
	x509AsBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		log.Println("Marshal error", err)
		return nil
	}

	rsa := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PUBLIC KEY",
		Bytes: x509AsBytes,
	})
	return rsa
}

func main() {

	certs := Get(os.Args[1])

	fmt.Printf("%#v\n", certs)

	for _, c := range certs {
		p := Pem(c)
		fmt.Printf("%v\n", p)
	}

}
