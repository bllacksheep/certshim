package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"encoding/pem"
)

func GetCertificateChain(fqdn string) []*x509.Certificate {
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

func PemEncodeCertificate(cert *x509.Certificate) []byte {
	rsa := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return rsa
}

func main() {
	domain := os.Args[1]
	chain := GetCertificateChain(domain)
	for _, certificate := range chain {
		b := PemEncodeCertificate(certificate)
		fmt.Printf("%v\n", string(b))
	}
}
