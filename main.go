package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

type Certificate struct {
	Name string
	Pem  []byte
}

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

func PemEncodeCertificate(cert *x509.Certificate) *Certificate {
	name := cert.Issuer.CommonName
	return &Certificate{
		name,
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})}
}

func main() {
	domain := os.Args[1]
	chain := GetCertificateChain(domain)
	for _, certificate := range chain {
		cert := PemEncodeCertificate(certificate)
		fmt.Printf("%v\n", string(cert.Name))
	}
}
