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
	Issuer []byte
	Pem    []byte
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
	rsa := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return &Certificate{
		cert.RawIssuer,
		rsa,
	}
}

func main() {
	domain := os.Args[1]
	chain := GetCertificateChain(domain)
	for _, certificate := range chain {
		cert := PemEncodeCertificate(certificate)
		fmt.Printf("%v\n", string(cert.Issuer))
	}
}
