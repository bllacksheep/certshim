package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
)

const path string = "/usr/local/share/ca-certificates"
const ext string = ".pem.crt"

type Certificate struct {
	Name string
	Pem  string
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
	certificate_common_name := cert.Issuer.CommonName
	certificate_pem_bytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	certificate_pem_armored := string(certificate_pem_bytes)
	return &Certificate{
		certificate_common_name,
		certificate_pem_armored,
	}
}

func main() {
	domain := os.Args[1]
	chain := GetCertificateChain(domain)
	for _, certificate := range chain {
		cert := PemEncodeCertificate(certificate)
		full_path := filepath.Join(path, cert.Name + ext)
		f, err := os.OpenFile(full_path, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		f.WriteString(cert.Pem)
	}
}
