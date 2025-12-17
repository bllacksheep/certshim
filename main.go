package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
)

type Certificate struct {
	Name string
	Pem  string
}

func GetCertificateChain(fqdn string) []*x509.Certificate {
	fqdn_verified := verifyDomain(fqdn)
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", fqdn_verified+":443", conf)
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

func verifyDomain(d string) string {
	return d
}

func localStore() string {
	const local_certificate_store = ".local/share/ca-certificates"
	user_home := os.Getenv("HOME")
	local_store_fullpath := filepath.Join(user_home, local_certificate_store)
	err := os.MkdirAll(local_store_fullpath, 0755)
	if err != nil {
		panic(err)
	}
	return local_store_fullpath
}

func InstallChain(certificate_chain []*x509.Certificate) {
	const ext string = ".pem.crt"
	local_store := localStore()	
	for i := 0; i < len(certificate_chain); i++ {
		certificate := PemEncodeCertificate(certificate_chain[i])
		local_cert_fullpath := filepath.Join(local_store, certificate.Name + ext)
		f, err := os.OpenFile(local_cert_fullpath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		f.WriteString(certificate.Pem)
	}
}

func main() {
	if len(os.Args) < 2 {
		panic("provide an fqdn as arg")
	}
	InstallChain(GetCertificateChain(os.Args[1]))
}
