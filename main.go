package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
)

const certificate_local_store = ".local/share/ca-certificates"
const certificate_file_extension string = ".pem.crt"

type Certificate struct {
	Name string
	Pem  string
}

func verifyDomain(d string) string {
	return d
}

func GetCertificateChain(fqdn string) []*x509.Certificate {
	fqdn_verified := verifyDomain(fqdn)
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", fqdn_verified+":443", conf)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates
}

func pemEncodeCertificates(chain []*x509.Certificate) []*Certificate {
	var certificates []*Certificate
	for i := 0; i < len(chain); i++ {
		if chain[i].IsCA {
			certificate_pem_bytes := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: chain[i].Raw,
			})
			certificate_pem_armored := string(certificate_pem_bytes)
			certificate_common_name := chain[i].Issuer.CommonName
			certificates = append(certificates, &Certificate{
				certificate_common_name,
				certificate_pem_armored,
			})
		}
	}
	return certificates
}

func localStore(location string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic("no home")
	}
	local_store_fullpath := filepath.Join(home, location)
	err = os.MkdirAll(local_store_fullpath, 0755)
	if err != nil {
		panic(err)
	}
	return local_store_fullpath
}


func InstallChain(certificate_chain []*x509.Certificate) {
	local_store := localStore(certificate_local_store)
	certificates := pemEncodeCertificates(certificate_chain)
	for i := 0; i < len(certificates); i++ {
		local_cert_fullpath := filepath.Join(local_store, certificates[i].Name+certificate_file_extension)
		f, err := os.OpenFile(local_cert_fullpath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		_, err = f.WriteString(certificates[i].Pem)
		if err != nil {
			panic(err)
		}
		log.Println("installed:", local_cert_fullpath)
	}
}

func main() {
	if len(os.Args) < 2 {
		panic("provide an fqdn as arg")
	}
	InstallChain(GetCertificateChain(os.Args[1]))
}
