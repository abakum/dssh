package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"os"
	"path/filepath"

	"github.com/abakum/dssh/internal/tool"
)

func main() {
	const (
		ROOT     = "internal"
		FILEMODE = 0600
		CA       = "ca"
	)
	flag.Parse()
	tool.Priv(flag.Arg(0), flag.Arg(1))
	wd, err := os.Getwd()
	Panic(err)

	name := filepath.Join(wd, ROOT, CA)
	_, err = os.Stat(name)
	if err == nil {
		os.Exit(0)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Panic(err)

	data, err := x509.MarshalPKCS8PrivateKey(key)
	Panic(err)

	err = os.WriteFile(name, data, FILEMODE)
	Panic(err)
}

func Panic(err error) {
	if err != nil {
		panic(err)
	}
}
