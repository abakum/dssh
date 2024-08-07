// Code generated by https://github.com/abakum/embed-encrypt; DO NOT EDIT.

package main

import (
	_ "embed"
	"github.com/abakum/embed-encrypt/encryptedfs"
)

//go:embed key.enc
var key []byte

//go:embed "internal/ca.enc"
var CAEnc []byte

func init() {
	CA = encryptedfs.DecByte(CAEnc, key)
}
