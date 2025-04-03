package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func SignerFromPem(pemBytes []byte) (ssh.Signer, error) {

	// read pem block
	err := errors.New("pem decode failed, no key found")
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, err
	}

	// generate signer instance from plain key
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing plain private key failed %v", err)
	}

	return signer, nil
}

func ReadPemFile(fileName string) (ssh.Signer, error) {
	pem, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	res, err := SignerFromPem(pem)
	if err != nil {
		return nil, err
	}
	return res, nil
}
