/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/trzsz/ssh_config"
	"golang.org/x/crypto/ssh"
)

// If hostkeys are known for the destination host then this default is modified to prefer their algorithms.

var openHostKeyAlgos = []string{
	ssh.KeyAlgoED25519, ssh.CertAlgoED25519v01,
	ssh.KeyAlgoSKED25519, ssh.CertAlgoSKED25519v01, // ?
	ssh.KeyAlgoECDSA256, ssh.CertAlgoECDSA256v01,
	ssh.KeyAlgoECDSA384, ssh.CertAlgoECDSA384v01,
	ssh.KeyAlgoECDSA521, ssh.CertAlgoECDSA521v01,
	ssh.KeyAlgoSKECDSA256, ssh.CertAlgoSKECDSA256v01, //?
	ssh.KeyAlgoDSA, ssh.CertAlgoDSAv01,
	ssh.KeyAlgoRSA, ssh.CertAlgoRSAv01,
	ssh.KeyAlgoRSASHA256, ssh.CertAlgoRSASHA256v01,
	ssh.KeyAlgoRSASHA512, ssh.CertAlgoRSASHA512v01,
}

/*
ssh -Q HostKeyAlgorithms
ssh-ed25519
ssh-ed25519-cert-v01@openssh.com
sk-ssh-ed25519@openssh.com
sk-ssh-ed25519-cert-v01@openssh.com
ecdsa-sha2-nistp256
ecdsa-sha2-nistp256-cert-v01@openssh.com
ecdsa-sha2-nistp384
ecdsa-sha2-nistp384-cert-v01@openssh.com
ecdsa-sha2-nistp521
ecdsa-sha2-nistp521-cert-v01@openssh.com
sk-ecdsa-sha2-nistp256@openssh.com
sk-ecdsa-sha2-nistp256-cert-v01@openssh.com
webauthn-sk-ecdsa-sha2-nistp256@openssh.com
ssh-dss
ssh-dss-cert-v01@openssh.com
ssh-rsa
ssh-rsa-cert-v01@openssh.com
rsa-sha2-256
rsa-sha2-256-cert-v01@openssh.com
rsa-sha2-512
rsa-sha2-512-cert-v01@openssh.com
*/

// certKeyAlgoNames is a mapping from known certificate algorithm names to the
// corresponding public key signature algorithm.
//
// This map must be kept in sync with the one in certs.go.
var certKeyAlgoNames = map[string]string{
	ssh.CertAlgoRSAv01:        ssh.KeyAlgoRSA,
	ssh.CertAlgoRSASHA256v01:  ssh.KeyAlgoRSASHA256,
	ssh.CertAlgoRSASHA512v01:  ssh.KeyAlgoRSASHA512,
	ssh.CertAlgoDSAv01:        ssh.KeyAlgoDSA,
	ssh.CertAlgoECDSA256v01:   ssh.KeyAlgoECDSA256,
	ssh.CertAlgoECDSA384v01:   ssh.KeyAlgoECDSA384,
	ssh.CertAlgoECDSA521v01:   ssh.KeyAlgoECDSA521,
	ssh.CertAlgoSKECDSA256v01: ssh.KeyAlgoSKECDSA256,
	ssh.CertAlgoED25519v01:    ssh.KeyAlgoED25519,
	ssh.CertAlgoSKED25519v01:  ssh.KeyAlgoSKED25519,
}

// supportedHostKeyAlgos specifies the supported host-key algorithms (i.e. methods
// of authenticating servers)
var supportedHostKeyAlgos = map[string]bool{
	ssh.CertAlgoRSASHA256v01: true, ssh.CertAlgoRSASHA512v01: true,
	ssh.CertAlgoRSAv01: true, ssh.CertAlgoDSAv01: true, ssh.CertAlgoECDSA256v01: true,
	ssh.CertAlgoECDSA384v01: true, ssh.CertAlgoECDSA521v01: true, ssh.CertAlgoED25519v01: true,

	ssh.KeyAlgoECDSA256: true, ssh.KeyAlgoECDSA384: true, ssh.KeyAlgoECDSA521: true,
	ssh.KeyAlgoRSASHA256: true, ssh.KeyAlgoRSASHA512: true,
	ssh.KeyAlgoRSA: true, ssh.KeyAlgoDSA: true,

	ssh.KeyAlgoED25519: true,
}

func SetSupported(config *ssh.ClientConfig) {
	HostKeyAlgorithms := []string{}
	for _, algo := range config.HostKeyAlgorithms {
		_, ok := supportedHostKeyAlgos[algo]
		if ok {
			HostKeyAlgorithms = append(HostKeyAlgorithms, algo)
		}
	}
	config.HostKeyAlgorithms = HostKeyAlgorithms
}

func debugHostKeyAlgorithmsConfig(config *ssh.ClientConfig) {
	debug("user declared algorithms: %v", config.HostKeyAlgorithms)
	SetSupported(config)
	debug("client supported algorithms: %v", config.HostKeyAlgorithms)
}

func appendHostKeyAlgorithmsConfig(config *ssh.ClientConfig, algoSpec string) error {
	for _, algo := range strings.Split(algoSpec, ",") {
		algo = strings.TrimSpace(algo)
		if algo != "" {
			config.HostKeyAlgorithms = append(config.HostKeyAlgorithms, algo)
		}
	}
	debugHostKeyAlgorithmsConfig(config)
	return nil
}

func removeHostKeyAlgorithmsConfig(config *ssh.ClientConfig, algoSpec string) error {
	var buf strings.Builder
	for _, algo := range strings.Split(algoSpec, ",") {
		if buf.Len() > 0 {
			buf.WriteRune('|')
		}
		buf.WriteString("(^")
		for _, c := range algo {
			switch c {
			case '*':
				buf.WriteString(".*")
			case '?':
				buf.WriteRune('.')
			case '(', ')', '[', ']', '{', '}', '.', '+', ',', '-', '^', '$', '|', '\\':
				buf.WriteRune('\\')
				buf.WriteRune(c)
			default:
				buf.WriteRune(c)
			}
		}
		buf.WriteString("$)")
	}
	expr := buf.String()
	debug("algorithms regexp: %s", expr)
	re, err := regexp.Compile(expr)
	if err != nil {
		return fmt.Errorf("compile algorithms regexp failed: %v", err)
	}

	algorithms := make([]string, 0)
	for _, algo := range config.HostKeyAlgorithms {
		if re.MatchString(algo) {
			continue
		}
		algorithms = append(algorithms, algo)
	}
	config.HostKeyAlgorithms = algorithms
	debugHostKeyAlgorithmsConfig(config)
	return nil
}

func insertHostKeyAlgorithmsConfig(config *ssh.ClientConfig, algoSpec string) error {
	var algorithms []string
	for _, algo := range strings.Split(algoSpec, ",") {
		algo = strings.TrimSpace(algo)
		if algo != "" {
			algorithms = append(algorithms, algo)
		}
	}
	config.HostKeyAlgorithms = append(algorithms, config.HostKeyAlgorithms...)
	debugHostKeyAlgorithmsConfig(config)
	return nil
}

func replaceHostKeyAlgorithmsConfig(config *ssh.ClientConfig, algoSpec string) error {
	config.HostKeyAlgorithms = nil
	for _, algo := range strings.Split(algoSpec, ",") {
		algo = strings.TrimSpace(algo)
		if algo != "" {
			config.HostKeyAlgorithms = append(config.HostKeyAlgorithms, algo)
		}
	}
	debugHostKeyAlgorithmsConfig(config)
	return nil
}

func setupHostKeyAlgorithmsConfig(args *SshArgs, config *ssh.ClientConfig) error {
	algoSpec := getOptionConfig(args, "HostKeyAlgorithms")
	if algoSpec == ssh_config.Default("HostKeyAlgorithms") {
		// Не указан HostKeyAlgorithms
		if idKeyAlgorithms.Len() == 0 {
			return nil
		}
		return insertHostKeyAlgorithmsConfig(config, strings.Join(idKeyAlgorithms.List(), ","))
	}
	switch algoSpec[0] {
	case '+':
		return appendHostKeyAlgorithmsConfig(config, algoSpec[1:])
	case '-':
		return removeHostKeyAlgorithmsConfig(config, algoSpec[1:])
	case '^':
		return insertHostKeyAlgorithmsConfig(config, algoSpec[1:])
	default:
		return replaceHostKeyAlgorithmsConfig(config, algoSpec)
	}
}
