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

var _ = []string{
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

// supportedHostKeyAlgos specifies the supported host-key algorithms (i.e. methods
// of authenticating servers)
var supportedHostKeyAlgos = NewStringSet(
	ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01,
	ssh.CertAlgoRSAv01, ssh.CertAlgoDSAv01, ssh.CertAlgoECDSA256v01,
	ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01, ssh.CertAlgoED25519v01,

	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSA, ssh.KeyAlgoDSA,

	ssh.KeyAlgoED25519,
)

func setSupported(config *ssh.ClientConfig) {
	HostKeyAlgorithms := NewStringSet()
	for _, algo := range config.HostKeyAlgorithms {
		if supportedHostKeyAlgos.Contains(algo) {
			HostKeyAlgorithms.Add(algo)
		}
	}
	config.HostKeyAlgorithms = HostKeyAlgorithms.List()
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
	return nil
}

func setupHostKeyAlgorithmsConfig(args *SshArgs, config *ssh.ClientConfig) error {
	// debug("host key algorithms: %v", config.HostKeyAlgorithms)
	defer func() {
		setSupported(config)
		debug("client supported algorithms: %v", config.HostKeyAlgorithms)
	}()
	algoSpec := getOptionConfig(args, "HostKeyAlgorithms")
	if algoSpec == ssh_config.Default("HostKeyAlgorithms") {
		// Не указан HostKeyAlgorithms
		debug("default algorithms: %v", config.HostKeyAlgorithms)
		return nil
	}
	defer func() {
		debug("user declared algorithms: %v", config.HostKeyAlgorithms)
	}()
	switch algoSpec[0] {
	case '+':
		// If the specified list begins with a ‘+’ character, then the specified items will be appended to the default set instead of replacing them.
		// a,b + a,c -> b,a,c
		removeHostKeyAlgorithmsConfig(config, algoSpec[1:])
		config.HostKeyAlgorithms = NewStringSet(config.HostKeyAlgorithms...).Add(strings.Split(algoSpec[1:], ",")...).List()
		return nil
	case '-':
		// If the specified list begins with a ‘-’ character, then the specified items (including wildcards) will be removed from the default set instead of replacing them.
		// a,b -a,c -> b
		return removeHostKeyAlgorithmsConfig(config, algoSpec[1:])
	case '^':
		// If the specified list begins with a ‘^’ character, then the specified items will be placed at the head of the default set.
		// a,b ^a,c -> a,c,b
		config.HostKeyAlgorithms = NewStringSet(strings.Split(algoSpec[1:], ",")...).Add(config.HostKeyAlgorithms...).List()
		return nil
	default:
		config.HostKeyAlgorithms = NewStringSet(strings.Split(algoSpec, ",")...).List()
		return nil
	}
}
