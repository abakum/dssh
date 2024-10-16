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
	"strings"

	"github.com/trzsz/ssh_config"
	"golang.org/x/crypto/ssh"
)

const (
	kexAlgoDH1SHA1                = "diffie-hellman-group1-sha1"
	kexAlgoDH14SHA1               = "diffie-hellman-group14-sha1"
	kexAlgoDH14SHA256             = "diffie-hellman-group14-sha256"
	kexAlgoDH16SHA512             = "diffie-hellman-group16-sha512"
	kexAlgoECDH256                = "ecdh-sha2-nistp256"
	kexAlgoECDH384                = "ecdh-sha2-nistp384"
	kexAlgoECDH521                = "ecdh-sha2-nistp521"
	kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org"
	kexAlgoCurve25519SHA256       = "curve25519-sha256"

	// For the following kex only the client half contains a production
	// ready implementation. The server half only consists of a minimal
	// implementation to satisfy the automated tests.
	kexAlgoDHGEXSHA1   = "diffie-hellman-group-exchange-sha1"
	kexAlgoDHGEXSHA256 = "diffie-hellman-group-exchange-sha256"

	// Implemented?
	kexAlgoDH18SHA512 = "diffie-hellman-group18-sha512"
	kexAlgoExt        = "ext-info-c"
	kexAlgoStrict     = "kex-strict-c-v00@openssh.com"
)

/*
ssh -Q KexAlgorithms
diffie-hellman-group1-sha1
diffie-hellman-group14-sha1
diffie-hellman-group14-sha256
diffie-hellman-group16-sha512
diffie-hellman-group18-sha512
diffie-hellman-group-exchange-sha1
diffie-hellman-group-exchange-sha256
ecdh-sha2-nistp256
ecdh-sha2-nistp384
ecdh-sha2-nistp521
curve25519-sha256
curve25519-sha256@libssh.org
*/

// supportedKexAlgos specifies the supported key-exchange algorithms in
// preference order.
var supportedKexAlgos = NewStringSet(
	kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH,
	// P384 and P521 are not constant-time yet, but since we don't
	// reuse ephemeral keys, using them for ECDH should be OK.
	kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521,
	kexAlgoDH14SHA256, kexAlgoDH16SHA512, kexAlgoDH14SHA1,
	kexAlgoDH1SHA1,
)

var defaultOpenSSHKexAlgos = NewStringSet(
	// curve25519-sha256 curve25519-sha256@libssh.org
	kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH,
	// ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521
	kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521,
	// diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,
	kexAlgoDHGEXSHA256, kexAlgoDH16SHA512, kexAlgoDH18SHA512,
	// diffie-hellman-group14-sha256
	kexAlgoDH14SHA256,
	//ext-info-c,kex-strict-c-v00@openssh.com
	kexAlgoExt, kexAlgoStrict,
)

// preferredKexAlgos specifies the default preference for key-exchange
// algorithms in preference order. The diffie-hellman-group16-sha512 algorithm
// is disabled by default because it is a bit slower than the others.
var preferredKexAlgos = NewStringSet(
	kexAlgoCurve25519SHA256, kexAlgoCurve25519SHA256LibSSH,
	kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521,
	kexAlgoDH14SHA256, kexAlgoDH14SHA1,
)

func setSupportedKexAlgos(config *ssh.ClientConfig) {
	newSet := NewStringSet()
	for _, algo := range config.KeyExchanges {
		if supportedKexAlgos.Contains(algo) {
			newSet.Add(algo)
		}
	}
	config.KeyExchanges = newSet.List()
}

func setupKexAlgorithmsConfig(args *SshArgs, config *ssh.ClientConfig) {
	defer func() {
		setSupportedKexAlgos(config)
		if len(config.KeyExchanges) == 0 {
			// Нет алгоритмов из KexAlgorithms тогда пусть x/crypto/ssh присвоит дефолтные
			config.KeyExchanges = preferredKexAlgos.List()
		}
		debug("client supported KEX algorithms: %v", config.KeyExchanges)
	}()
	algoSpec := getOptionConfig(args, "KexAlgorithms")
	if algoSpec == ssh_config.Default("KexAlgorithms") || algoSpec == "" {
		// Нет  -o KexAlgorithms=a,b,...
		config.KeyExchanges = defaultOpenSSHKexAlgos.List()
		debug("default KEX algorithms: %v", config.KeyExchanges)
		return
	}
	defer func() {
		debug("user declared algorithms: %v", config.KeyExchanges)
	}()
	algos := strings.Split(algoSpec[1:], ",")
	switch algoSpec[0] {
	case '+':
		// If the specified list begins with a ‘+’ character, then the specified items will be appended to the default set instead of replacing them.
		// a,b + a,c -> b,a,c
		config.KeyExchanges = NewStringSet(config.KeyExchanges...).DelRegExp(algos...).Add(algos...).List()
	case '-':
		// If the specified list begins with a ‘-’ character, then the specified items (including wildcards) will be removed from the default set instead of replacing them.
		// a,b -a,c -> b
		config.KeyExchanges = NewStringSet(config.KeyExchanges...).DelRegExp(algos...).List()
	case '^':
		// If the specified list begins with a ‘^’ character, then the specified items will be placed at the head of the default set.
		// a,b ^a,c -> a,c,b
		config.KeyExchanges = NewStringSet(algos...).Add(config.KeyExchanges...).List()
	default:
		config.KeyExchanges = NewStringSet(strings.Split(algoSpec, ",")...).List()
	}
}
