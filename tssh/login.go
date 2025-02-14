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
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alessio/shellescape"
	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var enableDebugLogging bool = false
var enableWarningLogging bool = true

var DebugPrefix = "debug"
var DebugF = func(format string) string {
	return fmt.Sprintf("\033[0;36m%s:\033[0m %s\r\n", DebugPrefix, format)
}

var debug = func(format string, a ...any) {
	if !enableDebugLogging {
		return
	}
	fmt.Fprintf(os.Stderr, DebugF(format), a...)
}

var WarningF = func(format string) string {
	return fmt.Sprintf("\033[0;33mWarning: %s\033[0m\r\n", format)
}

var warning = func(format string, a ...any) {
	if !enableWarningLogging {
		return
	}
	fmt.Fprintf(os.Stderr, WarningF(format), a...)
}

var InfoF = func(format string) string {
	return fmt.Sprintf("%s\r\n", format)
}

var info = func(format string, a ...any) {
	fmt.Fprintf(os.Stderr, InfoF(format), a...)
}

type sshParam struct {
	host    string
	port    string
	user    string
	addr    string
	proxy   []string
	command string
}

type sshSession struct {
	client    *ssh.Client
	session   *ssh.Session
	serverIn  io.WriteCloser
	serverOut io.Reader
	serverErr io.Reader
	cmd       string
	tty       bool
}

// Закрываем сессию и клиента при закрытии ввода
type serverWriteCloser struct {
	io.WriteCloser
	session *ssh.Session
}

func (s *serverWriteCloser) Close() error {
	s.session.Close()
	return nil
}

func newServerWriteCloser(session *ssh.Session) (*serverWriteCloser, error) {
	wc, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	return &serverWriteCloser{
		wc,
		session,
	}, nil
}

func (s *sshSession) Close() {
	if s.serverIn != nil {
		s.serverIn.Close()
	}
	if s.session != nil {
		s.session.Close()
	}
	if s.client != nil {
		s.client.Close()
	}
}

func joinHostPort(host, port string) string {
	if !strings.HasPrefix(host, "[") && strings.ContainsRune(host, ':') {
		return fmt.Sprintf("[%s]:%s", host, port)
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func parseDestination(dest string) (user, host, port string) {
	// user
	idx := strings.Index(dest, "@")
	if idx >= 0 {
		user = dest[:idx]
		dest = dest[idx+1:]
	}

	// port
	idx = strings.Index(dest, "]:")
	if idx > 0 && dest[0] == '[' { // ipv6 port
		port = dest[idx+2:]
		dest = dest[1:idx]
	} else {
		tokens := strings.Split(dest, ":")
		if len(tokens) == 2 { // ipv4 port
			port = tokens[1]
			dest = tokens[0]
		}
	}

	host = dest
	return
}

func getSshParam(args *SshArgs) (*sshParam, error) {
	param := &sshParam{}

	// login dest
	destUser, destHost, destPort := parseDestination(args.Destination)
	args.Destination = destHost

	// login host
	param.host = destHost
	if hostName := getConfig(destHost, "HostName"); hostName != "" {
		var err error
		param.host, err = expandTokens(hostName, args, param, "%h")
		if err != nil {
			return nil, err
		}
	}

	// login user
	if args.LoginName != "" {
		param.user = args.LoginName
	} else if destUser != "" {
		param.user = destUser
	} else {
		userName := getConfig(destHost, "User")
		if userName != "" {
			param.user = userName
		} else {
			currentUser, err := user.Current()
			if err != nil {
				return nil, fmt.Errorf("get current user failed: %v", err)
			}
			userName = currentUser.Username
			if idx := strings.LastIndexByte(userName, '\\'); idx >= 0 {
				userName = userName[idx+1:]
			}
			param.user = userName
		}
	}

	// login port
	if args.Port > 0 {
		param.port = strconv.Itoa(args.Port)
	} else if destPort != "" {
		param.port = destPort
	} else {
		port := getConfig(destHost, "Port")
		if port != "" {
			param.port = port
		} else {
			param.port = "22"
		}
	}

	// login addr
	param.addr = joinHostPort(param.host, param.port)

	// login proxy
	command := args.Option.get("ProxyCommand")
	if command != "" && args.ProxyJump != "" {
		return nil, fmt.Errorf("cannot specify -J with ProxyCommand")
	}
	if command != "" {
		param.command = command
	} else if args.ProxyJump != "" {
		param.proxy = strings.Split(args.ProxyJump, ",")
	} else {
		proxy := getConfig(destHost, "ProxyJump")
		if proxy != "" {
			param.proxy = strings.Split(proxy, ",")
		} else {
			command := getConfig(destHost, "ProxyCommand")
			if command != "" {
				param.command = command
			}
		}
	}

	// expand proxy
	var err error
	if param.command != "" {
		param.command, err = expandTokens(param.command, args, param, "%hnpr")
		if err != nil {
			return nil, fmt.Errorf("expand ProxyCommand [%s] failed: %v", param.command, err)
		}
	}
	for i := 0; i < len(param.proxy); i++ {
		param.proxy[i], err = expandTokens(param.proxy[i], args, param, "%hnpr")
		if err != nil {
			return nil, fmt.Errorf("expand ProxyJump [%s] failed: %v", param.proxy[i], err)
		}
	}

	return param, nil
}

var acceptHostKeys []string
var sshLoginSuccess atomic.Bool

func ensureNewline(file *os.File) error {
	if _, err := file.Seek(-1, io.SeekEnd); err != nil {
		return nil
	}
	buf := make([]byte, 1)
	if n, err := file.Read(buf); err != nil || n != 1 || buf[0] == '\n' {
		return nil
	}
	if _, err := file.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func orderedScanHostKeys(hostPort string, firstHostPublicKey ssh.PublicKey) (otherHostPublicKeys []ssh.PublicKey) {
	const (
		BadAlgoritm = "no such algorithm"
		TO          = time.Second * 2
	)
	firstHostPublicKeyFound := false
	KeyScanCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), firstHostPublicKey.Marshal()) {
			firstHostPublicKeyFound = true // Try detect MIM atack
		}
		otherHostPublicKeys = append(otherHostPublicKeys, key)
		return fmt.Errorf(BadAlgoritm)
	}
	config := &ssh.ClientConfig{
		HostKeyCallback:   KeyScanCallback,
		HostKeyAlgorithms: []string{BadAlgoritm},
		Timeout:           TO,
	}
	// Get HostKeyAlgorithms.
	client, err := ssh.Dial("tcp", hostPort, config)
	if err != nil {
		// Look findAgreedAlgorithms from ~\go\pkg\mod\golang.org\x\crypto@v0.23.0\ssh\common.go
		if !strings.Contains(err.Error(), "ssh: no common algorithm for host key;") {
			return
		}
		ss := strings.Split(err.Error(), "server offered: [")
		if len(ss) < 2 {
			return
		}
		ss = strings.Split(ss[1], "]")
		if len(ss) < 2 {
			return
		}
		HostKeyAlgorithms := strings.Fields(ss[0])

		// Do not search RSA again.
		CertAlgoRSA := false
		KeyAlgoRSA := false
		for _, HostKeyAlgorithm := range HostKeyAlgorithms {
			switch HostKeyAlgorithm {
			case ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSAv01:
				if CertAlgoRSA {
					continue
				}
				CertAlgoRSA = true
			case ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA:
				if KeyAlgoRSA {
					continue
				}
				KeyAlgoRSA = true
			}

			config.HostKeyAlgorithms = []string{HostKeyAlgorithm}
			client, err := ssh.Dial("tcp", hostPort, config)
			if err != nil {
				continue
			}
			client.Close()
		}
		if firstHostPublicKeyFound {
			return
		}
		// Not found first key - no trust to other keys
		return []ssh.PublicKey{}
	}
	client.Close()
	return []ssh.PublicKey{}
}

func goScanHostKeys(hostPort string, firstHostPublicKey ssh.PublicKey, args *SshArgs) (allHostPublicKeys []ssh.PublicKey) {
	const (
		BadAlgoritm = "no such algorithm"
		TO          = time.Second * 2
	)
	chIn := make(chan ssh.PublicKey, 12)
	chOut := make(chan map[string]ssh.PublicKey)
	go func() {
		keys := make(map[string]ssh.PublicKey)
		ok := false
		for key := range chIn {
			if bytes.Equal(firstHostPublicKey.Marshal(), key.Marshal()) {
				ok = true
			}
			keys[key.Type()] = key
		}
		if !ok {
			// Not found firstHostPublicKey - no trust to other keys
			keys = nil
		}
		// debug("%+v", keys)
		chOut <- keys
	}()
	KeyScanCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		chIn <- key
		return fmt.Errorf(BadAlgoritm)
	}

	config := &ssh.ClientConfig{
		HostKeyCallback:   KeyScanCallback,
		HostKeyAlgorithms: []string{BadAlgoritm},
		Timeout:           TO,
	}
	// Get HostKeyAlgorithms.
	client, err := ssh.Dial("tcp", hostPort, config)
	if err != nil {
		// Look findAgreedAlgorithms from ~\go\pkg\mod\golang.org\x\crypto@v0.23.0\ssh\common.go
		if !strings.Contains(err.Error(), "ssh: no common algorithm for host key;") {
			return
		}
		ss := strings.Split(err.Error(), "server offered: [")
		if len(ss) < 2 {
			return
		}
		ss = strings.Split(ss[1], "]")
		if len(ss) < 2 {
			return
		}
		HostKeyAlgorithms := strings.Fields(ss[0]) // Ordered by supportedHostKeyAlgos

		var wg sync.WaitGroup
		// Do not search RSA again.
		CertAlgoRSA := false
		KeyAlgoRSA := false
		algoritms := NewStringSet(getHostKeyAlgorithms(args)...)
		for _, HostKeyAlgorithm := range HostKeyAlgorithms {
			switch HostKeyAlgorithm {
			case ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSAv01:
				if CertAlgoRSA {
					continue
				}
				CertAlgoRSA = true
				algoritms.Add(ssh.CertAlgoRSAv01)
			case ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA:
				if KeyAlgoRSA {
					continue
				}
				KeyAlgoRSA = true
				algoritms.Add(ssh.KeyAlgoRSA)
			}

			wg.Add(1)
			go func(HostKeyAlgorithm string) {
				defer wg.Done()
				config := &ssh.ClientConfig{
					HostKeyCallback:   KeyScanCallback,
					HostKeyAlgorithms: []string{HostKeyAlgorithm},
					Timeout:           TO,
				}
				client, err := ssh.Dial("tcp", hostPort, config)
				if err == nil {
					client.Close()
				}
			}(HostKeyAlgorithm)
		}
		wg.Wait()                         // Last dial.
		time.Sleep(time.Millisecond * 10) // Wait last KeyScanCallback.
		// Return result
		close(chIn)
		keys := <-chOut
		if keys == nil {
			return []ssh.PublicKey{firstHostPublicKey}
		}

		for _, algorithm := range algoritms.List() {
			key, ok := keys[algorithm]
			if !ok {
				continue
			}
			allHostPublicKeys = append(allHostPublicKeys, key)
		}
		return
	}
	client.Close()
	return
}

func writeKnownHost(path, host string, _ net.Addr, key ssh.PublicKey) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := ensureNewline(file); err != nil {
		return err
	}

	hostNormalized := knownhosts.Normalize(host)
	if strings.ContainsAny(hostNormalized, "\t ") {
		return fmt.Errorf("host '%s' contains spaces", hostNormalized)
	}
	line := knownhosts.Line([]string{hostNormalized}, key) + "\n"
	return writeAll(file, []byte(line))
}

func addHostKey(path, host string, remote net.Addr, key ssh.PublicKey, ask bool, args *SshArgs) error {
	keyNormalizedLine := knownhosts.Line([]string{host}, key)
	for _, acceptKey := range acceptHostKeys {
		if acceptKey == keyNormalizedLine {
			return nil
		}
	}

	once := true
	keys := []ssh.PublicKey{key}
	if ask {
		if sshLoginSuccess.Load() {
			// fmt.Fprintf(os.Stderr, "\r\n\033[0;31mThe public key of the remote server has changed after login.\033[0m\r\n")
			info("")
			// info("\033[0;31mThe public key of the remote server has changed after login.\033[0m")
			info(format31("The public key of the remote server has changed after login."))
			return fmt.Errorf("host key changed")
		}

		// fmt.Fprintf(os.Stderr, "The authenticity of host '%s' can't be established.\r\n", host)
		info("The authenticity of host '%s' can't be established.", host)

		keys = goScanHostKeys(host, key, args)

		// List other keys for select by fingerprint. Without dot at the end for copyPaste.
		for _, key := range keys {
			fingerprint := ssh.FingerprintSHA256(key)
			// fmt.Fprintf(os.Stderr, "%s key fingerprint is %s\r\n", key.Type(), fingerprint)
			info("%s key fingerprint is %s", key.Type(), fingerprint)
		}

		stdin, closer, err := getKeyboardInput()
		if err != nil {
			return err
		}
		defer closer()

		reader := bufio.NewReader(stdin)
		fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no/all/[fingerprint])? ")

	readInput:
		for {
			input, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			input = strings.TrimSpace(input)

			for _, keyByFingerprint := range keys {
				if input == ssh.FingerprintSHA256(keyByFingerprint) {
					keys = []ssh.PublicKey{keyByFingerprint}
					break readInput
				}
			}
			input = strings.ToLower(input)
			if input == "yes" {
				break
			} else if input == "no" {
				return fmt.Errorf("host key not trusted")
			} else if input == "all" {
				once = false
				break
			}
			fmt.Fprintf(os.Stderr, "Please type 'yes', 'no', 'all' or the fingerprint: ")
		}
	}

	for _, key := range keys {
		acceptHostKeys = append(acceptHostKeys, keyNormalizedLine)

		if err := writeKnownHost(path, host, remote, key); err != nil {
			warning("Failed to add the host to the list of known hosts (%s): %v", path, err)
			return nil
		}

		warning("Permanently added '%s' (%s) to the list of known hosts.", host, key.Type())
		if once {
			break
		}
	}
	return nil
}

func getHostKeyCallback(args *SshArgs, param *sshParam) (ssh.HostKeyCallback, *knownhosts.HostKeyDB, error) {
	primaryPath := ""
	var files []string
	addKnownHostsFiles := func(key string, user bool) error {
		knownHostsFiles := getOptionConfigSplits(args, key)
		if len(knownHostsFiles) == 0 {
			debug("%s is empty", key)
			return nil
		}
		if len(knownHostsFiles) == 1 && strings.ToLower(knownHostsFiles[0]) == "none" {
			debug("%s is none", key)
			return nil
		}
		for _, path := range knownHostsFiles {
			var resolvedPath string
			if user {
				path = ExpandEnv(path)
				expandedPath, err := expandTokens(path, args, param, "%CdhijkLlnpru")
				if err != nil {
					return fmt.Errorf("expand UserKnownHostsFile [%s] failed: %v", path, err)
				}
				resolvedPath = resolveHomeDir(expandedPath)
				if primaryPath == "" {
					primaryPath = resolvedPath
				}
			} else {
				resolvedPath = resolveEtcDir(path)
			}
			if !isFileExist(resolvedPath) {
				debug("%s [%s] does not exist", key, resolvedPath)
				continue
			}
			if !canReadFile(resolvedPath) {
				if user {
					warning("%s [%s] can't be read", key, resolvedPath)
				} else {
					debug("%s [%s] can't be read", key, resolvedPath)
				}
				continue
			}
			debug("add %s: %s", key, resolvedPath)
			files = append(files, resolvedPath)
		}
		return nil
	}

	if err := addKnownHostsFiles("UserKnownHostsFile", true); err != nil {
		return nil, nil, err
	}
	if err := addKnownHostsFiles("GlobalKnownHostsFile", false); err != nil {
		return nil, nil, err
	}

	khDB, err := knownhosts.NewDB(files...)
	if err != nil {
		return nil, nil, fmt.Errorf("new knownhosts failed: %v", err)
	}

	cb := func(host string, remote net.Addr, key ssh.PublicKey) error {
		kh := khDB.HostKeyCallback()
		err := kh(host, remote, key)
		if err == nil {
			return nil
		}
		strictHostKeyChecking := strings.ToLower(getOptionConfig(args, "StrictHostKeyChecking"))
		if knownhosts.IsHostKeyChanged(err) {
			path := primaryPath
			if path == "" {
				path = "~/.ssh/known_hosts"
			}
			info(format31("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
				"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"+
				"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"+
				"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n"+
				"Someone could be eavesdropping on you right now (man-in-the-middle attack)!")+"\r\n"+
				"It is also possible that a host key has just been changed.\r\n"+
				"The fingerprint for the %s key sent by the remote host is\r\n"+
				"%s\r\n"+
				"Please contact your system administrator.\r\n"+
				"Add correct host key in %s to get rid of this message.",
				key.Type(), ssh.FingerprintSHA256(key), path)
		} else if knownhosts.IsHostUnknown(err) && primaryPath != "" {
			ask := true
			switch strictHostKeyChecking {
			case "yes":
				return err
			case "accept-new", "no", "off":
				ask = false
			}
			return addHostKey(primaryPath, host, remote, key, ask, args)
		}
		switch strictHostKeyChecking {
		case "no", "off":
			return nil
		default:
			return err
		}
	}

	// return caKeysCallback(cb, caKeys(files...)), kh, nil
	return cb, khDB, nil
}

type sshSigner struct {
	path   string
	priKey []byte
	pubKey ssh.PublicKey
	signer ssh.Signer
}

func (s *sshSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *sshSigner) initSigner() error {
	if s.signer != nil {
		return nil
	}
	prompt := fmt.Sprintf("Enter passphrase for key '%s': ", s.path)
	for i := 0; i < 3; i++ {
		secret, err := readSecret(prompt)
		if err != nil {
			return err
		}
		if len(secret) == 0 {
			continue
		}
		s.signer, err = ssh.ParsePrivateKeyWithPassphrase(s.priKey, secret)
		if err == x509.IncorrectPasswordError {
			continue
		}
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("passphrase incorrect")
}

func (s *sshSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if err := s.initSigner(); err != nil {
		return nil, err
	}
	debug("sign without algorithm: %s", ssh.FingerprintSHA256(s.pubKey))
	return s.signer.Sign(rand, data)
}

func (s *sshSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if err := s.initSigner(); err != nil {
		return nil, err
	}
	if signer, ok := s.signer.(ssh.AlgorithmSigner); ok {
		debug("sign with algorithm [%s]: %s", algorithm, ssh.FingerprintSHA256(s.pubKey))
		return signer.SignWithAlgorithm(rand, data, algorithm)
	}
	debug("sign without algorithm: %s", ssh.FingerprintSHA256(s.pubKey))
	return s.signer.Sign(rand, data)
}

func newPassphraseSigner(path string, priKey []byte, err *ssh.PassphraseMissingError) *sshSigner {
	pubKey := err.PublicKey
	if pubKey == nil {
		pubPath := path + ".pub"
		pubData, err := os.ReadFile(pubPath)
		if err != nil {
			warning("read public key [%s] failed: %v", pubPath, err)
			return nil
		}
		pubKey, _, _, _, err = ssh.ParseAuthorizedKey(pubData)
		if err != nil {
			warning("parse public key [%s] failed: %v", pubPath, err)
			return nil
		}
	}
	return &sshSigner{path: path, priKey: priKey, pubKey: pubKey}
}

func isFileExist(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func canReadFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

func getSigner(dest string, path string) *sshSigner {
	path = resolveHomeDir(path)
	privateKey, err := os.ReadFile(path)
	if err != nil {
		warning("read private key [%s] failed: %v", path, err)
		return nil
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		if e, ok := err.(*ssh.PassphraseMissingError); ok {
			if passphrase := getSecretConfig(dest, "Passphrase"); passphrase != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(passphrase))
			} else {
				return newPassphraseSigner(path, privateKey, e)
			}
		}
		if err != nil {
			warning("parse private key [%s] failed: %v", path, err)
			return nil
		}
	}
	return &sshSigner{path: path, pubKey: signer.PublicKey(), signer: signer}
}

func readSecret(prompt string) (secret []byte, err error) {
	fmt.Fprintf(os.Stderr, "%s", prompt)
	// defer fmt.Fprintf(os.Stderr, "\r\n")
	defer info("")

	stdin, closer, err := getKeyboardInput()
	if err != nil {
		return nil, err
	}
	defer closer()

	return term.ReadPassword(int(stdin.Fd()))
}

func getPasswordAuthMethod(args *SshArgs, host, user string) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(args, "PasswordAuthentication")) == "no" {
		debug("disable auth method: password authentication")
		return nil
	}

	idx := 0
	rememberPassword := false
	return ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		idx++
		if idx == 1 {
			password := args.Option.get("Password")
			if password == "" {
				password = getSecretConfig(args.Destination, "Password")
			} else {
				encoded, err := encodeSecret([]byte(password))
				if err == nil {
					debug("the password for '%s' is '%s'", args.Destination, password)
					warning("insert next line\r\nIgnoreUnknown *\r\nto the beginning of the file [~/.ssh/config] and append after [Host %s] next line\r\n encPassword %s", args.Destination, encoded)
				} else {
					warning("%v", err)
				}
			}
			if password != "" {
				rememberPassword = true
				debug("trying the password configuration for '%s'", args.Destination)
				return password, nil
			}
		} else if idx == 2 && rememberPassword {
			warning("the password configuration for '%s' is incorrect", args.Destination)
		}
		secret, err := readSecret(fmt.Sprintf("%s@%s's password: ", user, host))
		if err != nil {
			return "", err
		}
		return string(secret), nil
	}), 3)
}

func readQuestionAnswerConfig(dest string, idx int, question string) string {
	qhex := hex.EncodeToString([]byte(question))
	debug("the hex code for question '%s' is %s", question, qhex)
	if answer := getSecretConfig(dest, qhex); answer != "" {
		return answer
	}

	if secret := getSecretConfig(dest, "totp"+qhex); secret != "" {
		if answer := getTotpCode(secret); answer != "" {
			return answer
		}
	}

	if command := getSecretConfig(dest, "otp"+qhex); command != "" {
		if answer := getOtpCommandOutput(command); answer != "" {
			return answer
		}
	}

	qkey := fmt.Sprintf("QuestionAnswer%d", idx)
	debug("the configuration key for question '%s' is %s", question, qkey)
	if answer := getSecretConfig(dest, qkey); answer != "" {
		return answer
	}

	qsecret := fmt.Sprintf("TotpSecret%d", idx)
	debug("the totp secret key for question '%s' is %s", question, qsecret)
	if secret := getSecretConfig(dest, qsecret); secret != "" {
		if answer := getTotpCode(secret); answer != "" {
			return answer
		}
	}

	qcmd := fmt.Sprintf("OtpCommand%d", idx)
	debug("the otp command key for question '%s' is %s", question, qcmd)
	if command := getSecretConfig(dest, qcmd); command != "" {
		if answer := getOtpCommandOutput(command); answer != "" {
			return answer
		}
	}

	return ""
}

func getKeyboardInteractiveAuthMethod(args *SshArgs, host, user string) ssh.AuthMethod {
	if strings.ToLower(getOptionConfig(args, "KbdInteractiveAuthentication")) == "no" {
		debug("disable auth method: keyboard interactive authentication")
		return nil
	}

	idx := 0
	questionSeen := make(map[string]struct{})
	questionTried := make(map[string]struct{})
	questionWarned := make(map[string]struct{})
	return ssh.RetryableAuthMethod(ssh.KeyboardInteractive(
		func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			var answers []string
			for _, question := range questions {
				idx++
				if _, seen := questionSeen[question]; !seen {
					questionSeen[question] = struct{}{}
					answer := readQuestionAnswerConfig(args.Destination, idx, question)
					if answer != "" {
						questionTried[question] = struct{}{}
						answers = append(answers, answer)
						continue
					}
				} else if _, tried := questionTried[question]; tried {
					if _, warned := questionWarned[question]; !warned {
						questionWarned[question] = struct{}{}
						warning("the question answer configuration of '%s' for '%s' is incorrect", question, args.Destination)
					}
				}
				secret, err := readSecret(fmt.Sprintf("(%s@%s) %s", user, host, strings.ReplaceAll(question, "\n", "\r\n")))
				if err != nil {
					return nil, err
				}
				answers = append(answers, string(secret))
			}
			return answers, nil
		}), 3)
}

var getDefaultSigners = func() func() []*sshSigner {
	var once sync.Once
	var signers []*sshSigner
	return func() []*sshSigner {
		once.Do(func() {
			for _, name := range []string{"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "identity"} {
				path := filepath.Join(userHomeDir, ".ssh", name)
				if !isFileExist(path) {
					continue
				}
				if signer := getSigner(name, path); signer != nil {
					signers = append(signers, signer)
				}
			}
		})
		return signers
	}
}()

func getPublicKeysAuthMethod(args *SshArgs, param *sshParam) (pubKeySigners []ssh.Signer) {
	if strings.ToLower(getOptionConfig(args, "PubkeyAuthentication")) == "no" {
		debug("disable auth method: public key authentication")
		return nil
	}

	fingerprints := NewStringSet()
	addPubKeySigners := func(signers []*sshSigner) {
		for _, signer := range signers {
			fingerprint := ssh.FingerprintSHA256(signer.pubKey)
			if fingerprints.Contains(fingerprint) {
				continue
			}
			pubKeySigners = append(pubKeySigners, addCertSigner(args, param, signer.signer, fingerprints)...)

			debug("will attempt key: %s %s %s", signer.path, signer.pubKey.Type(), ssh.FingerprintSHA256(signer.pubKey))
			fingerprints.Add(fingerprint)
			pubKeySigners = append(pubKeySigners, signer)
		}
	}

	// Ключи и сертификаты из args.Config
	if args.Config != nil {
		for _, signer := range args.Config.GetAllSigner(args.Destination) {
			addPubKeySigners([]*sshSigner{{path: "args-identity", pubKey: signer.PublicKey(), signer: signer}})
		}
		if len(pubKeySigners) > 0 { // Указаны ключи в args.Config других не ищем
			return
		}

		// А вот сертификаты из args.Config подписываем всеми доступными ключами для клиентов ssh и putty
		for _, caSigner := range args.Config.GetAllCASigner(args.Destination) {
			if caSigner.Signer != nil {
				addPubKeySigners([]*sshSigner{{path: "args-certificate", pubKey: caSigner.Signer.PublicKey(), signer: caSigner.Signer}})
			}
		}
	}

	// Ключи из IdentityAgent
	if strings.ToLower(getOptionConfig(args, "IdentitiesOnly")) == "no" {
		if agentClient := getAgentClient(args, param, "IdentityAgent"); agentClient != nil {
			signers, err := agentClient.Signers()
			if err != nil {
				warning("get ssh agent signers failed: %v", err)
			} else {
				for _, signer := range signers {
					addPubKeySigners([]*sshSigner{{path: "ssh-agent", pubKey: signer.PublicKey(), signer: signer}})
				}
			}
		}
	} else {
		debug("disable IdentityAgent by IdentitiesOnly")
	}

	// Ключи из IdentityFile
	identities := args.Identity.values
	for _, identity := range getAllOptionConfig(args, "IdentityFile") {
		expandedIdentity, err := expandTokens(identity, args, param, "%CdhijkLlnpru")
		if err != nil {
			warning("expand IdentityFile [%s] failed: %v", identity, err)
			continue
		}
		identities = append(identities, expandedIdentity)
	}

	if len(identities) == 0 { // Ключи из ~/.ssh/id_*
		addPubKeySigners(getDefaultSigners())
	} else {
		for _, identity := range identities {
			if signer := getSigner(args.Destination, identity); signer != nil {
				addPubKeySigners([]*sshSigner{signer})
			}
		}
	}

	return
}

func getAuthMethods(args *SshArgs, param *sshParam) (authMethods []ssh.AuthMethod, idKeyAlgorithms []string) {
	if signers := getPublicKeysAuthMethod(args, param); len(signers) > 0 {
		debug("add auth method: public key authentication")
		authMethods = append(authMethods, ssh.PublicKeys(signers...))

		idKeyAlgoSet := NewStringSet()
		for _, signer := range signers {
			idKeyAlgoSet.Add(signer.PublicKey().Type())

			// publicKey := signer.PublicKey()
			// algo := publicKey.Type()
			// if !idKeyAlgoSet.Contains(algo) {
			// 	idKeyAlgorithms = append(idKeyAlgorithms, algo)
			// 	idKeyAlgoSet.Add(algo)
			// }
		}
		idKeyAlgorithms = idKeyAlgoSet.List()
	}
	if authMethod := getKeyboardInteractiveAuthMethod(args, param.host, param.user); authMethod != nil {
		debug("add auth method: keyboard interactive authentication")
		authMethods = append(authMethods, authMethod)
	}
	if authMethod := getPasswordAuthMethod(args, param.host, param.user); authMethod != nil {
		debug("add auth method: password authentication")
		authMethods = append(authMethods, authMethod)
	}
	return
}

type cmdAddr struct {
	addr string
}

func (*cmdAddr) Network() string {
	return "cmd"
}

func (a *cmdAddr) String() string {
	return a.addr
}

type cmdPipe struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	addr   string
}

func (p *cmdPipe) LocalAddr() net.Addr {
	return &cmdAddr{"127.0.0.1:22"}
}

func (p *cmdPipe) RemoteAddr() net.Addr {
	return &cmdAddr{p.addr}
}

func (p *cmdPipe) Read(b []byte) (int, error) {
	return p.stdout.Read(b)
}

func (p *cmdPipe) Write(b []byte) (int, error) {
	return p.stdin.Write(b)
}

func (p *cmdPipe) SetDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) SetReadDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) SetWriteDeadline(t time.Time) error {
	return nil
}

func (p *cmdPipe) Close() error {
	err := p.stdin.Close()
	err2 := p.stdout.Close()
	if err != nil {
		return err
	}
	return err2
}

func execProxyCommand(args *SshArgs, param *sshParam) (net.Conn, string, error) {
	command, err := expandTokens(param.command, args, param, "%hnpr")
	if err != nil {
		return nil, param.command, err
	}
	command = resolveHomeDir(command)
	debug("exec proxy command: %s", command)

	argv, err := splitCommandLine(command)
	if err != nil || len(argv) == 0 {
		return nil, command, fmt.Errorf("split proxy command failed: %v", err)
	}
	if enableDebugLogging {
		for i, arg := range argv {
			debug("proxy command argv[%d] = %s", i, arg)
		}
	}
	cmd := exec.Command(argv[0], argv[1:]...)

	cmdIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, command, err
	}
	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, command, err
	}
	if err := cmd.Start(); err != nil {
		return nil, command, err
	}

	return &cmdPipe{stdin: cmdIn, stdout: cmdOut, addr: param.addr}, command, nil
}

func execLocalCommand(args *SshArgs, param *sshParam) {
	if strings.ToLower(getOptionConfig(args, "PermitLocalCommand")) != "yes" {
		return
	}
	localCmd := getOptionConfig(args, "LocalCommand")
	if localCmd == "" {
		return
	}
	expandedCmd, err := expandTokens(localCmd, args, param, "%CdfHhIijKkLlnprTtu")
	if err != nil {
		warning("expand LocalCommand [%s] failed: %v", localCmd, err)
		return
	}
	resolvedCmd := resolveHomeDir(expandedCmd)
	debug("exec local command: %s", resolvedCmd)

	argv, err := splitCommandLine(resolvedCmd)
	if err != nil || len(argv) == 0 {
		warning("split local command [%s] failed: %v", resolvedCmd, err)
		return
	}
	if enableDebugLogging {
		for i, arg := range argv {
			debug("local command argv[%d] = %s", i, arg)
		}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		warning("exec local command [%s] failed: %v", resolvedCmd, err)
	}
}

func parseRemoteCommand(args *SshArgs, param *sshParam) (string, error) {
	command := args.Option.get("RemoteCommand")
	if args.Command != "" && command != "" && strings.ToLower(command) != "none" {
		return "", fmt.Errorf("cannot execute command-line and remote command")
	}
	if args.Command != "" {
		if len(args.Argument) == 0 {
			return args.Command, nil
		}
		return shellescape.QuoteCommand(append([]string{args.Command}, args.Argument...)), nil
	}
	if strings.ToLower(command) == "none" {
		return "", nil
	}
	if command == "" {
		command = getConfig(args.Destination, "RemoteCommand")
	}
	expandedCmd, err := expandTokens(command, args, param, "%CdhijkLlnpru")
	if err != nil {
		return "", fmt.Errorf("expand RemoteCommand [%s] failed: %v", command, err)
	}
	return expandedCmd, nil
}

func parseCmdAndTTY(args *SshArgs, param *sshParam) (cmd string, tty bool, err error) {
	cmd, err = parseRemoteCommand(args, param)
	if err != nil {
		return
	}

	if args.DisableTTY && args.ForceTTY {
		err = fmt.Errorf("cannot specify -t with -T")
		return
	}
	if args.DisableTTY {
		tty = false
		return
	}
	if args.ForceTTY {
		tty = true
		return
	}

	requestTTY := getConfig(args.Destination, "RequestTTY")
	switch strings.ToLower(requestTTY) {
	case "", "auto":
		tty = isTerminal && (cmd == "")
	case "no":
		tty = false
	case "force":
		tty = true
	case "yes":
		tty = isTerminal
	default:
		err = fmt.Errorf("unknown RequestTTY option: %s", requestTTY)
	}
	return
}

func dialWithTimeout(client *ssh.Client, network, addr string, timeout time.Duration) (conn net.Conn, err error) {
	done := make(chan struct{}, 1)
	go func() {
		defer close(done)
		conn, err = client.Dial(network, addr)
		done <- struct{}{}
	}()
	select {
	case <-time.After(timeout):
		err = fmt.Errorf("dial [%s] timeout", addr)
	case <-done:
	}
	return
}

var lastServerAliveTime atomic.Pointer[time.Time]

type connWithTimeout struct {
	net.Conn
	timeout   time.Duration
	firstRead bool
}

func (c *connWithTimeout) Read(b []byte) (n int, err error) {
	if !c.firstRead {
		n, err = c.Conn.Read(b)
		if err == nil {
			now := time.Now()
			lastServerAliveTime.Store(&now)
		}
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		defer close(done)
		n, err = c.Conn.Read(b)
		done <- struct{}{}
	}()
	select {
	case <-time.After(c.timeout):
		err = fmt.Errorf("first read timeout")
	case <-done:
	}
	c.firstRead = false
	return
}

func setupLogLevel(args *SshArgs) func() {
	previousDebug := enableDebugLogging
	previousWarning := enableWarningLogging
	reset := func() {
		enableDebugLogging = previousDebug
		enableWarningLogging = previousWarning
	}
	if args.Debug {
		enableDebugLogging = true
		enableWarningLogging = true
		return reset
	}
	switch strings.ToLower(getOptionConfig(args, "LogLevel")) {
	case "quiet", "fatal", "error":
		enableDebugLogging = false
		enableWarningLogging = false
	case "debug", "debug1", "debug2", "debug3":
		enableDebugLogging = true
		enableWarningLogging = true
	case "info", "verbose":
		fallthrough
	default:
		enableDebugLogging = false
		enableWarningLogging = true
	}
	return reset
}

func getNetworkAddressFamily(args *SshArgs) string {
	if args.IPv4Only {
		if args.IPv6Only {
			return "tcp"
		}
		return "tcp4"
	}
	if args.IPv6Only {
		return "tcp6"
	}
	switch strings.ToLower(getOptionConfig(args, "AddressFamily")) {
	case "inet":
		return "tcp4"
	case "inet6":
		return "tcp6"
	default:
		return "tcp"
	}
}

func sshConnect(args *SshArgs, client *ssh.Client, proxy string) (*ssh.Client, *sshParam, bool, error) {
	param, err := getSshParam(args)
	if err != nil {
		return nil, nil, false, err
	}

	// resetLogLevel := setupLogLevel(args)
	// defer resetLogLevel()

	if client := connectViaControl(args, param); client != nil {
		return client, param, true, nil
	}

	authMethods, idKeyAlgorithms := getAuthMethods(args, param)
	cb, kh, err := getHostKeyCallback(args, param)
	if err != nil {
		return nil, param, false, err
	}
	config := &ssh.ClientConfig{
		User:              param.user,
		Auth:              authMethods,
		Timeout:           10 * time.Second,
		HostKeyCallback:   cb,
		HostKeyAlgorithms: kh.HostKeyAlgorithms(param.addr),
		BannerCallback: func(banner string) error {
			_, err := fmt.Fprint(os.Stderr, "Banner of ", param.addr, ":", strings.ReplaceAll(banner, "\n", "\r\n"))
			return err
		},
		ClientVersion: "SSH-2.0-" + "tssh_" + kTsshVersion,
	}
	// Перед вызовом setupHostKeyAlgorithmsConfig должен быть установлен HostKeyAlgorithms.
	// >If hostkeys are known for the destination host then this default is modified to prefer their algorithms.
	// debug("HostKeyAlgorithms %v", config.HostKeyAlgorithms)
	debug("IdKeyAlgorithms %v", idKeyAlgorithms)
	// kh после https://github.com/skeema/knownhosts/tree/certs-backwards-compat уже понимает @cert-authority
	// но пока не объединили с main добавим idKeyAlgorithms
	// config.HostKeyAlgorithms = NewStringSet(config.HostKeyAlgorithms...).Add(idKeyAlgorithms...).List()
	setupHostKeyAlgorithmsConfig(args, config)
	setupKexAlgorithmsConfig(args, config)

	if err := setupCiphersConfig(args, config); err != nil {
		return nil, param, false, err
	}

	network := getNetworkAddressFamily(args)

	proxyConnect := func(client *ssh.Client, proxy string) (*ssh.Client, *sshParam, bool, error) {
		debug("login to [%s], addr: %s", args.Destination, param.addr)
		conn, err := dialWithTimeout(client, network, param.addr, 10*time.Second)
		if err != nil {
			return nil, param, false, fmt.Errorf("proxy [%s] dial tcp [%s] failed: %v", proxy, param.addr, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
		if err != nil {
			return nil, param, false, fmt.Errorf("proxy [%s] new conn [%s] failed: %v", proxy, param.addr, err)
		}
		debug("login to [%s] success", args.Destination)
		return ssh.NewClient(ncc, chans, reqs), param, false, nil
	}

	// has parent client
	if client != nil {
		return proxyConnect(client, proxy)
	}

	// proxy command
	if param.command != "" {
		debug("login to [%s], addr: %s", args.Destination, param.addr)
		conn, cmd, err := execProxyCommand(args, param)
		if err != nil {
			return nil, param, false, fmt.Errorf("exec proxy command [%s] failed: %v", cmd, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(conn, param.addr, config)
		if err != nil {
			return nil, param, false, fmt.Errorf("proxy command [%s] new conn [%s] failed: %v", cmd, param.addr, err)
		}
		debug("login to [%s] success", args.Destination)
		return ssh.NewClient(ncc, chans, reqs), param, false, nil
	}

	// no proxy
	if len(param.proxy) == 0 {
		debug("login to [%s], addr: %s", args.Destination, param.addr)
		conn, err := net.DialTimeout(network, param.addr, config.Timeout)
		if err != nil {
			return nil, param, false, fmt.Errorf("dial tcp [%s] failed: %v", param.addr, err)
		}
		ncc, chans, reqs, err := ssh.NewClientConn(&connWithTimeout{conn, config.Timeout, true}, param.addr, config)
		if err != nil {
			return nil, param, false, fmt.Errorf("new conn [%s] failed: %v", param.addr, err)
		}
		debug("login to [%s] success", args.Destination)
		return ssh.NewClient(ncc, chans, reqs), param, false, nil
	}

	// has proxies
	var proxyClient *ssh.Client
	for _, proxy = range param.proxy {
		proxyClient, _, _, err = sshConnect(&SshArgs{Destination: proxy}, proxyClient, proxy)
		if err != nil {
			return nil, param, false, err
		}
	}
	return proxyConnect(proxyClient, proxy)
}

func keepAlive(client *ssh.Client, args *SshArgs) {
	getOptionValue := func(option string) int {
		value, err := strconv.Atoi(getOptionConfig(args, option))
		if err == nil {
			return value
		}
		return 0
	}

	serverAliveInterval := getOptionValue("ServerAliveInterval")
	if serverAliveInterval <= 0 {
		return
		// serverAliveInterval = 10
	}
	serverAliveCountMax := getOptionValue("ServerAliveCountMax")
	if serverAliveCountMax <= 0 {
		serverAliveCountMax = 3
	}

	go func() {
		intervalTime := time.Duration(serverAliveInterval) * time.Second
		t := time.NewTicker(intervalTime)
		defer t.Stop()
		n := 0
		for range t.C {
			if lastTime := lastServerAliveTime.Load(); lastTime != nil && time.Since(*lastTime) < intervalTime {
				n = 0
				continue
			}
			if _, _, err := client.SendRequest("keepalive@trzsz-ssh", true, nil); err != nil {
				n++
				if n >= serverAliveCountMax {
					client.Close()
					return
				}
			} else {
				n = 0
			}
		}
	}()
}

// Нужен ли перенос агента.
// Если да то находим пайп агента, ищем не используется ли этот пайп для IdentityAgent если используется дописываем сессию
// иначе добавляем агента в список агентов
func sshAgentForward(args *SshArgs, param *sshParam, client *ssh.Client, session *ssh.Session) {
	if ForwardAgent := getOptionConfig(args, "ForwardAgent"); !args.ForwardAgent &&
		(args.NoForwardAgent || ForwardAgent == "" || strings.EqualFold(ForwardAgent, "no")) {
		return
	}

	addr, err := getForwardAgentAddr(args, param)
	if err != nil {
		warning("get forward agent addr failed: %v", err)
		return
	}
	addr = filepath.Clean(addr)
	_, ok := agents[addr]
	if !ok {
		// Не было IdentityAgent
		extendedAgent := getAgentClient(args, param, "ForwardAgent")
		if extendedAgent == nil {
			return
		}
		agents[addr] = &xAgent{extendedAgent: extendedAgent}
	}
	agents[addr].client = client
	agents[addr].session = session
}

func sshLogin(args *SshArgs) (ss *sshSession, err error) {
	ss = &sshSession{}
	var param *sshParam
	defer func() {
		if err != nil {
			ss.Close()
		} else {
			sshLoginSuccess.Store(true)
			// execute local command if necessary
			execLocalCommand(args, param)
		}
	}()

	// ssh login
	var control bool
	ss.client, param, control, err = sshConnect(args, nil, "")
	if err != nil {
		return
	}

	// parse cmd and tty
	ss.cmd, ss.tty, err = parseCmdAndTTY(args, param)
	if err != nil {
		return
	}

	// keep alive
	if !control {
		keepAlive(ss.client, args)
	}

	// stdio forward
	if args.StdioForward != "" {
		return
	}

	// ssh forward
	if !control {
		sshForward(ss.client, args, param)
	}

	// no command
	if args.NoCommand {
		return
	}

	// new session
	ss.session, err = ss.client.NewSession()
	if err != nil {
		err = fmt.Errorf("ssh new session failed: %v", err)
		return
	}

	// send and set env
	var term string
	term, err = sendAndSetEnv(args, ss.session)
	if err != nil {
		return
	}

	// session input and output
	ss.serverIn, err = newServerWriteCloser(ss.session) //ss.session.StdinPipe()
	if err != nil {
		err = fmt.Errorf("stdin pipe failed: %v", err)
		return
	}
	ss.serverOut, err = ss.session.StdoutPipe()
	if err != nil {
		err = fmt.Errorf("stdout pipe failed: %v", err)
		return
	}
	ss.serverErr, err = ss.session.StderrPipe()
	if err != nil {
		err = fmt.Errorf("stderr pipe failed: %v", err)
		return
	}

	if !control {
		afterLoginFuncs.Add(func() {

			// x11 forward
			sshX11Forward(args, ss.client, ss.session)
		})

		sshAgentForward(args, param, ss.client, ss.session)
	}

	// not terminal or not tty
	if !isTerminal || !ss.tty {
		return
	}

	// request pty session
	width, height, err := getTerminalSize()
	if err != nil {
		err = fmt.Errorf("get terminal size failed: %v", err)
		return
	}
	if term == "" {
		term = os.Getenv("TERM")
		if term == "" {
			term = "xterm-256color"
		}
	}
	if err = ss.session.RequestPty(term, height, width, ssh.TerminalModes{}); err != nil {
		err = fmt.Errorf("request pty failed: %v", err)
		return
	}

	return
}
