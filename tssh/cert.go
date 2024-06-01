package tssh

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/trzsz/ssh_config"
	"golang.org/x/crypto/ssh"
)

type HostsCerts map[string]string

// Ищем сертификаты хостов в KnownHosts файлах
func caKeys(files ...string) HostsCerts {
	hostCerts := make(HostsCerts)
	const CertAuthority = "cert-authority"
	var (
		marker string
		hosts  []string
		pubKey ssh.PublicKey
	)
	for _, file := range files {
		rest, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if !bytes.Contains(rest, []byte("@"+CertAuthority+" ")) {
			continue
		}
	parse:
		for {
			marker, hosts, pubKey, _, rest, err = ssh.ParseKnownHosts(rest)
			if err != nil {
				if err == io.EOF {
					break parse
				}
				continue parse
			}
			if marker != CertAuthority {
				continue parse
			}
			csHosts := strings.Join(hosts, ",")
			debug("@%s %s %s", marker, csHosts, ssh.FingerprintSHA256(pubKey))
			hostCerts[ssh.FingerprintSHA256(pubKey)] = csHosts
		}
	}
	return hostCerts
}

// Если найдены сертификаты хостов то возвращаем ssh.CertChecker.CheckHostKey иначе cb
func caKeysCallback(cb ssh.HostKeyCallback, hostCerts HostsCerts) ssh.HostKeyCallback {
	if len(hostCerts) == 0 {
		return cb
	}
	certCheck := &ssh.CertChecker{
		IsHostAuthority: func(p ssh.PublicKey, addr string) bool {
			fingerprint := ssh.FingerprintSHA256(p)
			hosts, ok := hostCerts[fingerprint]
			if ok {
				if hosts != "*" {
					h, _, err := net.SplitHostPort(addr)
					ok = false
					if err == nil {
						for _, host := range strings.Split(hosts, ",") {
							if h != host {
								continue
							}
							ok = true
							break
						}
					}
				}
			}
			s := ""
			if !ok {
				s = "not "
			}
			debug("host %s %sknown by certificate %s", addr, s, fingerprint)
			return ok
		},
		HostKeyFallback: cb,
	}
	return certCheck.CheckHostKey
}

var KeyAlgo2id = map[string]string{
	ssh.KeyAlgoRSA:        "id_rsa",
	ssh.KeyAlgoDSA:        "id_dsa",
	ssh.KeyAlgoECDSA256:   "id_ecdsa",
	ssh.KeyAlgoSKECDSA256: "id_ecdsa-sk",
	ssh.KeyAlgoECDSA384:   "id_ecdsa",
	ssh.KeyAlgoECDSA521:   "id_ecdsa",
	ssh.KeyAlgoED25519:    "id_ed25519",
	ssh.KeyAlgoSKED25519:  "id_ecdsa-sk",
}

// Добавляем в слайс pubKeySigners ключи сертификатов
// Добавляем в набор fingerprints отпечаток замка
//
// IdentityFile + "-cert" or IdentityFile + "-cert.pub" or CertificateFile
// Используем в addPubKeySigners
func addCertSigner(args *SshArgs, param *sshParam, signer ssh.Signer, fingerprints *StringSet) (pubKeySigners []ssh.Signer) {
	const SW = " signed with "
	pubKey := signer.PublicKey()
	pref, ok := KeyAlgo2id[pubKey.Type()]
	if !ok {
		// Не поддерживается KeyAlgo
		return
	}
	fpSigner := ssh.FingerprintSHA256(pubKey)
	userHomeSsh := filepath.Join(userHomeDir, ".ssh")

	if args.Config != nil {
		// Шаблоны сертификатов из args.Config подписываем signer
		// если IsInclude то пишем в файлы для клиентов ssh и putty
		for _, CASigner := range args.Config.GetAllCASigner(args.Destination) {
			fpCA := ssh.FingerprintSHA256(CASigner.Signer.PublicKey())
			fingerprint := fpSigner + SW + fpCA
			if fingerprints.Contains(fingerprint) {
				debug("has already %s", fingerprint)
				continue
			}
			cert := NewCertificate(
				CASigner.Certificate.Serial,
				CASigner.Certificate.CertType,
				CASigner.Certificate.KeyId,
				CASigner.Certificate.ValidBefore,
				CASigner.Certificate.ValidAfter,
				CASigner.Certificate.ValidPrincipals...,
			)
			cert.Key = pubKey
			if err := cert.SignCert(rand.Reader, CASigner.Signer); err != nil {
				warning("%v", err)
				continue
			}
			certSigner, err := ssh.NewCertSigner(&cert, signer)
			if err != nil {
				warning("%v", err)
				continue
			}
			certPubKey := certSigner.PublicKey()
			debug("will attempt key: %s %s %s", "args-certificate", certPubKey.Type(), ssh.FingerprintSHA256(certPubKey))
			fingerprints.Add(fingerprint)
			pubKeySigners = append(pubKeySigners, certSigner)

			// Пишем авторизацию хоста для ssh и putty
			if fpSigner == fpCA {
				pref = "ca"
				bb := bytes.NewBufferString("@cert-authority * ")
				bb.Write(ssh.MarshalAuthorizedKey(pubKey))
				err = writeFile(filepath.Join(userHomeSsh, cert.KeyId), bb.Bytes(), 0644)
				if err != nil {
					warning("%v", err)
				}
			}
			// Пишем авторизацию клиента для ssh и putty
			if args.Config.IsInclude(args.Destination) {
				err := writeFile(filepath.Join(userHomeSsh, pref+"-cert.pub"),
					ssh.MarshalAuthorizedKey(&cert), 0644)
				if err != nil {
					warning("%v", err)
				}
				// А можно ли без этого обойтись?
				// err = writeFile(filepath.Join(userHomeSsh, pref+".pub"), data, 0644)
				// if err != nil {
				// 	warning("%v", err)
				// }
			}
		}
	}
	path := filepath.Join(userHomeSsh, pref+"-cert")

	paths := []string{}
	certificateFiles := getAllOptionConfig(args, "CertificateFile")
	if len(certificateFiles) == 0 {
		paths = append(paths, path)
		paths = append(paths, path+".pub")
	} else {
		for _, path := range certificateFiles {
			path = expandEnv(path)
			expanded, err := expandTokens(path, args, param, "%CdhijkLlnpru")
			if err != nil {
				warning("expand CertificateFile [%s] failed: %v", path, err)
				continue
			}
			paths = append(paths, resolveHomeDir(expanded))
		}
	}
	// Читаем сертификаты из id_x-cert или те что указаны в CertificateFile.
	// Подписываем их signer и добавляем в pubKeySigners
	for _, path := range paths {
		if !isFileExist(path) {
			continue
		}
		pubKeyBytes, err := os.ReadFile(path)
		if err != nil {
			warning("%v", err)
			continue
		}
		// Пока один замок. Надо несколько замков
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
		if err != nil {
			warning("%v", err)
			continue
		}
		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			continue
		}
		fpSigner := ssh.FingerprintSHA256(cert.Key)
		fpCA := ssh.FingerprintSHA256(cert.SignatureKey)
		fingerprint := fpSigner + " signed with " + fpCA
		if fingerprints.Contains(fingerprint) {
			debug("has already %s", fingerprint)
			continue
		}
		if cert.CertType != ssh.UserCert {
			continue
		}
		if !bytes.Equal(pubKey.Marshal(), cert.Key.Marshal()) {
			continue
		}
		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			warning("%v", err)
			continue
		}
		certPubKey := certSigner.PublicKey()
		debug("will attempt key: %s %s %s", path, certPubKey.Type(), ssh.FingerprintSHA256(certPubKey))
		fingerprints.Add(fingerprint)
		pubKeySigners = append(pubKeySigners, certSigner)
	}
	return
}

// Если переменные окружения найдены тогда заменяем
func expandEnv(s string) string {
	if !strings.Contains(s, "$") || strings.Count(s, "${") != strings.Count(s, "}") {
		return s
	}
	LookupEnv := func(key string) string {
		if value, ok := os.LookupEnv(key); ok {
			return value
		}
		// Не найдена переменная окружения
		if strings.Contains(s, "${") {
			return fmt.Sprintf("${%s}", key)
		}
		return fmt.Sprintf("$%s", key)
	}
	return os.Expand(s, LookupEnv)
}

func unquote(s string) string {
	u, err := strconv.Unquote(s)
	if err != nil {
		return s
	}
	return u
	// ss, err := splitCommandLine(s)
	// if err != nil || len(ss) == 0 {
	// 	return s
	// }
	// return ss[0]
}

//------------------------------------------------

type CASigner struct {
	ssh.Certificate // func newCertificate
	ssh.Signer      // CA signer
}

func NewCASigner(Certificate ssh.Certificate, Signer ssh.Signer) *CASigner {
	return &CASigner{
		Certificate: Certificate,
		Signer:      Signer,
	}
}

func NewCertificate(
	Serial uint64,
	CertType uint32,
	KeyId string,
	ValidBefore uint64,
	ValidAfter uint64,
	ValidPrincipals ...string,
) ssh.Certificate {
	var permits = make(map[string]string)
	for _, permit := range []string{
		"X11-forwarding",
		"agent-forwarding",
		"port-forwarding",
		"pty",
		"user-rc",
	} {
		permits["permit-"+permit] = ""
	}

	return ssh.Certificate{
		Serial:          Serial,
		CertType:        CertType,
		KeyId:           KeyId,
		ValidBefore:     ValidBefore,
		ValidAfter:      ValidAfter,
		ValidPrincipals: ValidPrincipals,
		Permissions:     ssh.Permissions{Extensions: permits},
	}
}

type Config struct {
	*ssh_config.Config
	Signers  map[string][]ssh.Signer // id signer
	CASigner map[string][]*CASigner  // CA signer
	Include  *StringSet              // Писать ли алиас в config и файлы id_x-cert.pub
}

func NewConfig(config *ssh_config.Config) *Config {
	return &Config{
		Config:   config,
		Signers:  make(map[string][]ssh.Signer),
		CASigner: make(map[string][]*CASigner),
		Include:  NewStringSet(),
	}
}

func (c *Config) GetAllSigner(alias string) []ssh.Signer {
	return c.Signers[alias]
}

func (c *Config) GetAllCASigner(alias string) []*CASigner {
	return c.CASigner[alias]
}
func (c *Config) IsInclude(alias string) bool {
	return c.Include.Contains(alias)
}

func (f *Config) UnmarshalText(b []byte) error {
	return nil
}

// Пишем файл name если его содержимое отличается от data
func writeFile(name string, data []byte, perm fs.FileMode) error {
	old, err := os.ReadFile(name)
	if err != nil || !bytes.EqualFold(old, data) {
		return os.WriteFile(name, data, perm)
	}
	return nil
}
