package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/abakum/dssh/tssh"
	"github.com/abakum/pageant"
	"github.com/abakum/winssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Время модификации
func ModTime(name string) (unix int64) {
	info, err := os.Stat(name)
	if err == nil {
		unix = info.ModTime().Unix()
	}
	return
}

// Возвращаем сигнеров от агента, и сертификаты от агента и самоподписанный сертификат ЦС.
// Пишем ветку реестра SshHostCAs для putty клиента и файл UserKnownHostsFile для ssh клиента чтоб они доверяли хосту по сертификату от ЦС caSigner.
// Если новый ключ ЦС (.ssh/ca.pub) или новый ключ от агента пишем сертификат в файл для ssh клиента и ссылку на него в реестр для putty клиента чтоб хост с ngrokSSH им доверял.
// Если новый ключ ЦС пишем конфиги и сертифкаты для sshd от OpenSSH чтоб sshd доверял клиентам putty, ssh.
func getSigners(caSigner ssh.Signer, id string, principals ...string) (signers []ssh.Signer, userKnownHostsFile string) {
	// разрешения для сертификата пользователя
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

	ss := []ssh.Signer{caSigner}
	// agent
	rw, err := pageant.NewConn()
	if err == nil {
		defer rw.Close()
		ea := agent.NewClient(rw)
		eas, err := ea.Signers()
		if err == nil {
			ss = append(ss, eas...)
		}
	}
	// в ss ключ ЦС caSigner и ключи от агента
	if len(ss) < 2 {
		Println(fmt.Errorf("no keys from agent - не получены ключи от агента %v", err))
	}
	userKnownHostsFile = filepath.Join(SshUserDir, id)
	newCA := false
	for i, idSigner := range ss {
		signers = append(signers, idSigner)

		pub := idSigner.PublicKey()

		pref := "ca"
		if i > 0 {
			ok := false
			pref, ok = tssh.KeyAlgo2id[pub.Type()]
			if !ok {
				continue
			}
		}

		data := ssh.MarshalAuthorizedKey(pub)
		name := filepath.Join(SshUserDir, pref+".pub")
		old, err := os.ReadFile(name)
		newPub := err != nil || !bytes.Equal(data, old)
		var mtCA int64
		if i == 0 { // CA
			newCA = newPub
			if newCA {
				certHost(caSigner, repo)
			}
		}
		if newPub {
			Println(name, os.WriteFile(name, data, FILEMODE))
			if i == 0 { // ca.pub  idSigner is caSigner
				bb := bytes.NewBufferString("@cert-authority * ")
				bb.Write(data)
				// пишем файл UserKnownHostsFile для ssh клиента чтоб он доверял хосту по сертификату ЦС caSigner
				Println(userKnownHostsFile, os.WriteFile(userKnownHostsFile, bb.Bytes(), FILEMODE))
				// for putty ...they_verify_me_by_certificate
				// пишем SshHostCAs для putty клиента чтоб он доверял хосту по сертификату ЦС caSigner
				// PuttyHostCA(id, strings.TrimSpace(strings.TrimPrefix(string(data), pub.Type())))
				Conf(filepath.Join(SshHostCAs, id), EQ, map[string]string{
					"PublicKey":       strings.TrimSpace(strings.TrimPrefix(string(data), pub.Type())),
					"Validity":        "*",
					"PermitRSASHA1":   "0",
					"PermitRSASHA256": "1",
					"PermitRSASHA512": "1",
				})
			}
		}
		mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner),
			[]string{caSigner.PublicKey().Type()})
		if err != nil {
			Println(err)
			continue
		}
		//ssh-keygen -s ca -I id -n user -V forever ~\.ssh\id_*.pub
		certificate := ssh.Certificate{
			Key:             idSigner.PublicKey(),
			CertType:        ssh.UserCert,
			KeyId:           id,
			ValidBefore:     ssh.CertTimeInfinity,
			ValidPrincipals: principals,
			Permissions:     ssh.Permissions{Extensions: permits},
		}
		if certificate.SignCert(rand.Reader, mas) != nil {
			Println(err)
			continue
		}

		certSigner, err := ssh.NewCertSigner(&certificate, idSigner)
		if err != nil {
			Println(err)
			continue
		}
		// добавляем сертификат в слайс результата signers
		signers = append(signers, certSigner)

		if i == 0 { // CA
			mtCA = ModTime(name)
		}

		//если новый ключ ЦС или новый ключ от агента пишем сертификат в файл для ssh клиента и ссылку на него в реестр для putty клиента
		name = filepath.Join(SshUserDir, pref+"-cert.pub")
		if newCA || newPub || mtCA > ModTime(name) {
			err = os.WriteFile(name,
				ssh.MarshalAuthorizedKey(&certificate),
				FILEMODE)
			Println(name, err)
			if i == 1 {
				// пишем ссылку на один сертификат (первый) в ветку реестра id для putty клиента
				if err == nil {
					// for I_verify_them_by_certificate_they_verify_me_by_certificate
					// PuTTY -load id user@host
					// Пишем сертификат value для putty клиента
					// PuttySessionCert(id, name)
					Conf(filepath.Join(Sessions, id), EQ, map[string]string{"DetachedCertificate": name})
					// PuttySessionCert(SSHJ, name)
					Conf(filepath.Join(Sessions, SSHJ), EQ, map[string]string{"DetachedCertificate": name})
				}
				// PuTTY
				Conf(filepath.Join(Sessions, "Default%20Settings"), EQ, newMap(Keys, Defs))
				// PuttySession("Default%20Settings", Keys, Defs)
			}
		}
	}
	return
}

// net.SplitHostPort со значениями по умолчанию
func SplitHostPort(hp, host, port string) (h, p string) {
	hp = strings.ReplaceAll(hp, "*", ALL)
	h, p, err := net.SplitHostPort(hp)
	if err == nil {
		if p == "" {
			p = port
		}
		if h == "" {
			h = host
		}
		return h, p
	}
	// Нет :
	// _, err = strconv.Atoi(hp)
	// if err == nil {
	// 	return host, hp
	// }
	if hp == "" {
		hp = host
	}
	return hp, port
}

func UserHomeDir(s string) string {
	if strings.HasPrefix(s, "~") {
		s = filepath.Join(winssh.UserHomeDirs(), strings.TrimPrefix(s, "~"))
	}
	return s
}
