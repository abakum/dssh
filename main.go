package main

/*
git clone https://github.com/abakum/dssh
cd dssh
Копируем dssh.zip в .
unzip -a dssh.zip
go run github.com/abakum/embed-encrypt
go install

В файл ~/.ssh/config дописываются алиасы хостов dssh, ssh-j, ssh-j.com.
На всякий случай создаются копии старых файлов .old
Создаются файлы ~/.ssh/ssh-j  и ~/.ssh/dssh

Если запускается dssh -P то:
Создаются файлы сессий из ~/.ssh/config в ~/.putty/sessions
Создаются файлы сертификатов хостов  в ~/.putty/sshhostcas
Переписывается файл ~/.putty/sshhostkeys замками ssh-j.com
*/

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	rdebug "runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/abakum/menu"
	"github.com/abakum/putty_hosts"
	"github.com/abakum/winssh"
	"github.com/trzsz/go-arg"
	"github.com/trzsz/ssh_config"

	. "github.com/abakum/dssh/tssh"
	version "github.com/abakum/version/lib"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
)

type Parser struct {
	*arg.Parser
}

func (p *Parser) WriteHelp(w io.Writer) {
	var b bytes.Buffer
	p.Parser.WriteHelp(&b)
	s := strings.Replace(b.String(), "  -v, --version          show program's version number and exit\n", "", 1)
	fmt.Fprint(w, s)

}

func NewParser(config arg.Config, dests ...interface{}) (*Parser, error) {
	p, err := arg.NewParser(config, dests...)
	return &Parser{p}, err
}

const (
	PORT     = "22"
	ALL      = "0.0.0.0"
	LH       = "127.0.0.1"
	FILEMODE = 0644
	DIRMODE  = 0755
	TOR      = time.Second * 15 //reconnect TO
	TOW      = time.Second * 5  //watch TO
	SSH2     = "SSH-2.0-"
	OSSH     = "OpenSSH_for_Windows"
	RESET    = "-r"
	SSHJ     = "ssh-j"
	SSHJ2    = "127.0.0.2"
	JumpHost = SSHJ + ".com"
	EQ       = "="
	TERM     = "xterm-256color"
)

var (
	_    = encryptedfs.ENC
	_    = version.Ver
	Keys = []string{
		"UserName", "HostName", "PortNumber", "AgentFwd",
		"RemoteForward", "LocalForward", "DynamicForward",
		"ProxyHost", "ProxyMethod", "ProxyUsername", "ProxyPort", "ProxyLocalhost",
		"Protocol", "WarnOnClose", "FullScreenOnAltEnter", "TerminalType",
	}
	Defs = []string{
		winssh.UserName(), LH, PORT, "0",
		"", "", "",
		"", "0", "", PORT, "1",
		"ssh", "0", "1", TERM,
	}
	SshUserDir = winssh.UserHomeDirs(".ssh")
	Cfg        = filepath.Join(SshUserDir, "config")
	KnownHosts = filepath.Join(SshUserDir, "known_hosts")
	args       SshArgs
	Std        = menu.Std
	repo       = base() // Имя репозитория `dssh` оно же имя алиаса в .ssh/config
	imag       string   // Имя исполняемого файла `dssh` оно же имя посредника. Можно изменить чтоб не указывать имя посредника.
)

//go:generate go run github.com/abakum/version
//go:generate go run cmd/main.go
//go:generate go run github.com/abakum/embed-encrypt
//go:generate go list -f '{{.EmbedFiles}}'

//encrypted:embed internal/ca
var CA []byte // Ключ ЦС

//go:embed VERSION
var Ver string

// `dssh` `dssh -d` `dssh :` - args.Daemon или args.Dest==`:` значит сервер если имя пустое пустое значит `dssh`
//
//	запустит сервер ssh на адресе `127.0.0.1:2222`
//	подготовит алиас `ssh-j.com` и запустит его для переноса сессии с белого адреса `ssh-j.com:22` на серый `127.0.0.1:2222`
//	подготовит алиас `dssh` для подключения к серверу локально
//	подготовит алиас `ssh-j` для подключения к серверу через `dssh@ssh-j.com`
//	`dssh dssh` подключится к серверу локально.
//	`dssh @` подключится к серверу через посредника `dssh@ssh-j.com`.
//
//	`dssh -d foo@` - args.Daemon значит сервер а имя `foo`
//	Можно переименовать `dssh` в `foo` и запустить `foo`
//	`dssh foo@` подключится к нему через посредника `foo@ssh-j.com`.
//	Можно переименовать `dssh` в `foo` и запустить `foo @`
func main() {
	SetColor()

	// tssh
	DebugPrefix = l.Prefix()
	DebugF = func(format string) string {
		return fmt.Sprintf("%s%s %s\r\n", l.Prefix(), src(9), format)
	}
	WarningF = func(format string) string {
		return fmt.Sprintf("%s%s %s\r\n", le.Prefix(), src(9), format)
	}

	exe, err := os.Executable()
	Fatal(err)
	imag = strings.Split(filepath.Base(exe), ".")[0]

	ips := ints()
	Println(runtime.GOARCH, runtime.GOOS, GoVer(), repo, Ver, ips)
	FatalOr("not connected - нет сети", len(ips) == 0)

	key, err := x509.ParsePKCS8PrivateKey(CA)
	Fatal(err)

	// CA signer
	signer, err := ssh.NewSignerFromKey(key)
	Fatal(err)

	defer closer.Close()
	closer.Bind(cleanup)

	// Like `parser := arg.MustParse(&args)` but override built in option `-v, --version` of package `arg`
	parser, err := NewParser(arg.Config{}, &args)
	Fatal(err)

	a2s := make([]string, 0) // without built in option
	deb := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-help", "--help":
			parser.WriteHelp(Std)
			return
		case "-h":
			parser.WriteUsage(Std)
			return
		case "-version", "--version":
			Println(args.Version())
			return
		case "-v":
			deb = true
		default:
			a2s = append(a2s, arg)
		}
	}

	if err := parser.Parse(a2s); err != nil {
		parser.WriteUsage(Std)
		Fatal(err)
	}
	if args.Ver {
		Println(args.Version())
		return
	}
	args.Debug = args.Debug || deb

	sshj := `
Host ` + SSHJ + `
 User _
 HostName ` + SSHJ2 + `
 UserKnownHostsFile ~/.ssh/` + repo + `
 KbdInteractiveAuthentication no
 PasswordAuthentication no
 ProxyJump ` + repo + `@` + JumpHost
	u, h, p := ParseDestination(args.Destination) //tssh
	if h == "" && p == "" && strings.Contains(args.Destination, ":") {
		args.Daemon = true
	}
	if u == "" {
		u = imag // Имя для посредника ssh-j.com
	}
	if args.Daemon {
		hh := ""
		switch h {
		case "":
			h = LH
			hh = h
		case "*":
			h = ALL
			hh = ips[len(ips)-1]
		case "_":
			h = ips[0]
			hh = h
		}
		if p == "" {
			p = "2222"
		}

		go func() {
			s := useLineShort(u, repo, imag)
			for {
				server(h, p, repo, s, signer)
				winssh.KidsDone(os.Getpid())
				Println("server has been stopped - сервер остановлен")
				time.Sleep(TOR)
			}
		}()
		rc := "-T "
		if args.Debug {
			rc += "--debug "
		}
		rc += JumpHost
		// var args SshArgs
		// mustParse(&args, strings.Fields(rc))
		args.Destination = JumpHost
		args.DisableTTY = true
		client(signer, local(hh, p, repo)+sshj+sshJ(JumpHost, u, hh, p))
		s := fmt.Sprintf("`tssh %s`", rc)
		i := 0
		for {
			Println(s, "has been started")
			code := TsshMain(&args)
			if code == 0 {
				i = 0
			} else {
				if i > 3 || i == 0 {
					return
				}
				i++
			}
			time.Sleep(TOR)
		}
	} // Сервис

	// Клиенты
	if h == "" && p == "" {
		// `dssh user@` or just `dssh`
		args.Destination = SSHJ
		client(signer, sshj, SSHJ)
		Println(Errorf("tssh exit with code:%d", TsshMain(&args)))
		return
	}
	switch args.Destination {
	case repo, SSHJ:
		client(signer, sshj, args.Destination)
	}
	code := TsshMain(&args)
	if args.Background {
		Println("tssh started in background with code:", code)
		closer.Hold()
	} else {
		Println("tssh exit with code:", code)
	}
}

// tssh
func canReadFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

// tssh
func isFileExist(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// Пишем config для ssh клиентов
func client(signer ssh.Signer, config string, hosts ...string) {
	cfg, err := ssh_config.Decode(strings.NewReader(config))
	if err != nil {
		Println(err)
		return
	}
	Println(config)
	args.Config = NewConfig(cfg)

	cert := NewCertificate(0, ssh.UserCert, repo, ssh.CertTimeInfinity, 0, repo)
	caSigner := []*CASigner{NewCASigner(cert, signer)}
	for i, alias := range hosts {
		// args.Config.Signers[alias] = []ssh.Signer{signer} // Не буду использовать CA как ключ
		args.Config.CASigner[alias] = caSigner
		args.Config.Include.Add(alias)

		if args.ForPutty {
			if i == 0 {
				Conf(filepath.Join(Sessions, "Default%20Settings"), EQ, newMap(Keys, Defs))
				data := ssh.MarshalAuthorizedKey(signer.PublicKey())
				Conf(filepath.Join(SshHostCAs, alias), EQ, map[string]string{
					"PublicKey":       strings.TrimSpace(strings.TrimPrefix(string(data), signer.PublicKey().Type())),
					"Validity":        "*",
					"PermitRSASHA1":   "0",
					"PermitRSASHA256": "1",
					"PermitRSASHA512": "1",
				})
			}
			for _, pref := range KeyAlgo2id {
				name := filepath.Join(SshUserDir, pref+"-cert.pub")
				if canReadFile(name) {
					Conf(filepath.Join(Sessions, alias), EQ, map[string]string{"DetachedCertificate": name})
					break
				}
			}
		}
	}
	b, err := os.ReadFile(Cfg)
	if err != nil {
		Println(err)
		return
	}
	old, err := ssh_config.DecodeBytes(b)
	if err != nil {
		Println(err)
		return
	}

	cfg = MergeConfigs(old, cfg)
	if cfg == nil {
		Println("empty config")
		return
	}
	err = WriteFile(Cfg, []byte(cfg.String()), FILEMODE)
	if err != nil {
		Println(err)
	}
	if args.ForPutty {
		Println("SshToPutty", SshToPutty())
	}
}

// Пишем файл name если его содержимое отличается от data
func WriteFile(name string, data []byte, perm fs.FileMode) error {
	old, err := os.ReadFile(name)
	if err != nil || !bytes.EqualFold(old, data) {
		if err == nil {
			os.WriteFile(name+".old", old, perm)
		}
		return os.WriteFile(name, data, perm)
	}
	return nil
}

func mustParse(args *SshArgs, a []string) {
	parser, err := NewParser(arg.Config{}, args)
	Fatal(err)
	err = parser.Parse(a)
	Fatal(err)
}

func ints() (ips []string) {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifac := range ifaces {
			addrs, err := ifac.Addrs()
			if err != nil || ifac.Flags&net.FlagUp == 0 || ifac.Flags&net.FlagRunning == 0 || ifac.Flags&net.FlagLoopback != 0 {
				continue
			}
			for _, addr := range addrs {
				if strings.Contains(addr.String(), ":") {
					continue
				}
				ips = append(ips, strings.Split(addr.String(), "/")[0])
			}
		}
		slices.Reverse(ips)
	}
	return
}

func cleanup() {
	winssh.KidsDone(os.Getpid())
	Println("cleanup done")
	if runtime.GOOS == "windows" {
		menu.PressAnyKey("Press any key - Нажмите любую клавишу", TOW)
	}
}

func FingerprintSHA256(pubKey ssh.PublicKey) string {
	return pubKey.Type() + " " + ssh.FingerprintSHA256(pubKey)
}

func useLineShort(u, repo, imag string) string {
	return fmt.Sprintf(
		"\n\tlocal - локально `%s %s` or over jump host - или через посредника `%s%s`"+
			"\n\tlocal - локально `ssh %s` or over jump host - или через посредника и агента `ssh %s`"+
			"\n\tlocal - локально `putty @%s` or over jump host - или через посредника и агента `putty @%s`"+
			"\n\tlocal - локально `plink -load %s -no-antispoof` or over jump host - или через посредника и агента `plink -load %s -no-antispoof`",
		imag, repo, imag, strings.TrimPrefix(" "+u+"@", " "+imag+"@"),
		imag, SSHJ,
		imag, SSHJ,
		imag, SSHJ,
	)
}

func SshToPutty() (err error) {
	bs, err := os.ReadFile(Cfg)
	if err != nil {
		return
	}
	cfg, err := ssh_config.DecodeBytes(bs)
	if err != nil {
		return
	}
	for _, host := range cfg.Hosts {
		for _, pattern := range host.Patterns {
			s := pattern.String()
			if s != "*" && !strings.Contains(s, ".") {
				session := strings.ReplaceAll(s, "?", "7")
				session = strings.ReplaceAll(session, "*", "8")
				Conf(filepath.Join(Sessions, session), EQ, newMap(Keys, Defs,
					ssh_config.Get(s, "User"),
					ssh_config.Get(s, "HostName"),
					ssh_config.Get(s, "Port"),
					yes(ssh_config.Get(s, "ForwardAgent")),
					ssh_config.Get(s, "RemoteForward"),
					ssh_config.Get(s, "LocalForward"),
					ssh_config.Get(s, "DynamicForward"),
					ssh_config.Get(s, "ProxyJump"),
				))
			}
		}
	}
	return

}

func yes(s string) string {
	if strings.EqualFold(s, "yes") {
		return "1"
	}
	return "0"
}

func bool2string(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Пишем config для ssh клиента

// Алиас rc это клиент дальнего переноса -R на стороне sshd
func sshJ(host, u, h, p string) string {
	//ssh-keyscan ssh-j.com -f ~/.ssh/ssh-j
	s := `ssh-j.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCf7bgcKf2oDCpMdHjIqUkMihxpiVZ3j0zrRUeKhgn4FXx1FXerCe7cojAVuGcFsTH4JzIiK6SInKMRt8UANUBggae2llCHFsjV7L6NcLPgaByhWi4gOZba+FT1A0PSX7T8BFNPOmcu696PNILFru98BRf2Vd43E9mBAintLH5Ya6XnOQf9D44XNWToebokcEv48ju0dWDiRwt5IhQPj+cVZstWWJaqGueoR9GWcgSiPT6bISp0lSJfSq/ird7EEKJrU3f2g7Zi20DiDNJS7lfuWDKZeAphoZTXhciIlVRDWQHR8ssgiWVkcjWWi0LgDZ7hhhh+pcfvf71qpnOR0m2b
ssh-j.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPXSkWZ8MqLVM68cMjm+YR4geDGfqKPEcIeC9aKVyUW32brmgUrFX2b0I+z4g6rHYRwGeqrnAqLmJ6JJY0Ufm80=
ssh-j.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIiyFQuTwegicQ+8w7dLA7A+4JMZkCk8TLWrKPklWcRt
`
	if args.ForPutty {
		for _, line := range strings.Split(s, "\n") {
			if line == "" {
				continue
			}
			k, v, err := putty_hosts.ToPutty(line)
			if err != nil {
				Println(err)
				return ""
			} else {
				Conf(SshHostKeys, " ", map[string]string{k: v})
			}
		}
	}
	// Для ssh и tssh
	name := path.Join(SshUserDir, SSHJ)
	err := WriteFile(name, []byte(s), FILEMODE)
	if err != nil {
		Println(err)
		return ""
	}
	return `
Host ` + host + `
 User ` + u + `
 UserKnownHostsFile ~/.ssh/` + SSHJ + `
 PasswordAuthentication no
 PubkeyAuthentication no
 KbdInteractiveAuthentication no
 ExitOnForwardFailure yes
 StdinNull no
 RemoteForward ` + SSHJ2 + `:` + PORT + ` ` + h + `:` + p + `
`
}

// Алиас для локального доступа. Попробовать sshd.
func local(h, p, repo string) string {
	return `
Host ` + repo + `
 User _
 HostName ` + h + `
 Port ` + p + `
 UserKnownHostsFile ~/.ssh/` + repo + `
 KbdInteractiveAuthentication no
 PasswordAuthentication no
`
}

// Разбивает ProxyHost на части для putty
func newMap(keys, defs []string, values ...string) (kv map[string]string) {
	kv = make(map[string]string)
	ProxyLocalhost := false
	for i, k := range keys {
		v := defs[i]
		if len(values) > i {
			v = values[i]
		}
		switch k {
		case "HostName":
			ProxyLocalhost = strings.HasPrefix(v, "127.0.0.")
		case "RemoteForward":
			if v == "" {
				continue
			}
			k = "PortForwardings"
			v = "R" + strings.Replace(v, " ", "=", 1)
		case "LocalForward":
			if v == "" {
				continue
			}
			k = "PortForwardings"
			v = "L" + strings.Replace(v, " ", "=", 1)
		case "DynamicForward":
			if v == "" {
				continue
			}
			k = "PortForwardings"
			v = "D" + v
		case "ProxyHost":
			if v == "" {
				defs[i+1] = "0"
				defs[i+2] = defs[0]
				defs[i+3] = defs[2]
			} else {
				defs[i+1] = "6"
				ss := strings.Split(v, "@")
				if len(ss) > 1 {
					defs[i+2] = ss[0]
					v = ss[1]
				}
				ss = strings.Split(v, ":")
				if len(ss) > 1 {
					v = ss[0]
					defs[i+3] = ss[1]
				}
				defs[i+4] = bool2string(ProxyLocalhost)
			}
		}
		kv[k] = v
	}
	return
}

func GoVer() (s string) {
	info, ok := rdebug.ReadBuildInfo()
	s = "go"
	if ok {
		s = info.GoVersion
	}
	return
}

func base() string {
	info, ok := rdebug.ReadBuildInfo()
	if ok {
		return path.Base(info.Path) //info.Main.Path
	}
	exe, err := os.Executable()
	if err == nil {
		return strings.Split(filepath.Base(exe), ".")[0]
	}
	dir, err := os.Getwd()
	if err == nil {
		return filepath.Base(dir)
	}
	return "main"
}

// Если установлен sshd от OpenSSH обновляем TrustedUserCAKeys (ssh/trusted_user_ca_keys) и HostCertificate.
// Пишем конфиг I_verify_them_by_key_they_verify_me_by_certificate.
// Пишем конфиг I_verify_them_by_certificate_they_verify_me_by_certificate.
// Предлагаем включить один из этих конфигов в __PROGRAMDATA__/ssh/sshd_config.
func certHost(caSigner ssh.Signer, id string) (err error) {
	// ssh-keygen -s ca -I ngrokSSH -h -V always:forever c:\ProgramData\ssh\ssh_host_ecdsa_key.pub
	// move c:\ProgramData\ssh\ssh_host_ecdsa_key-cert.pub c:\ProgramData\ssh\host_certificate
	sshHostKeyPub := GetHostPub()
	if sshHostKeyPub == "" {
		return fmt.Errorf("not found OpenSSH keys")
	}
	//type ca.pub>>c:\ProgramData\ssh\trusted_user_ca_keys
	sshHostDir := filepath.Dir(sshHostKeyPub)
	TrustedUserCAKeys := filepath.Join(sshHostDir, "trusted_user_ca_keys")
	ca := caSigner.PublicKey()
	data := ssh.MarshalAuthorizedKey(ca)
	old, err := os.ReadFile(TrustedUserCAKeys)
	newCA := err != nil || !bytes.Equal(data, old)
	if newCA {
		err = WriteFile(TrustedUserCAKeys, data, FILEMODE)
		Println(TrustedUserCAKeys, err)
		if err != nil {
			return
		}
	}

	pub, err := os.Stat(sshHostKeyPub)
	if err != nil {
		return
	}
	in, err := os.ReadFile(sshHostKeyPub)
	if err != nil {
		return
	}
	out, _, _, _, err := ssh.ParseAuthorizedKey(in)
	if err != nil {
		out, err = ssh.ParsePublicKey(in)
	}
	if err != nil {
		return
	}
	HostCertificate := filepath.Join(sshHostDir, "host_certificate")
	cert, err := os.Stat(HostCertificate)
	newPub := true
	if err == nil {
		newPub = cert.ModTime().Unix() < pub.ModTime().Unix()
	}
	if !(newCA || newPub) {
		return nil
	}

	//newCA || newPub
	mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner), []string{ca.Type()})
	if err != nil {
		return
	}
	certificate := ssh.Certificate{
		Key:         out,
		CertType:    ssh.HostCert,
		KeyId:       id,
		ValidBefore: ssh.CertTimeInfinity,
		// ValidAfter:  uint64(time.Now().Unix()),
		// ValidBefore: uint64(time.Now().AddDate(1, 0, 0).Unix()),
	}
	err = certificate.SignCert(rand.Reader, mas)
	if err != nil {
		return
	}
	data = ssh.MarshalAuthorizedKey(&certificate)
	err = WriteFile(HostCertificate, data, FILEMODE)
	Println(HostCertificate, err)
	if err != nil {
		return
	}

	include := filepath.Join(sshHostDir, "I_verify_them_by_key_they_verify_me_by_certificate")
	s := programData2etc(`HostCertificate __PROGRAMDATA__/ssh/host_certificate
Match Group administrators
AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
`)
	err = WriteFile(include, []byte(s), FILEMODE)
	Println(include, err)
	if err != nil {
		return
	}
	Println(programData2etc("Insert to __PROGRAMDATA__/ssh/sshd_config line `Include I_verify_them_by_key_they_verify_me_by_certificate`."))

	include = filepath.Join(sshHostDir, "authorized_principals")
	err = WriteFile(include, []byte(id), FILEMODE)
	Println(include, err)
	if err != nil {
		return
	}

	include = filepath.Join(sshHostDir, "I_verify_them_by_certificate_they_verify_me_by_certificate")
	s = programData2etc(`TrustedUserCAKeys __PROGRAMDATA__/ssh/trusted_user_ca_keys
AuthorizedPrincipalsFile __PROGRAMDATA__/ssh/authorized_principals
HostCertificate __PROGRAMDATA__/ssh/host_certificate
`)
	err = WriteFile(include, []byte(s), FILEMODE)
	Println(include, err)
	Println(programData2etc("Or insert to __PROGRAMDATA__/ssh/sshd_config line `I_verify_them_by_certificate_they_verify_me_by_certificate`."))
	return
}

// Получить один замок
func GetHostPub() (pub string) {
	for _, id := range KeyAlgo2id {
		pub = filepath.Join(GlobalSshPath(), strings.Replace(id, "id_", "ssh_host_", 1)+".pub")
		_, err := os.Stat(pub)
		Println(pub, err)
		if err == nil {
			return
		}
	}
	return ""
}

func programData2etc(s string) string {
	if runtime.GOOS != "windows" {
		return strings.ReplaceAll(s, "__PROGRAMDATA__", "/etc")
	}
	return s
}

func MergeConfigs(items ...*ssh_config.Config) (target *ssh_config.Config) {
	const NN = "\n\n"
	switch len(items) {
	case 0:
		return
	case 1:
		return items[0]
	}
	clean := func(old string) string {
		old = strings.TrimSpace(old)
		old = strings.ReplaceAll(old, "\r\n", "\n") // windows->linux
		old = strings.ReplaceAll(old, "\r", "\n")   // darwin->linux
		for strings.Contains(old, NN) {             // Убираем пустые строки
			old = strings.ReplaceAll(old, NN, "\n")
		}
		return old
	}
	run := func(src, rep *ssh_config.Config) (mid *ssh_config.Config) {
		src, _ = ssh_config.Decode(strings.NewReader(clean(src.String())))
		rep, _ = ssh_config.Decode(strings.NewReader(clean(rep.String())))
		// rPatterns := make(map[string]bool)
		rPatterns := NewStringSet()
		for _, rh := range rep.Hosts {
			for _, rp := range rh.Patterns {
				if rp.String() == "*" {
					continue
				}
				// rPatterns[rp.String()] = true
				rPatterns.Add(rp.String())
			}
		}
		s := ""
		for _, sh := range src.Hosts {
			old := strings.TrimSpace(sh.String()) + NN
			i := len(sh.Patterns)
			for _, sp := range sh.Patterns {
				// if rPatterns[sp.String()] {
				if rPatterns.Contains(sp.String()) {
					i--
					old = strings.Replace(old, sp.String(), "", 1)
				}
			}
			if i > 0 {
				s += old
			}
		}
		for _, rh := range rep.Hosts {
			switch len(rh.Patterns) {
			case 0:
				continue
			case 1:
				if rh.Patterns[0].String() == "*" {
					continue
				}
			}
			s += strings.TrimSpace(rh.String()) + NN
		}
		mid, _ = ssh_config.Decode(strings.NewReader(strings.TrimSpace(s)))
		return
	}
	n := 0
	for {
		if n+1 >= len(items) {
			return
		}
		target = run(items[n], items[n+1])
		n++
	}
}

// tssh
func ParseDestination(dest string) (user, host, port string) {
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
