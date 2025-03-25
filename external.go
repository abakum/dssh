package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/abakum/dssh/tssh"
	"github.com/abakum/go-ser2net/pkg/ser2net"
	"github.com/abakum/pageant"
	"github.com/abakum/winssh"
	"github.com/trzsz/ssh_config"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	EQ       = "="
	TERM     = "xterm-256color"
	PUTTY    = "putty" // signed https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
	TELNET   = "telnet"
	PLINK    = "plink"
	BUSYBOX  = "busybox"
	MICROCOM = "microcom"
	PORT     = "22"
	SSH      = "ssh"
	CHROME   = "chrome"
)

var (
	Keys = []string{
		"UserName", "HostName", "PortNumber", "AgentFwd",
		"RemoteForward", "LocalForward", "DynamicForward",
		"ProxyHost", "ProxyMethod", "ProxyUsername", "ProxyPort", "ProxyLocalhost", "ProxyDNS", "ProxyTelnetCommand",
		"Protocol", "WarnOnClose", "FullScreenOnAltEnter", "TerminalType",
	}
	Defs = []string{
		winssh.UserName(), LH, PORT, "0",
		"", "", "",
		"", "0", "", PORT, "1", "1", "",
		SSH, "0", "1", TERM,
	}
)

func notPuttyNewConsole(bin string, cmd *exec.Cmd) {
	if bin != PUTTY {
		createNewConsole(cmd)
	}
}

// dssh on args.Destination
func isDssh(or bool) bool {
	if or {
		return true
	}
	switch args.Destination {
	case ".", repo, ":", SSHJ:
		return true
	}
	return false
}

func externalClient(external *bool, exe string) (signers []ssh.Signer, err error) {
	if isDssh(false) && *external {
		s := "-u"
		if args.Telnet {
			s = "-Z"
		}
		s = fmt.Sprintf(" `%s %s %s`", repo, s, args.Destination)
		var conn net.Conn
		conn, err = pageant.NewConn()
		if err != nil {
			err = fmt.Errorf("requires a ssh-agent - для запуска %s нужен агент ключей %v", s, err)
			args.Putty = false
			args.Telnet = false
			*external = false
			return
		}
		defer conn.Close()
		signers, err = agent.NewClient(conn).Signers()
		if err != nil || len(signers) < 1 {
			err = fmt.Errorf("requires at least one key from the ssh-agent - для запуска %s нужен хотя бы один ключ от агента ключей", s)
			args.Putty = false
			args.Telnet = false
			*external = false
			return
		}
		run := func(s, cert string) (err error) {
			if isFileExist(cert) {
				return
			}
			opts := []string{}
			if args.LoginName != "" {
				opts = append(opts, "-l", args.LoginName)
			}
			cmd := exec.Command(exe, append(opts, args.Destination, "exit")...)
			Println(fmt.Errorf("must be run at least once before - до запуска %s нужно хотя бы раз запустить `%s`", s, cmd))
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			if isFileExist(cert) {
				return
			}
			return fmt.Errorf("couldn't create certificate - не удалось создать сертификат %s", cert)
		}
		err = run(s, filepath.Join(SshUserDir, repo))
		if err != nil {
			args.Putty = false
			args.Telnet = false
			*external = false
			return
		}
		for _, sig := range signers {
			pref, ok := KeyAlgo2id[sig.PublicKey().Type()]
			if !ok {
				continue
			}
			err = run(s, filepath.Join(SshUserDir, pref+"-cert.pub"))
			if err != nil {
				args.Putty = false
				args.Telnet = false
				*external = false
				return
			}
		}
	}
	return
}

func cmdRun(cmd *exec.Cmd, ctx context.Context, r io.Reader, zu bool, Serial, host string, Ser2net int, Baud string, exit string, println ...func(v ...any)) (err error) {
	// PrintLn(3, cmd, r, zu, Z, Serial, host, Ser2net)
	// time.Sleep(time.Second * 5)
	run := func() {
		err = cmd.Start()
		PrintLn(3, cmd, err)
		if err == nil {
			cmd.Wait()
		}
	}
	hp := JoinHostPort(host, Ser2net)
	if isHP(hp) {
		// Подключаемся к существующему сеансу
		if r != nil {
			// -Z22 && serial==""
			// -u22 && serial==""
			// -uH:2 && serial!=""
			go func() {
				run()
				closer.Close()
			}()
			setRaw(&once)
			return cons(ctx, ioc, hp, Baud, exit, println...)
		}

		if !zu {
			// Без управления
			time.AfterFunc(time.Millisecond*111, func() {
				Println(ToExitPress, exit+EL)
			})
			run()
			return
		}

		// -zu
		var wc io.WriteCloser
		wc, err = cmd.StdinPipe()
		if err != nil {
			return
		}
		err = cmd.Start()
		Println(cmd, err)
		if err != nil {
			return
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		w, _ := ser2net.NewSerialWorker(ctx, hp, ser2net.BaudRate(strconv.Atoi(Baud)))
		defer w.Stop()
		go w.Worker()

		defer func() {
			println[0]("Connection", hp, "closed", w.SerialClose(), w)
		}()

		chanByte := make(chan byte, B16)
		// t := time.AfterFunc(time.Millisecond*time.Duration(ser2net.TOopen), func() {
		t := time.AfterFunc(time.Second, func() {
			SetMode(w, ctx, nil, chanByte, EED, 0, println...)
		})
		defer t.Stop()

		w.NewCancel(func() error {
			closer.Close()
			return nil
		})
		setRaw(&once)
		w.CancelCopy(newSideWriter(wc, args.EscapeChar, hp, chanByte), ioc)
		cmd.Cancel()
		return
	}

	if r != nil {
		// -Z
		// -Z22
		// -u22
		delay := time.Second
		if Cygwin {
			delay *= 2
		}
		time.AfterFunc(delay, func() {
			run()
			closer.Close()
		})
		setRaw(&once)
		return rfc2217(ctx, ioc, Serial, host, Ser2net, Baud, exit, println...)
	}

	// -zu
	// -zZ
	var wc io.WriteCloser
	if zu {
		// -zu
		wc, err = cmd.StdinPipe()
		if err != nil {
			return
		}
	}

	chanError := make(chan error, 1)
	chanByte := make(chan byte, B16)
	chanSerialWorker := make(chan *ser2net.SerialWorker, 1)
	go func() {
		chanError <- s2n(ctx, r, chanByte, chanSerialWorker, Serial, host, Ser2net, Baud, exit, println...)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-chanError:
		return
	case w := <-chanSerialWorker:
		defer w.Stop()
		err = cmd.Start()
		Println(cmd, err)
		if err != nil {
			return
		}

		if zu {
			// w.CancelCopy(newSideWriter(wc, args.EscapeChar, Serial, chanByte), ser2net.ReadWriteCloser{Reader: os.Stdin, WriteCloser: nil, Cygwin: Cygwin})
			setRaw(&once)
			w.CancelCopy(newSideWriter(wc, args.EscapeChar, Serial, chanByte), ioc)
		} else {
			time.AfterFunc(time.Millisecond*111, func() {
				Println(ToExitPress, exit+EL)
			})
		}
		cmd.Wait()
	}
	return
}
func optTelnet(bin, host string, lNear int) (opt string) {
	switch bin {
	case TELNET:
		opt = fmt.Sprintln("-e\021", host, lNear) // -e^Q
	case BUSYBOX:
		opt = fmt.Sprintln(TELNET, "-e\021", host, lNear) // -e^Q
	default:
		opt = fmt.Sprintln("-"+TELNET, host, "-P", lNear)
	}
	return
}
func look(bins ...string) (path, bin string, err error) {
	for _, item := range bins {
		path, err = exec.LookPath(item)
		if err == nil {
			bin = item
			return
		}
		err = fmt.Errorf("not found - не найден %s", item)
	}
	return
}

// Разбивает ProxyHost на части для putty и ssh
func newMap(keys, defs []string, values ...string) (kv map[string]string) {
	kv = make(map[string]string)
	for i, k := range keys {
		v := defs[i]
		if len(values) > i {
			v = values[i]
		}
		switch k {
		case "HostName":
		case "RemoteForward":
			k = "PortForwardings"
			if v != "" {
				v = "R" + strings.Replace(v, " ", "=", 1)
			}
		case "LocalForward":
			k = "PortForwardings"
			if v != "" {
				v = "L" + strings.Replace(v, " ", "=", 1)
			}
		case "DynamicForward":
			k = "PortForwardings"
			if v != "" {
				v = "D" + v
			}
		case "ProxyMethod", "ProxyUsername", "ProxyPort", "ProxyLocalhost", "ProxyDNS", "ProxyTelnetCommand":
			continue
		case "ProxyHost":
			kv["ProxyMethod"] = "0"
			kv["ProxyUsername"] = ""
			kv["ProxyPort"] = defs[2]
			kv["ProxyLocalhost"] = bool2string(localHost(kv["HostName"]))
			kv["ProxyDNS"] = "1"
			kv["ProxyTelnetCommand"] = ""
			userHostPort := func(metod, port string) {
				kv["ProxyMethod"] = metod
				userV := strings.Split(v, "@")
				if len(userV) > 1 {
					kv["ProxyUsername"] = userV[0]
					v = userV[1]
				}
				hostV := strings.Split(v, ":")
				kv["ProxyPort"] = port
				if len(hostV) > 1 {
					v = hostV[0]
					kv["ProxyPort"] = hostV[1]
				}
				// kv["ProxyLocalhost"] = bool2string(ProxyLocalhost)
			}
			metodV := strings.Split(v, "://")
			switch strings.ToLower(metodV[0]) {
			case "":
			case "socks4a", "4a":
				kv["ProxyDNS"] = "2"
				fallthrough
			case "socks4", "4":
				v = metodV[1]
				userHostPort("1", "1080")
			case "socks", "socks5", "5":
				v = metodV[1]
				userHostPort("2", "1080")
			case "http", "https", "connect":
				v = metodV[1]
				userHostPort("3", "3128")

			default:
				if strings.Contains(strings.TrimSpace(v), " ") {
					// ProxyTelnetCommand
					kv["ProxyMethod"] = "5"
					v = strings.Replace(v, "%h", "%host", 1)
					v = strings.Replace(v, "%p", "%port", 1)
					v = strings.Replace(v, "%u", "%user", 1)
					kv["ProxyTelnetCommand"] = v
					v = ""
				} else {
					userHostPort("6", "22")
				}
			}
		}
		kv[k] = v
	}
	return
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
			if s != "*" && !strings.Contains(s, ".") && s != ":" {
				session := strings.ReplaceAll(s, "?", "7")
				session = strings.ReplaceAll(session, "*", "8")
				proxy := ssh_config.Get(s, "ProxyJump")
				if proxyC := ssh_config.Get(s, "ProxyCommand"); proxyC != "" {
					proxy = proxyC
				}
				if proxyP := ssh_config.Get(s, "ProxyPutty"); proxyP != "" {
					proxy = ExpandEnv(proxyP)
				}
				Conf(filepath.Join(Sessions, session), EQ, newMap(Keys, Defs,
					ssh_config.Get(s, "User"),
					ssh_config.Get(s, "HostName"),
					ssh_config.Get(s, "Port"),
					yes(ssh_config.Get(s, "ForwardAgent")),
					ssh_config.Get(s, "RemoteForward"),
					ssh_config.Get(s, "LocalForward"),
					ssh_config.Get(s, "DynamicForward"),
					proxy,
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

// Пишем config для ssh клиентов
func client(signer ssh.Signer, signers []ssh.Signer, config string, hosts ...string) {
	cfg, err := ssh_config.Decode(strings.NewReader(config))
	if err != nil {
		Println(err)
		return
	}
	switch args.Destination {
	case repo, SSHJ, JumpHost:
		Println(config)
	}
	args.Config = NewConfig(cfg)

	cert := NewCertificate(0, ssh.UserCert, repo, ssh.CertTimeInfinity, 0, repo)
	caSigner := []*CASigner{NewCASigner(cert, signer)}
	for i, alias := range hosts {
		// args.Config.Signers[alias] = []ssh.Signer{signer} // Не буду использовать CA как ключ
		args.Config.CASigner[alias] = caSigner
		args.Config.Include.Add(alias)

		if args.Putty {
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
			for _, sig := range signers {
				pref, ok := KeyAlgo2id[sig.PublicKey().Type()]
				if !ok {
					continue
				}
				name := filepath.Join(SshUserDir, pref+"-cert.pub")
				if !isFileExist(name) || !canReadFile(name) {
					continue
				}
				Conf(filepath.Join(Sessions, alias), EQ, map[string]string{"DetachedCertificate": name})
				// PuTTY может принять только один сертифицикат
				break
			}
		}
	}
	b, err := os.ReadFile(Cfg)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		Fatal(err)
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
	if args.Putty || (Win7 && !Cygwin) || args.Telnet {
		Println("SshToPutty", SshToPutty())
	}
}

// Пишем файл name если его содержимое отличается от data
func WriteFile(name string, data []byte, perm fs.FileMode) error {
	old, err := os.ReadFile(name)
	if err != nil || !bytes.EqualFold(old, data) {
		if err == nil && args.Debug {
			os.WriteFile(name+".old", old, perm)
		}
		return os.WriteFile(name, data, perm)
	}
	return nil
}

// Пишем config для ssh клиента
// Это алиас для -R на стороне sshd
func sshJ(host, u, h, p string) string {
	//ssh-keyscan ssh-j.com -f ~/.ssh/ssh-j
	alias := `
Host ` + host + `
 User ` + u + `
 UserKnownHostsFile ~/.ssh/` + SSHJ + `
 PasswordAuthentication no
 PubkeyAuthentication no
 KbdInteractiveAuthentication no`
	if h != "" {
		alias += `
 SessionType none
 ExitOnForwardFailure yes
 StdinNull no
 RequestTTY no
 RemoteForward ` + SSHJ2 + `:` + PORT + ` ` + h + `:` + p + `
`
	}
	return alias
}

// Алиас для локального доступа. Попробовать dssh.
func local(h, p, repo string) string {
	alias := `
Host ` + repo + ` .
 User _
 HostName ` + h + `
 Port ` + p + `
 UserKnownHostsFile ~/.ssh/` + repo + `
 KbdInteractiveAuthentication no
 PasswordAuthentication no
 RequestTTY yes
 ` // EnableTrzsz ` + enableTrzsz
	return alias
}
