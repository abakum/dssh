package main

/*
Как собрать:
`git clone https://github.com/abakum/dssh`
`cd dssh`
Копируем секретный dssh.zip в .
В нём:
	ключ шифрования вложений `key.enc`,
	секретный алгоритм извлечения ключа шифрования вложений в `internal\tool\tool.go` (не показывай никому),
	ключ Центра Сертификации `internal\ca`. Его можно обновлять запуском `go run cmd/main.go`
`unzip -a dssh.zip`
`go run github.com/abakum/embed-encrypt` этим генерируется код для вложений `encrypted_fs.go`
`go install`

Запускаем `dssh -v` как сервис. Первый раз с `-v` чтоб зарезервировать `~/.ssh/config`.
Пробно запускаем `dssh .` или `ssh dssh` как клиента на том же хосте что и сервис.
Запускаем `dssh -v :` или `ssh ssh-j` как клиента через посредника `dssh@ssh-j.com` на хосте за NAT. Первый раз с `-v` чтоб зарезервировать `~/.ssh/config`.

В файл ~/.ssh/config дописываются алиасы хостов dssh, ssh-j, ssh-j.com.
Если указан параметр `-v` или `--debug` то на всякий случай создаются копии старых файлов .old
Создаются файлы `~/.ssh/ssh-j` и `~/.ssh/dssh`

Если указан параметр `-P` или `--putty` то:
Создаются файлы сессий из `~/.ssh/config` в `~/.putty/sessions`
Создаются файлы сертификатов хостов  в `~/.putty/sshhostcas`
Дописывается файл `~/.putty/sshhostkeys` замками ssh-j.com
Тоже самое и для Windows из %USERPROFILE%\.ssh\config в реестр CURRENT_USER\SOFTWARE\SimonTatham\PuTTY
*/

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/abakum/go-ser2net/pkg/ser2net"
	"github.com/abakum/menu"
	"github.com/abakum/putty_hosts"
	"github.com/abakum/winssh"
	"github.com/containerd/console"
	"github.com/mattn/go-isatty"
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
	RESTART  = "--restart"
	SSHJ     = "ssh-j"
	SSHJ2    = "127.0.0.2"
	JumpHost = SSHJ + ".com"
	EQ       = "="
	TERM     = "xterm-256color"
	PUTTY    = "putty" // signed https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
	LISTEN   = "2222"
	TELNET   = "telnet"
	PLINK    = "plink"
	RFC2217  = 22170
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
	repo       = base()     // Имя репозитория `dssh` оно же имя алиаса в .ssh/config
	rev        = revision() // Имя для посредника.
	imag       string       // Имя исполняемого файла `dssh` его можно изменить чтоб не указывать имя для посредника.
	Windows    = runtime.GOOS == "windows"
	Win        = Windows
	Cygwin     = isatty.IsCygwinTerminal(os.Stdin.Fd())
	once       = false
	OverSSH    = os.Getenv("SSH_CONNECTION") != ""
	BUSYBOX    = "busybox"
	MICROCOM   = false
)

//go:generate go run github.com/abakum/version
//go:generate go run cmd/main.go
//go:generate go run github.com/abakum/embed-encrypt
//go:generate go list -f '{{.EmbedFiles}}'

//encrypted:embed internal/ca
var CA []byte // Ключ ЦС

//go:embed VERSION
var Ver string

// `dssh` `dssh -d` `dssh -l revision` `revision` Где revision  это что-то типа 59d7a68a020c992ca41819553e888fad8f9684c1 (смотри `dssh -V`)
//
//	запустит сервер ssh на адресе `127.0.0.1:2222`.
//	подготовит алиас `ssh-j.com` и запустит его для переноса сессии с белого адреса `ssh-j.com:22` на серый `127.0.0.1:2222`.
//	подготовит алиас `dssh` для подключения к серверу локально.
//	подготовит алиас `ssh-j` для подключения к серверу через `dssh@ssh-j.com`.
//	`dssh .` `dssh dssh` `ssh dssh` подключится к серверу локально.
//	`dssh :` `dssh ssh-j` `revision :` `dssh -l revision ssh-j` `ssh ssh-j` подключится к серверу через посредника `revision@ssh-j.com`.
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
	Println(build(Ver, ips))
	FatalOr("not connected - нет сети", len(ips) == 0)

	anyKey, err := x509.ParsePKCS8PrivateKey(CA)
	Fatal(err)

	// CA signer
	signer, err := ssh.NewSignerFromKey(anyKey)
	Fatal(err)

	// Like `parser := arg.MustParse(&args)` but override built in option `-v, --version` of package `arg`
	parser, err := NewParser(arg.Config{}, &args)
	Fatal(err)

	// tools
	SecretEncodeKey = key
	if args.NewHost ||
		args.EncSecret ||
		args.InstallTrzsz ||
		args.InstallPath != "" ||
		args.TrzszVersion != "" ||
		args.TrzszBinPath != "" ||
		false {
		TsshMain(&args)
		return
	}

	a2s := make([]string, 0) // Без встроенных параметров -h -v
	// cli := false
	for i, arg := range os.Args[1:] {
		switch strings.ToLower(arg) {
		case "-help", "--help":
			parser.WriteHelp(Std)
			return
		case "-h":
			if os.Args[i+1:][i] != "-H" {
				parser.WriteUsage(Std)
				return
			}
			a2s = append(a2s, "--path")
		case "-version", "--version":
			Println(args.Version())
			return
		case "-v":
			if os.Args[i+1:][i] == "-V" {
				Println(args.Version())
				return
			}
			a2s = append(a2s, "--debug")
		default:
			// if strings.HasPrefix(arg, "-") {
			// 	switch arg[len(arg)-1:] {
			// 	case "c", "F", "J", "W": //"i", "o", "D", "L", "R"
			// 		cli = true
			// 	}
			// }
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

	cli := fmt.Sprint(args.Option) != "{map[]}"
	enableTrzsz := "yes"
	switch strings.ToLower(args.EscapeChar) {
	case "":
		args.EscapeChar = "~"
	case "none":
	default:
		enableTrzsz = "no"
	}
	args.Option.UnmarshalText([]byte("EscapeChar=" + args.EscapeChar))

	exit := ""
	if Windows {
		exit = " или <^Z>"
	}
	if Cygwin {
		exit = " или <^C>"
	}

	bins := []string{PUTTY, PLINK, TELNET}
	if args.Unix { // Параметр чтоб эмулировать Юникс на хосте с Виндовс
		Win = false
	}
	if OverSSH {
		Win = false
	}
	if !Win {
		// В Юниксе используем консольные приложения plink или telnet
		bins = bins[1:]
	}
	if args.Telnet { // Параметр чтоб эмулировать отсутствие putty и plink при наличии telnet
		bins = []string{TELNET}
	}
	execPath, bin, err := look(bins...)
	if args.Putty && err != nil {
		Fatal(fmt.Errorf("not found - не найдены %v", bins))
	}

	lNear := args.Ser2net
	if lNear == 0 {
		lNear = RFC2217
	}

	serial := args.Serial
	BS := args.Baud != "" || serial != ""
	if BS || lNear > 0 {
		enableTrzsz = "no"
		switch args.Destination {
		case "", ".", repo:
			// Локальный последовательный порт
			serial = getFirstUsbSerial(serial, args.Baud, Print)
			if serial == "" {
				Println(ErrNotFoundFreeSerial)
				Println("we will try to use RFC2217 - будем пробовать использовать RFC2217")
				if lNear < 0 {
					// dssh --baud 9
					// dssh --path com3
					lNear = RFC2217
				}
			}
		}
		if lNear < 0 && args.Putty {
			switch args.Destination {
			case "":
				// dssh --putty --unix --telnet --baud 9
				MICROCOM = !Windows && bin == TELNET && exec.Command("busybox", "microcom", "--help").Run() == nil
			default:
				// dssh --putty --baud 9 :
				// dssh --putty --path com3 :
				lNear = RFC2217
			}
		}
	}
	lFar := lNear

	if lNear > -1 {
		switch args.Destination {
		case "":
		case ".", repo:
			lFar++
			fallthrough
		default:
			args.LocalForward.UnmarshalText([]byte(fmt.Sprintf("%d:%s:%d", lNear, LH, lFar)))
			// a2s = append(a2s, "-L", fmt.Sprintf("%d:%s:%d", lNear, LH, lFar))
			// if err := parser.Parse(a2s); err != nil {
			// 	Fatal(err)
			// }
		}
	}

	// Println(fmt.Sprintf("args %+v", args))
	Println(repo, strings.Join(a2s, " "))
	defer closer.Close()
	closer.Bind(cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	closer.Bind(cancel)

	u, h, p := ParseDestination(args.Destination) //tssh
	// `dssh` как `dssh -d`
	// `foo` как `dssh foo@` как `dssh -dl foo`

	if args.LoginName != "" {
		u = args.LoginName // dssh -l foo
	}
	if u == "" {
		u = rev // Имя для посредника ssh-j.com
		if imag != repo {
			u = imag // Если бинарный файл переименован то вместо ревизии имя переименованного бинарного файла и будет именем для посредника ssh-j.com
		}
	}
	sshj := `
Host ` + SSHJ + `
 User _
 HostName ` + SSHJ2 + `
 UserKnownHostsFile ~/.ssh/` + repo + `
 KbdInteractiveAuthentication no
 PasswordAuthentication no
 ProxyJump ` + u + `@` + JumpHost + `
 EnableTrzsz ` + enableTrzsz
	if args.Restart || BS || lNear > 0 {
		// CGI
		cli = true
		args.Command = repo
		// args.ForceTTY = true
		args.Argument = nil
		if args.Restart {
			// dssh --restart
			if args.Destination == "" {
				args.Destination = ":" // Рестарт сервера за NAT
			}
			args.Argument = append(args.Argument, "--restart")
		} else {
			// BS || nearL > 0
			if args.Destination != "" {
				if args.Baud != "" {
					args.Argument = append(args.Argument, "--baud", args.Baud)
				}
				if serial != "" {
					args.Argument = append(args.Argument, "--serial", serial)
				}
				if lFar > 0 {
					args.Argument = append(args.Argument, "--2217", strconv.Itoa(lFar))
				}
				if exit != "" {
					args.Argument = append(args.Argument, "--exit", exit)
				}
				if args.Putty {
					if Win {
						args.Argument = append(args.Argument, "--putty")
					}
				}
			} else {
				// Локальная последовательная консоль
				if args.Putty {
					// dssh --putty --baud 9
					// Хуже чем `dssh --baud 9` так как нельзя сменить скорость
					BaudRate := ser2net.BaudRate(strconv.Atoi(args.Baud))
					opt := fmt.Sprintln("-serial", serial, "-sercfg", fmt.Sprintf("%d,8,1,N,N", BaudRate))
					if lNear > 0 {
						// dssh --putty --2217 0
						opt = optTelnet(bin == TELNET, lNear)
					} else if MICROCOM {
						opt = fmt.Sprintln("microcom", "-s", BaudRate, serial)
						execPath = BUSYBOX
					}

					cmd := exec.CommandContext(ctx, execPath, strings.Fields(opt)...)
					run := func() {
						err = cmd.Start()
						PrintLn(3, cmd, err)
						cmd.Wait()
					}

					if !Win {
						// dssh --unix --putty --baud 9
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stdout
						if lNear > 0 {
							if bin == TELNET {
								// dssh --telnet --unix --putty --2217 0
								time.AfterFunc(time.Second, func() {
									exit := "<^]><q><Enter>"
									if Cygwin {
										exit = "<^C>"
									}
									Println(ToExitPress, exit)
								})
							} else {
								// dssh --unix --putty --2217 0
								// Microsoft Telnet выпадает
								// Linux Telnet виснет
								w, err := cmd.StdinPipe()
								if err == nil {
									chanByte := make(chan byte, B16)

									chanError := make(chan error, 1)
									go func() {
										chanError <- s2n(ctx, nil, chanByte, serial, lNear, args.Baud, "", Println)
									}()
									select {
									case err = <-chanError:
										Println(err)
									case <-time.After(time.Second):
										err := cmd.Start()
										Println(cmd, err)
										if err == nil {
											setRaw(&once)
											io.Copy(newSideWriter(w, args.EscapeChar, serial, exit, chanByte, Println), os.Stdin)
											if cmd.Process != nil {
												cmd.Process.Release()
											}
										}
										return
									}
								}
							}
							go func() {
								s2n(ctx, nil, nil, serial, lNear, "", args.Baud, Println)
								closer.Close()
							}()
						}
						cmd.Stdin = os.Stdin
					} else {
						// Win
						// dssh --putty --baud 9
						notPutty(bin, cmd) // dssh --telnet -putty --2217 0
						if lNear > 0 {
							// dssh --putty --2217 0
							// dssh --telnet --putty --baud 0
							t := time.AfterFunc(time.Second, func() {
								run()
								closer.Close()
							})
							setRaw(&once)
							Println(s2n(ctx, os.Stdin, nil, serial, lNear, args.Baud, " или <^C>", Println))
							t.Stop() // Если не успел стартануть то и не надо
							return
						}
					}
					exit := "<^C>"
					if MICROCOM {
						exit = "<^X>"
					}
					Println(ToExitPress, exit)
					run()
					return
				}
				setRaw(&once)
				if lNear > 0 {
					// dssh --2217 0
					Println(rfc2217(ctx, ReadWriteCloser{os.Stdin, os.Stdout}, serial, lNear, args.Baud, exit, Println))
					return
				}
				// dssh --baud 9
				Println(ser(ctx, ReadWriteCloser{os.Stdin, os.Stdout}, serial, args.Baud, exit, Println))
				return
			}
		}
	}

	cli = cli ||
		fmt.Sprint(args.Identity) != "{[]}" ||
		fmt.Sprint(args.DynamicForward) != "{[]}" ||
		fmt.Sprint(args.LocalForward) != "{[]}" ||
		fmt.Sprint(args.RemoteForward) != "{[]}" ||
		args.Command != "" ||
		args.ForwardAgent ||
		args.NoForwardAgent ||
		args.DisableTTY ||
		args.ForceTTY ||
		args.IPv4Only ||
		args.IPv6Only ||
		args.Gateway ||
		args.Background ||
		args.NoCommand ||
		args.CipherSpec != "" ||
		args.ConfigFile != "" ||
		args.StdioForward != "" ||
		args.X11Untrusted ||
		args.NoX11Forward ||
		args.X11Trusted ||
		args.Reconnect ||
		args.DragFile ||
		args.TraceLog ||
		args.Relay ||
		args.Zmodem ||
		args.Putty ||
		false
	if cli && args.Destination == "" {
		args.Destination = "@"
	}
	daemon := false
	switch args.Destination {
	case "@": // Меню tssh.
		args.Destination = ""
	case ":", SSHJ: // `dssh :` как `dssh ssh-j` как `foo -l dssh :`
		args.Destination = SSHJ
		args.LoginName = "_"
	case ".", repo: // `dssh .` как `dssh dssh` или `foo -l dssh .` как `foo -l dssh dssh`
		args.Destination = repo
		args.LoginName = "_"
	default:
		daemon = h+p == ""
	}
	if args.Daemon || !cli && daemon {
		args.Daemon = true
		hh := ""
		switch h {
		case "":
			h = LH
		case "*":
			h = ALL
			hh = ips[len(ips)-1]
		case "_":
			h = ips[0]
		}
		if hh == "" {
			hh = h
		}
		if p == "" {
			p = LISTEN
			if args.Port != 0 {
				p = strconv.Itoa(args.Port)
			}
		}

		go func() {
			s := usage(repo, imag)
			for {
				server(h, p, repo, s, signer, Println, Print)
				winssh.KidsDone(os.Getpid())
				Println("server has been stopped - сервер остановлен")
				time.Sleep(TOR)
			}
		}()
		rc := ""
		if args.Debug {
			rc += "-v "
		}
		rc += JumpHost
		args.Destination = JumpHost
		args.DisableTTY = true
		client(signer, local(hh, p, repo, enableTrzsz)+sshj+sshJ(JumpHost, u, hh, p))
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
	client(signer, sshj+sshJ(JumpHost, u, "", p), repo, SSHJ)
	if args.Putty {
		opt := ""
		if args.Destination != "" {
			if lNear > 0 {
				// dssh --putty --2217 0 :
				// dssh --unix --putty --2217 0 :
				opt = optTelnet(bin == TELNET, lNear)
			}
			if opt == "" {
				// dssh --putty  :
				switch bin {
				case PUTTY:
					opt = "@" + args.Destination
				case PLINK:
					opt = fmt.Sprintln("-no-antispoof", "-load", args.Destination)
				case TELNET:
					// dssh --telnet --putty :
					// За неимением...
					execPath = "ssh"
					opt = args.Destination
				}
			}
		}
		// dssh --putty
		// dssh --telnet --putty :
		// dssh --telnet --putty --2217 0 :
		cmd := exec.CommandContext(ctx, execPath, strings.Fields(opt)...)
		run := func() {
			err = cmd.Start()
			PrintLn(3, cmd, err)
			cmd.Wait()
		}
		if Win || lNear > 0 {
			notPutty(bin, cmd)
			if lNear > 0 {
				// dssh --putty --2217 0 :
				// dssh --telnet --putty --2217 0 :
				// dssh --putty --baud 9 :
				// dssh --telnet --putty --baud 9 :
				// dssh --unix --putty --2217 0 :
				// dssh --unix --telnet --putty --2217 0 :
				// dssh --unix --putty --baud 9 :
				// dssh --unix --telnet --putty --baud 9 :
				if !OverSSH {
					time.AfterFunc(time.Second*5, func() {
						run()
						closer.Close()
					})
				}
			} else {
				// dssh --putty  :
				Println(ToExitPress, "<^C>")
				run()
				return
			}
		} else {
			exit := "<Enter><e><x><i><t><Enter>"
			if bin == TELNET {
				// dssh --unix --telnet --putty :
				// ssh ssh-j
				exit += " или <Enter><~><.>"
			} else {
				// dssh --unix --putty :
				// plink -load ssh-j
				ConsoleCP()
			}
			Println(ToExitPress, exit)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			run()
			return
		}
	}
	// dssh --baud 9 :
	// dssh --2217 0 :
	// Лучше чем `dssh --baud 9 :` - можно и скорость менять и с разных хостов управлять
	setRaw(&once)
	if (enableTrzsz == "no" || args.Destination == repo) && !(BS || lNear > 0) {
		Println(ToExitPress, "<Enter><"+args.EscapeChar+"><.>")
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
	if args.Putty {
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
		// slices.Reverse(ips)
	}
	return
}

func cleanup() {
	winssh.KidsDone(os.Getpid())
	Println("cleanup done")
	// if !IsConsole() {
	// 	menu.PressAnyKey("Press any key - Нажмите любую клавишу", TOW)
	// }
}

func FingerprintSHA256(pubKey ssh.PublicKey) string {
	return pubKey.Type() + " " + ssh.FingerprintSHA256(pubKey)
}

func usage(repo, imag string) string {
	s := fmt.Sprintf(
		"\n\tlocal - локально `%s .` or over jump host - или через посредника `%s :`"+
			"\n\tlocal - локально `ssh %s` or over jump host - или через посредника `ssh %s`",
		imag, imag,
		repo, SSHJ,
	)
	if args.Putty {
		s += fmt.Sprintf(
			"\n\tlocal - локально `putty @%s` or over jump host - или через посредника `putty @%s`"+
				"\n\tlocal - локально `plink -no-antispoof -load %s` or over jump host - или через посредника и агента `plink -no-antispoof -load %s`",
			repo, SSHJ,
			repo, SSHJ,
		)
	}
	return s
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
	if args.Putty {
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
 RemoteForward ` + SSHJ2 + `:` + PORT + ` ` + h + `:` + p + `
`
	}
	return alias
}

// Алиас для локального доступа. Попробовать sshd.
func local(h, p, repo, enableTrzsz string) string {
	alias := `
Host ` + repo + `
 User _
 HostName ` + h + `
 Port ` + p + `
 UserKnownHostsFile ~/.ssh/` + repo + `
 KbdInteractiveAuthentication no
 PasswordAuthentication no
 ` // EnableTrzsz ` + enableTrzsz
	return alias
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
	if !Win {
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
		rPatterns := NewStringSet()
		for _, rh := range rep.Hosts {
			for _, rp := range rh.Patterns {
				if rp.String() == "*" {
					continue
				}
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

func setRaw(already *bool) {
	if *already {
		return
	}
	*already = true

	var (
		err      error
		current  console.Console
		settings string
	)

	current, err = console.ConsoleFromFile(os.Stdin)
	if err == nil {
		err = current.SetRaw()
		if err == nil {
			closer.Bind(func() { current.Reset() })
			PrintLn(3, "Set raw by go")
			return
		}
	}

	if isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		settings, err = sttySettings()
		if err == nil {
			err = sttyMakeRaw()
			if err == nil {
				closer.Bind(func() { sttyReset(settings) })
				PrintLn(3, "Set raw by stty")
				return
			}
		}
	}
	PrintLn(3, err)

}

func sttyMakeRaw() error {
	cmd := exec.Command("stty", "raw", "-echo")
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func sttySettings() (string, error) {
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func sttyReset(settings string) {
	cmd := exec.Command("stty", settings)
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
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

func optTelnet(telnet bool, lNear int) (opt string) {
	opt = fmt.Sprintln("-telnet", LH, "-P", lNear)
	if telnet {
		// dssh --telnet --putty --2217 0 :
		opt = fmt.Sprintln(LH, lNear)
	}
	return
}

func notPutty(bin string, cmd *exec.Cmd) {
	if bin != PUTTY {
		createNewConsole(cmd)
	}
}

func IsConsole() bool {
	for _, s := range []*os.File{os.Stderr, os.Stdout, os.Stdin} {
		if _, err := console.ConsoleFromFile(s); err == nil {
			return true
		}
	}
	return false
}
