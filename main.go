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

Если указан параметр `-u` или `--putty` то:
Создаются файлы сессий из `~/.ssh/config` в `~/.putty/sessions`
Создаются файлы сертификатов хостов  в `~/.putty/sshhostcas`
Дописывается файл `~/.putty/sshhostkeys` замками ssh-j.com
Тоже самое и для Windows из %USERPROFILE%\.ssh\config в реестр CURRENT_USER\SOFTWARE\SimonTatham\PuTTY
*/

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
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
	"github.com/ncruces/rethinkraw/pkg/chrome"
	"github.com/pkg/browser"
	"github.com/trzsz/go-arg"
	"github.com/trzsz/ssh_config"
	"github.com/unixist/go-ps"

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
	SSHJ2    = LH //"127.0.0.2"
	JumpHost = SSHJ + ".com"
	EQ       = "="
	TERM     = "xterm-256color"
	PUTTY    = "putty" // signed https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
	LISTEN   = PORT + PORT
	TELNET   = "telnet"
	PLINK    = "plink"
	RFC2217  = 2320
	WEB2217  = 8080
	LockFile = "lockfile"
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
	Win7       = isWin7() // Виндовс7 не поддерживает ENABLE_VIRTUAL_TERMINAL_INPUT и ENABLE_VIRTUAL_TERMINAL_PROCESSING
	usePuTTY   bool
	once       = false
	OverSSH    = os.Getenv("SSH_CONNECTION") != ""
	BUSYBOX    = "busybox"
	MICROCOM   = false
	tmp        = filepath.Join(os.TempDir(), repo)
	ips        = ser2net.Ints()
)

//go:generate go run github.com/abakum/version
//go:generate go run cmd/main.go
//go:generate go run github.com/abakum/embed-encrypt
//go:generate go list -f '{{.EmbedFiles}}'

//encrypted:embed internal/ca
var CA []byte // Ключ ЦС

//go:embed VERSION
var Ver string

// `dssh` `dssh -d` `dssh -l revision` `revision` Где revision  это что-то типа 59d7a68 (смотри `dssh -V`)
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
	DebugF = func(format string) string {
		return fmt.Sprintf("%s%s %s\r\n", l.Prefix(), src(9), format)
	}
	WarningF = func(format string) string {
		return fmt.Sprintf("%s%s %s\r\n", le.Prefix(), src(9), format)
	}

	exe, err := os.Executable()
	Fatal(err)
	imag = strings.Split(filepath.Base(exe), ".")[0]

	Println(build(Ver, ips))
	if ips[0] == LH {
		Println(fmt.Errorf("not connected - нет сети"))
	}

	anyKey, err := x509.ParsePKCS8PrivateKey(CA)
	Fatal(err)

	// CA signer
	signer, err := ssh.NewSignerFromKey(anyKey)
	Fatal(err)

	// Like `parser := arg.MustParse(&args)` but override built in option `-v, --version` of package `arg`
	parser, err := NewParser(arg.Config{}, &args)
	Fatal(err)

	a2s := make([]string, 0) // Без встроенных параметров -h -v
	// cli := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-H":
			arg = "--path"
		case "-v":
			arg = "--debug"
		}
		switch strings.ToLower(arg) {
		case "-help", "--help":
			parser.WriteHelp(Std)
			return
		case "-h":
			parser.WriteUsage(Std)
			return
		case "-v", "-version", "--version":
			Println(args.Version())
			return
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

	// log.SetFlags(lf.Flags() | log.Lmicroseconds)
	log.SetFlags(lf.Flags())
	log.SetPrefix(lf.Prefix())
	if !args.Debug {
		log.SetOutput(io.Discard)
	}

	// tools
	SecretEncodeKey = key
	if args.NewHost ||
		args.EncSecret ||
		args.InstallTrzsz ||
		args.InstallPath != "" ||
		args.TrzszVersion != "" ||
		args.TrzszBinPath != "" ||
		false {
		Tssh(&args)
		return
	}

	if Cygwin {
		// cygpath -w ~/.ssh
		cygUserDir, err := cygpath("~")
		if err != nil {
			cygUserDir = "~"
		}
		cygUserDir = filepath.Join(cygUserDir, ".ssh")
		Println(fmt.Sprintf(`You can make a link - Можно сделать ссылку 'mklink /d "%s" "%s"'`, cygUserDir, SshUserDir))
	} else {
		usePuTTY = Win7 && !(args.DisableTTY || args.NoCommand)
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
	if Win7 && Cygwin {
	} else {
		if Windows {
			exit = " или <^Z>"
		}
		if Cygwin {
			exit = " или <^C>"
		}
	}
	quit := "<Enter>" + args.EscapeChar + "." + exit

	bins := []string{PUTTY, PLINK, TELNET}

	closerBug := args.Putty && Win7 && Cygwin
	if closerBug {
		args.Unix = false
	}

	if OverSSH || args.Unix {
		// В Юниксе используем консольные приложения plink или telnet
		bins = bins[1:]
		// Не создаёт новую консоль для запуска консольных приложений.
		Win = false
	}
	if args.Telnet {
		// Параметр чтоб эмулировать отсутствие putty и plink при наличии telnet или busybox microcom
		bins = []string{TELNET}
	}
	execPath, bin, err := look(bins...)
	if args.Putty && err != nil {
		Fatal(fmt.Errorf("not found - не найдены %v", bins))
	}

	if args.Putty && bin == TELNET {
		Println(fmt.Errorf("not found - не найдены PuTTY, plink"))
	}

	u, h, p := ParseDestination(args.Destination) //tssh
	s2, dial := dest2hd(h, ips...)
	nNear, nFar := near2far(portOB(args.Ser2net, RFC2217), &args, s2)
	wNear, wFar := near2far(portOB(args.Ser2web, WEB2217), &args, s2)

	djh := ""
	djp := ""
	if args.DirectJump != "" {
		dj := args.DirectJump
		if strings.Count(args.DirectJump, ":") == 0 {
			dj += ":" + LISTEN
		}
		djh, djp, err = net.SplitHostPort(dj)
		if err == nil {
			s2, dial = dest2hd(djh, ips...)
			djh = dial
			args.Destination = repo // Не локальный
			if djh == LH {
				args.Destination = "." // Локальный
			}

			for _, ip := range ips {
				if ip == djh {
					args.Destination = "." // Локальный
					break
				}
			}
			if djp == "" {
				djp = LISTEN
			}
		} else {
			Println(fmt.Errorf("error in param - ошибка в параметре '%s -j %s' %v", repo, args.DirectJump, err))
		}
	}

	serial := usbSerial(args.Serial)
	BS := args.Baud != "" || serial != ""
	if BS || nNear > 0 || wNear > 0 {
		enableTrzsz = "no"
		switch args.Destination {
		case "", LH, ".", "_", ips[0], "*", ips[len(ips)-1], ALL:
			// Локальный последовательный порт
			serial = getFirstUsbSerial(serial, args.Baud, Print)
			nNear = comm(serial, s2, nNear, wNear)
		default:
			usePuTTY = false
		}
		if nNear < 0 && (args.Putty || args.Telnet) {
			switch args.Destination {
			case "", LH:
				if bin == TELNET {
					if Win {
						// dssh --putty --telnet --baud 9
						// dssh --telnet --baud 9
						nNear = RFC2217
					} else {
						// dssh --putty --telnet --baud 9 --unix
						// dssh --telnet --baud 9 --unix
						MICROCOM = exec.Command("busybox", "microcom", "--help").Run() == nil
						if !MICROCOM {
							nNear = RFC2217
						}
					}
				}
			default:
				// dssh --putty --baud 9 :
				// dssh --putty --path com3 :
				nNear = RFC2217
			}
		}
	}

	// Println(fmt.Sprintf("args %+v", args))
	Println(repo, strings.Join(a2s, " "))
	defer closer.Close()
	closer.Bind(cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	closer.Bind(cancel)

	args.StdioForward = ser2net.LocalPort(args.StdioForward)
	if args.StdioForward != "" && args.Destination == "" {
		// Телнет сервер dssh -22
		// Телнет клиент без RFC2217 dssh -W:2322
		setRaw(&once)
		forwardSTDio(ctx, ser2net.ReadWriteCloser{Reader: os.Stdin, WriteCloser: os.Stdout}, args.StdioForward, quit, Println)
		return
	}

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
	if args.Restart || BS || nNear > 0 || wNear > 0 {
		Println("-r || -UU || -HH || -22 || -88")
		// CGI
		cli = true
		args.Command = repo
		// args.ForceTTY = true
		args.Argument = []string{}
		if args.Restart {
			// dssh --restart
			if args.Destination == "" {
				args.Destination = ":" // Рестарт сервера за NAT
			}
			args.Argument = append(args.Argument, "--restart")
		} else {
			Println("-UU || -HH || -22 || -88")
			switch args.Destination {
			case "", LH, "_", ips[0], "*", ips[len(ips)-1], ALL:
				// Println(`case "", LH, "_", ips[0], "*", ips[len(ips)-1], ALL:`)
				// Локальная последовательная консоль
				// Println("Local serial console - Локальная последовательная консоль")
				if args.Putty || args.Telnet {
					Println("(-UU || -HH || -22 || -88) && (-u || -Z)")
					// dssh -uUU хуже чем `dssh -UU` так как нельзя сменить скорость
					BaudRate := ser2net.BaudRate(strconv.Atoi(args.Baud))
					opt := fmt.Sprintln("-serial", serial, "-sercfg", fmt.Sprintf("%d,8,1,N,N", BaudRate))
					if nNear > 0 {
						Println("(-UU || -HH || -22 || -88) && (-u || -Z) && -22")
						opt = optTelnet(bin == TELNET, nNear)
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
					if !Win || Win7 && bin == TELNET {
						Println("(-UU || -HH || -22 || -88) && (-u || -Z) && (!Win || Win7 && -Z)")
						// dssh -uz
						// dssh -zuUU
						// dssh -zuUU
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stdout
						if nNear > 0 {
							Println("(-UU || -HH || -22 || -88) && (-u || -Z) && (!Win || Win7 && -Z) && -22")
							if bin == TELNET {
								Println("(-UU || -HH || -22 || -88) && (-u || -Z) && (!Win || Win7 && -Z) && -22 && -Z")
								// dssh --telnet --unix --putty --2217 0
								// dssh -uzZ22
								// dssh -Zz22
								cmd.Stdin = os.Stdin
								chanError := make(chan error, 2)
								chanSerialWorker := make(chan *ser2net.SerialWorker, 2)
								go func() {
									chanError <- s2n(ctx, nil, nil, chanSerialWorker, serial, s2, nNear, args.Baud, "", Println)
								}()
								select {
								case <-ctx.Done():
									return
								case err = <-chanError:
									return
								case w := <-chanSerialWorker:
									defer w.Stop()
									time.AfterFunc(time.Millisecond*111, func() {
										exit := "<^]>q<Enter>"
										if Cygwin && !Win7 {
											exit = "<^C>"
										}
										Println(ToExitPress, exit)
									})
									run()
								}
								return
							} else {
								Println("(-UU || -HH || -22 || -88) && (-u || -Z) && (!Win || Win7 && -Z) && -22 && !-Z")
								// dssh -uz22
								// dssh --unix --putty --2217 0
								// Microsoft Telnet выпадает
								// Linux Telnet виснет
								w, err := cmd.StdinPipe()
								if err == nil {
									chanByte := make(chan byte, B16)
									chanSerialWorker := make(chan *ser2net.SerialWorker, 2)

									chanError := make(chan error, 2)

									go func() {
										chanError <- s2n(ctx, nil, chanByte, chanSerialWorker, serial, s2, nNear, args.Baud, quit, Println)
									}()
									select {
									case err = <-chanError:
										Println(err)
									// case <-time.After(time.Second):
									case sw := <-chanSerialWorker:
										// Println("select", sw)
										err := cmd.Start()
										Println(cmd, err)
										if err == nil {
											setRaw(&once)
											Println(mess(quit, serial))
											sw.Copy(newSideWriter(w, args.EscapeChar, serial, chanByte, Println), os.Stdin)
											cmd.Wait()
										}
										return
									}
								}
							}
							Println("-------------------------------------------------------")
							// go func() {
							// 	Println(s2n(ctx, nil, nil, nil, serial, s2, nNear, args.Baud, "", Println))
							// 	closer.Close()
							// }()
						}
					} else {
						Println("(-UU || -HH || -22 || -88) && (-u || -Z) && !(!Win || Win7 && -Z)")
						// Win
						// dssh --putty --baud 9
						notPutty(bin, cmd) // dssh --telnet -putty --2217 0
						if nNear > 0 {
							Println("(-UU || -HH || -22 || -88) && (-u || -Z) && !(!Win || Win7 && -Z) && -22")
							// dssh --putty --2217 0
							// dssh --telnet --putty --baud 0
							// dssh -u22
							t := time.AfterFunc(time.Second*2, func() {
								run()
								closer.Close()
							})
							setRaw(&once)
							Println(s2n(ctx, os.Stdin, nil, nil, serial, s2, nNear, args.Baud, ". или <^C>", Println))
							t.Stop() // Если не успел стартануть то и не надо
							return
						}
					}
					if closerBug && bin != TELNET {
						setRaw(&once) //Отключаем ^C
						Println("To exit press [X] button of window " + bin + " - Чтоб выйти нажми  кнопку [X] окна " + bin)
						run()
						return
					}
					Println("!closerBug || bin == TELNET")
					exit := "<^C>"
					if MICROCOM {
						exit = "<^X>"
					}
					if bin != TELNET || MICROCOM {
						Println(ToExitPress, exit)
					}
					run()
					return
				}
				setRaw(&once)
				if wNear > -1 {
					Println("-88")
					hp := newHostPort(dial, wFar, serial, true)

					if isHP(hp.dest()) {
						// Подключаемся к существующему сеансу
						hp.read()
						Println(hp.String())

						go cancelByFile(ctx, cancel, hp.name(), TOW)
						Println(browse(ctx, dial, wFar, cancel))
						return
					}
					t := time.AfterFunc(time.Second*2, func() {
						Println(browse(ctx, dial, wFar, nil))
					})

					s2w(ctx, ser2net.ReadWriteCloser{Reader: os.Stdin, WriteCloser: os.Stdout}, nil, serial, s2, wNear, args.Baud, ". или ^C", Println)
					t.Stop() // Если не успел стартануть то и не надо
					return
				}
				// setRaw(&once)
				if nNear > 0 {
					Println("-22")
					Println(rfc2217(ctx, ser2net.ReadWriteCloser{Reader: os.Stdin, WriteCloser: os.Stdout}, serial, s2, nNear, args.Baud, exit, Println))
					return
				}
				// dssh -UU
				// dssh -Hcmd
				// dssh -H:2322
				Println("-UU || -Hcmd | -H:2322")
				Println(cons(ctx, ser2net.ReadWriteCloser{Reader: os.Stdin, WriteCloser: os.Stdout}, serial, args.Baud, exit, Println))
				return
			default:
				if args.Debug {
					args.Argument = append(args.Argument, "--debug")
				}
				if args.Baud != "" {
					args.Argument = append(args.Argument, "--baud", args.Baud)
				}
				if serial != "" {
					args.Argument = append(args.Argument, "--path", serial)
				}
				if nFar > 0 {
					args.Argument = append(args.Argument, "--2217", strconv.Itoa(nFar))
				}
				if wFar > 0 {
					args.Argument = append(args.Argument, "--web", strconv.Itoa(wFar))
				}
				if exit != "" {
					args.Argument = append(args.Argument, "--exit", exit)
				}
				if args.Putty {
					args.Argument = append(args.Argument, "--putty")
				}
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
		args.DirectJump != "" ||
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
	case "*", ALL, ips[len(ips)-1], "_", ips[0]:
		daemon = true
	default:
		switch h {
		case "*", ALL, ips[len(ips)-1], "_", ips[0]:
			daemon = true
		default:
			daemon = h+p == ""
		}
	}
	if args.Daemon || !cli && daemon {
		args.Daemon = true
		hh := dial
		h = s2
		// switch h {
		// case "", LH:
		// 	h = LH
		// case "*", ips[len(ips)-1], ALL:
		// 	h = ALL
		// 	hh = ips[len(ips)-1]
		// case "_", ips[0]:
		// 	h = ips[0]
		// }
		// if hh == "" {
		// 	hh = h
		// }
		if p == "" {
			p = LISTEN
			if args.Port != 0 {
				p = strconv.Itoa(args.Port)
			}
		}
		client(signer, local(hh, p, repo)+sshj+sshJ(JumpHost, u, hh, p))
		args.Destination = JumpHost
		go func() {
			s := fmt.Sprintf("`tssh %s`", JumpHost)
			i := 0
			hp := hh + ":" + p
			if p == LISTEN {
				if hh == LH {
					hp = ":"
				} else {
					hp = hh
				}
			} else {
				if hh == LH {
					hp = ":" + p
				}
			}
			for {
				Println(s, "has been started - запущен")
				Println("to connect use - чтоб подключится используй:")
				ss := ""
				if len(ips) != 0 {
					ss = fmt.Sprintf("over jump host - через посредника `%s :`", imag)
				}
				Println(fmt.Sprintf("local - локально `%s .` direct - напрямую `%s -j%s`", imag, imag, hp), ss)
				ss = ""
				if len(ips) != 0 {
					ss = fmt.Sprintf("\t`%s -u :`", imag)
				}
				Println(fmt.Sprintf("\tPuTTY\t`%s -u .`\t`%s -uj%s`%s", imag, imag, hp, ss))
				ss = ""
				if len(ips) != 0 {
					ss = fmt.Sprintf("\t`%s -uz :`", imag)
				}
				Println(fmt.Sprintf("\tplink\t`%s -uz .`\t`%s -uzj%s`%s", imag, imag, hp, ss))
				if len(ips) != 0 {
					ss = fmt.Sprintf("\t`%s -Z :`", imag)
				}
				Println(fmt.Sprintf("\tssh\t`%s -Z .`\t`%s -Zj%s`%s", imag, imag, hp, ss))
				code := Tssh(&args)
				if code == 0 {
					Println(s, code)
					i = 0
				} else {
					Println(fmt.Errorf("%s %d", s, code))
					if i > 3 || i == 0 {
						return
					}
					i++
				}
				if hh != LH {
					// Не получается через ssh-j.com будем подключаться напрямую через dssh -j host:port .
					return
				}
				time.Sleep(TOR)
			}
		}()
		for {
			Println(fmt.Sprintf("%s daemon waiting on - сервер ожидает на %s:%s", repo, h, p))
			psPrintln(filepath.Base(exe), "", 0)
			server(s2, p, repo, s2, signer, Println, Print)
			KidsDone(os.Getpid())
			Println("server has been stopped - сервер остановлен")
			time.Sleep(TOR)
		}
	} // Сервис

	// Клиенты
	if djh != "" && djp != "" {
		client(signer, local(djh, djp, repo)+sshj+sshJ(JumpHost, u, djh, djp), repo, SSHJ)
	} else {
		client(signer, sshj+sshJ(JumpHost, u, "", p), repo, SSHJ)
	}
	// Println(fmt.Sprintf("%+v",args))
	if args.Putty || args.Telnet || usePuTTY {
		opt := ""
		if args.Destination != "" {
			if nNear > 0 {
				// dssh --putty --2217 0 :
				// dssh --unix --putty --2217 0 :
				opt = optTelnet(bin == TELNET, nNear)
			} else {
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
					if Win7 {
						Win = false
					}
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
		if Win || nNear > 0 {
			notPutty(bin, cmd)
			if nNear > 0 {
				// dssh --putty --2217 0 :
				// dssh --telnet --putty --2217 0 :
				// dssh --putty --baud 9 :
				// dssh --telnet --putty --baud 9 :
				// dssh --unix --putty --2217 0 :
				// dssh --unix --telnet --putty --2217 0 :
				// dssh --unix --putty --baud 9 :
				// dssh --unix --telnet --putty --baud 9 :
				if !OverSSH {
					time.AfterFunc(TOW, func() {
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
			if bin == TELNET {
				// dssh --unix --telnet --putty :
				// ssh ssh-j
				if enableTrzsz == "no" || args.Destination == repo {
					Println(ToExitPress, "<Enter><"+args.EscapeChar+"><.>")
				}
			} else {
				// dssh --unix --putty :
				// plink -load ssh-j
				ConsoleCP()
			}
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
	if BS || nNear > 0 || wNear > 0 {
		setRaw(&once)
		if wNear > 0 {
			// dssh --web 0 :
			// dssh --web 0 .
			time.AfterFunc(time.Second*2, func() {
				Println(browse(ctx, dial, wFar, nil))
			})
		}
	} else if (enableTrzsz == "no" || args.Destination == repo) && args.StdioForward == "" {
		Println(ToExitPress, "<Enter><"+args.EscapeChar+"><.>")
	}

	code := Tssh(&args)
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

func isFileExist(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) { // os.IsNotExist(err)
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

		if args.Putty || usePuTTY {
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
				name := filepath.Join(SshUserDir, pref+".pub")
				if !isFileExist(name) {
					continue
				}
				name = filepath.Join(SshUserDir, pref+"-cert.pub")
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
	if args.Putty || (Win7 && !Cygwin) {
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

func cleanup() {
	// winssh.KidsDone(os.Getpid())
	time.Sleep(time.Millisecond * 111)
	KidsDone(os.Getpid())
	Println("cleanup done")
	// if !IsConsole() {
	// 	menu.PressAnyKey("Press any key - Нажмите любую клавишу", TOW)
	// }
}

func FingerprintSHA256(pubKey ssh.PublicKey) string {
	return pubKey.Type() + " " + ssh.FingerprintSHA256(pubKey)
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
	if args.Putty || usePuTTY {
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
 LogLevel debug
 RequestTTY no
 RemoteForward ` + SSHJ2 + `:` + PORT + ` ` + h + `:` + p + `
`
	}
	return alias
}

// Алиас для локального доступа. Попробовать sshd.
func local(h, p, repo string) string {
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

func cygpath(path string) (string, error) {
	cmd := exec.Command("cygpath", "-w", path)
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func PidDone(pid int) {
	Process, err := os.FindProcess(pid)
	if err == nil {
		Println("pid", pid, "done", Process.Kill())
		return
	}
	Println("pid", pid, err)
}

func TimeDone(after, before time.Time) {
	pes, err := ps.Processes()
	if err != nil {
		return
	}
	for _, p := range pes {
		if p == nil {
			continue
		}
		ct := p.CreationTime().Unix()
		if ct >= after.Unix() && ct <= before.Unix() {
			Println(p.Pid(), p.PPid(), p.Executable(), p.CreationTime())
			PidDone(p.Pid())
		}
	}
}

func dest2hd(Destination string, ips ...string) (host, dial string) {
	switch Destination {
	case "_", ips[0]:
		return ips[0], ips[0]
	case "*", ips[len(ips)-1], ALL:
		return ALL, ips[len(ips)-1]
	case "", ".", LH:
		return LH, LH
	default:
		return Destination, Destination
	}
}

func all2dial(host string) string {
	if host == ALL {
		return ips[len(ips)-1]
	}
	return host
}

func portOB(opt, base int) int {
	if opt >= 0 && opt <= 9 {
		return base + opt
	}
	return opt
}

func near2far(iNear int, args *SshArgs, s2 string) (oNear, oFar int) {
	oNear = iNear
	oFar = iNear
	if iNear > -1 {
		switch args.Destination {
		case "", LH:
		case ".":
			oNear += 10
			fallthrough
		default:
			args.LocalForward.UnmarshalText([]byte(fmt.Sprintf("%s:%d:%s:%d", LH, oNear, s2, oFar)))
		}
	}
	return
}

func MkdirTemp(path string) (name string, err error) {
	name = filepath.Join(tmp, path)
	err = os.MkdirAll(name, DIRMODE)
	if errors.Is(err, fs.ErrExist) { //os.IsExist(err)
		err = nil
	}
	return
}

// Открывает dest в Хроме или другом браузере.
// Побочно посылает в chanString
func browse(ctx context.Context, dial string, port int, cancel context.CancelFunc) (err error) {
	dest := fmt.Sprintf("http://%s:%d", dial, port)
	if OverSSH {
		Println("On remote side open - Открой на дальней стороне", dest)
		return
	}
	if !chrome.IsInstalled() {
		Println("Install chrome")
		after := time.Now()
		before := after.Add(time.Second * 3)
		err = browser.OpenURL(dest)
		if err != nil {
			return
		}
		Println("browse", dest)
		closer.Bind(func() {
			TimeDone(after, before)
		})
		return
	}
	root := fmt.Sprintf("%s_%d", dial, port)
	temp, err := MkdirTemp(root)
	if err != nil {
		return
	}
	for i := 0; true; i++ {
		if i > 9 {
			return fmt.Errorf("too many chromes")
		}
		temp, err = MkdirTemp(filepath.Join(root, strconv.Itoa(i)))
		if err != nil {
			return
		}
		lf := filepath.Join(temp, LockFile)
		if i == 0 && cancel != nil {
			go cancelByFile(ctx, cancel, lf, TOW)
		}
		if !isFileExist(lf) {
			break
		}
	}

	chromeCmd := chrome.Command(dest, temp, temp)
	err = chromeCmd.Start()
	if err != nil {
		return
	}
	Println("chrome", dest)
	go func() {
		<-ctx.Done()
		chromeCmd.Close()
	}()
	err = chromeCmd.Wait()
	if err != nil {
		return
	}
	closer.Close()
	return
}

func KidsDone(ppid int) {
	if ppid < 1 {
		return
	}
	pes, err := ps.Processes()
	if err != nil {
		return
	}
	for _, p := range pes {
		if p == nil {
			continue
		}
		if p.PPid() == ppid && p.Pid() != ppid {
			PidDone(p.Pid())
		}
	}
}

// Если serial это команда то запускаем web-сервер или telnet-сервер.
// Даже если параметр --2217 не задан.
func comm(serial, s2 string, nNear, wNear int) int {
	if serial == "" {
		xNear := nNear
		url := "telnet"
		if wNear > 0 {
			xNear = wNear
			url = "http"
		} else if nNear < 0 {
			// dssh --baud 9
			// dssh --path com3
			nNear = RFC2217
			xNear = RFC2217
		}
		if serial != "" {
			Println(fmt.Sprintf("we will try to use %q over - будем пробовать использовать %s через %s://%s:%d", serial, serial, url, s2, xNear))
		} else {
			Println(fmt.Sprintf("we will try to use - будем пробовать использовать %s://%s:%d", url, s2, xNear))
		}
	}
	return nNear
}

func cancelByFile(ctx context.Context, cancel func(), name string, delay time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			if !isFileExist(name) {
				if cancel != nil {
					cancel()
				}
				return
			}
		}
	}
}

// Чтоб  использовать третий порт для windows используй -H3 или -Hcom3 или -H\\.\com3.
// Можно указать -H1410 или -Hcu.usbserial-1410 или -H/dev/cu.usbserial-1410 для darwin.
// Можно указать -H0 или -HttyUSB0 или -H/dev/ttyUSB0.
func usbSerial(s string) (path string) {
	if !ser2net.SerialPath(s) {
		// Поиск первого USB порта getFirstUsbSerial
		return s
	}
	trim := func(r string) string {
		return r
	}
	dir := "/dev/"
	s2l := strings.ToLower(s)
	base := "ttyUSB"
	switch runtime.GOOS {
	case "darwin":
		base = "cu.usbserial-"
	case "windows":
		dir = `\\.\`
		base = "COM"
		trim = func(r string) string {
			if strings.HasPrefix(strings.ToUpper(r), dir+base) {
				return strings.TrimPrefix(r, dir)
			}
			return r
		}
	}
	_, err := strconv.Atoi(s)
	if err != nil {
		if strings.HasPrefix(s2l, dir) {
			return trim(s)
		}
		return trim(dir + s)
	}
	return trim(dir + base + s)
}

func psPrintln(name, parent string, ppid int) {
	var ss []string
	pes, err := ps.Processes()
	if err != nil {
		return
	}
	for _, p := range pes {
		if p == nil {
			continue
		}
		ok := true
		if ppid == 0 {
			ok = parent == ""
			if !ok {
				pp, err := ps.FindProcess(p.PPid())
				ok = err != nil && pp != nil && pp.Executable() == parent
			}
		} else {
			ok = p.PPid() == ppid
		}
		// fmt.Printf("%q==%q %v", p.Executable(), name, ok && p.Executable() == name)
		if ok && p.Executable() == name {
			ss = append(ss, p.CreationTime().Local().Format("20060102T150405"))
		}
	}
	if len(ss) > 1 {
		Println(fmt.Errorf("%v", ss))
	}
}

// Типа stfioForward
func forwardSTDio(ctx context.Context, s io.ReadWriteCloser, addr, exit string, println ...func(v ...any)) (err error) {
	conn, err := net.Dial("tcp", addr)
	for _, p := range println {
		p(fmt.Sprintf("telnet://%s", addr), err)
	}
	if err != nil {
		return
	}
	defer conn.Close()

	go ser2net.Copy(ctx, s, conn)
	println[0](mess(exit, "$"+addr))
	_, err = ser2net.Copy(ctx, newSideWriter(conn, args.EscapeChar, "", nil, println...), s)
	return
}

func isHP(hostport string) (ok bool) {
	_, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return
	}
	conn, err := net.DialTimeout("tcp", hostport, time.Second)
	if err != nil {
		return
	}
	conn.Close()
	return true
}
