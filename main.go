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

Запускаем `dssh -v` как сервис. Первый раз с `-v`. Если указан параметр `-v` или `--debug` то на всякий случай создаются копии старых файлов .old
Обязательно запускаем `dssh .` как клиента через посредника `dssh@ssh-j.com` на хосте за NAT.
В файл ~/.ssh/config дописываются алиасы хостов dssh, ssh-j, ssh-j.com.
Создаются файлы известных хостов `~/.ssh/ssh-j` (по запросу) и `~/.ssh/dssh`
Если агент ключей получает ключ id_x то создаётся сертификат `~/.ssh/id_x-cert.pub`
Без этого файла и доступа к агенту ключей в момент запуска доступ к dssh-серверу через putty или ssh не возможен.

Если указан параметр `-u` или `--putty` то:
Создаются файлы сессий из `~/.ssh/config` в `~/.putty/sessions`
Создаётся сертификат хоста  в `~/.putty/sshhostcas`
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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/abakum/go-ser2net/pkg/ser2net"
	"github.com/abakum/go-serial"
	"github.com/abakum/go-stun/stun"
	"github.com/abakum/menu"
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
	SSHJ2    = LH
	JumpHost = SSHJ + ".com"
	PORTT    = 5000
	PORTW    = 8000
	PORTS    = 2200
	PORTV    = 5500
	LockFile = "lockfile"
	SEP      = ","
)

var (
	_          = encryptedfs.ENC
	_          = version.Ver
	SshUserDir = winssh.UserHomeDirs(".ssh")
	Cfg        = filepath.Join(SshUserDir, "config")
	KnownHosts = filepath.Join(SshUserDir, "known_hosts")
	args       SshArgs
	Std        = menu.Std
	repo       = base()     // Имя репозитория `dssh` оно же имя алиаса в .ssh/config
	rev        = revision() // Имя для посредника.
	imag       string       // Имя исполняемого файла `dssh` его можно изменить чтоб не указывать имя для посредника.
	Windows    = runtime.GOOS == "windows"
	Cygwin     = isatty.IsCygwinTerminal(os.Stdin.Fd())
	Win7       = isWin7() // Windows 7 не поддерживает ENABLE_VIRTUAL_TERMINAL_INPUT и ENABLE_VIRTUAL_TERMINAL_PROCESSING
	once,
	SP bool
	ZerroNewWindow = os.Getenv("SSH_CONNECTION") != ""
	tmp            = filepath.Join(os.TempDir(), repo)
	ips            = ser2net.Ints()
	EED            = "<Enter>~."
	EEDE           = EED
	ioc            = ser2net.ReadWriteCloser{Reader: os.Stdin, WriteCloser: os.Stdout, Cygwin: Cygwin}
	listen         = strconv.Itoa(PORTS)
	tt             *time.Timer
	eips           []string
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
	// parser, err := NewParser(arg.Config{Out: io.Discard, Exit: func(int) {}}, &args)
	parser, err := NewParser(arg.Config{}, &args)
	Fatal(err)

	a2s := []string{}   // Без встроенных параметров -h -v и без аргументов после args.Destination
	lasts := []string{} // После args.Destination
	command := false
	errError := ""
	for _, arg := range os.Args[1:] {
		if command {
			lasts = append(lasts, arg)
			continue
		}
		switch arg {
		case "-H":
			arg = "--path"
		case "-v":
			arg = "--debug"
		}
		switch strings.ToLower(arg) {
		case "--help":
			parser.WriteHelp(Std)
			return
		case "-h":
			parser.WriteUsage(Std)
			return
		case "-v", "--version":
			Println(args.Version())
			return
		default:
			a2s = append(a2s, arg)
		}
		args = SshArgs{}
		err = parser.Parse(a2s) // Для определения args.Destination

		if err != nil {
			if errError == err.Error() {
				break
			}
			ua := "unknown argument -"
			if strings.HasPrefix(err.Error(), ua) {
				ua = strings.TrimPrefix(err.Error(), ua)
				if strings.Contains(strings.ToLower(ua), "h") {
					// -ath
					parser.WriteUsage(Std)
					return
				}
				if strings.Contains(ua, "V") {
					// -ATV
					Println(args.Version())
					return
				}
			}
			// Println(arg, err)
			errError = err.Error()
			continue
		}
		if args.Destination != "" {
			command = true
		}
	}

	// Println(os.Args[0], a2s, lasts)
	args = SshArgs{}
	if err := parser.Parse(a2s); err != nil {
		parser.WriteUsage(Std)
		Fatal(err)
	}
	if args.Ver {
		Println(args.Version())
		return
	}

	args.Command = ""
	args.Argument = []string{}
	if len(lasts) > 0 {
		// args.Command = as[0]
		// args.Argument = as[1:]

		// Так в Linux подставляются переменные среды
		args.Command = strings.Join(lasts, " ")
		// if args.ForceTTY {
		// 	setRaw(&once)
		// }
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

	EED = "<Enter>" + args.EscapeChar + "."
	exit := " или <^D>"
	if Windows {
		exit = " или <^Z>"
	}
	EEDE = EED + exit

	autoDirectJump := ""
	autoDirectJumpOnce := false
	// -j  Это автообход посредника для dssh-сервера с внешним IP и `dssh +`
	adj := func() (s string) {
		cgi := exec.Command(repo, "-T", ":", repo, "-j")
		cgi.Stdin = os.Stdin
		cgi.Stderr = os.Stderr
		output, err := cgi.Output()
		Println(string(output), err)
		if err != nil {
			return
		}
		ips := strings.Split(string(output), SEP)
		for _, ip := range ips {
			if ip != LH && isHP(JoinHostPort(ip, PORTS)) {
				Println("-j", ip)
				return ip
			}
		}
		return
	}
	if args.DirectJump && args.Destination == "" {
		autoDirectJumpOnce = true
		autoDirectJump = adj()
		if autoDirectJump == "" {
			Println(fmt.Errorf("auto directJump failed - без посредника не обойтись"))
			args.DirectJump = false
			args.Destination = "."
		} else {
			Println("directJump success - Дальше без посредника")
			args.Destination = autoDirectJump
		}
	}

	u, h, p := ParseDestination(args.Destination) //tssh
	p = portPB(p, PORTS)
	s2, dial := host2LD(h)
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
	tmpU := filepath.Join(tmp, u)
	dot := psPrint(filepath.Base(exe), "", 0, PrintNil) > 1 && isFileExist(tmpU)
	portT := portOB(args.Ser2net, PORTT)
	portW := portOB(args.Ser2web, PORTW)
	portV := portOB(args.VNC, PORTV)

	argsShare := args.Share
	if args.Share {
		// Отдаём свою консоль через dssh-сервер
		portT, portW = optS(portT, portW)
		if args.Destination == "" || isDssh() {
			// -s
			// -s .
			// -s :
			args.Share = !(dot || args.Destination == "")
			args.Destination = ":"
			if !args.Share {
				args.Destination = ""
			}
		}
	}
	emptyCommand := args.Command == "" && !args.NoCommand
	if args.Use {
		if args.Destination == "" || isDssh() {
			portT, portW = optS(portT, portW)
			// Используем консоль dssh-сервера
			// -0
			// -0 .
			// -0 :
			if !dot {
				args.Destination = ":"
				// -20 :
			}
		} else {
			if emptyCommand {
				// -0 X
				// Используем консоль sshd-сервера X
				portT, portW = optS(portT, portW)
				// X dssh -HH -UU -22 -88

			} else {
				args.Use = false
				Println(fmt.Errorf("option -0 only used without command - ключ -0 используется только если нет команды"))
				// X command
			}
		}
	}
	// Заменяем `dssh .` на `dssh :` если на хосте не запущен dssh-сервер
	switch args.Destination {
	case ".", repo:
		if !dot {
			args.Destination = ":"
		}
	}

	loc := localHost(args.Destination)

	optL(portT, &args, s2, loc, dot)
	optL(portW, &args, s2, loc, dot)

	external := args.Putty || args.Telnet

	switch args.Serial {
	case "H":
		args.Serial = ":"
		if args.Destination == "" && !isHP(JoinHostPort(LH, PORTT)) {
			args.Destination = ":"
			if dot {
				args.Destination = "."
			}
		} else if isDssh() {
			args.Serial = ""
			if portT < 0 {
				portT = PORTT
			}
		}
	case "_", "+":
		args.Serial += ":"
	}
	if strings.HasSuffix(args.Serial, ":") {
		args.Serial += strconv.Itoa(PORTT)
	}

	if args.Baud == "" {
		if args.Destination == "" && external || // -u || -Z
			args.Unix && !external { // -z
			args.Baud = "U"
		}
	}

	vncDirect := portV > 0 && !loc
	if vncDirect && isDssh() && !args.DirectJump {
		// -70 : Это Показывающий подключается к Наблюдателю с внешним IP и `dssh +`
		if !autoDirectJumpOnce {
			autoDirectJump = adj()
		}
		if autoDirectJump == "" {
			Println(fmt.Errorf("let's not abuse the kindness of - не будем злоупотреблять добротой %s", JumpHost))
			vncDirect = false
		} else {
			args.DirectJump = true
			args.Destination = autoDirectJump
		}
	}
	BSnw := args.Serial != "" || args.Baud != "" || portT > 0 || portW > 0

	if !loc && Win7 && !(args.DisableTTY || args.NoCommand || Cygwin || external || BSnw) {
		s := PUTTY
		_, err := exec.LookPath(s)
		args.Putty = err == nil
		if !args.Putty { //
			s = SSH
			_, err := exec.LookPath(s)
			args.Telnet = err == nil
		}
		external = args.Putty || args.Telnet
		if external {
			Println(fmt.Errorf("trying to use - в Windows 7 пробую использовать " + s))
		}

	}
	if args.Command != "" && args.Putty && !args.Unix {
		Println(fmt.Errorf("for run will use - для запуска %q будем использовать plink", args.Command))
		args.Unix = true
	}
	if Win7 && !(Cygwin || external) {
		Println(fmt.Errorf("try to use - в Windows 7 попробуй использовать `-88`"))
	}

	djh := ""
	djp := ""
	if args.DirectJump {
		dj := args.Destination
		if strings.Count(dj, ":") == 0 {
			dj += ":" + listen
		}
		djh, djp, err = net.SplitHostPort(dj)
		if err == nil {
			s2, dial = host2LD(djh)
			djh = dial
			// if args.Command != "" {
			// 	args.Command = args.Destination + " " + args.Command
			// }
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
				djp = listen
			}
		} else {
			Println(fmt.Errorf("error in param - ошибка в параметре `%s -j %s` %v", repo, args.Destination, err))
		}
	}
	loc = localHost(args.Destination)

	if Win7 && args.Telnet {
		pe := func(s string) {
			if args.Unix {
				return
			}
			Println(fmt.Errorf("can't run in a separate window - не могу запускать " + s + " в отдельном окне на Windows 7"))
		}
		if loc {
			pe(TELNET)
		} else {
			pe(SSH)
			args.Unix = true
		}
	}

	external = args.Putty || args.Telnet
	signers, err := externalClient(&external, exe)
	if err != nil {
		Println(err)
	}

	ser, sw, sh, sp := swSerial(args.Serial)
	SP = ser == "" || sw == "s"
	if loc && Win7 && Cygwin && SP {
		if args.Unix && args.Putty {
			Println(fmt.Errorf("can't interrupt - не могу прервать plink в Cygwin на Windows 7"))
		}
		args.Unix = false
	}
	ZerroNewWindow = ZerroNewWindow || args.Unix
	existsPuTTY := false
	extSer := false
	extTel := false
	bins := []string{}
	if !args.Telnet {
		if ZerroNewWindow {
			bins = []string{PLINK}
		} else {
			bins = []string{PUTTY, PLINK}
		}
	}
	var execPath, bin string
	if external {
		_, err := exec.LookPath(TELNET)
		if err == nil {
			extTel = true
			bins = append(bins, TELNET)
		}

		if !Windows {
			_, err := exec.LookPath(BUSYBOX)
			if err == nil {
				if SP && !args.Telnet {
					// putty plink busybox
					extSer = exec.Command(BUSYBOX, MICROCOM, "--help").Run() == nil
				} else {
					// putty plink telnet
					// putty plink busybox
					if !extTel {
						extTel = exec.Command(BUSYBOX, TELNET).Run() == nil
					}
				}
				if extSer || extTel {
					bins = append(bins, BUSYBOX)
				}
			}
		}

		// putty plink telnet - extTel
		// putty plink busybox - extTel
		// putty plink busybox - extSer
		execPath, bin, err = look(bins...)
		if err != nil {
			if external {
				Println(fmt.Errorf("not found - не найдены %v", bins))
			}
		} else {
			switch bin {
			case PUTTY, PLINK:
				existsPuTTY = true
				extSer = true
				extTel = true
			default:
				if args.Putty {
					Println(fmt.Errorf("not found - не найдены PuTTY, plink"))
				}
			}
		}
	}
	external = extSer || extTel

	if Cygwin {
		// cygpath -w ~/.ssh
		cygUserDir, err := cygpath("~")
		if err != nil {
			cygUserDir = "~"
		}
		cygUserDir = filepath.Join(cygUserDir, ".ssh")
		Println(fmt.Sprintf(`You can make a link - Можно сделать ссылку 'mklink /d "%s" "%s"'`, cygUserDir, SshUserDir))
	}

	if external && loc {
		switch sw {
		case "t":
			if isHP(ser) {
				if portT < 0 || localHost(sh) {
					portT = sp
				}
			} else {
				Println(fmt.Errorf("not connected to - не удалось подключиться к %q", ser))
				return
			}
		case "", "s":
			if portT < 0 && !extSer {
				portT = PORTT
			}
		case "c":
			if portT < 0 {
				portT = PORTT
			}
		}
	}
	BSnw = ser != "" || args.Baud != "" || portT > 0 || portW > 0
	var mode serial.Mode
	if BSnw {
		enableTrzsz = "no"
		if loc || args.Destination == "." {
			// Локальный последовательный порт
			usbSerial := ""
			usbSerial, mode = getFirstUsbSerial(ser, args.Baud, Print)
			ser, sw, _, _ = swSerial(usbSerial)
			SP = ser == "" || sw == "s"
			BSnw = BSnw || ser != ""
			portT = comm(ser, s2, portT, portW)
			BSnw = BSnw || portT > 0 || portW > 0
		}
	}

	// Println(fmt.Sprintf("args %+v", args))
	Println(os.Args[0], a2s, args.Command)

	defer closer.Close()
	closer.Bind(cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	closer.Bind(cancel)

	args.StdioForward = ser2net.LocalPort(args.StdioForward)
	if args.StdioForward != "" && args.Destination == "" {
		// Телнет сервер dssh -22
		// Телнет клиент без RFC2217 dssh -W:5002
		setRaw(&once)
		forwardSTDio(ctx, ioc, args.StdioForward, EEDE, Println)
		return
	}
	nw := func(s2, dial string) {
		if portW > 0 {
			if portT > 0 {
				Println(repo, "-H", ser, "-2", portT)
				go func() {
					setRaw(&once)
					Println(rfc2217(ctx, ioc, ser, s2, portT, args.Baud, exit, Println))
					closer.Close()
				}()
				// Даже если -H: это может быть set2net или hub4com или RouterOS позволяющие только одного клиента
				time.Sleep(time.Second)
				ser = JoinHostPort(s2, portT)
			}
			Println(repo, "-H", ser, "-8", portW)
			if hp := newHostPort(dial, portW, ser); isHP(hp.dest()) {
				// Подключаемся к существующему сеансу
				hp.read()
				Println(hp.String())

				go cancelByFile(ctx, cancel, hp.name(), TOW)
				Println(ToExitPress, "<^C>")
				Println(browse(ctx, dial, portW, cancel))
				return
			}
			// Стартуем веб сервер
			t := time.AfterFunc(time.Second*2, func() {
				Println(browse(ctx, dial, portW, nil))
			})
			defer t.Stop() // Если не успел стартануть то и не надо

			setRaw(&once)
			if portT > 0 {
				Println(s2w(ctx, nil, nil, ser, s2, portW, args.Baud, "", PrintNil))
			} else {
				Println(s2w(ctx, ioc, nil, ser, s2, portW, args.Baud, ". или ^C", Println))
			}
		} else {
			Println(repo, "-H", ser, "-2", portT)
			setRaw(&once)
			Println(rfc2217(ctx, ioc, ser, s2, portT, args.Baud, exit, Println))
		}
	}

	sshj := `
Host ` + SSHJ + ` :
 User _
 HostName ` + SSHJ2 + `
 UserKnownHostsFile ~/.ssh/` + repo + `
 KbdInteractiveAuthentication no
 PasswordAuthentication no
 RequestTTY yes
 ProxyJump ` + u + `@` + JumpHost + `
 EnableTrzsz ` + enableTrzsz

	if args.Command == "" && (args.Restart || args.Stop || BSnw || vncDirect) {
		// Println("CGI")
		cli = true
		// args.ForceTTY = true
		args.Argument = []string{}
		if args.Restart || args.Stop {
			// dssh --restart
			if args.Destination == "" {
				args.Destination = ":" // Рестарт сервера за NAT
			}
			args.Command = repo
			if args.Restart {
				args.Argument = append(args.Argument, RESTART)
			}
			if args.Stop {
				s := winssh.UserName()
				hostname, err := os.Hostname()
				if err == nil {
					s += "@" + hostname
				}
				s += " " + winssh.Banner()
				args.Argument = append(args.Argument, "--exit", s)
			}
		} else {
			// Println("-UU || -HH || -22 || -88")
			if loc {
				Println("Local console - Локальная консоль", ser)
				if external {
					opt := ""
					if portT > 0 {
						opt = optTelnet(bin, dial, portT)
					} else {
						// mode := getMode(serial, args.Baud)
						if !existsPuTTY && extSer {
							opt = fmt.Sprintln(MICROCOM, "-s", mode.BaudRate, ser)
							execPath = BUSYBOX
						} else {
							opt = fmt.Sprintln("-serial", ser, "-sercfg", fmt.Sprintf("%s,N", ser2net.Mode{Mode: mode}))
						}
					}

					opts := strings.Fields(opt)
					if args.Command != "" {
						opts = append(opts, args.Command)
					}
					cmd := exec.CommandContext(ctx, execPath, opts...)
					run := func() {
						err = cmd.Start()
						PrintLn(3, cmd, err)
						cmd.Wait()
					}
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stdout
					if portT > 0 {
						if extTel && args.Telnet {
							if !ZerroNewWindow && Windows {
								if !Win7 {
									createNewConsole(cmd)
									Println(cmdRun(cmd, ctx, os.Stdin, false, ser, s2, portT, args.Baud, exit, Println))
									return
								}
							}

							// Println("-zZ || -zu && !existsPuTTY")
							cmd.Stdin = os.Stdin
							ec := "q"
							if bin == BUSYBOX {
								ec = "e"
							}
							exit := "<^Q>" + ec + "<Enter>"
							if Cygwin && !Win7 {
								exit = "<^C>"
							}
							Println(cmdRun(cmd, ctx, nil, false, ser, s2, portT, args.Baud, exit, PrintNil))
							return
						}
						// !extTel || !args.Telnet
						if ZerroNewWindow {
							if bin == PLINK {
								ConsoleCP()
							} else {
								Println("-zu22", fmt.Errorf("plink not found"))
								return
							}
							// Println("-zu22")
							Println(cmdRun(cmd, ctx, nil, true, ser, s2, portT, args.Baud, exit, Println))
							return
						}
						if bin != PUTTY {
							Println("-u22", fmt.Errorf("PuTTY not found"))
							if bin == PLINK {
								createNewConsole(cmd)
							} else {
								Println("-u22", fmt.Errorf("plink not found"))
								return
							}
						}
						// Println("-u22")
						if Win7 && Cygwin {
							exit = "<^Z><^Z>"
						}
						Println(cmdRun(cmd, ctx, os.Stdin, false, ser, s2, portT, args.Baud, exit, Println))
						return
					}
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stdout
					cmd.Stdin = os.Stdin
					// Println("-u || -zu || extSer")
					exit := "<^C>"
					switch bin {
					case PUTTY:
						if Win7 && Cygwin {
							exit = "[X] on window with - на окне с PuTTY"
						}
					case PLINK:
						ConsoleCP()
					default:
						if extSer {
							exit = "<^X>"
						}
					}
					Println(ToExitPress, exit)
					run()
					return
				}
				// !external && loc
				if portT > 0 || portW > 0 {
					// Println("portT > 0 || portW > 0")
					nw(s2, dial)
					return
				}
				// Println("-HH || -Hcmd | -H:")
				setRaw(&once)
				Println(cons(ctx, ioc, ser, args.Baud, exit, Println))
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
		args.DirectJump ||
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
	// case "*", ALL, ips[len(ips)-1], "_", ips[0]:
	// 	daemon = true
	default:
		daemon = localHost(args.Destination)
		// switch h {
		// case "*", ALL, ips[len(ips)-1], "_", ips[0]:
		// 	daemon = true
		// default:
		// 	daemon = h+p == ""
		// }
		if !daemon {
			daemon = h+p == listen
		}
	}
	// Сервис.
	if args.Daemon || !cli && daemon {
		args.Daemon = true
		hh := dial
		h = s2
		if p == listen {
			if args.Port != 0 {
				p = strconv.Itoa(args.Port)
			}
		}
		client(signer, signers, local(hh, p, repo)+sshj+sshJ(JumpHost, u, hh, p))
		args.Destination = JumpHost
		time.AfterFunc(time.Second, func() {
			s := fmt.Sprintf("`tssh %s`", JumpHost)
			i := 0
			hp := hh + ":" + p
			if p == listen {
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

			prox := "local or over jump host - локально или через посредника"
			if s2 != ALL && s2 != LH {
				prox = "local - локально"
			}
			var once sync.Once
			for {
				var ss, eip, m string
				j := "`" + imag + " -j %s`"
				if ips[0] != LH && hh != LH {
					eip, m, err = GetExternalIP(time.Second, "stun.sipnet.ru:3478", "stun.l.google.com:19302", "stun.fitauto.ru:3478")
					if err == nil {
						Println(m)
						ehp := eip + ":" + p
						if p != listen {
							eip = ehp
						}
						if isHP(ehp) {
							ss = fmt.Sprintf("или WAN "+j, eip)
						} else {
							Println(fmt.Errorf("на роутере не настроен перенос %s->%s", ehp, hp))
						}
					}
				}
				Println("to connect use - чтоб подключится используй:")
				Println(fmt.Sprintf("%s `%s .` over - через LAN "+j, prox, imag, hp), ss)
				j = "\t`" + imag + "  -u%s`"
				if ss != "" {
					ss = fmt.Sprintf(j, "j "+eip)
				}
				Println(fmt.Sprintf("\tPuTTY"+j+j, " .", "j "+hp) + ss)
				j = "\t`" + imag + " -uz%s`"
				if ss != "" {
					ss = fmt.Sprintf(j, "j "+eip)
				}
				Println(fmt.Sprintf("\tplink"+j+j, " .", "j "+hp) + ss)
				j = "\t`" + imag + "  -Z%s`"

				// Список слушающих IP для CGI -j
				eips = []string{}
				if ss != "" {
					// WAN
					ss = fmt.Sprintf(j, "j "+eip)
					eips = append(eips, eip)
				}
				if s2 == ALL {
					eips = append(eips, ips...)
				} else {
					eips = append(eips, s2)
				}

				Println(fmt.Sprintf("\tssh"+j+j, " .", "j "+hp) + ss)
				lhListen := s2 == LH || s2 == ALL
				if portV > 0 {
					if lhListen {
						Println(fmt.Errorf("not compatible - не совместимы `--vnc %d  %s`", portV, s2))
					} else {
						once.Do(func() {
							// dssh --vnc 0 _
							startViewer(portV, false)
							go func() {
								for _, ip := range eips {
									if ip == LH {
										continue
									}
									// Показывающий на `dssh` или `dssh +`, подключись ко мне. Я Наблюдатель на `dssh _` жду тебя на порту portV на адресе ip
									cgi := exec.CommandContext(ctx, repo, "-T", ":", repo, "--vnc", JoinHostPort(ip, portV))
									cgi.Stdin = os.Stdin
									cgi.Stderr = os.Stderr
									createNewConsole(cgi)
									err := cgi.Start()
									Println(cgi, err)
									if err == nil {
										Println(cgi, cgi.Wait(), "done")
										return
									}
								}
							}()
						})
					}
				}
				if !lhListen {
					return
				}
				// dssh
				// dssh +
				Println(s, "has been started - запущен")
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
				time.Sleep(TOR)
			}
		})
		if os.WriteFile(tmpU, []byte{}, FILEMODE) == nil {
			closer.Bind(func() { os.Remove(tmpU) })
		}
		for {
			Println(fmt.Sprintf("%s daemon waiting on - сервер ожидает на %s:%s", repo, h, p))
			psPrint(filepath.Base(exe), "", 0, Println)
			exit := server(s2, p, repo, s2, signer, Println, Print)
			KidsDone(os.Getpid())
			if exit == "" {
				Println("the daemon will restart after - сервер перезапустится через", TOR)
			} else if strings.Contains(exit, "@") {
				Println("the daemon is stopped by - сервер остановлен клиентом", exit)
				return
			} else {
				Println(exit)
				return
			}
			time.Sleep(TOR)
		}
	} // Сервис

	// Клиенты
	if djh != "" && djp != "" {
		client(signer, signers, local(djh, djp, repo)+sshj+sshJ(JumpHost, u, djh, djp), repo, SSHJ)
	} else {
		client(signer, signers, sshj+sshJ(JumpHost, u, "", p), repo, SSHJ)
	}
	// Println(fmt.Sprintf("%+v",args))
	if external {
		opt := ""
		if args.Destination != "" {
			if portT > 0 {
				// dssh -u22 :
				// dssh -Z22 :
				opt = optTelnet(bin, LH, portT)
			} else {
				// dssh -u :
				switch bin {
				case PUTTY:
					opt = "@" + args.Destination
				case PLINK:
					opt = fmt.Sprintln("-no-antispoof", "-load", args.Destination)
				case TELNET, BUSYBOX:
					// dssh -Z :
					// За неимением...
					execPath = SSH
					opt = args.Destination
					// if Win7 {
					// 	ZerroNewWindow = true
					// }
				}
			}
		}
		// dssh -u22 : plink over telnet to remote
		// dssh -Z22 : telnet over telnet to remote
		// dssh -u : putty to remote
		// dssh -zu : plink to remote
		// dssh -Z : ssh to remote
		// dssh -zZ : ssh to remote
		opts := strings.Fields(opt)
		if args.Command != "" {
			opts = append(opts, args.Command)
		}
		cmd := exec.CommandContext(ctx, execPath, opts...)
		run := func() {
			err = cmd.Start()
			PrintLn(3, cmd, err)
			cmd.Wait()
		}
		if !ZerroNewWindow || portT > 0 {
			notPuttyNewConsole(bin, cmd)
			if portT > 0 {
				// dssh -u22 :
				// dssh -Z22 :
				if !ZerroNewWindow {
					time.AfterFunc(TOW, func() {
						run()
						closer.Close()
					})
				}
			} else {
				// dssh -u :
				Println(ToExitPress, "<^C>")
				run()
				return
			}
		} else {
			// ZerroNewWindow
			if extTel && args.Telnet {
				// dssh -zZ :
				// ssh ssh-j
				if enableTrzsz == "no" || args.Destination == repo {
					Println(ToExitPress, EED)
				}
			} else {
				// dssh -zu :
				// plink -load ssh-j
				ConsoleCP()
			}
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if args.ForceTTY {
				setRaw(&once)
			}
			run()
			return
		}
	}
	if vncDirect {
		// --vnc 0
		if isDssh() {
			startViewer(portV, true)
		} else if args.Destination != "" && emptyCommand {
			// -70 vnc.server.with.sshd
			startViewer(portV, true)
			args.Argument = []string{}
			lhp := JoinHostPort(LH, portV)
			switch goos(args.Destination) {
			case "windows":
				if vncserver == "" {
					vncserver = vncserverWindows
				}
				vncserver = strings.TrimSuffix(strings.ToLower(vncserver), ".exe")
				args.Command = fmt.Sprintf(
					"sc query %s|findstr RUNNING&&(%s -controlservice -connect %s&set/p p=Press Enter to disconnect&%s -controlservice -disconnectall&exit)&"+
						"%s -start&%s -controlservice -connect %s&set/p p=Press Enter to stop&%s -stop",
					vncserver, vncserver, lhp, vncserver,
					vncserver, vncserver, lhp, vncserver)
			default:
				if vncserver == "" {
					vncserver = vncserverEtc
				}
				if vncSecurityTypes == "" {
					vncSecurityTypes = vncSecurityTypesEtc
				}
				if display == "" {
					display = ":" + strconv.Itoa(portV-PORTV)
				}
				args.Command = fmt.Sprintf(
					"%s -SecurityTypes %s %s;"+
						"which vncconnect&&vncconnect -display %s %s||"+
						"which vncconfig&&vncconfig -display %s -connect %s&&killall tigervncconfig;"+
						"echo Press Enter to kill;read -rn1;%s -kill %s",
					vncserver, vncSecurityTypes, display,
					display, lhp,
					display, lhp,
					vncserver, display)
			}
			Println(args.Command)
			time.AfterFunc(time.Second, func() {
				switch runtime.GOOS {
				case "windows", "linux":
					established(ctx, lhp, true, Println)
				default:
					watchDarwin(ctx, nil, lhp, Println)
				}
				closer.Close()
			})
		}
	}
	// dssh -HH :
	// dssh -UU :
	// dssh -22 :
	// dssh -88 :
	if BSnw {
		setRaw(&once)
		share := func() {
			if ser == "" {
				ser, mode = getFirstUsbSerial(ser, args.Baud, PrintNil)
				if ser == "" {
					Println(ErrNotFoundFreeSerial)
				} else {
					portT, portW = optS(portT, portW)
				}
			}
			// Println("share", "serial", serial, "args.Baud", args.Baud, "portT", portT, "portW", portW)
			if portT > 0 || portW > 0 {
				Println("Share console - Отдаю консоль", ser, "через", args.Destination)
				// Обратный перенос портов
				args.NoCommand = true
				if portT > 0 {
					s4 := fmt.Sprintf("%s:%d:%s:%d", LH, portT, LH, portT)
					Println("-R", s4)
					args.RemoteForward.UnmarshalText([]byte(s4))
				}
				if portW > 0 {
					s4 := fmt.Sprintf("%s:%d:%s:%d", LH, portW, LH, portW)
					Println("-R", s4)
					args.RemoteForward.UnmarshalText([]byte(s4))
				}
				tt = time.AfterFunc(time.Second, func() {
					nw(LH, LH)
					closer.Close()
				})
			} else if h, p, err := net.SplitHostPort(ser); err == nil {
				Println("Remote console - Консоль", ser, "через", args.Destination)
				s4 := fmt.Sprintf("%s:%s:%s:%s", LH, p, h, p)
				Println("-L", s4)
				args.LocalForward.UnmarshalText([]byte(s4))
				args.NoCommand = true
				LHp := net.JoinHostPort(LH, p)
				time.AfterFunc(time.Second, func() {
					setRaw(&once)
					Println(cons(ctx, ioc, LHp, args.Baud, exit, Println))
					closer.Close()
				})
			}
		}
		// Println(args.Destination, isDssh(), args.Share)
		if isDssh() {
			if args.Share {
				share()
			} else {
				cgi(ctx, portT, portW, &args, ser, dial, exit)
			}
		} else {
			if args.Destination != "" && emptyCommand && args.Use {
				cgi(ctx, portT, portW, &args, ser, LH, "")
			} else {
				share()
			}
		}
	} else if (enableTrzsz == "no" || args.Destination == repo) && args.StdioForward == "" {
		Println(ToExitPress, EED)
	}
	if len(args.Argument) > 0 && args.Command == "" {
		args.Command = repo
	}

	code := Tssh(&args)
	if args.Background {
		Println("tssh started in background with code:", code)
		// closer.Hold()
	} else {
		if code != 0 {
			Println("tssh exit with code:", code)
			if argsShare && tt != nil {
				Println("Local console - Локальная консоль", ser)
				closer.Hold()
			}
		}
	}
}

// Какая ОС на sshd
func goos(dest string) (s string) {
	echo := exec.Command(repo, "-T", dest, "echo", "~")
	echo.Stdin = os.Stdin
	output, err := echo.Output()
	if err != nil {
		Println(echo, output, err)
		return
	}
	out := string(output)
	Println(echo, output, out)
	switch {
	case strings.HasPrefix(out, "~"):
		return "windows"
	case strings.HasPrefix(out, "/Users/"):
		return "darwin"
	case strings.HasPrefix(out, "/home/"):
		return "linux"
	}
	return
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

func cleanup() {
	// winssh.KidsDone(os.Getpid())
	time.Sleep(time.Millisecond * 111)
	KidsDone(os.Getpid())
	Println("cleanup done" + DECTCEM + EL) // показать курсор, очистить строку
}

func FingerprintSHA256(pubKey ssh.PublicKey) string {
	return pubKey.Type() + " " + ssh.FingerprintSHA256(pubKey)
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

func host2LD(host string) (listen, dial string) {
	switch host {
	case "_":
		return ips[len(ips)-1], ips[len(ips)-1]
	case "*", "+", ALL:
		return ALL, ips[0]
	case "", ".", LH:
		return LH, LH
	default:
		return host, host
	}
}

// portOB(1,5900) return 5901.
// portOB(5910,5900) return 5910.
func portOB(opt, base int) int {
	if opt >= 0 && opt <= 9 {
		return base + opt
	}
	return opt
}

// portPB("1",5900) return 5901.
// portPB("",5900) return 5900.
func portPB(p string, base int) string {
	if ui, err := strconv.ParseUint(p, 10, 16); err == nil {
		base = portOB(int(ui), base)
	}
	return strconv.Itoa(base)
}

// Что-то выполнить на дальнем dssh
func cgi(ctx context.Context, portT, portW int, args *SshArgs, serial, host, exit string) {
	Println("Remote console - Консоль", serial, "на", repo)
	if args.Debug {
		args.Argument = append(args.Argument, "--debug")
	}
	if args.Baud != "" {
		args.Argument = append(args.Argument, "--baud", args.Baud)
	}
	if serial != "" {
		args.Argument = append(args.Argument, "--path", serial)
	}
	if portT > 0 {
		args.Argument = append(args.Argument, "--2217", strconv.Itoa(portT))
		if exit == "" {
			s4 := fmt.Sprintf("%s:%d:%s:%d", LH, portT, LH, portT)
			Println("-L", s4)
			args.LocalForward.UnmarshalText([]byte(s4))
		}
	}
	if portW > 0 {
		args.Argument = append(args.Argument, "--web", strconv.Itoa(portW))
		if exit == "" {
			s4 := fmt.Sprintf("%s:%d:%s:%d", LH, portW, LH, portW)
			Println("-L", s4)
			args.LocalForward.UnmarshalText([]byte(s4))
		}
		time.AfterFunc(time.Second, func() {
			Println(browse(ctx, host, portW, nil))
		})
	}
	if exit != "" {
		args.Argument = append(args.Argument, "--exit", exit)
	}
	if len(args.Argument) > 0 {
		// args.Command = repo
		if exit == "" && !args.DisableTTY {
			args.ForceTTY = true
		}
	}
}

func startViewer(portV int, R bool) {
	if portV < 0 {
		return
	}
	vncViewerP := strconv.Itoa(portV)
	if R {
		args.Argument = append(args.Argument, "--vnc", vncViewerP)
		s4 := fmt.Sprintf("%s:%d:%s:%d", LH, portV, LH, portV)
		Println("-R", s4)
		args.RemoteForward.UnmarshalText([]byte(s4))
	}
	if vncviewer == "" {
		vncviewer = vncviewerEtc
		if runtime.GOOS == "windows" {
			vncviewer = vncviewerWindows
		}
	}
	if !isHP(net.JoinHostPort(LH, vncViewerP)) {
		vnc := exec.Command(vncviewer, "-listen", vncViewerP)
		err := vnc.Start()
		Println(vnc, err)
		if err != nil {
			return
		}
		vnc.Process.Release()
		time.Sleep(time.Second)
	}
}

func optL(port int, args *SshArgs, s2 string, loc, dot bool) {
	if port < 0 || loc || args.Share {
		return
	}
	switch args.Destination {
	case ".", repo:
		// -22 . Отдаём свою консоль через dssh-сервер
		// -22
		args.Destination = ""
	case ":", SSHJ:
		if dot {
			args.Destination = ""
			return
		}
		// -22 : Используем консоль dssh-сервера
		s4 := fmt.Sprintf("%s:%d:%s:%d", LH, port, s2, port)
		Println("-L", s4)
		args.LocalForward.UnmarshalText([]byte(s4))
	}
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
func browse(ctx context.Context, dial string, port int, cancel context.CancelFunc) (err error) {
	dest := "http://" + JoinHostPort(dial, port)
	// dest := fmt.Sprintf("http://%s:%d", dial, port)
	if ZerroNewWindow {
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
	Println(CHROME, dest)
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

// Если serial занят то запускаем web-сервер или telnet-сервер.
// Даже если параметр --2217 не задан.
func comm(serial, s2 string, portT, portW int) int {
	if serial == "" {
		port := portT
		url := "telnet"
		if portW > 0 {
			port = portW
			url = "http"
		} else if portT < 0 {
			// dssh --baud 9
			// dssh --path com3
			portT = PORTT
			port = PORTT
		}
		if serial != "" {
			Println(fmt.Sprintf("we will try to use %q over - будем пробовать использовать %s через %s://%s:%d", serial, serial, url, s2, port))
		} else {
			Println(fmt.Sprintf("we will try to use - будем пробовать использовать %s://%s:%d", url, s2, port))
		}
	}
	return portT
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

func psPrint(name, parent string, ppid int, print func(v ...any)) (i int) {
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
	i = len(ss)
	if i > 1 {
		print(fmt.Errorf("%v", ss))
	}
	return
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
	_, err = ser2net.Copy(ctx, newSideWriter(conn, args.EscapeChar, "", nil), s)
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

func PrintNil(v ...any) {
}

func JoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func localHost(host string) (ok bool) {
	if strings.HasPrefix(host, "127.0.0.") {
		return true
	}
	for _, ip := range append(ips, "", LH, "_", "*", ALL, "+") {
		if ip == args.Destination {
			ok = true
			return
		}
	}
	return
}

func swSerial(s string) (ser, sw, h string, p int) {
	ser = s
	if ser == "" {
		return
	}
	_, ok := ser2net.IsCommand(ser)
	if ok {
		sw = "c"
		// Команда или интерпретатор команд
		return
	}
	if ser2net.SerialPath(ser) {
		// Последовательный порт
		ser = serial.PortName(ser)
		sw = "s"
	}
	if h, p, err := net.SplitHostPort(ser); err == nil {
		// Клиент telnet
		if p, err := strconv.ParseUint(p, 10, 16); err == nil {
			p := portOB(int(p), PORTT)
			return ser2net.LocalPort(JoinHostPort(h, p)), "t", h, p
		}
	}
	return
}

func optS(portT, portW int) (t, w int) {
	if portT < 0 && portW < 0 {
		if Win7 && !Cygwin {
			return portT, PORTW
			// -80
		} else {
			// -20
			return PORTT, portW
		}
	}
	return portT, portW
}

func GetExternalIP(timeout time.Duration, servers ...string) (ip, message string, err error) {
	type IPfromSince struct {
		IP, From string
		Since    time.Duration
		Err      error
	}

	ch := make(chan *IPfromSince)
	defer close(ch)

	var once sync.Once
	t := time.AfterFunc(timeout, func() {
		once.Do(func() {
			ch <- &IPfromSince{"", strings.Join(servers, ","), timeout, fmt.Errorf("timeout")}
		})
	})
	defer t.Stop()
	for _, server := range servers {
		go func(s string) {
			client := stun.NewClient()
			client.SetServerAddr(s)
			t := time.Now()
			ip, err := client.GetExternalIP()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err, "from", s)
				return
			}
			// time.Sleep(time.Second)
			once.Do(func() {
				ch <- &IPfromSince{ip, s, time.Since(t), nil}
			})
		}(server)
	}
	i := <-ch
	message = fmt.Sprint(i.Err, " get external IP")
	if i.Err == nil {
		message = fmt.Sprint("External IP: ", i.IP)
	}
	message += fmt.Sprint(" from ", i.From, " since ", i.Since.Seconds(), "s")

	if i.Err != nil {
		return "127.0.0.1", message, fmt.Errorf("%s", message)
	}

	// time.Sleep(time.Second * 3)

	return i.IP, message, nil
}
