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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/abakum/go-ser2net/pkg/ser2net"
	"github.com/abakum/go-serial"
	"github.com/abakum/go-stun/stun"
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
	PORTC    = 2290
	LockFile = "lockfile"
	SEP      = ","
	Enter    = "<Enter>"
	CtrC     = "<^C>"
	AnyKey   = "Any key - Любую клавишу"
)

var (
	_          = encryptedfs.ENC
	_          = version.Ver
	SshUserDir = winssh.UserHomeDirs(".ssh")
	Cfg        = filepath.Join(SshUserDir, "config")
	KnownHosts = filepath.Join(SshUserDir, "known_hosts")
	args       SshArgs
	repo       = base()     // Имя репозитория `dssh` оно же имя алиаса в .ssh/config
	rev        = revision() // Имя для посредника.
	imag       string       // Имя исполняемого файла `dssh` его можно изменить чтоб не указывать имя для посредника.
	// win        = runtime.GOOS == "windows"
	Cygwin = isatty.IsCygwinTerminal(os.Stdin.Fd())
	Win7   = isWin7() // Windows 7 не поддерживает ENABLE_VIRTUAL_TERMINAL_INPUT и ENABLE_VIRTUAL_TERMINAL_PROCESSING
	once,
	SP bool
	ZerroNewWindow = os.Getenv("SSH_CONNECTION") != ""
	tmp            = filepath.Join(os.TempDir(), repo)
	ips            = ser2net.Ints()
	EED            = Enter + "~."
	EEDE           = EED
	ioc            = ser2net.ReadWriteCloser{Reader: os.Stdin, WriteCloser: os.Stdout, Cygwin: Cygwin}
	listen         = strconv.Itoa(PORTS)
	tt             *time.Timer
	eips           []string
	errAbuse       = fmt.Errorf("let's not abuse the kindness of - не будем злоупотреблять добротой %q", JumpHost)
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
	if len(lasts) > 0 && !args.NoCommand {
		// args.Command = as[0]
		// args.Argument = as[1:]

		// Так в Linux подставляются переменные среды
		args.Command = strings.Join(lasts, " ")
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
	enableTrzsz := "no"
	exit := " или <^D>"

	switch strings.ToLower(args.EscapeChar) {
	case "":
		args.EscapeChar = "~"
	case "none":
		exit = "<^D>"
		if win {
			exit = "<^Z>"
		}
		EED = ""
		enableTrzsz = "yes"
	default:
		EED = Enter + args.EscapeChar + "."
	}
	EEDE = EED + exit
	args.Option.UnmarshalText([]byte("EscapeChar=" + args.EscapeChar))

	// `dssh` как `dssh -d`
	// `foo` как `dssh foo@` как `dssh -dl foo`
	setU := func(fromDest string) string {
		if args.LoginName != "" {
			return args.LoginName // dssh -l foo
		}
		if fromDest != "" {
			return fromDest
		}
		if imag != repo {
			return imag // Если бинарный файл переименован то вместо ревизии имя переименованного бинарного файла и будет именем для посредника ssh-j.com
		}
		return rev // Имя для посредника ssh-j.com
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer closer.Close()
	cleanup := func() {
		Std.WriteString("\n" + DECTCEM + REL) // показать курсор, очистить строку
		Debug("cleanup")
		<-ctx.Done()
		if !KidsDone(os.Getpid()) {
			Println("cleanup done")
		}
	}
	closer.Bind(cleanup)
	closer.Bind(cancel)

	if args.ProxyJump != "" && isDssh(args.Destination == "") && !args.DirectJump {
		args.DirectJump = true
		args.Destination = ":"
	}

	// -j  Это автообход посредника для dssh-сервера с внешним IP и `dssh`
	autoDirectJump := ""

	if (args.Sftp || args.Scp) && isDssh(args.Destination == "") {
		// Пытаемся напрямую но без фанатизма в отличии от -7
		args.DirectJump = true
	}
	// if args.DirectJump && isDssh(args.Destination == "") {
	if args.DirectJump && args.Destination == "" {
		autoDirectJump = getHP(ctx, autoDirectJump, setU(""))
		if autoDirectJump == "." {
			Println(fmt.Errorf("auto -j failed - без посредника не обойтись"))
			if args.ProxyJump != "" {
				Println(fmt.Sprintf("try over jump host - пробуем через посредника %q", args.ProxyJump))
				// -jJX ~> -jJX .
				// -jJX :~> -jJX :
			} else {
				args.DirectJump = false
				// -j ~> .
				// -j :~> :
			}
			if args.Destination == "" {
				args.Destination = autoDirectJump
			}
		} else {
			Println("auto -j success - Дальше через", autoDirectJump)
			// -j ~> -j autoDirectJump
			args.Destination = autoDirectJump
		}
	}

	u, h, pd := ParseDestination(args.Destination) //tssh

	p := portPB(pd, PORTS)

	bind, dial := host2BD(h)
	u = setU(u)

	tmpU := filepath.Join(tmp, u)
	// dot := psPrint(filepath.Base(exe), "", 0, PrintNil) > 1 && isFileExist(tmpU)
	dot := isFileExist(tmpU)
	portT := portOB(args.Ser2net, PORTT)
	portW := portOB(args.Ser2web, PORTW)
	portV := portOB(args.VNC, PORTV)

	if portV > 0 && args.Destination == "" && !args.DirectJump && !args.Use {
		// -70~> -s70
		Println(repo, "-s7", portV)
		shareVNC(ctx, portV, "", "")
		return
	}
	argsShare := args.Share
	if args.Share {
		// Отдаём свою консоль через dssh-сервер
		portT, portW = optS(portT, portW, portV)
		if isDssh(args.Destination == "") {
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
	if args.Use {
		if portV > 0 && args.Destination == "" && !args.DirectJump {
			useVNC(portV, "", "")
			return
		}
		if isDssh(args.Destination == "") {
			portT, portW = optS(portT, portW, portV)
			// Используем консоль dssh-сервера
			// -0
			// -0 .
			// -0 :
			if !dot {
				args.Destination = ":"
				// -20 :
			}
		} else {
			if args.Command == "" {
				// -0 X
				// Используем консоль sshd-сервера X
				portT, portW = optS(portT, portW, portV)
				// X dssh -HH -UU -22 -88

			} else if portV < 0 {
				args.Use = false
				Println(fmt.Errorf("option `--use` disabled by presence of command `%s %v` наличие команды отменяет ключ `--use`", args.Command, args.Argument))
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
	vncDirect := portV > 0 && !loc
	// Если loc то dssh-сервер без посредника и `dssh -T : dssh host.dssh:portV``
	if vncDirect && isDssh(false) {
		// -70 :
		// -70 .
		autoDirectJump = getHP(ctx, autoDirectJump, u)
		if autoDirectJump == "." {
			Println(errAbuse)
			vncDirect = false
			args.Destination = "_"
			loc = true
			bind, dial = host2BD(args.Destination)
			// Println(repo, args.Destination)
			// -70 _
		} else {
			args.DirectJump = true
			args.Destination = autoDirectJump
		}
	}

	optL(portT, &args, bind, loc, dot)
	optL(portW, &args, bind, loc, dot)

	external := args.Putty || args.Telnet

	switch args.Serial {
	case "H":
		args.Serial = ":"
		if args.Destination == "" {
			// -HH
			// Ищем среди локальных ips:5000
			lhIPs := []string{LH}
			if ips[0] != LH {
				lhIPs = append(lhIPs, ips...)
			}
			for _, ip := range lhIPs {
				ser := JoinHostPort(ip, PORTT)
				if isHP(ser) {
					args.Serial = ser
					break
				}
			}
			if args.Serial == ":" {
				// Не нашли тогда пробуем на dssh
				args.Destination = ":"
				if dot {
					args.Destination = "."
				}
			}
		}
		if isDssh(false) {
			// -HH .~>-20 .
			// -HH :~>-20 :
			args.Serial = ""
			if portT < 0 {
				portT = PORTT
			}
			Println(repo, "-2", portT, args.Destination)
		} else {
			// -HH x~>-H: x
			Println(repo, "-H"+args.Serial, args.Destination)
		}
	}
	ser, sw, sh, sp := swSerial(args.Serial, loc || args.Destination == ".")

	if args.Baud == "" {
		if args.Destination == "" && external || // -u || -Z
			args.Unix && !external { // -z
			args.Baud = "U"
		}
	}

	BSnw := ser != "" || args.Baud != "" || portT > 0 || portW > 0
	noAutoPutty := loc || args.DisableTTY || args.NoCommand || Cygwin || external || BSnw || portV > 0 || args.Sftp || args.Scp
	if Win7 && !noAutoPutty {
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
			bind, dial = host2BD(djh)
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

	external = false
	signers, certPub, err := externalClient(exe, &external, &args.Putty, &args.Telnet)
	if err != nil {
		Println(err)
	}

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

		if !win {
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
			ser, sw, _, _ = swSerial(usbSerial, true)
			SP = ser == "" || sw == "s"
			BSnw = BSnw || ser != ""
			portT = comm(ser, bind, portT, portW)
			BSnw = BSnw || portT > 0 || portW > 0
		}
	}

	// Println(fmt.Sprintf("args %+v", args))
	Println(os.Args[0], a2s, args.Command)

	// defer closer.Close()
	// closer.Bind(cleanup)
	// closer.Bind(cancel)

	args.StdioForward = ser2net.LocalPort(args.StdioForward)
	if args.StdioForward != "" && args.Destination == "" {
		// Телнет сервер dssh -22
		// Телнет клиент без RFC2217 dssh -W:5002
		setRaw(&once)
		forwardSTDio(ctx, ioc, args.StdioForward, EEDE, Println)
		return
	}
	portTW := func(bind, dial string) {
		if portT > 0 {
			if hp := JoinHostPort(bind, portT); isHP(hp) {
				Println(repo, "-H", hp)
			} else {
				Println(repo, "-H", ser, "-2", portT)
			}
		}
		if portW > 0 {
			if portT > 0 {
				go func() {
					setRaw(&once)
					Println(rfc2217(ctx, ioc, os.Stderr, ser, bind, portT, args.Baud, exit, Println))
					closer.Close()
				}()
				// Даже если -H: это может быть set2net или hub4com или RouterOS позволяющие только одного клиента
				time.Sleep(time.Second)
				ser = JoinHostPort(bind, portT)
			}
			if hp := newHostPort(dial, portW, ser); isHP(hp.dest()) {
				// Подключаемся к существующему сеансу
				print(repo, "-H", hp.dest())
				hp.read()
				Println(hp.String())

				go cancelByFile(ctx, cancel, hp.name(), TOW)
				Println(ToExitPress, CtrC)
				Println(browse(ctx, dial, portW, cancel))
				return
			}
			t := time.AfterFunc(time.Second*2, func() {
				Println(browse(ctx, dial, portW, nil))
			})
			defer t.Stop() // Если не успел стартануть то и не надо

			// Стартуем веб сервер
			setRaw(&once)
			if portT > 0 {
				Println(s2w(ctx, nil, nil, nil, ser, bind, portW, args.Baud, "", PrintNil))
			} else {
				Println(repo, "-H", ser, "-8", portW)
				Println(s2w(ctx, ioc, os.Stderr, nil, ser, bind, portW, args.Baud, ". или ^C", Println))
			}
		} else {
			setRaw(&once)
			Println(rfc2217(ctx, ioc, os.Stderr, ser, bind, portT, args.Baud, exit, Println))
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
				args.Argument = append(args.Argument, "--exit", userNameAtHostname())
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
							opt = fmt.Sprintln(MICROCOM, "-s", mode.BaudRate, serial.DevName(ser))
							execPath = BUSYBOX
						} else {
							opt = fmt.Sprintln("-serial", serial.DevName(ser), "-sercfg", fmt.Sprintf("%s,N", ser2net.Mode{Mode: mode}))
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
							if !ZerroNewWindow && win {
								if !Win7 {
									createNewConsole(cmd)
									Println(cmdRun(cmd, ctx, os.Stdin, os.Stderr, false, ser, bind, portT, args.Baud, exit, Println))
									return
								}
							}

							// Println("-zZ || -zu && !existsPuTTY")
							cmd.Stdin = os.Stdin
							ec := "q"
							if bin == BUSYBOX {
								ec = "e"
							}
							exit := "<^Q>" + ec + Enter
							if Cygwin && !Win7 {
								exit = CtrC
							}
							Println(cmdRun(cmd, ctx, nil, nil, false, ser, bind, portT, args.Baud, exit, PrintNil))
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
							Println(cmdRun(cmd, ctx, nil, nil, true, ser, bind, portT, args.Baud, exit, Println))
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
						// if Win7 && Cygwin {
						// 	exit = "<^Z><^Z>"
						// }
						Println(cmdRun(cmd, ctx, os.Stdin, os.Stderr, false, ser, bind, portT, args.Baud, exit, Println))
						return
					}
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stdout
					cmd.Stdin = os.Stdin
					// Println("-u || -zu || extSer")
					exit := CtrC
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
					portTW(bind, dial)
					return
				}
				// Println("-HH || -Hcmd | -H:")
				setRaw(&once)
				Println(cons(ctx, ioc, os.Stderr, ser, args.Baud, exit, Println))
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
	case "+":
		args.Destination = LH
		daemon = true
	case "@": // Меню tssh.
		args.Destination = ""
	case ":", SSHJ: // `dssh :` как `dssh ssh-j` как `foo -l dssh :`
		args.Destination = SSHJ
		args.LoginName = "_"
	case ".", repo: // `dssh .` как `dssh dssh` или `foo -l dssh .` как `foo -l dssh dssh`
		args.Destination = repo
		args.LoginName = "_"
	default:
		daemon = localHost(args.Destination)
		if !daemon {
			daemon = h+p == listen
		}
	}
	// Сервис.
	if args.Daemon || !cli && daemon {
		args.Daemon = true
		os.MkdirAll(tmp, DIRMODE)
		if os.WriteFile(tmpU, []byte{}, FILEMODE) == nil {
			closer.Bind(func() { os.Remove(tmpU) })
		}

		// var ctxServer context.Context
		// var cancelServer context.CancelFunc
		ctxServer, cancelServer := context.WithCancel(ctx)
		stopped := false
		holdR := func() {
			defer func() {
				stopped = true
				cancelServer()
			}()
			b := make([]byte, 4096)
		restart:
			for {
				n, err := os.Stdin.Read(b)
				if err != nil {
					return
				}
				for _, r := range string(b[:n]) {
					switch r {
					case 'r', 'R', 'к', 'К':
						cancelServer()
						continue restart
					}
					return
				}
				return
			}
		}
		hh := dial
		h = bind
		if p == listen {
			if args.Port != 0 {
				p = strconv.Itoa(args.Port)
			}
		}
		time.AfterFunc(time.Second, func() {
			s := fmt.Sprintf("`tssh %s`", JumpHost)
			i := 0
			h0 := dial
			if bind == ALL {
				h0 = ips[0]
			}
			hp := h0 + ":" + p
			if p == listen {
				if h0 == LH {
					hp = ":"
				} else {
					hp = h0
				}
			} else {
				if h0 == LH {
					hp = ":" + p
				}
			}

			prox := "local - локально"
			lhListen := bind == LH || bind == ALL
			if lhListen {
				prox = "local or over jump host - локально или через посредника"
				if portV > 0 {
					Println(fmt.Errorf("not compatible - не совместимы `--vnc %d  %s`", portV, bind))
				}
			}
			// var once sync.Once
			ss, eip, m := "", "", ""
			eips = []string{}
			j := "\t`" + imag + " -j %s`"
			if ips[0] != LH && (bind == ALL || bind == ips[0]) {
				// Есть Сеть и слушаем не только на лупбэке
				eip, m, err = GetExternalIP(time.Second, "stun.sipnet.ru:3478", "stun.l.google.com:19302", "stun.fitauto.ru:3478")
				if err == nil {
					Println(m)
					ehp := net.JoinHostPort(eip, p)
					if p != listen {
						eip = ehp
					}
					if strings.HasPrefix(cgiJ(ctx, u, ehp), net.JoinHostPort(strings.Join(ips, SEP), p)) {
						// Удалось подключиться к себе значит перенос в роутере настроен
						ss = fmt.Sprintf("\t%s\t\t\t\t\t\t"+j+" over - через WAN", imag, eip)
						// Список слушающих IP для CGI -j
						eips = append(eips, eip)
					} else {
						Println(fmt.Errorf("the router does not forward - роутер не переносит %s~>%s", ehp, net.JoinHostPort(ips[0], p)))
					}
				}
			}
			if bind == ALL {
				eips = append(eips, ips...)
			} else {
				eips = append(eips, bind)
			}
			Println("to connect use - чтоб подключится используй:")
			lan := " over - через LAN"
			if hp == ":" {
				lan = " local - локально"
			}
			Println(fmt.Sprintf("\t%s\t`%s .` %s", imag, imag, prox))
			Println(fmt.Sprintf("\t%s\t\t"+j+lan, imag, hp))
			if ss != "" {
				Println(ss)
			}
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

			if ss != "" {
				// WAN
				ss = fmt.Sprintf(j, "j "+eip)
			}

			Println(fmt.Sprintf("\tssh"+j+j, " .", "j "+hp) + ss)
			// Println(ToExitPress, CtrC)
			Println(ToExitPress, Enter)
			Println("For restart press - Для перезапуска нажми R" + Enter)
			if !lhListen {
				if portV > 0 {
					// dssh -77 .
					// dssh -77 _
					startViewer(portV, false)
					for _, ip := range eips {
						if ip == LH {
							continue
						}
						// Показывающий на `dssh` или `dssh +`, подключись ко мне. Я Наблюдатель на `dssh _` жду тебя на порту portV на адресе ip
						cgi := exec.CommandContext(ctx, repo, "-Tl", u, ":", repo, "--vnc", strconv.Itoa(portV), "-j", net.JoinHostPort(ip, p))
						cgi.Stdin = os.Stdin
						cgi.Stderr = os.Stderr
						createNewConsole(cgi)
						err := cgi.Start()
						Println(cgi, err)
						if err == nil {
							go func() {
								Println(cgi, cgi.Wait(), "done")
								closer.Close()
							}()
							break
						}
					}
				}
				holdR()
				return
			}
			go holdR()
			client(signer, signers,
				local(hh, p, repo)+sshj+sshJ(JumpHost, u, hh, p))
			args.Destination = JumpHost
			for {
				// Перезапуск ssh-клиента для ssh-j
				// dssh
				// dssh +
				Println(s, "has been started - запущен")
				code := Tssh(&args)
				if code == 0 {
					Println(s, code)
					i = 0
				} else {
					Println(fmt.Errorf("%s %d", s, code))
					if i == 0 {
						Println("первая попытка не удачна дальше не пробуем")
						return
					}
					if i > 3 {
						Println("3 попытки подряд не удачны дальше не пробуем")
						return
					}
					i++
				}
				time.Sleep(TOR)
			}
		})
		for {
			// Перезапуск dssh-сервера
			Println(fmt.Sprintf("%s daemon waiting on - сервер ожидает на %s:%s -l %s", repo, h, p, u))
			psPrint(filepath.Base(exe), "", 0, Println)
			// Доступ к сервисам на dssh-сервере через LH
			exit := server(ctxServer, cancelServer, u, bind, p, repo, LH, signer, Println, Print)
			if stopped {
				exit = userNameAtHostname()
			}
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
			ctxServer, cancelServer = context.WithCancel(ctx)
			time.Sleep(TOR)
		}
	} // Сервис

	// Клиенты
	dj := ""
	if djh != "" && djp != "" {
		dj = net.JoinHostPort(djh, djp)
		client(signer, signers,
			local(djh, djp, repo)+
				sshj+sshJ(JumpHost, u, djh, djp),
			repo, SSHJ)
	} else {
		client(signer, signers,
			sshj+sshJ(JumpHost, u, "", p),
			repo, SSHJ)
	}

	if portV > 0 && (args.Share || args.Use) {
		if !vncDirect {
			Println(fmt.Errorf("не удалось подключится напрямую к %s", repo))
			return
		}
		if args.Use {
			useVNC(portV, u, dj)
		}
		if args.Share {
			shareVNC(ctx, portV, u, dj)
		}
		return
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
				Println(ToExitPress, CtrC)
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
		if isDssh(false) {
			// -70 .
			startViewer(portV, true)
		} else if args.Destination != "" {
			if args.Command == "" {
				// -70 vnc.server.with.sshd
				startViewer(portV, true)
				sshVNC(ctx, portV)
			} else {
				args.VNC = -1
				portV = portOB(args.VNC, PORTV)
				vncDirect = false
				Println(fmt.Errorf("option `--vnc` disabled by presence of command `%s %v` наличие команды отменяет ключ `--vnc`", args.Command, args.Argument))
			}
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
					portT, portW = optS(portT, portW, portV)
				}
			}
			// Println("share", "serial", serial, "args.Baud", args.Baud, "portT", portT, "portW", portW)
			if portT > 0 || portW > 0 {
				Println("Share console - Отдаю консоль", ser, "через", args.Destination)
				// Обратный перенос портов
				args.NoCommand = true
				if portT > 0 {
					lhp := JoinHostPort(LH, portT)
					s4 := lhp + ":" + lhp
					Println("-R", s4)
					args.RemoteForward.UnmarshalText([]byte(s4))
				}
				if portW > 0 {
					lhp := JoinHostPort(LH, portW)
					s4 := lhp + ":" + lhp
					Println("-R", s4)
					args.RemoteForward.UnmarshalText([]byte(s4))
				}
				time.AfterFunc(time.Second, func() {
					portTW(LH, LH)
					closer.Close()
				})
			} else if sw == "t" {
				Println("Remote console - Консоль", ser, "через", args.Destination)
				lhp := JoinHostPort(LH, sp)
				s4 := lhp + ":" + ser
				Println("-L", s4)
				args.LocalForward.UnmarshalText([]byte(s4))
				args.NoCommand = true
				time.AfterFunc(time.Second, func() {
					setRaw(&once)
					Println(cons(ctx, ioc, os.Stderr, lhp, args.Baud, exit, Println))
					closer.Close()
				})
			}
		}
		// Println(args.Destination, isDssh(false), args.Share)
		if isDssh(false) {
			if args.Share {
				share()
			} else {
				cgi(ctx, portT, portW, &args, ser, exit)
			}
		} else {
			if args.Destination != "" && args.Command == "" && args.Use {
				// -0 X
				cgi(ctx, portT, portW, &args, ser, "")
			} else {
				share()
			}
		}
	} else if (enableTrzsz == "no" || args.Destination == repo) && args.StdioForward == "" && !vncDirect {
		Println(ToExitPress, EED)
	}
	if len(args.Argument) > 0 && args.Command == "" {
		args.Command = repo
	}

	sxStart := func() {
		if !(args.Sftp || args.Scp) {
			return
		}
		if args.Destination == SSHJ {
			// Println(fmt.Errorf("please don't abuse the kindness of - пожалуйста не злоупотребляйте добротой %q", JumpHost))
			Println(errAbuse)
			return
		}
		_, h, pd := ParseDestination(args.Destination)
		if h == "" {
			h = LH
		}
		p = portPB(pd, PORTS)
		if pd == "" && !isDssh(args.DirectJump) {
			p = PORT
		}
		// Алиас
		au, ah, ap, aj, err := SshToUHPJ(h)
		if err == nil {
			if au != "" {
				u = au
			}
			if ah != "" {
				h = ah
			}
			if ap != "" {
				p = ap
			}
			if p == "" {
				p = PORT
			}
		}
		if win && isDssh(args.DirectJump && args.Destination != "") {
			// -9j x
			// -9 :
			// -9 .
			if args.DirectJump {
				if certPub == "" {
					// Может удастся съэкономить
					ok := true
					_, certPub, err = externalClient(exe, &ok)
					if err != nil {
						certPub = ""
					}
				}
				if certPub != "" {
					u += ";x-DetachedCertificate=" + url.QueryEscape(certPub)
					// Security~>Load Authorities from PuTTY
					// Безопасность~>Загрузить центры сертификации из PuTTY
					WinSCP := `SOFTWARE\Martin Prikryl\WinSCP 2`
					Conf(filepath.Join(WinSCP, "Configuration", "Interface"), EQ, map[string]string{
						"SshHostCAsFromPuTTY": "1",
					})
				}
			} else {
				h, p = LH, strconv.Itoa(PORTS)
			}
			if h == LH {
				// Иногда то что не работает с -D работает с -L
				// lhp := JoinHostPort(LH, PORTC)
				lhp := net.JoinHostPort(LH, dPort(LH))
				s4 := lhp + ":" + net.JoinHostPort(h, p)
				Println("-L", s4)
				args.LocalForward.UnmarshalText([]byte(s4))
				go sx(ctx, u, lhp)
				return
			}
		} else if args.ProxyJump == "" && aj == "" {
			// Без посредников
			go sx(ctx, u, net.JoinHostPort(h, p))
			return
		}
		// Сохраняет хосты в кэше
		dp := dPort(LH)
		s4 := net.JoinHostPort(LH, dp)
		Println("-D", s4)
		args.DynamicForward.UnmarshalText([]byte(s4))

		SOCKS := 1 // socks4
		if args.Socks5 {
			SOCKS++
		}

		u += fmt.Sprintf(";x-ProxyMethod=%d;x-ProxyHost=%s;x-ProxyPort=%s", SOCKS, LH, dp)
		time.AfterFunc(time.Second, func() { sx(ctx, u, net.JoinHostPort(h, p)) })
	}
	sxStart()

	code := Tssh(&args)
	if args.Background {
		Println("tssh started in background with code:", code)
		// closer.Hold()
	} else {
		if code != 0 {
			Println("tssh exit with code:", code)
			if argsShare && tt != nil {
				Println("Local console - Локальная консоль", ser)
				// Println(ToExitPress, Enter)
				// os.Stdin.Read([]byte{0})
				holdClose(false)
			}
		}
	}
}

// Какая ОС на sshd
func goos(dest string) (s string) {
	echo := exec.Command(repo, "-T", dest, "echo", "~")
	echo.Stdin = os.Stdin
	setRaw(&once)
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
			closer.Bind(func() {
				current.Reset()
			})
			PrintLn(3, "Set raw by go")
			return
		}
	}

	if isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		settings, err = sttySettings()
		if err == nil {
			err = sttyMakeRaw()
			if err == nil {
				closer.Bind(func() {
					sttyReset(settings)
				})
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

// Завершает процесс с pid
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

// Резолвит локальные dssh алиасы
func host2BD(host string) (bind, dial string) {
	switch host {
	case "_":
		return ips[0], ips[0]
	case "", ALL:
		return ALL, LH
	case ".", "+", LH:
		return LH, LH
	}
	return host, host
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
func cgi(ctx context.Context, portT, portW int, args *SshArgs, serial, exit string) {
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
			// sshd
			lhp := JoinHostPort(LH, portT)
			s4 := lhp + ":" + lhp
			Println("-L", s4)
			args.LocalForward.UnmarshalText([]byte(s4))
		}
	}
	if portW > 0 {
		args.Argument = append(args.Argument, "--web", strconv.Itoa(portW))
		if exit == "" || args.DirectJump {
			lhp := JoinHostPort(LH, portW)
			s4 := lhp + ":" + lhp
			Println("-L", s4)
			args.LocalForward.UnmarshalText([]byte(s4))
		}
		time.AfterFunc(time.Second, func() {
			Println(browse(ctx, LH, portW, nil))
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

func optL(port int, args *SshArgs, bind string, loc, dot bool) {
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
		s4 := JoinHostPort(LH, port) + ":" + JoinHostPort(bind, port)
		Println("-L", s4)
		args.LocalForward.UnmarshalText([]byte(s4))
	}
}

// Создаёт tmp/path
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

// Завершает дочерние процессы
func KidsDone(ppid int) (done bool) {
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
			done = true
		}
	}
	return
}

// Если serial занят то запускаем web-сервер или telnet-сервер.
// Даже если параметр --2217 не задан.
func comm(serial, bind string, portT, portW int) int {
	if serial == "" {
		// Занят
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
		Println(fmt.Sprintf("we will try to use - будем пробовать использовать %s://%s:%d", url, bind, port))
	}
	return portT
}

// Через delay вызывает cancel если нет name
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

// Типа ps
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

// Типа stfioForward только с ~.
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

// Слушает ли кто hostport
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
func dPort(host string) (portC string) {
	portC = strconv.Itoa(PORTC)
	ln, err := net.Listen("tcp4", net.JoinHostPort(host, "0"))
	if err == nil {
		hostport := ln.Addr().String()
		ln.Close()
		_, p, err := net.SplitHostPort(hostport)
		if err == nil {
			return p
		}
	}
	return
}

func PrintNil(v ...any) {
}

// Как net.JoinHostPort только port int
func JoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// Является ли host локальным IP
func localHost(host string) (ok bool) {
	if strings.HasPrefix(host, "127.0.0.") {
		return true
	}
	for _, ip := range append(ips, "", LH, "_", ALL, "+") {
		if ip == host {
			ok = true
			return
		}
	}
	return
}

// Похож ли path на команду
func likeCommand(path string) (ok bool) {
	if strings.Contains(path, " ") {
		return true
	}
	path = strings.ToLower(path)
	for _, sh := range []string{"cmd", "powershell", "bash", "zsh", "ash", "sh"} {
		if strings.HasPrefix(path, sh) {
			return true
		}
	}
	return false
}

// Что там с параметром -H
func swSerial(s string, local bool) (ser, sw, h string, p int) {
	ser = s
	if ser == "" {
		return
	}
	ok := likeCommand(ser)
	if local {
		_, ok = ser2net.IsCommand(ser)
	}
	if ok {
		sw = "c"
		// Команда или интерпретатор команд
		return
	}
	if ser2net.SerialPath(ser) {
		// Последовательный порт
		ser = serial.PortName(ser)
		sw = "s"
		return
	}
	h, p = shp(s, PORTT)
	return JoinHostPort(h, p), "t", h, p
}

// Для win7 используем веб интерфейс вместо кривой консоли
func optS(portT, portW, portV int) (t, w int) {
	if portT < 0 && portW < 0 && portV < 0 {
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

// Через STUN ищем внешний IP
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

func shp(s string, base int) (h string, i int) {
	if s == "" {
		return
	}
	var p string
	_, err := strconv.ParseUint(s, 10, 16)
	if err == nil {
		// 2, 5500
		_, h = host2BD("")
		i, err = strconv.Atoi(portPB(s, base))
		if err != nil {
			i = base
		}
		return
		// LH, 5502
	}
	// 1:
	// 1:2
	h, p, err = net.SplitHostPort(s)
	if err != nil {
		h, p = s, ""
	}
	_, h = host2BD(h)
	i, err = strconv.Atoi(portPB(p, base))
	if err != nil {
		i = base
	}
	return
	// 1, 5500
	// 1, 5502
}

// Найдём адрес для доступа к dssh-серверу
func getHP(ctx context.Context, once, u string) (s string) {
	s = "."
	if once == s {
		// Уже пробовал и не успешно
		return
	}
	so, portS := SplitHostPort(cgiJ(ctx, u, ":"), "", PORTS)
	if so == "" {
		return
	}
	ips := strings.Split(so, SEP)
	for _, ip := range ips {
		hp := net.JoinHostPort(ip, portS)
		if ip != "" && ip != LH && isHP(hp) {
			return hp
		}
	}
	return
}

// dest="." Получаем список локальных адресов dssh-сервера через посредника.
// dest=":" Получаем список адресов dssh-сервера через посредника.
// Иначе получаем список локальных адресов dssh-сервера напрямую.
func cgiJ(ctx context.Context, u, dest string) (s string) {
	to, toC := context.WithTimeout(ctx, time.Second*3)
	defer toC()
	opts := []string{"-Tl", u}
	switch dest {
	case ":":
		opts = append(opts, ":", repo, "--eips")
	case ".":
		opts = append(opts, ":", repo, "--ips")
	default:
		opts = append(opts, "-j", dest, repo, "--ips")
	}
	cgi := exec.CommandContext(to, repo, opts...)
	cgi.Stdin = os.Stdin
	if args.Debug {
		cgi.Stderr = os.Stderr
	}
	// createNewConsole(cgi)
	output, err := cgi.Output()
	Debug(output, err)
	s = string(output)
	Println(s, err)
	return
}

func cliDaemon() (cli, daemon bool) {
	if args.Daemon { // dssh -d x
		return false, true
	}

	_, h, _ := ParseDestination(args.Destination)
	cli = args.Command != "" ||
		args.ForwardAgent ||
		args.NoForwardAgent ||
		args.DisableTTY ||
		args.ForceTTY ||
		args.IPv4Only ||
		args.IPv6Only ||
		args.Gateway ||
		args.Background ||
		args.NoCommand ||
		// args.Port != 0 ||
		// args.LoginName != "" ||
		fmt.Sprint(args.Identity) != "{[]}" ||
		args.CipherSpec != "" ||
		args.ConfigFile != "" ||
		args.ProxyJump != "" ||
		fmt.Sprint(args.Option) != "{map[]}" ||
		args.StdioForward != "" ||
		fmt.Sprint(args.DynamicForward) != "{[]}" ||
		fmt.Sprint(args.LocalForward) != "{[]}" ||
		fmt.Sprint(args.RemoteForward) != "{[]}" ||
		args.X11Untrusted ||
		args.NoX11Forward ||
		args.X11Trusted ||
		args.Reconnect ||
		args.DragFile ||
		args.TraceLog ||
		args.Relay ||
		args.Zmodem ||
		args.Putty ||
		// args.Baud != "" ||
		// args.Serial != "" ||
		// args.Ser2net != -1 ||
		// args.Ser2web != -1 ||
		// args.Stop ||
		// args.Restart ||
		// args.Unix ||
		// args.Telnet ||
		args.EscapeChar != "" ||
		args.Socks5 ||
		args.DirectJump ||
		// args.Share ||
		// args.Use ||
		// args.VNC != -1 ||
		!localHost(h) || // dssh {_ + local LH ALL ""}
		false
	return cli, !cli
}

func userNameAtHostname() (s string) {
	s = winssh.UserName() + "@"
	hostname, err := os.Hostname()
	if err == nil {
		s += hostname
	}
	s += " " + winssh.Banner()
	return
}

func Debug(v ...any) {
	if args.Debug {
		PrintLn(3, v...)
	}
}
