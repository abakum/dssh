package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/go-ansiterm"
	"github.com/abakum/go-netstat/netstat"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/trzsz/go-arg"
	"golang.org/x/crypto/ssh"
)

type cgiArgs struct {
	Baud    string `arg:"-U,--baud" placeholder:"baUd" help:"set baud rate of serial console"`
	Serial  string `arg:"-H,--path" placeholder:"patH" help:"device path (name for Windows) of serial console"`
	Ser2net int    `arg:"-2,--2217" placeholder:"port" help:"RFC2217 telnet port for serial console over telnet" default:"-1"`
	Ser2web int    `arg:"-8,--web" placeholder:"port" help:"web port for serial console over web" default:"-1"`
	Exit    string `arg:"--exit" help:"exit shortcut"`
	Restart bool   `arg:"-r,--restart" help:"restart daemon"`
	Debug   bool   `arg:"-v,--debug" help:"verbose mode for debugging, similar to ssh's -v"`
	Unix    bool   `arg:"-z,--unix" help:"zero new window"`
	VNC     string `arg:"--vnc" placeholder:"hostname[:vncViewerListen]" help:"address of direct accesible dssh with vncviewer -listen [vncViewerListen]"`
}

var Exit string

// Сервер sshd.
// h, p хост, порт,
// repo имя в сертификате,
// signer ключ ЦС,
// authorizedKeys замки разрешённых пользователей,
// CertCheck имя разрешённого пользователя в сертификате.
func server(h, p, repo, s2 string, signer ssh.Signer, Println func(v ...any), Print func(v ...any)) string { //, authorizedKeys []gl.PublicKey
	if isHP(net.JoinHostPort(s2, p)) {
		return fmt.Sprintf("Already used - Уже используется %s:%s", s2, p)
	}
	Println(ToExitPress, "<^C>")

	authorizedKeys := FileToAuthorized(filepath.Join(SshUserDir, "authorized_keys"), signer.PublicKey())

	ctxRWE, caRW := context.WithCancel(context.Background())
	defer caRW()

	ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

	server := gl.Server{
		Addr: net.JoinHostPort(h, p),
		// next for ssh -R host:port:x:x
		ReversePortForwardingCallback: gl.ReversePortForwardingCallback(func(ctx gl.Context, host string, port uint32) bool {
			// if host == LH {
			// 	// Когда dssh-сервер и dssh-клиент на одном хосте
			// 	if hp := newHostPort(host, int(port), ""); hp.read() == nil && hp.Path == "" {
			// 		Println("Attempt to bind - Начать слушать", host, port, "denied - отказанно")
			// 		return false
			// 	}
			// }
			Println("Attempt to bind - Начать слушать", host, port, "granted - позволено")
			return true
		}),
		RequestHandlers: map[string]gl.RequestHandler{
			"tcpip-forward":        ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
			"cancel-tcpip-forward": ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
		},
		// before for ssh ssh -R host:port:x:x

		// next for ssh -L x:dhost:dport
		LocalPortForwardingCallback: gl.LocalPortForwardingCallback(func(ctx gl.Context, dhost string, dport uint32) bool {
			// if dhost == LH {
			// 	// Когда dssh-сервер и dssh-клиент на одном хосте
			// 	if hp := newHostPort(dhost, int(dport), ""); hp.read() == nil && hp.Path == "" {
			// 		Println("Port forwarding is disabled - Запрешён перенос", dhost, dport)
			// 		return false
			// 	}
			// }
			Println("Accepted forward - Разрешен перенос", dhost, dport)
			return true
		}),
		ChannelHandlers: map[string]gl.ChannelHandler{
			"session":      winssh.SessionHandler, // to allow agent forwarding
			"direct-tcpip": gl.DirectTCPIPHandler, // to allow local forwarding
		},
		// before for ssh -L x:dhost:dport

		SubsystemHandlers: map[string]gl.SubsystemHandler{
			"sftp":                  winssh.SubsystemHandlerSftp,  // to allow sftp
			winssh.AgentRequestType: winssh.SubsystemHandlerAgent, // to allow agent forwarding
		},
		SessionRequestCallback: SessionRequestCallback,
		// IdleTimeout:            -time.Second * 100, // send `keepalive` every 100 seconds
		// MaxTimeout:             -time.Second * 300, // сlosing the session after 300 seconds with no response
		Version: winssh.Banner(repo, Ver),
	}

	// next for server key
	// server.AddHostKey(signer)
	server.AddHostKey(certSigner(signer, signer, repo)) //selfsigned ca
	// before for server key

	// next for client keys
	publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
		if ctx.User() == "_" {
			ctx.SetValue("user", winssh.UserName())
		}
		Println("User", ctx.Value("user"), "from", ctx.RemoteAddr())

		cert, ok := key.(*ssh.Certificate)
		if !ok {
			ok = winssh.Authorized(key, authorizedKeys)
			s := "was not"
			if ok {
				s = "was"
			}
			Println(s, "authorized by the key", FingerprintSHA256(key))
			return ok
		}
		// next for certificate of client
		if cert.CertType != ssh.UserCert {
			Println(fmt.Errorf("ssh: cert has type %d", cert.CertType))
			return false
		}
		if !gl.KeysEqual(cert.SignatureKey, signer.PublicKey()) {
			Println(fmt.Errorf("ssh: certificate signed by unrecognized authority %s", FingerprintSHA256(cert.SignatureKey)))
			return false
		}
		certCheck := &ssh.CertChecker{}
		if err := certCheck.CheckCert(repo, cert); err != nil { //ctx.User()
			Println(err)
			return false
		}
		//  cert.Permissions
		Println("was authorized by certificate", FingerprintSHA256(cert.SignatureKey))
		return true

	})

	server.SetOption(publicKeyOption)
	// before for client keys

	gl.Handle(func(s gl.Session) {
		defer s.Exit(0)
		Println(s.Context().ClientVersion())
		var args cgiArgs
		if len(s.Command()) > 1 && s.Command()[0] == repo {
			parser, err := NewParser(arg.Config{}, &args)
			if err == nil {
				err = parser.Parse(s.Command()[1:])
			}
			if err != nil {
				winssh.ShellOrExec(s)
				return
			}
		} else {
			winssh.ShellOrExec(s)
			return
		}
		Println("CGI", s.Command())
		// Покажу клиенту протокол на стороне сервера
		lss := log.New(s.Stderr(), "\r:>", lf.Flags())
		ps := []func(v ...any){lss.Println, Println}
		print := func(a ...any) {
			for _, p := range ps {
				p(a...)
			}
		}
		vncViewerHP, doStop := func() (addr string, started bool) {
			if args.VNC == "" {
				return
			}
			h, p := SplitHostPort(args.VNC, "", strconv.Itoa(PORTV))
			if h != "" {
				forw := exec.CommandContext(s.Context(), repo, fmt.Sprintf("-NL%s:%s:%s:%s", LH, p, LH, p), h)
				err := forw.Start()
				print(forw, err)
				if err != nil {
					return
				}
				go func() {
					forw.Wait()
				}()
				time.Sleep(time.Second * 2)
			}
			var start, conn, killall, disconn *exec.Cmd
			switch runtime.GOOS {
			case "windows":
				if vncserver == "" {
					vncserver = vncserverWindows
				}
				psCount := psPrint(vncserver, "", 0, PrintNil)
				if psCount < 1 {
					start = exec.Command(vncserver, "-start")
					err := start.Run()
					print(start, err)
					if err != nil {
						return
					}
					started = true
				}
				conn = exec.CommandContext(s.Context(), vncserver, "-controlservice", "-connect", LH)
				disconn = exec.Command(vncserver, "-controlservice", "-disconnectall")
			default:
				if vncserver == "" {
					vncserver = vncserverEtc
				}
				if vncSecurityTypes == "" {
					vncSecurityTypes = vncSecurityTypesEtc
				}
				optSecurityTypes := []string{"-SecurityTypes", vncSecurityTypes}
				if display == "" {
					display = ":" + p[len(p)-1:]
				}
				optDisplay := []string{"-display", display}
				start = exec.Command(vncserver, append(optSecurityTypes, optDisplay...)...)
				err := start.Run()
				print(start, err)
				// which vncconnect&&vncconnect %display% %LH%||
				// which vncconfig&&vncconfig %display% -connect %LH%&&killall tigervncconfig
				vncconnect, err := exec.LookPath("vncconnect")
				if err == nil {
					conn = exec.CommandContext(s.Context(), vncconnect, append(optDisplay, LH)...)
				} else {
					conn = exec.CommandContext(s.Context(), "vncconfig", append(optDisplay, "-connect", LH)...)
					killall = exec.Command("killall", "tigervncconfig")
				}
				disconn = exec.Command(vncserver, append(optDisplay, "-kill")...)
			}
			conn.Cancel = func() error {
				return disconn.Run()
			}
			err := conn.Start()
			print(conn, err)
			if err != nil {
				return
			}
			go func() {
				conn.Wait()
			}()
			if killall != nil {
				killall.Run()
			} else {
				time.Sleep(time.Second)
			}
			addr = LH + ":" + p
			return
		}()
		if doStop {
			defer func() {
				stop := exec.Command(vncserver, "-stop")
				print(stop, stop.Run())
			}()
		}

		if args.Baud == "" {
			if args.Serial == "H" { // -HH
				args.Serial = ""
				args.Baud = "U"
			}
			if args.Unix { // -z
				args.Baud = "U"
			}
		}
		portT := portOB(args.Ser2net, PORTT)
		portW := portOB(args.Ser2web, PORTW)
		switch {
		case args.Restart:
			caRW()
		case args.Baud != "" || args.Serial != "" || portT > 0 || portW > 0:
			// Покажу клиенту и на сервере протокол на стороне сервера
			ser, _ := getFirstUsbSerial(args.Serial, args.Baud, lss.Print)

			// Покажу клиенту протокол IAC
			log.SetFlags(lf.Flags())
			log.SetPrefix("\r:>")
			if args.Debug {
				log.SetOutput(s.Stderr())
			} else {
				log.SetOutput(io.Discard)
			}

			portT = comm(ser, s2, portT, portW)
			if portT > 0 && portW < 0 {
				// dssh -22 :
				// p2 := portOB(portT, RFC2217)
				// dssh -22 :
				// dssh -22 .
				print(repo, "-H", ser, "-2", portT)
				print(rfc2217(s.Context(), s, ser, s2, portT, args.Baud, args.Exit, ps...))
				return
			}
			if portW > 0 {
				if portT > 0 {
					print(repo, "-H", ser, "-2", portT)
					go func() {
						print(rfc2217(s.Context(), s, ser, s2, portT, args.Baud, args.Exit, ps...))
						s.Close()
					}()
					time.Sleep(time.Second)
					ser = JoinHostPort(s2, portT)
				}
				print(repo, "-H", ser, "-8", portW)
				if hp := newHostPort(s2, portW, ser); isHP(hp.dest()) {
					// Подключаемся к существующему сеансу
					hp.read()
					print(hp.String())

					cancelByFile(s.Context(), nil, hp.name(), TOW)
					return
				}

				if portT > 0 {
					print(s2w(s.Context(), nil, nil, ser, s2, portW, args.Baud, "", PrintNil))
				} else {
					print(s2w(s.Context(), s, nil, ser, s2, portW, args.Baud, ". или <^C>", ps...))
				}
				return
			}
			// dssh -UU :
			print(cons(s.Context(), s, ser, args.Baud, args.Exit, ps...))
		case vncViewerHP != "":
			switch runtime.GOOS {
			case "windows", "linux":
				go func() {
					established(s.Context(), vncViewerHP, true, Println)
					s.Close()
				}()
			}
			lss.Println("Press any key to stop - Нажми любую клавишу чтоб остановить VNC")
			_, _ = s.Read([]byte{0})
		case args.Exit != "":
			caRW()
			Exit = args.Exit
		}
	})

	switch runtime.GOOS {
	case "windows", "linux":
		sa := server.Addr
		all := strings.HasPrefix(sa, ALL) || strings.HasPrefix(sa, ":")
		if runtime.GOOS == "linux" && all {
			sa = "::" + strings.TrimPrefix(sa, ALL)
		}
		go func() {
			watch(ctxRWE, caRW, sa, Print)
			Println("local done")
			server.Close()
		}()
		if !all {
			go established(ctxRWE, sa, false, Print)
		}
	case "darwin":
		noidle()
	}
	Println("ListenAndServe", server.ListenAndServe())
	return Exit
}

// Не спать! Товарищи депутаты.
func noidle() {
	cmd := exec.Command("pmset", "noidle")
	err := cmd.Start()
	Println(cmd.Args, err)
}

// Подписываем ключём ЦС caSigner замок хоста hostSigner и его принципал
func certSigner(caSigner, hostSigner ssh.Signer, id string) ssh.Signer {
	certificate := ssh.Certificate{
		Key:         hostSigner.PublicKey(),
		CertType:    ssh.HostCert,
		KeyId:       id,
		ValidBefore: ssh.CertTimeInfinity,
	}
	switch 1 {
	case 0:
		mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner), []string{caSigner.PublicKey().Type()})
		if err != nil {
			return hostSigner
		}
		err = certificate.SignCert(rand.Reader, mas)
		if err != nil {
			Println(err)
			return hostSigner
		}
	case 1:
		err := certificate.SignCert(rand.Reader, caSigner)
		if err != nil {
			Println(err)
			return hostSigner
		}
	}
	certSigner, err := ssh.NewCertSigner(&certificate, hostSigner)
	if err != nil {
		Println(err)
		return hostSigner
	}
	return certSigner
}

// Баннер без префикса SSH2
func CutSSH2(s string) string {
	after, _ := strings.CutPrefix(s, SSH2)
	return after

}

// Меняю заголовок окна у клиента
func SetConsoleTitle(s gl.Session) {
	clientVersion := s.Context().ClientVersion()
	if s.RawCommand() == "" && !strings.Contains(clientVersion, OSSH) {
		// Not for OpenSSH_for_Windows
		time.AfterFunc(time.Millisecond*333, func() {
			title := fmt.Sprintf("%c]0;%s%c", ansiterm.ANSI_ESCAPE_PRIMARY, CutSSH2(clientVersion)+"@"+CutSSH2(s.Context().ServerVersion()), ansiterm.ANSI_BEL)
			s.Write([]byte(title))
		})
	}
}

// call ca() and return on `Service has been stopped`
func watch(ctx context.Context, ca context.CancelFunc, dest string, Print func(v ...any)) {
	if strings.HasPrefix(dest, ":") && !strings.HasPrefix(dest, ":::") {
		dest = ALL + dest
	}
	old := -1
	ste_ := ""
	t := time.NewTicker(TOW)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			new, ste := netSt(func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Listen && s.LocalAddr.String() == dest
			})
			if new == 0 {
				Print("The service has been stopped - Служба остановлена\n\t", dest)
				if ca != nil {
					ca()
				}
				return
			}
			if old != new {
				if new > old {
					Print("\nThe service is running - Служба работает\n", ste)
				}
				ste_ = ste
				old = new
			}
			if ste_ != ste {
				Print("The service has been changed - Служба сменилась\n", ste)
				ste_ = ste
			}
		case <-ctx.Done():
			Print("watch ", dest, " done\n")
			return
		}
	}
}

// Что там с подключениями к dest
func established(ctx context.Context, dest string, exit bool, Print func(v ...any)) {
	old := 0
	ste_ := ""
	t := time.NewTicker(TOW)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			new, ste := netSt(func(s *netstat.SockTabEntry) bool {
				return s.State == netstat.Established && s.LocalAddr.String() == dest
			})
			if old != new {
				switch {
				case new == 0:
					Print(dest, " There are no connections - Нет подключений\n")
					if exit {
						return
					}
				case old > new:
					Print(dest, " Connections have decreased - Подключений уменьшилось\n", ste)
				default:
					Print(dest, " Connections have increased - Подключений увеличилось\n", ste)
				}
				ste_ = ste
				old = new
			}
			if ste_ != ste {
				Print(dest, " Сonnections have changed - Подключения изменились\n", ste)
				ste_ = ste
			}
		case <-ctx.Done():
			Print("established ", dest, " done\n")
			return
		}
	}
}

// Коллекционируем Process.Pid и завершаем
func tcp2pids(accept netstat.AcceptFn, pids map[int]string) {
	tabs, err := netstat.TCPSocks(accept)
	if err != nil {
		return
	}
	if len(tabs) == 0 {
		Println("tcp2pids quit")
		pids[0] = ""
		return
	}
	for _, tab := range tabs {
		if tab.Process != nil {
			pids[tab.Process.Pid] = tab.String()
		}
	}
	// Нет подключения - конец работе
	Println("tcp2pids", pids)
}

// Что там с подключениями к dest
func remoteAddr2pids(ctx context.Context, dest string) (ok bool) {
	pids := make(map[int]string)
	t := time.NewTicker(TOW)
	defer func() {
		t.Stop()
		// Завершаем браузеры
		for k, v := range pids {
			if k == 0 {
				continue
			}
			Println(v)
			PidDone(k)
		}
	}()
	for {
		select {
		case <-t.C:
			tcp2pids(func(s *netstat.SockTabEntry) bool {
				if s.State == netstat.Established && s.RemoteAddr.String() == dest {
					return true
				}
				return false
			}, pids)
			_, ok = pids[0]
			if ok {
				return
			}
		case <-ctx.Done():
			return false
		}
	}
}

// Согласно фильтру accept возвращает количество i и список s
func netSt(accept netstat.AcceptFn) (i int, s string) {
	tabs, _ := netstat.TCPSocks(accept)
	tabs6, _ := netstat.TCP6Socks(accept)
	for _, tab := range append(tabs, tabs6...) {
		s += "\t" + tab.String() + "\n"
	}
	i = len(tabs)
	return
}

// Читаю name и добавляю замки из in в authorized
func FileToAuthorized(name string, in ...ssh.PublicKey) (authorized []gl.PublicKey) {
	authorizedKeysMap := map[string]ssh.PublicKey{}
	for _, pubKey := range in {
		authorizedKeysMap[string(pubKey.Marshal())] = pubKey
	}
	authorizedKeysBytes, err := os.ReadFile(name)
	if err == nil {
		for len(authorizedKeysBytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
			if err == nil {
				authorizedKeysMap[string(pubKey.Marshal())] = pubKey
				authorizedKeysBytes = rest
			}
		}
	}
	for _, pubKey := range authorizedKeysMap {
		authorized = append(authorized, pubKey)
	}
	return
}

func SessionRequestCallback(s gl.Session, requestType string) bool {
	if s == nil {
		return false
	}
	Println(s.RemoteAddr(), requestType, s.RawCommand())
	return true
}
