package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
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

// Сервер sshd.
// h, p хост, порт,
// repo имя в сертификате,
// signer ключ ЦС,
// authorizedKeys замки разрешённых пользователей,
// CertCheck имя разрешённого пользователя в сертификате.
func server(h, p, repo, use string, signer ssh.Signer, Println func(v ...any), Print func(v ...any)) { //, authorizedKeys []gl.PublicKey

	authorizedKeys := FileToAuthorized(filepath.Join(SshUserDir, "authorized_keys"), signer.PublicKey())

	ctxRWE, caRW := context.WithCancel(context.Background())
	defer caRW()

	ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

	server := gl.Server{
		Addr: net.JoinHostPort(h, p),
		// next for ssh -R host:port:x:x
		ReversePortForwardingCallback: gl.ReversePortForwardingCallback(func(ctx gl.Context, host string, port uint32) bool {
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
		if len(s.Command()) < 2 || s.Command()[0] != repo {
			winssh.ShellOrExec(s)
			return
		}
		//len(s.Command()) > 1 && s.Command()[0] == repo
		var cgi cgiArgs
		parser, err := NewParser(arg.Config{}, &cgi)
		Println("CGI", s.Command(), err)
		if err != nil {
			return
		}
		err = parser.Parse(s.Command()[1:])
		if err != nil {
			return
		}
		switch {
		case cgi.Restart:
			caRW()
		case cgi.Baud != "" || cgi.Serial != "" || cgi.Ser2net > 0:
			log.SetFlags(log.Lshortfile)
			log.SetPrefix(">")
			log.SetOutput(s.Stderr())
			baud := baudRate(strconv.Atoi(cgi.Baud))
			cgi.Serial = getFirstUsbSerial(cgi.Serial, baud, log.Print)
			if cgi.Serial == "" {
				return
			}
			if cgi.Ser2net < 1 {
				ser(s, &cgi, baud, log.Println, Println)
				return
			}
			// err := s2n(s, &cgi, baud, log.Println)
			err := s2n(s.Context(), s, cgi.Serial, cgi.Ser2net, baud, log.Println, Println)
			if err != nil {
				log.Println(err, "\r")
				if true { //cgi.Putty
					log.Println("Try run plink\r")

				}

			}
		}
	})

	// lt.Printf("%s daemon waiting on - сервер ожидает на %s\n", repo, server.Addr)
	Println(fmt.Sprintf("%s daemon waiting on - сервер ожидает на %s", repo, server.Addr))
	Println("to connect use - чтоб подключится используй", use)

	switch runtime.GOOS {
	case "windows", "linux":
		go func() {
			watch(ctxRWE, caRW, server.Addr, Print)
			Println("local done")
			server.Close()
		}()
		go established(ctxRWE, server.Addr, false, Print)
	}
	Println("ListenAndServe", server.ListenAndServe())
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
	if strings.HasPrefix(dest, ":") {
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

// Согласно фильтру accept возвращает количество i и список s
func netSt(accept netstat.AcceptFn) (i int, s string) {
	tabs, err := netstat.TCPSocks(accept)
	if err != nil {
		return
	}
	for _, tab := range tabs {
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
