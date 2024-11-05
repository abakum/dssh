package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PatrickRudolph/telnet"
	"github.com/abakum/go-ser2net/pkg/ser2net"
	"github.com/abakum/winssh"
	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

const (
	CtrlC       = 0x03 // ^C END OF TEXT
	CtrlZ       = 0x1A // ^Z SUBSTITUTE
	BackSpace   = 0x7F
	IS3         = 0x1D // ^] INFORMATION SEPARATOR THREE (group separator)
	ToExitPress = "To exit press - Чтоб выйти нажми"
	B16         = 16
	K1          = 1024
)

var (
	ErrNotFoundFreeSerial = fmt.Errorf("a free USB serial port was not found - не найден свободный последовательный порт USB")
	ErrNotSerial          = fmt.Errorf("this is not a serial port - это не последовательный порт")
)

type cgiArgs struct {
	Baud    string `arg:"-U,--baud" placeholder:"baUd" help:"set baud rate of serial console"`
	Serial  string `arg:"-H,--path" placeholder:"patH" help:"device path (name for Windows) of serial console"`
	Ser2net int    `arg:"-2,--2217" placeholder:"port" help:"RFC2217 telnet port for serial console over telnet" default:"-1"`
	Ser2web int    `arg:"-8,--web" placeholder:"port" help:"web port for serial console over web" default:"-1"`
	Putty   bool   `arg:"-u,--putty" help:"run PuTTY"`
	Exit    string `arg:"--exit" help:"exit shortcut"`
	Restart bool   `arg:"-r,--restart" help:"restart daemon"`
}

type ReadWriteCloser struct {
	io.Reader
	io.WriteCloser
}

type WriteCloser struct {
	io.Writer
	io.Closer
}

func isSerial(serial string) error {
	if serial == "" {
		return ErrNotFoundFreeSerial
	}
	_, ok := ser2net.IsCommand(serial)
	if ok {
		return ErrNotSerial
	}
	return nil
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

// Подключаем последовательный порт Serial к сессии ssh или локально.
// Завершение сессии через `<Enter>~.`
func ser(ctx context.Context, s io.ReadWriteCloser, Serial, Baud, exit string, println ...func(v ...any)) error {
	err := isSerial(Serial)
	if err != nil {
		return err
	}

	BaudRate := ser2net.BaudRate(strconv.Atoi(Baud))
	w, _ := ser2net.NewSerialWorker(ctx, Serial, BaudRate)
	mode := w.Mode()
	port, err := serial.Open(Serial, &mode)
	if err != nil {
		var portErr serial.PortError
		if errors.As(err, &portErr) {
			return err
		}
		return err
	}
	w.SetSerial(port)
	msg := fmt.Sprintf("%s opened - открыт", w)
	print := func(a ...any) {
		for _, p := range println {
			p(a...)
		}
	}
	print(msg)

	defer func() {

		err = ser2net.SerialClose(port)

		msg = fmt.Sprintf("%s closed - закрыт %v", w, w.SerialClose())
		print(msg)
	}()

	go io.Copy(s, port)

	chanByte := make(chan byte, B16)
	t := time.AfterFunc(time.Second, func() {
		SetMode(w, ctx, nil, chanByte, exit, 0, println...)
	})

	_, err = io.Copy(newSideWriter(port, args.EscapeChar, Serial, exit, chanByte, println...), s)
	t.Stop()
	return err
}

// Подключаем консоль Serial к сессии ssh или локально.
// Завершение сессии через `<Enter>~.`
func con(ctx context.Context, s io.ReadWriteCloser, Serial, Baud, exit string, println ...func(v ...any)) error {
	if Serial == "" {
		return ErrNotFoundFreeSerial
	}

	w, _ := ser2net.NewSerialWorker(ctx, Serial, ser2net.BaudRate(strconv.Atoi(Baud)))
	print := func(a ...any) {
		for _, p := range println {
			p(a...)
		}
	}
	go w.Worker()

	i, err := w.NewIoReadWriteCloser()
	if nil != err {
		return err
	}
	print(w)
	defer func() {
		i.Close()
		err = w.SerialClose()
		print(w)
	}()

	go w.Copy(s, i)

	chanByte := make(chan byte, B16)
	t := time.AfterFunc(time.Second, func() {
		SetMode(w, ctx, nil, chanByte, exit, 0, println...)
	})
	// if !strings.Contains(w.String(), ",") {
	// 	Serial = ""
	// }
	_, err = w.CopyAfter(newSideWriter(i, args.EscapeChar, Serial, exit, chanByte, println...), s, time.Millisecond*77)
	t.Stop()
	return err
}

func getFirstSerial(isUSB bool, Baud string) (name, list string) {
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil || len(ports) == 0 {
		return
	}
	ok := false
	for _, port := range ports {
		usb := ""
		if port.IsUSB {
			SerialNumber := ""
			if port.SerialNumber != "" {
				SerialNumber = fmt.Sprintf(" #_%s", port.SerialNumber)
			}
			usb = fmt.Sprintf(" USB Vid_%s&Pid_%s%s", port.VID, port.PID, SerialNumber)
		}
		list += fmt.Sprintf("\r\n%s%s %s ", port.Name, usb, port.Product)
		if !ok {
			if isUSB && !port.IsUSB {
				continue
			}
			// Занят?
			sp, err := serial.Open(port.Name, &serial.Mode{
				BaudRate: ser2net.BaudRate(strconv.Atoi(Baud)),
				DataBits: 8,
			})
			if err != nil {
				list += fmt.Sprintf(" %s", err)
				if strings.HasSuffix(err.Error(), "Permission denied") && !Win {
					list += fmt.Sprintf(" try run `sudo usermod -a -G dialout %s` then reboot", winssh.UserName())
				}
				continue
			}
			_, err = sp.GetModemStatusBits()
			ser2net.SerialClose(sp)
			if err != nil {
				list += fmt.Sprintf(" %s", err)
				continue
			}
			ok = true
			name = port.Name
		}
	}
	list += "\r\n"
	return
}

// Телнет сервер RFC2217 ждёт на telnet://host:Ser2net.
// SetMode использует r или chanByte для смены serial.Mode порта Serial.
// На консоль клиента println[0] выводит протокол через ssh канал.
// Локально println[1] выводит протокол.
func s2n(ctx context.Context, r io.Reader, chanB chan byte, chanW chan *ser2net.SerialWorker, Serial, host string, Ser2net int, Baud, exit string, println ...func(v ...any)) error {
	if Serial == "" {
		return ErrNotFoundFreeSerial
	}
	w, _ := ser2net.NewSerialWorker(ctx, Serial, ser2net.BaudRate(strconv.Atoi(Baud)))
	go w.Worker()
	t := time.AfterFunc(time.Millisecond*333, func() {
		if chanW != nil {
			chanW <- w
		}
		SetMode(w, ctx, r, chanB, exit, Ser2net, println...)
	})
	print := func(a ...any) {
		for _, p := range println {
			p(a...)
		}
	}
	print("TELNET server is listening at:", "telnet://"+net.JoinHostPort(host, strconv.Itoa(Ser2net)))
	hp := newHostPort(host, Ser2net, Serial, false)
	hp.write()
	err := w.StartTelnet(host, Ser2net)
	t.Stop()
	hp.remove()

	if err != nil {
		print(err)
	}
	return err
}

// Web сервер ждёт на порту web.
// SetMode использует r или chanByte для смены serial.Mode порта Serial.
// На консоль клиента println[0] выводит протокол через ssh канал.
// Локально println[1] выводит протокол.
func s2w(ctx context.Context, r io.Reader, chanByte chan byte, Serial, host string, wp int, Baud, exit string, println ...func(v ...any)) error {
	if Serial == "" {
		return ErrNotFoundFreeSerial
	}
	w, _ := ser2net.NewSerialWorker(ctx, Serial, ser2net.BaudRate(strconv.Atoi(Baud)))
	go w.Worker()
	t := time.AfterFunc(time.Millisecond*333, func() {
		SetMode(w, ctx, r, chanByte, exit, wp, println...)
	})

	log.SetPrefix("\r>" + log.Prefix())
	log.SetFlags(log.Lshortfile)

	hp := newHostPort(host, wp, Serial, true)
	hp.write()
	err := w.StartGoTTY(host, wp, "", false)
	t.Stop()
	hp.remove()

	if err != nil {
		for _, p := range println {
			p(err)
		}
	}
	return err
}

func getFirstUsbSerial(serialPort, Baud string, print func(v ...any)) (serial string) {
	if serialPort != "" {
		return serialPort
	}
	serial, list := getFirstSerial(true, Baud)
	print(list)
	return
}

// Типа baudWriter только управлением последоватальным портом через chanByte
type sideWriter struct {
	io.WriteCloser
	l        []byte         // last 2 bytes
	t        byte           // EscapeChar
	chanByte chan byte      // side chan
	name     string         // Имя порта
	println  func(v ...any) // log
	exit     string
}

func newSideWriter(w io.WriteCloser, escapeChar, name, exit string, chanByte chan byte, println ...func(v ...any)) *sideWriter {
	var t byte
	switch strings.ToLower(escapeChar) {
	case "none", "":
		t = 0
	default:
		t = escapeChar[0]
	}

	logPrintln := func(v ...any) {}
	for _, p := range println {
		logPrintln = p
		break
	}
	logPrintln(mess("<Enter><"+escapeChar+">", exit, name))
	return &sideWriter{
		w,
		[]byte{'\r', '\r'},
		t,
		chanByte,
		name,
		logPrintln,
		exit,
	}
}

// Некоторые устройства имеют короткий буфер и медленно из него читают.
// Будем передавать по одному байту за раз.
func (w *sideWriter) Write1(p []byte) (int, error) {
	var err error
	for i, b := range p {
		_, err = w.WriteCloser.Write([]byte{b})
		if err != nil {
			return i, err
		}
	}
	return len(p), nil
}

// Изменяем скорость и режим порта  по нажатию`<Enter><EscapeChar>(0-9)`.
func (w *sideWriter) Write(pp []byte) (int, error) {
	if w.t == 0 {
		// return w.WriteCloser.Write(pp)
		return w.Write1(pp)
	}
	o := len(pp)
	p := append(w.l, pp...) //+2
	switch {
	case bytes.Contains(p, []byte{'\r', w.t, '.'}):
		if w.chanByte != nil {
			w.chanByte <- '.'
		}
		if o > 1 {
			p = bytes.ReplaceAll(p, []byte{'\r', w.t, '.'}, []byte{})
		} else {
			p = []byte{BackSpace}
		}
		w.Write1(p)
		return 0, fmt.Errorf(`<Enter><%c><.> was pressed`, w.t)
	case w.name != "" && bytes.Contains(p, []byte{'\r', w.t}):
		// w.println(mess("", w.exit))
		fmt.Fprint(os.Stderr, "\a")
		for _, key := range []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'z', 'Z', w.t} {
			if bytes.Contains(p, []byte{'\r', w.t, key}) {
				switch key {
				case w.t:
					if o > 1 {
						p = bytes.ReplaceAll(p, []byte{'\r', w.t, key}, []byte{key})
					} else {
						return o, nil
					}
				case 'z', 'Z':
					if o > 1 {
						p = bytes.ReplaceAll(p, []byte{'\r', w.t, key}, []byte{CtrlZ})
					} else {
						p = bytes.ReplaceAll(p, []byte{'\r', w.t, key}, []byte{'\r', w.t, BackSpace, CtrlZ})
					}
				default:
					if w.chanByte != nil {
						w.chanByte <- key
					}
					if o > 1 {
						p = bytes.ReplaceAll(p, []byte{'\r', w.t, key}, []byte{})
					} else {
						w.l = []byte{'\r', w.t}
						return w.Write1([]byte{BackSpace})
					}
				}
				break
			}
		}
	}
	if len(p) > 1 {
		p = p[2:] //-2
	}
	n := len(p)

	switch n {
	case 0:
		w.l = []byte{'\r', '\r'}
		return o, nil
	case 1:
		w.l = []byte{w.l[1], p[0]}
	default:
		w.l = []byte{p[n-2], p[n-1]}
	}

	// _, err := w.WriteCloser.Write(p)
	_, err := w.Write1(p)
	return o, err // Надо вызывающему коду сказать что записанно именно o байт а не n - иначе беда
}

func rn(ss ...string) (s string) {
	for _, v := range ss {
		s += v + "\n"
	}
	return strings.TrimSuffix(strings.ReplaceAll(s, "\n", "\r\n"), "\n")
}

func mess(esc, exit, serial string) string {
	if isSerial(serial) != nil {
		return rn("",
			ToExitPress+" "+esc+"<.>"+exit,
		)
	}
	// Костыль для ser2web
	enter := ""
	tep := " " + esc + "<.>"
	if strings.HasSuffix(exit, " ") {
		enter = "<Enter>"
		tep = ""
	}
	return rn("",
		ToExitPress+tep+exit,
		"To change mode of serial port press - Чтоб сменить режим последовательного порта нажми "+esc+"<x>"+enter,
		"Where x from 0 to 9 - Где 0[115200], 1[19200], 2[2400], 3[38400], 4[4800], 5[57600], 6[DataBits], 7[Parity], 8[StopBits], 9[9600]",
	)
}

type hostPort struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
	Web  bool   `json:"web"`
}

func newHostPort(host string, port int, path string, web bool) hostPort {
	os.MkdirAll(tmp, DIRMODE)
	return hostPort{all2dial(host), port, path, web}

}

func (hp *hostPort) read() (err error) {
	bytes, err := os.ReadFile(hp.name())
	if err != nil {
		return
	}
	return json.Unmarshal(bytes, hp)
}

func (hp *hostPort) write() (err error) {
	bytes, err := json.Marshal(hp)
	if err != nil {
		return
	}
	return os.WriteFile(hp.name(), bytes, FILEMODE)
}
func (hp *hostPort) dest() string {
	return fmt.Sprintf("%s:%d", hp.Host, hp.Port)
}

func (hp *hostPort) name() string {
	return filepath.Join(tmp, fmt.Sprintf("%s_%d.json", hp.Host, hp.Port))
}
func (hp *hostPort) String() string {
	if hp.Web {
		return fmt.Sprintf("start http://%s:%d %s", hp.Host, hp.Port, hp.Path)
	}
	return fmt.Sprintf("telnet %s %d %s", hp.Host, hp.Port, hp.Path)
}

func (hp *hostPort) remove() (err error) {
	return os.Remove(hp.name())
}

// Запускает ser2net server на telnet://host:Ser2net подключает к нему s через телнет клиента.
func rfc2217(ctx context.Context, cancel func(), s io.ReadWriteCloser, Serial, host string, Ser2net int, Baud, exit string, println ...func(v ...any)) (err error) {

	var (
		sw   *ser2net.SerialWorker
		conn *telnet.Connection
	)

	hp := newHostPort(host, Ser2net, Serial, false)
	chanByte := make(chan byte, B16)
	conn, err = telnet.Dial(hp.dest())

	if err != nil {
		// Новый сеанс
		chanError := make(chan error, 2)
		chanSerialWorker := make(chan *ser2net.SerialWorker, 2)
		go func() {
			chanError <- s2n(ctx, nil, chanByte, chanSerialWorker, Serial, host, Ser2net, Baud, exit, println...)
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err = <-chanError:
			return
		case sw = <-chanSerialWorker:
			conn, err = telnet.Dial(hp.dest())
		}
	} else {
		// Подключаемся к существующему сеансу
		hp.read()
		if isSerial(hp.Path) == ErrNotSerial {
			Serial = hp.Path
		} else {
			Serial = ""
		}
		go cancelByFile(ctx, cancel, hp.name(), TOW)
	}
	for _, p := range println {
		p(hp.String(), err)
	}
	// Println(hp.String(), err)
	if err != nil {
		return
	}
	defer conn.Close()

	if sw == nil {
		go ser2net.Copy(ctx, s, conn)
		_, err = ser2net.CopyAfter(ctx, newSideWriter(conn, args.EscapeChar, Serial, exit, chanByte, println...), s, time.Millisecond*77)
		return
	}
	go sw.Copy(s, conn)
	_, err = sw.CopyAfter(newSideWriter(conn, args.EscapeChar, Serial, exit, chanByte, println...), s, time.Millisecond*77)
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
	_, err = ser2net.Copy(ctx, newSideWriter(conn, args.EscapeChar, "", exit, nil, println...), s)
	return
}

// Через r или напрямую по chanByte управляет режимами последовательного порта w
func SetMode(w *ser2net.SerialWorker, ctx context.Context, r io.Reader, chanByte chan byte, exit string, Ser2net int, println ...func(v ...any)) {
	press := mess("", exit, w.Name())
	print := func(a ...any) {
		for _, p := range println {
			p(a...)
		}
	}
	prin := func(a ...any) {
		for _, p := range println {
			p(a...)
			break
		}
	}

	if Ser2net > 0 {
		print(w)

		defer func() {
			w.Stop()
			w.SerialClose()
			print(w)

		}()
	}

	if chanByte == nil {
		chanByte = make(chan byte, B16)
	}
	if r != nil {
		prin(press)
		buffer := make([]byte, B16)
		go func() {
			for {
				select {
				case <-ctx.Done():
					chanByte <- CtrlC
					return
				default:
					n, err := r.Read(buffer)
					if err != nil {
						chanByte <- CtrlZ
						return
					}
					for _, b := range buffer[:n] {
						// Если фильтровать ошибочный ввод то как же дать понять что он ошибочен
						// if b < '0' || b > '9' {
						// 	continue
						// }
						chanByte <- b
					}
				}
			}
		}()
	}
	const (
		DataBits = "set data bits - установлено кол-во бит"
		Parity   = "set parity - установлена чётность"
		StopBits = "set stop bits - установлено кол-во стоповых бит"
		BaudRate = "set baud - установлена скорость"
	)
	old := w.Mode()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
			mode := w.Mode()
			msg := ""
			if mode.DataBits != old.DataBits {
				msg = DataBits
			}
			if mode.Parity != old.Parity {
				msg = Parity
			}
			if mode.StopBits != old.StopBits {
				msg = StopBits
			}
			if mode.BaudRate != old.BaudRate {
				msg = BaudRate
			}
			if msg != "" {
				print(fmt.Sprintf("%s %s", w, msg))
				old = mode
			}
		case b := <-chanByte:
			mode := w.Mode()
			msg := ""
			switch b {
			case '\n':
				continue
			case '.', CtrlC, CtrlZ:
				return
			case '6':
				switch mode.DataBits {
				case 5:
					mode.DataBits = 6
				case 6:
					mode.DataBits = 7
				case 7:
					mode.DataBits = 8
				default:
					mode.DataBits = 5
				}
				msg = DataBits
			case '7':
				switch mode.Parity {
				case serial.NoParity:
					mode.Parity = serial.OddParity
				case serial.OddParity:
					if mode.DataBits < 8 {
						// https://datatracker.ietf.org/doc/html/rfc2217
						//  EVEN parity is only valid if the data size is set to less than 8 bits
						mode.Parity = serial.EvenParity
					} else {
						mode.Parity = serial.MarkParity
					}
				case serial.EvenParity:
					mode.Parity = serial.MarkParity
				case serial.MarkParity:
					mode.Parity = serial.SpaceParity
				case serial.SpaceParity:
					mode.Parity = serial.NoParity
				}
				msg = Parity
			case '8':
				switch mode.StopBits {
				case serial.OneStopBit:
					if mode.DataBits == 5 {
						// https://datatracker.ietf.org/doc/html/rfc2217
						//  Stop bit 1.5 is supported by most com port hardware only if data size is set to 5 bits
						mode.StopBits = serial.OnePointFiveStopBits
					} else {
						mode.StopBits = serial.TwoStopBits
					}
				case serial.OnePointFiveStopBits:
					mode.StopBits = serial.TwoStopBits
				case serial.TwoStopBits:
					mode.StopBits = serial.OneStopBit
				}
				msg = StopBits
			case '0', '1', '2', '3', '4', '5', '9':
				mode.BaudRate = ser2net.BaudRate(int(b-'0'), nil)
				msg = BaudRate
			}
			if msg == "" {
				prin(press)
				continue
			}
			w.SetMode(&mode)
		}
	}
}
