package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
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
)

var (
	ErrNotFoundFreeSerial = fmt.Errorf("not found free serial USB port - не найден свободный последовательный порт USB")
)

type cgiArgs struct {
	Baud    string `arg:"-U,--baud" placeholder:"baUd" help:"set baud rate of serial console"`
	Serial  string `arg:"-H,--path" placeholder:"patH" help:"device path (name for Windows) of serial console"`
	Ser2net int    `arg:"-2,--2217" placeholder:"port" help:"RFC2217 telnet port for serial console over telnet" default:"-1"`
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

// Подключаем последовательный порт к сессии ssh или локально.
// Завершение сессии через `<Enter>~.`
// Если name пусто то ищем первый последовательный порт USB
func ser(ctx context.Context, s io.ReadWriteCloser, Serial, Baud, exit string, println ...func(v ...any)) error {
	if Serial == "" {
		return ErrNotFoundFreeSerial
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
	msg := fmt.Sprintf("%s opened - открыт\r", ser2net.Mode{Mode: mode, Name: Serial})
	for _, p := range println {
		p(msg)
	}
	w.SetSerial(port)

	defer func() {
		msg = fmt.Sprintf("%s closed - закрыт %v\r", ser2net.Mode{Mode: w.Mode(), Name: w.Name()}, err)
		err = ser2net.SerialClose(port)
		for _, p := range println {
			p(msg)
		}
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

// Телнет сервер RFC2217 ждёт на порту Ser2net.
// SetMode использует r или chanByte для смены serial.Mode порта Serial.
// На консоль клиента println[0] выводит протокол через ssh канал.
// Локально println[1] выводит протокол.
func s2n(ctx context.Context, r io.Reader, chanByte chan byte, Serial, host string, Ser2net int, Baud, exit string, println ...func(v ...any)) error {
	if Serial == "" {
		return ErrNotFoundFreeSerial
	}
	w, _ := ser2net.NewSerialWorker(ctx, Serial, ser2net.BaudRate(strconv.Atoi(Baud)))
	go w.Worker()
	t := time.AfterFunc(time.Second, func() {
		SetMode(w, ctx, r, chanByte, exit, Ser2net, println...)
	})

	err := w.StartTelnet(host, Ser2net)
	if err != nil {
		t.Stop()
		for _, p := range println {
			p(err, "\r")
		}
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
	t := time.AfterFunc(time.Second, func() {
		SetMode(w, ctx, r, chanByte, exit, wp, println...)
	})

	log.SetPrefix("\r>" + log.Prefix())
	log.SetFlags(log.Lshortfile)

	err := w.StartGoTTY(host, wp, "", false)
	if err != nil {
		t.Stop()
		for _, p := range println {
			p(err, "\r")
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
	// if serial == "" {
	// 	print(NotFoundFreeSerial)
	// }
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
		w.chanByte <- '.'
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
					w.chanByte <- key
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

func mess(esc, exit, namePort string) string {
	if namePort == "" {
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

// Запускает ser2net server на 127.0.0.1:Ser2net подключает к нему s через телнет клиента
func rfc2217(ctx context.Context, s io.ReadWriteCloser, Serial, host string, Ser2net int, Baud, exit string, println ...func(v ...any)) error {
	chanByte := make(chan byte, B16)

	if Serial != "" {
		chanError := make(chan error, 1)
		go func() {
			chanError <- s2n(ctx, nil, chanByte, Serial, host, Ser2net, Baud, exit, println...)
		}()
		select {
		case err := <-chanError:
			return err
		case <-time.After(time.Second):
		}
	}

	conn, err := telnet.Dial(fmt.Sprintf("%s:%d", host, Ser2net))
	if err != nil {
		return err
	}
	defer conn.Close()

	go io.Copy(s, conn)
	_, err = io.Copy(newSideWriter(conn, args.EscapeChar, Serial, exit, chanByte, println...), s)
	return err
}

// Через r или напрямую по chanByte управляет режимами последовательного порта w
func SetMode(w *ser2net.SerialWorker, ctx context.Context, r io.Reader, chanByte chan byte, exit string, Ser2net int, println ...func(v ...any)) {
	press := mess("", exit, w.Name())
	if Ser2net > 0 {
		for _, p := range println {
			p(w.String() + "\r")
		}

		defer func() {
			w.Stop()
			// w.SerialClose()
			for _, p := range println {
				p(w.String() + "\r")
			}
			// closer.Close()
		}()
	}

	if chanByte == nil {
		chanByte = make(chan byte, B16)
	}
	if r != nil {
		for _, p := range println {
			p(press)
			break
		}
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
	for {
		select {
		case <-ctx.Done():
			return
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
				case 7:
					mode.DataBits = 8
				case 8:
					mode.DataBits = 7
				}
				msg = "set data bits - установлено кол-во бит"
			case '7':
				switch mode.Parity {
				case serial.NoParity:
					mode.Parity = serial.OddParity
				case serial.OddParity:
					mode.Parity = serial.EvenParity
				case serial.EvenParity:
					mode.Parity = serial.MarkParity
				case serial.MarkParity:
					mode.Parity = serial.SpaceParity
				case serial.SpaceParity:
					mode.Parity = serial.NoParity
				}
				msg = "set parity - установлена чётность"
			case '8':
				switch mode.StopBits {
				case serial.OneStopBit:
					mode.StopBits = serial.OnePointFiveStopBits
				case serial.OnePointFiveStopBits:
					mode.StopBits = serial.TwoStopBits
				case serial.TwoStopBits:
					mode.StopBits = serial.OneStopBit
				}
				msg = "set stop bits - установлено кол-во стоповых бит"
			case '0', '1', '2', '3', '4', '5', '9':
				mode.BaudRate = ser2net.BaudRate(int(b-'0'), nil)
				msg = "set baud - установлена скорость"
			}
			if msg == "" {
				for _, p := range println {
					p(press)
					break
				}
				continue
			}
			err := w.SetMode(&mode)
			msg = fmt.Sprintf("%s %s %v\r", w, msg, err)
			for _, p := range println {
				p(msg)
			}
		}
	}
}

func LocateChrome() string {

	var paths []string
	switch runtime.GOOS {
	case "darwin":
		paths = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/google-chrome",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
		}
	case "windows":
		paths = []string{
			os.Getenv("LocalAppData") + "/Google/Chrome/Application/chrome.exe",
			os.Getenv("ProgramFiles") + "/Google/Chrome/Application/chrome.exe",
			os.Getenv("ProgramFiles(x86)") + "/Google/Chrome/Application/chrome.exe",
			os.Getenv("LocalAppData") + "/Chromium/Application/chrome.exe",
			os.Getenv("ProgramFiles") + "/Chromium/Application/chrome.exe",
			os.Getenv("ProgramFiles(x86)") + "/Chromium/Application/chrome.exe",
			os.Getenv("ProgramFiles(x86)") + "/Microsoft/Edge/Application/msedge.exe",
		}
	default:
		paths = []string{
			"/usr/bin/google-chrome-stable",
			"/usr/bin/google-chrome",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
		}
	}

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		return path
	}
	return ""
}
