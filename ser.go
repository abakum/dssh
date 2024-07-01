package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
	K16         = 16 * 1024
)

var (
	NotFoundFreeSerial = fmt.Errorf("not found free serial USB port - не найден свободный последовательный порт USB")
)

type cgiArgs struct {
	Baud    string `arg:"-b,--baud" placeholder:"baud" help:"set serial console baud rate"`
	Serial  string `arg:"-s,--serial" placeholder:"serial" help:"serial port for console"`
	Ser2net int    `arg:"-2,--2217" placeholder:"port" help:"RFC2217 telnet port for serial port console over telnet"`
	Putty   bool   `arg:"-P,--putty" help:"run putty"`
	Exit    string `arg:"-x,--exit" help:"exit message"`
	Restart bool   `arg:"-r,--restart" help:"restart daemon"`
}

type ReadWriteCloser struct {
	io.Reader
	io.WriteCloser
}

// Подключаем последовательный порт к сессии.
// Это псевдокоманда `dssh -t . "dssh -b 115200 -s com3"`.
// Завершение сессии через `<Enter>~.`
// Если name пусто то ищем первый последовательный порт USB
func ser(s io.ReadWriteCloser, Serial, Baud, exit string, println ...func(v ...any)) {
	if Serial == "" {
		for _, p := range println {
			p(NotFoundFreeSerial, "\r")
		}
		return
	}
	BaudRate := ser2net.BaudRate(strconv.Atoi(Baud))
	mode := serial.Mode{
		BaudRate: BaudRate,
		DataBits: 8,
	}
	port, err := serial.Open(Serial, &mode)
	if err != nil {
		var portErr serial.PortError
		if errors.As(err, &portErr) {
			for _, p := range println {
				p(err, portErr, "\r")
			}
			return
		}
		for _, p := range println {
			p(err, "\r")
		}
		return
	}
	m := fmt.Sprintf("%s@%s", Serial, ser2net.Mode{mode})
	msg := fmt.Sprintf("%s opened - открыт\r", m)
	for _, p := range println {
		p(msg)
	}

	defer func() {
		err = ser2net.SerialClose(port)
		msg = fmt.Sprintf("%s closed - закрыт %v\r", m, err)
		for _, p := range println {
			p(msg)
		}
	}()

	go func() {
		io.Copy(s, port)
	}()
	wp := func(v ...any) {}
	if len(println) > 0 {
		wp = (println[0])
	}
	io.Copy(newBaudWriter(port, "~", Serial, exit, BaudRate, wp), s)
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

type baudWriter struct {
	io.Writer
	l       []byte         // last 2 bytes
	t       byte           // EscapeChar
	port    serial.Port    // Для SetMode baud
	name    string         // Имя порта
	println func(v ...any) // log
	mode    serial.Mode
	exit    string
}

func newBaudWriter(port serial.Port, escapeChar, namePort, exit string, baud int, logPrintln func(v ...any)) *baudWriter {
	var t byte
	switch strings.ToLower(escapeChar) {
	case "none", "":
		t = 0
	default:
		t = escapeChar[0]
	}
	logPrintln(mess("<Enter><~>", exit))
	return &baudWriter{
		port,
		[]byte{'\r', '\r'},
		t,
		port,
		namePort,
		logPrintln,
		serial.Mode{
			BaudRate: baud,
			DataBits: 8,
		},
		exit,
	}
}

// Изменяем скорость порта  по нажатию`<Enter><EscapeChar>(0-9)`.
func (w *baudWriter) Write(pp []byte) (int, error) {
	if w.t == 0 {
		return w.Writer.Write(pp)
	}
	o := len(pp)
	p := append(w.l, pp...) //+2
	// Println(o, p, 6)
	switch {
	case bytes.Contains(p, []byte{'\r', w.t, CtrlZ}):
		return 0, fmt.Errorf(`<Enter><%c><^Z> was pressed`, w.t)
	case bytes.Contains(p, []byte{'\r', w.t, '.'}):
		return 0, fmt.Errorf(`<Enter><%c><.> was pressed`, w.t)
	case bytes.Contains(p, []byte{'\r', w.t}):
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
					msg, _ := switchMode(key, &w.mode, "")
					err := w.port.SetMode(&w.mode)
					w.println(fmt.Sprintf("%s@%s %v\r", w.name, msg, err))
					if o > 1 {
						p = bytes.ReplaceAll(p, []byte{'\r', w.t, key}, []byte{})
					} else {
						w.l = []byte{'\r', w.t}
						return w.Writer.Write([]byte{BackSpace})
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
	// Println(n, p)

	switch n {
	case 0:
		w.l = []byte{'\r', '\r'}
		return o, nil
	case 1:
		w.l = []byte{w.l[1], p[0]}
	default:
		w.l = []byte{p[n-2], p[n-1]}
	}
	_, err := w.Writer.Write(p)
	return o, err
}

// Используем r или chanByte для смены serial.Mode порта Serial.
// Телнет сервер ждёт на порту Ser2net.
// На консоль клиента println[0] выводит протокол через ssh канал.
// Локально println[1] выводит протокол.
func s2n(ctx context.Context, r io.Reader, chanByte chan byte, Serial string, Ser2net int, Baud, exit string, println ...func(v ...any)) error {
	if Serial == "" {
		return NotFoundFreeSerial
	}
	press := mess("", exit)
	w, _ := ser2net.NewSerialWorker(ctx, Serial, ser2net.BaudRate(strconv.Atoi(Baud)))
	go w.Worker()
	t := time.AfterFunc(time.Second, func() {
		// Если порт Ser2net занят то t.Stop отменит запуск управления последовательным портом
		for _, p := range println {
			p(fmt.Sprintf("%s@%s connected to %s:%d\r", Serial, ser2net.Mode{w.Mode()}, LH, Ser2net))
		}

		defer func() {
			w.Stop()
			w.SerialClose()
			for _, p := range println {
				p(w, "\r")
			}
		}()
		if chanByte == nil {
			chanByte = make(chan byte, K16)
		}
		if r != nil {
			for _, p := range println {
				p(press)
			}
			buffer := make([]byte, K16)
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
							// Если фильтровать ошибочный ввод то какже дать понять что он ошибочен
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
				msg, quit := switchMode(b, &mode, " ")
				if quit {
					return
				}
				if msg == "" {
					for _, p := range println {
						p(press)
					}
					continue
				}
				err := w.SetMode(&mode)
				msg = fmt.Sprintf("%s%s %v\r", w, msg, err)
				for _, p := range println {
					p(msg)
				}
			}
		}
	})

	err := w.StartTelnet(LH, Ser2net)
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

func newSideWriter(w io.WriteCloser, escapeChar, name, exit string, chanByte chan byte, logPrintln func(v ...any)) *sideWriter {
	var t byte
	switch strings.ToLower(escapeChar) {
	case "none", "":
		t = 0
	default:
		t = escapeChar[0]
	}
	logPrintln(mess("<Enter><~>", exit))
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

// Изменяем скорость и режим порта  по нажатию`<Enter><EscapeChar>(0-9)`.
func (w *sideWriter) Write(pp []byte) (int, error) {
	if w.t == 0 {
		return w.WriteCloser.Write(pp)
	}
	o := len(pp)
	p := append(w.l, pp...) //+2
	switch {
	case bytes.Contains(p, []byte{'\r', w.t, CtrlZ}):
		return 0, fmt.Errorf(`<Enter><%c><^Z> was pressed`, w.t)
	case bytes.Contains(p, []byte{'\r', w.t, '.'}):
		w.chanByte <- '.'
		return 0, fmt.Errorf(`<Enter><%c><.> was pressed`, w.t)
	case bytes.Contains(p, []byte{'\r', w.t}):
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
						return w.WriteCloser.Write([]byte{BackSpace})
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
	_, err := w.WriteCloser.Write(p)
	return o, err
}

func rn(ss ...string) (s string) {
	for _, v := range ss {
		s += v + "\n"
	}
	return strings.TrimSuffix(strings.ReplaceAll(s, "\n", "\r\n"), "\n")
}

func mess(esc, exit string) string {
	return rn("",
		ToExitPress+" "+esc+"<.>"+exit,
		"To change mode of serial port press - Чтоб сменить режим последовательного порта нажми "+esc+"<x>",
		"Where x from 0 to 9 - Где 0[115200], 1[19200], 2[2400], 3[38400], 4[4800], 5[57600], 6[DataBits], 7[Parity], 8[StopBits], 9[9600]",
	)
}

func switchMode(b byte, mode *serial.Mode, prefix string) (msg string, quit bool) {
	switch b {
	case '.', CtrlC, CtrlZ:
		quit = true
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
	if prefix == "" {
		prefix = ser2net.Mode{*mode}.String() + " "
	}
	msg = fmt.Sprintf("%s%s", prefix, msg)
	return
}

func rfc2217(ctx context.Context, s io.ReadWriteCloser, Serial string, Ser2net int, Baud, exit string, println ...func(v ...any)) {
	ch := make(chan byte, K16)
	go s2n(ctx, nil, ch, Serial, Ser2net, Baud, exit, println...)
	time.Sleep(time.Second)

	wp := func(v ...any) {}
	if len(println) > 0 {
		wp = (println[0])
	}

	conn, err := telnet.Dial(fmt.Sprintf("%s:%d", LH, Ser2net))
	if err != nil {
		wp(err, "\r")
		return
	}
	defer conn.Close()

	go io.Copy(s, conn)
	io.Copy(newSideWriter(conn, "~", Serial, exit, ch, wp), s)
}
