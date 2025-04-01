package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/go-ser2net/pkg/ser2net"
	"github.com/abakum/go-serial"
	"github.com/abakum/go-serial/enumerator"
	"github.com/abakum/winssh"
)

const (
	CtrlC       = 0x03 // ^C END OF TEXT
	CtrlZ       = 0x1A // ^Z SUBSTITUTE
	CtrlD       = 0x04 // ^D END OF TRANSMISSION
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

// Возвращаем имя первого не занятого порта.
// Список всех портов.
// Режим найденног порта.
func getFirstSerial(isUSB bool, Baud string) (name, list string, mode serial.Mode) {
	detailedPorts, err := enumerator.GetDetailedPortsList()
	if err != nil || len(detailedPorts) == 0 {
		return
	}
	ok := false
	for _, port := range detailedPorts {
		list += "\r\n" + serial.PortName(port.Name)
		if port.IsUSB {
			list += fmt.Sprintf(" USB Vid_%s&Pid_%s", port.VID, port.PID)
			SerialNumber := strings.TrimSpace(port.SerialNumber)
			if SerialNumber != "" {
				list += " #_" + SerialNumber
			}
		}
		Product := strings.TrimSpace(port.Product)
		if Product != "" {
			list += " " + Product
		}
		if !ok {
			if isUSB && !port.IsUSB {
				continue
			}
			// Занят?
			mode = getMode(port.Name)
			oldMode := ser2net.Mode{Mode: mode}.String()
			if b := ser2net.BaudRate(strconv.Atoi(Baud)); b != ser2net.OLDBAUD {
				mode.BaudRate = b
			}
			sp, err := serial.Open(port.Name, &mode)
			if err != nil {
				list += fmt.Sprintf(" %s", err)
				if strings.HasSuffix(err.Error(), "Permission denied") && !Windows {
					list += fmt.Sprintf(" try run `sudo usermod -a -G dialout %s` then reboot", winssh.UserName())
				}
				continue
			}
			sp.Close()
			ok = true
			name = port.Name
			list += " " + oldMode
		}
	}
	list += "\r\n"
	return
}

func getMode(name string) (mode serial.Mode) {
	mode.BaudRate = ser2net.OLDBAUD
	sp, err := serial.Open(name, &mode)
	if err != nil {
		mode = ser2net.DefaultMode
		return
	}
	defer sp.Close()
	return
}

// Ищем первый не занятый USB порт.
// Выводим список всех портов.
func getFirstUsbSerial(serialPort, Baud string, print func(v ...any)) (ser string, mode serial.Mode) {
	ser = serialPort
	mode = ser2net.DefaultMode
	if serialPort != "" {
		return
	}
	ser, list, mode := getFirstSerial(true, Baud)
	print(list)
	return
}

// Управление последоватальным портом через chanByte.
type sideWriter struct {
	io.WriteCloser
	l        []byte    // last 2 bytes
	t        byte      // EscapeChar
	chanByte chan byte // side chan
	name     string    // Имя порта
}

// Подслушиваем w. Если нажат escapeChar то следующий символ передаём в chanByte.
// Для протокола используем name, exit и println.
func newSideWriter(w io.WriteCloser, escapeChar, name string, chanByte chan byte) *sideWriter {
	var t byte
	switch strings.ToLower(escapeChar) {
	case "none", "":
		t = 0
	default:
		t = escapeChar[0]
	}

	return &sideWriter{
		w,
		[]byte{'\r', '\r'},
		t,
		chanByte,
		name,
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
	case Windows && bytes.Contains(p, []byte{CtrlZ}):
		if w.chanByte != nil {
			w.chanByte <- CtrlZ
		}
		w.Write1(p)
		return 0, fmt.Errorf(`<^Z> was pressed`)
	case !Windows && bytes.Contains(p, []byte{CtrlD}):
		if w.chanByte != nil {
			w.chanByte <- CtrlD
		}
		w.Write1(p)
		return 0, fmt.Errorf(`<^D> was pressed`)
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
		return 0, fmt.Errorf(Enter+`%c. was pressed`, w.t)
	case w.name != "" && bytes.Contains(p, []byte{'\r', w.t}):
		// w.println(mess("", w.exit))
		fmt.Fprint(os.Stderr, "\a")
		for _, key := range []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'z', 'Z', 'd', 'D', w.t} {
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
				case 'd', 'D':
					if o > 1 {
						p = bytes.ReplaceAll(p, []byte{'\r', w.t, key}, []byte{CtrlD})
					} else {
						p = bytes.ReplaceAll(p, []byte{'\r', w.t, key}, []byte{'\r', w.t, BackSpace, CtrlD})
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

func mess(exit, serial string) string {
	if strings.Contains(serial, "not connected") {
		return ""
	}
	if serial == "" {
		return rn("",
			ToExitPress+" "+exit,
		)
	}
	l1 := "(" + serial + ") " + ToExitPress + " " + exit
	esc := ""
	if strings.HasPrefix(exit, Enter) {
		esc = exit[:8]
	}
	if strings.Contains(serial, "$") || serial == "" {
		return rn("",
			l1,
		)
	}
	return rn("",
		l1,
		"To change mode of serial port press - Чтоб сменить режим последовательного порта нажми "+esc+"x, 0≤x≤9:",
		"0[115200], 1[19200], 2[2400], 3[38400], 4[4800], 5[57600], 6[DataBits], 7[Parity], 8[StopBits], 9[9600]",
	)
}

// Через r или напрямую по chanByte управляет режимами последовательного порта w.
func SetMode(w *ser2net.SerialWorker, ctx context.Context, r io.Reader, chanByte chan byte, exit string, Ser2net int, println ...func(v ...any)) {
	press := mess(exit, w.String())
	prin := func(a ...any) { println[0](a...) }

	if chanByte == nil {
		chanByte = make(chan byte, B16)
	}
	prin(press)
	if r != nil {
		// prin(press)
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
						if Windows {
							chanByte <- CtrlZ
						} else {
							chanByte <- CtrlD
						}
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
				press = mess(exit, w.String())
				prin(msg + press)
				old = mode
			}
		case b := <-chanByte:
			mode := w.Mode()
			msg := ""
			switch b {
			case '\n':
				continue
			case '.', CtrlC, CtrlZ, CtrlD:
				return
			case '6':
				switch mode.DataBits {
				case 7:
					mode.DataBits = 8
				case 8:
					mode.DataBits = 7
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
						mode.Parity = serial.NoParity
					}
				case serial.EvenParity:
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
						// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-dcb
						// The use of 5 data bits with 2 stop bits is an invalid combination, as is 6, 7, or 8 data bits with 1.5 stop bits.
						mode.StopBits = serial.TwoStopBits
					}
				case serial.OnePointFiveStopBits:
					// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-dcb
					// The use of 5 data bits with 2 stop bits is an invalid combination, as is 6, 7, or 8 data bits with 1.5 stop bits.
					if mode.DataBits == 5 {
						mode.StopBits = serial.OneStopBit
					} else {
						mode.StopBits = serial.TwoStopBits
					}
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
