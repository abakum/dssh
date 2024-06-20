package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"runtime"
	"strings"

	"github.com/abakum/go-ser2net/pkg/ser2net"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

// https://gist.github.com/dillonstreator/3e9162e6e0d0929a6543a64f4564b604
type CtxReader struct {
	ctx context.Context
	r   io.ReadCloser
}

// Чтения из последовательного порта с контекстом
func newCtxReader(ctx context.Context, r io.ReadCloser) *CtxReader {
	return &CtxReader{ctx, r}
}

func (r *CtxReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.r.Read(p)
	}
}

type cgiArgs struct {
	Baud    string `arg:"-b,--baud" placeholder:"baud" help:"set serial console baud rate"`
	Serial  string `arg:"-s,--serial" placeholder:"serial" help:"serial port for console"`
	Ser2net int    `arg:"-2,--2217" placeholder:"port" help:"RFC2217 telnet port for serial port console over telnet"`
	Restart bool   `arg:"-r,--restart" help:"restart daemon"`
}

// Подключаем последовательный порт к сессии.
// Это псевдокоманда `dssh -t . "dssh -b 115200 -s com3"`.
// Завершение сессии через `<Enter>~.`
// Если name пусто то ищем первый USB последовательный порт
func ser(s gl.Session, cgi *cgiArgs, baud int, println func(v ...any)) {

	port, err := serial.Open(cgi.Serial,
		&serial.Mode{
			BaudRate: baud,
		},
	)
	if err != nil {
		var portErr serial.PortError
		if errors.As(err, &portErr) {
			log.Println(err, portErr, "\r")
			Println(err, portErr)
			return
		}
		log.Println(err, "\r")
		Println(err)
		return
	}
	msg := fmt.Sprintf("%s@%d opened - открыт\r", cgi.Serial, baud)
	println(msg)
	println(mess("<Enter><~>"))

	Println(msg)
	defer func() {
		err = serialClose(port)
		msg = fmt.Sprintf("%s@%d closed - закрыт %v\r", cgi.Serial, baud, err)
		println(msg)
		Println(msg)
	}()

	go func() {
		io.Copy(s, port)
	}()
	io.Copy(newBaudWriter(port, "~", cgi.Serial, println), s)

}

func serialClose(port serial.Port) error {
	port.ResetInputBuffer()
	port.ResetOutputBuffer()
	port.Drain()
	return port.Close()
}

func mess(s string) string {
	return rn("",
		"To exit press - Чтоб выйти нажми "+s+"<.>",
		"To set baud press - Чтоб сменить скорость передачи нажми "+s+"<x>",
		"Where x (0-9) - Где x это 0 как 19200, 1 как 115200 и так далее 2400, 38400, 4800, 57600 и 9 как 9600",
	)
}

func getFirstSerial(isUSB bool, baud int) (name, list string) {
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
			sp, err := serial.Open(port.Name, &serial.Mode{BaudRate: baud})
			if err != nil {
				list += fmt.Sprintf(" %s", err)
				if strings.HasSuffix(err.Error(), "Permission denied") && runtime.GOOS != "windows" {
					list += fmt.Sprintf(" try run `sudo usermod -a -G dialout %s` then reboot", winssh.UserName())
				}
				continue
			}
			_, err = sp.GetModemStatusBits()
			serialClose(sp)
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
}

func newBaudWriter(port serial.Port, escapeChar, namePort string, logPrintln func(v ...any)) *baudWriter {
	var t byte
	switch strings.ToLower(escapeChar) {
	case "none", "":
		t = 0
	default:
		t = escapeChar[0]
	}
	return &baudWriter{
		port,
		[]byte{'\r', '\r'},
		t,
		port,
		namePort,
		logPrintln,
	}
}

func rn(ss ...string) (s string) {
	for _, v := range ss {
		s += v + "\n"
	}
	return strings.TrimSuffix(strings.ReplaceAll(s, "\n", "\r\n"), "\n")
}

// Изменяем скорость порта  по нажатию`<Enter><EscapeChar>(0-9)`.
func (w *baudWriter) Write(pp []byte) (int, error) {
	if w.t == 0 {
		return w.Writer.Write(pp)
	}
	const (
		Return    = '\r'
		CtrlZ     = 0x1A
		Dot       = '.'
		BackSpace = 0x7F
	)
	// Println(pp)
	p := append(w.l, pp...) //+2
	if bytes.Contains(p, []byte{Return, w.t}) {
		w.println(mess(""))
	}
	for _, key := range []byte{'0', '1', '2', '3', '4', '5', '9'} {
		if bytes.Contains(p, []byte{Return, w.t, key}) {
			baud := baudRate(int(key-'0'), nil)
			err := w.port.SetMode(&serial.Mode{BaudRate: baud})
			msg := fmt.Sprintf("%s@%d %v\r", w.name, baud, err)
			w.println(msg)
			Println(msg)
			p = bytes.ReplaceAll(p, []byte{Return, w.t, key}, []byte{Return, w.t, BackSpace})
		}
	}
	switch {
	case bytes.Contains(p, []byte{Return, w.t, CtrlZ}):
		return 0, fmt.Errorf(`<Enter>%c^Z was pressed`, w.t)
	case bytes.Contains(p, []byte{Return, w.t, Dot}):
		return 0, fmt.Errorf(`<Enter>%c. was pressed`, w.t)
	case bytes.Contains(p, []byte{Return, w.t, w.t}):
		p = bytes.ReplaceAll(p, []byte{Return, w.t, w.t}, []byte{Return, w.t, BackSpace})
	}
	p = p[2:] //-2
	n := len(pp)

	switch n {
	case 0:
		w.l = []byte{w.l[1], 0}
		return 0, nil
	case 1:
		w.l = []byte{w.l[1], p[0]}
	default:
		w.l = []byte{p[n-2], p[n-1]}
	}
	return w.Writer.Write(p)
}

func baudRate(b int, err error) (baud int) {
	baud = 9600
	if err != nil {
		return
	}
	switch b {
	case 0, 19200:
		baud = 19200
	case 1, 115200:
		baud = 115200
	case 2, 2400:
		baud = 2400
	case 3, 38400:
		baud = 38400
	case 4, 4800:
		baud = 4800
	case 5, 57600:
		baud = 57600
	}
	return
}

func s2n(ctx context.Context, cgi *cgiArgs, baud int, println func(v ...any), bind, closed, press string) {
	w, err := ser2net.NewSerialWorker(ctx, cgi.Serial, baud)
	msg := fmt.Sprintf("%s@%d opened - открыт, %s:%d listen - ожидает подключения\r", cgi.Serial, baud, bind, cgi.Ser2net)
	if err != nil {
		msg = fmt.Sprintf("%s@%d opened fail - не был открыт: %v\r", cgi.Serial, baud, err)
		println(msg)
		Println(msg)
		return
	}
	println(msg)
	Println(msg)
	println(press)

	go w.Worker()
	go func() {
		err = w.StartTelnet(bind, cgi.Ser2net)
		println(closed, err, "\r")
		Println(closed, err, "\r")
	}()
}
