package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/PatrickRudolph/telnet"
	"github.com/abakum/go-ser2net/pkg/ser2net"
)

// Если telnet://host:Ser2net уже слушает подключает к нему s через телнет клиента.
// Иначе запускает ser2net server на telnet://host:Ser2net и подключает к нему s через телнет клиента.
func rfc2217(ctx context.Context, s io.ReadWriteCloser, Serial, host string, Ser2net int, Baud, exit string, println ...func(v ...any)) (err error) {
	print := func(a ...any) {
		for _, p := range println {
			p(a...)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	_, local := s.(ser2net.ReadWriteCloser)
	if local && !ser2net.SerialPath(Serial) {
		exit = ""
	}
	quit := EED + exit

	// hp := fmt.Sprintf("%s:%d", all2dial(host), Ser2net)
	hp := JoinHostPort(ser2net.LocalPort(host), Ser2net)
	if isHP(hp) {
		// Подключаемся к существующему сеансу
		return cons(ctx, s, hp, args.Baud, exit, println...)
	}

	// Новый сеанс
	chanError := make(chan error, 1)
	chanByte := make(chan byte, B16)
	chanSerialWorker := make(chan *ser2net.SerialWorker, 1)
	go func() {
		chanError <- s2n(ctx, nil, chanByte, chanSerialWorker, Serial, host, Ser2net, Baud, quit, println...)
	}()
	var (
		w *ser2net.SerialWorker
		c *telnet.Connection
	)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-chanError:
		return
	case w = <-chanSerialWorker:
		defer w.Stop()
		c, err = telnet.Dial(hp, w.Client727, w.Client2217, w.Client1073)
		if err != nil {
			return
		}
		defer c.Close()
	}

	ss := "Serial"
	sp := Serial
	if strings.Contains(w.String(), "$") {
		// Команда или интерпретатор.
		Serial = ""
		ss = "Command"
	} else {
		if !ser2net.SerialPath(Serial) {
			ss = "Connection"
		}
	}
	defer func() {
		print(ss, sp, "closed", w.SerialClose(), w)
	}()

	go w.CopyCancel(s, c)
	println[0](mess(quit, w.String()))
	_, err = w.CancelCopy(newSideWriter(c, args.EscapeChar, Serial, chanByte), s)
	// Последний выдох
	ser2net.IAC(c, telnet.DO, telnet.TeloptLOGOUT)
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
	defer w.Stop()
	go w.Worker()
	t := time.AfterFunc(time.Millisecond*time.Duration(ser2net.TOopen), func() {
		defer w.Stop()
		print := func(a ...any) {
			for _, p := range println {
				p(a...)
			}
		}
		if strings.Contains(w.String(), "not connected") {
			print(w)
			// w.Stop()
			return
		}
		hp := JoinHostPort(host, Ser2net)
		print(fmt.Sprintf("use RFC2217 telnet server by `%s -H %s`", repo, ser2net.LocalPort(hp)))
		if chanW != nil {
			chanW <- w
		}
		SetMode(w, ctx, r, chanB, exit, Ser2net, println...)
		// w.Stop()
	})
	defer t.Stop()

	return w.StartTelnet(host, Ser2net)
}
