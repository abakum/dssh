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
func rfc2217(ctx context.Context, s io.ReadWriteCloser, wt io.Writer, Serial, host string, Ser2net int, Baud, exit string, println ...func(v ...any)) (err error) {
	print := func(a ...any) {
		for _, p := range println {
			p(a...)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	hp := JoinHostPort(ser2net.LocalPort(host), Ser2net)
	if isHP(hp) {
		// Подключаемся к существующему сеансу
		return cons(ctx, s, wt, hp, args.Baud, exit, println...)
	}

	// Новый сеанс
	chanError := make(chan error, 1)
	chanByte := make(chan byte, B16)
	chanSerialWorker := make(chan *ser2net.SerialWorker, 1)
	go func() {
		chanError <- s2n(ctx, nil, wt, chanByte, chanSerialWorker, Serial, host, Ser2net, Baud, EED+exit, println...)
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
	// println[0](mess(quit, w.String()))
	_, err = w.CancelCopy(newSideWriter(c, args.EscapeChar, Serial, chanByte), s)
	// Последний выдох
	ser2net.IAC(c, telnet.DO, telnet.TeloptLOGOUT)
	return
}

// Телнет сервер RFC2217 ждёт на telnet://host:Ser2net.
// SetMode использует r или chanByte для смены serial.Mode порта Serial.
// На консоль клиента println[0] выводит протокол через ssh канал.
// Локально println[1] выводит протокол.
func s2n(ctx context.Context, r io.Reader, wt io.Writer, chanB chan byte, chanW chan *ser2net.SerialWorker, Serial, host string, Ser2net int, Baud, exit string, println ...func(v ...any)) error {
	if Serial == "" {
		return ErrNotFoundFreeSerial
	}

	w, _ := ser2net.NewSerialWorker(ctx, Serial, ser2net.BaudRate(strconv.Atoi(Baud)))
	defer w.Stop()
	go w.Worker()
	// t := time.AfterFunc(time.Millisecond*time.Duration(ser2net.TOopen), func() {
	t := time.AfterFunc(time.Second, func() {
		defer w.Stop()
		print := func(a ...any) {
			for _, p := range println {
				p(a...)
			}
		}
		if strings.Contains(w.String(), "not connected") {
			print(w)
			return
		}
		hp := JoinHostPort(host, Ser2net)
		print(fmt.Sprintf("use RFC2217 telnet server by `%s -H %s`", repo, ser2net.LocalPort(hp)))
		if chanW != nil {
			chanW <- w
		}
		time.Sleep(time.Second)
		SetMode(w, ctx, r, wt, chanB, exit, Ser2net, println...)
	})
	defer t.Stop()

	return w.StartTelnet(host, Ser2net)
}
