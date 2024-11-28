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

	hp := fmt.Sprintf("%s:%d", all2dial(host), Ser2net)
	if isHP(hp) {
		// Подключаемся к существующему сеансу
		return cons(ctx, s, hp, args.Baud, exit, println...)
	}

	// Новый сеанс

	chanByte := make(chan byte, B16)
	chanError := make(chan error, 2)
	chanSerialWorker := make(chan *ser2net.SerialWorker, 2)
	go func() {
		chanError <- s2n(ctx, nil, chanByte, chanSerialWorker, Serial, host, Ser2net, Baud, exit, println...)
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

	print(w, "LikeSerial", !ser2net.SerialPath(Serial))
	defer func() {
		print("Serial", Serial, "closed", w.SerialClose(), w)
	}()

	if strings.Contains(w.String(), "$") {
		// Команда или интерпретатор.
		Serial = ""
	}

	go w.CopyCancel(s, c)
	_, err = w.CancelCopy(newSideWriter(c, args.EscapeChar, Serial, exit, chanByte, println...), s)
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
	print(fmt.Sprintf("use RFC2217 telnet server by `%s -H %s`", repo, ser2net.LocalPort(fmt.Sprintf("%s:%d", host, Ser2net))))
	err := w.StartTelnet(host, Ser2net)
	t.Stop()

	if err != nil {
		print(err)
	}
	return err
}
