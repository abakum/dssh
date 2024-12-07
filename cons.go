package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/go-ser2net/pkg/ser2net"
)

// Подключаем консоль Serial к сессии ssh или локально.
// Завершение сессии через `<Enter>~.`
func cons(ctx context.Context, s io.ReadWriteCloser, Serial, Baud, exit string, println ...func(v ...any)) (err error) {
	if Serial == "" {
		return ErrNotFoundFreeSerial
	}
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

	w, _ := ser2net.NewSerialWorker(ctx, Serial, ser2net.BaudRate(strconv.Atoi(Baud)))
	defer w.Stop()

	go w.Worker()

	c, err := w.NewIoReadWriteCloser()
	if err != nil {
		return err
	}
	defer c.Close()

	chanByte := make(chan byte, B16)

	t := time.AfterFunc(time.Second, func() {
		SetMode(w, ctx, nil, chanByte, quit, 0, println...)
		w.Stop()
	})

	ss := "Serial"
	sp := Serial
	if strings.Contains(w.String(), "$") {
		// Команда или интерпретатор.
		Serial = ""
		println[0](mess(quit, w.String()))
		ss = "Command"
	} else {
		if !ser2net.SerialPath(Serial) {
			ss = "Connection"
		}
		time.AfterFunc(time.Millisecond*77, func() { println[0](mess(quit, w.String())) })
	}
	defer func() {
		print(ss, sp, "closed", w.SerialClose(), w)
	}()

	go w.CopyCancel(s, c)
	_, err = w.CancelCopy(newSideWriter(c, args.EscapeChar, Serial, chanByte), s)
	t.Stop()
	return
}

// Web сервер ждёт на порту web.
// SetMode использует r или chanByte для смены serial.Mode порта Serial.
// На консоль клиента println[0] выводит протокол через ssh канал.
// Локально println[1] выводит протокол.
func s2w(ctx context.Context, r io.Reader, chanB chan byte, Serial, host string, wp int, Baud, exit string, println ...func(v ...any)) error {
	if Serial == "" {
		return ErrNotFoundFreeSerial
	}

	w, _ := ser2net.NewSerialWorker(ctx, Serial, ser2net.BaudRate(strconv.Atoi(Baud)))
	go w.Worker()

	t := time.AfterFunc(time.Millisecond*time.Duration(ser2net.TOopen), func() {
		SetMode(w, ctx, r, chanB, exit, wp, println...)
		w.Stop()
	})

	hp := newHostPort(host, wp, Serial)
	hp.write()
	err := w.StartGoTTY(host, wp, "", false)
	t.Stop()
	hp.remove()

	return err
}

type hostPort struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
}

func newHostPort(host string, port int, path string) hostPort {
	os.MkdirAll(tmp, DIRMODE)
	return hostPort{all2dial(host), port, path}

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
	return JoinHostPort(hp.Host, hp.Port)
}

func (hp *hostPort) name() string {
	return filepath.Join(tmp, fmt.Sprintf("%s_%d.json", hp.Host, hp.Port))
}
func (hp *hostPort) String() string {
	return fmt.Sprintf("start http://%s:%d %s", hp.Host, hp.Port, hp.Path)
}

func (hp *hostPort) remove() (err error) {
	return os.Remove(hp.name())
}
