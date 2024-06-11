package main

import (
	"context"
	"errors"
	"io"
	"log"

	gl "github.com/gliderlabs/ssh"
	"go.bug.st/serial.v1"
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

// Подключаем последовательный порт к сессии.
// Это псевдокоманда `dssh -t . "dssh -b 115200 -s com3"`.
// Завершение сессии через `<Enter>~.`
func ser(s gl.Session, name string, baud int) {
	log.SetFlags(log.Lshortfile)
	log.SetPrefix(">")
	log.SetOutput(s.Stderr())
	port, err := serial.Open(name,
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
	log.Println("Port", name, "opened\r")
	Println("Port", name, "opened")
	defer func() {
		err = port.Close()
		log.Println("Port", name, "closed", err, "\r")
		Println("Port", name, "closed", err)
	}()

	go func() {
		io.Copy(s, port)
	}()
	io.Copy(port, s)
}
