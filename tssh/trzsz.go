/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/trzsz/trzsz-go/trzsz"
	"github.com/xlab/closer"
)

const (
	ctrlZ = 0x1A // ^Z SUBSTITUTE
	ctrlD = 0x04 // ^D END OF TRANSMISSION
)

var outputWaitGroup sync.WaitGroup

func writeAll(dst io.Writer, data []byte) error {
	m := 0
	l := len(data)
	for m < l {
		n, err := dst.Write(data[m:])
		if err != nil {
			return err
		}
		m += n
	}
	return nil
}

// Заменяем разделители строк для Windows.
// Реагируем на  ^Z и ^D.
func wrapStdIO(serverIn io.WriteCloser, serverOut io.Reader, serverErr io.Reader, tty bool, escapeChar string) {
	win := runtime.GOOS == "windows"
	forwardIO := func(reader io.Reader, writer io.WriteCloser, input bool) {
		done := true
		if !input {
			done = false
			outputWaitGroup.Add(1)
		}
		defer writer.Close()
		buffer := make([]byte, 32*1024)
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				buf := buffer[:n]
				if win && isTerminal && tty && input && n == 1 && buf[0] == ctrlD {
					err = fmt.Errorf(`<^D> was pressed`)
				} else {
					if win && !tty {
						if input {
							buf = bytes.ReplaceAll(buf, []byte("\r\n"), []byte("\n"))
						} else {
							buf = bytes.ReplaceAll(buf, []byte("\n"), []byte("\r\n"))
						}
					}
					if err := writeAll(writer, buf); err != nil {
						warning("wrap stdio write failed: %v", err)
						return
					}
				}
			}
			if err != nil {
				if err == io.EOF && win && isTerminal && tty && input {
					// _, _ = writer.Write([]byte{ctrlZ})
					// continue
					err = fmt.Errorf(`<^Z> was pressed`)
				}
				if input {
					if strings.HasSuffix(err.Error(), "was pressed") {
						debug("%v", err)
						time.AfterFunc(time.Millisecond*222, func() {
							onExitFuncs.Cleanup()
							closer.Close()
						})
					}
					return // input EOF
				}
				// ignore output EOF
				if !done {
					outputWaitGroup.Done()
					done = true
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// if err != nil {
			// 	return
			// }
		}
	}
	if serverIn != nil {
		switch strings.ToLower(escapeChar) {
		case "none", "":
			go forwardIO(os.Stdin, serverIn, true)
		default:
			go forwardIO(newTildaReader(os.Stdin, escapeChar), serverIn, true)
		}

	}
	if serverOut != nil {
		go forwardIO(serverOut, os.Stdout, false)
	}
	if serverErr != nil {
		go forwardIO(serverErr, os.Stderr, false)
	}
}

func enableTrzsz(args *SshArgs, ss *sshSession) error {
	// not terminal or not tty
	if !isTerminal || !ss.tty {
		wrapStdIO(ss.serverIn, ss.serverOut, ss.serverErr, ss.tty, "")
		return nil
	}

	escapeChar := getOptionConfig(args, "EscapeChar")
	disableTrzsz := strings.ToLower(escapeChar) != "none"

	switch strings.ToLower(getExOptionConfig(args, "EnableTrzsz")) {
	case "no":
		disableTrzsz = true
	case "yes":
		disableTrzsz = false
	}
	enableZmodem := args.Zmodem || strings.ToLower(getExOptionConfig(args, "EnableZmodem")) == "yes"
	enableDragFile := args.DragFile || strings.ToLower(getExOptionConfig(args, "EnableDragFile")) == "yes"

	// disable trzsz ( trz / tsz )
	if disableTrzsz && !enableZmodem && !enableDragFile {
		wrapStdIO(ss.serverIn, ss.serverOut, ss.serverErr, ss.tty, escapeChar)
		onTerminalResize(func(width, height int) { _ = ss.session.WindowChange(height, width) })
		return nil
	}

	// support trzsz ( trz / tsz )

	wrapStdIO(nil, nil, ss.serverErr, ss.tty, "")

	trzsz.SetAffectedByWindows(false)

	if args.Relay || isNoGUI() {
		// run as a relay
		trzszRelay := trzsz.NewTrzszRelay(os.Stdin, os.Stdout, ss.serverIn, ss.serverOut, trzsz.TrzszOptions{
			DetectTraceLog: args.TraceLog,
		})
		// reset terminal size on resize
		onTerminalResize(func(width, height int) { _ = ss.session.WindowChange(height, width) })
		// setup tunnel connect
		trzszRelay.SetTunnelConnector(func(port int) net.Conn {
			conn, _ := dialWithTimeout(ss.client, "tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			return conn
		})
		return nil
	}

	width, _, err := getTerminalSize()
	if err != nil {
		return fmt.Errorf("get terminal size failed: %v", err)
	}

	// create a TrzszFilter to support trzsz ( trz / tsz )
	//
	//   os.Stdin  ┌────────┐   os.Stdin   ┌─────────────┐   ServerIn   ┌────────┐
	// ───────────►│        ├─────────────►│             ├─────────────►│        │
	//             │        │              │ TrzszFilter │              │        │
	// ◄───────────│ Client │◄─────────────┤             │◄─────────────┤ Server │
	//   os.Stdout │        │   os.Stdout  └─────────────┘   ServerOut  │        │
	// ◄───────────│        │◄──────────────────────────────────────────┤        │
	//   os.Stderr └────────┘                  stderr                   └────────┘
	trzszFilter := trzsz.NewTrzszFilter(os.Stdin, os.Stdout, ss.serverIn, ss.serverOut, trzsz.TrzszOptions{
		TerminalColumns: int32(width),
		DetectDragFile:  enableDragFile,
		DetectTraceLog:  args.TraceLog,
		EnableZmodem:    enableZmodem,
	})

	// reset terminal size on resize
	onTerminalResize(func(width, height int) {
		trzszFilter.SetTerminalColumns(int32(width))
		_ = ss.session.WindowChange(height, width)
	})

	// setup default paths
	trzszFilter.SetDefaultUploadPath(userConfig.defaultUploadPath)
	trzszFilter.SetDefaultDownloadPath(userConfig.defaultDownloadPath)

	// setup tunnel connect
	trzszFilter.SetTunnelConnector(func(port int) net.Conn {
		conn, _ := dialWithTimeout(ss.client, "tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		return conn
	})

	return nil
}

type tildaReader struct {
	io.Reader
	l []byte // last 2 bytes
	t byte   // EscapeChar
}

func newTildaReader(r io.Reader, escapeChar string) *tildaReader {
	var t byte
	switch strings.ToLower(escapeChar) {
	case "none", "":
		t = 0
	default:
		t = escapeChar[0]
	}
	return &tildaReader{
		r,
		[]byte{'\r', '\r'},
		t,
	}
}

// Заменяем `<Enter><EscapeChar><EscapeChar>` на `<Enter><EscapeChar>`.
// Реагируем на `<Enter><EscapeChar>.`
func (r *tildaReader) Read(pp []byte) (int, error) {
	if r.t == 0 {
		return r.Reader.Read(pp)
	}
	p := make([]byte, len(pp))
	n, err := r.Reader.Read(p)
	if err != nil {
		return n, err
	}

	p = append(r.l, p[:n]...) //+2
	switch {
	case bytes.Contains(p, []byte{'\r', r.t, '.'}):
		return 0, fmt.Errorf(`<Enter>%c. was pressed`, r.t)
	case bytes.Contains(p, []byte{'\r', r.t, r.t}):
		p = bytes.ReplaceAll(p, []byte{'\r', r.t, r.t}, []byte{'\r', r.t})
	}
	p = p[2:] //-2
	n = copy(pp, p)

	switch n {
	case 0:
		r.l = []byte{r.l[1], 0}
	case 1:
		r.l = []byte{r.l[1], p[0]}
	default:
		r.l = []byte{p[n-2], p[n-1]}
	}
	return n, nil
}
