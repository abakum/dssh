package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/dssh/tssh"
	"github.com/xlab/closer"
)

const (
	vncserverWindows    = "tvnserver.exe"
	vncserverEtc        = "vncserver"
	vncSecurityTypesEtc = "None"
	vncviewerWindows    = "vncviewer.exe"
	vncviewerEtc        = "vncviewer"
)

var (
	vncserver        = os.Getenv("VNC_SERVER")
	vncSecurityTypes = os.Getenv("VNC_SECURITY_TYPES")
	vncviewer        = os.Getenv("VNC_VIEWER")
)

// Ожидает подключения  vnc-сервера через порт 127.0.0.1:portV или через `dssh -l u -j destination` или `dssh -l u destination` или `dssh destination`
func useVNC(portV int, u, dj string) {
	// if portV < 0 || (args.DirectJump && args.Destination == "") {
	// 	return
	// }
	err := startViewer(portV, false)
	if err != nil {
		Println(err)
	}
	Println("To stop vncviewer press - Чтоб остановить vncviewer нажми <^C>")
	if args.Destination == "" {
		closer.Hold()
		return
	}
	lhp := JoinHostPort(LH, portV)
	s4 := lhp + ":" + lhp
	args.NoCommand = true
	args.RemoteForward.UnmarshalText([]byte(s4))

	opts := []string{repo}
	if args.NoCommand {
		opts = append(opts, "-N")
	}
	opts = append(opts, "-R", s4)
	if dj != "" {
		opts = append(opts, "-l", u, "-j", dj)
	} else {
		if args.LoginName != "" {
			opts = append(opts, "-l", args.LoginName)
		}
		if args.Destination != "" {
			opts = append(opts, args.Destination)
		}
	}
	forw := strings.Join(opts, " ")
	Println(forw)
	Println(forw, tssh.Tssh(&args), "done")

	// forw := exec.CommandContext(ctx, repo, opts...)
	// err := forw.Start()
	// Println(forw, err)
	// if err != nil {
	// 	return
	// }
	// forw.Wait()
}

func startViewer(portV int, R bool) (err error) {
	if portV < 0 {
		return fmt.Errorf("no port")
	}
	lhp := JoinHostPort(LH, portV)
	vncViewerP := strconv.Itoa(portV)
	if vncviewer == "" {
		vncviewer = vncviewerEtc
		if runtime.GOOS == "windows" {
			vncviewer = vncviewerWindows
		}
	}
	if !isHP(lhp) {
		// Если не запущен то запускаем
		vnc := exec.Command(vncviewer, "-listen", vncViewerP)
		err = vnc.Start()
		Println(vnc, err)
		if err != nil {
			return
		}
		time.Sleep(time.Second)
		vnc.Process.Release()
	}
	if !R {
		return
	}
	args.Argument = append(args.Argument, "--vnc", vncViewerP)
	s4 := lhp + ":" + lhp
	Println("-R", s4)
	args.RemoteForward.UnmarshalText([]byte(s4))
	return
}

func shareVNC(ctx context.Context, portV int, u, dj string) {
	d := args.Destination
	l := args.LoginName
	if dj != "" {
		d = dj
		l = u
	}

	vncViewerHP, stop, disconn := showVNC(ctx, portV, dj != "", d, l, Println)
	if stop != nil || (vncViewerHP != "" && disconn != nil) {
		defer func() {
			if stop != nil {
				Println(stop, stop.Run())
			} else if vncViewerHP != "" && disconn != nil {
				Println(disconn, disconn.Run())
			}
		}()
	}
	if vncViewerHP == "" {
		Println(fmt.Errorf("не удалось показать по VNC"))
		return
	}
	Println("To stop VNC - Чтоб остановить VNC нажми <^C>")
	switch runtime.GOOS {
	case "windows", "linux":
		established(ctx, vncViewerHP, true, Println)
	default:
		watchDarwin(ctx, nil, vncViewerHP, Println)
	}
}

// Показывает vnc-клиенту через порт 127.0.0.1:portV или через `dssh -l u -j destination` или `dssh -l u destination` или `dssh destination`
func showVNC(ctx context.Context, portV int, directJump bool, destination, u string, print func(a ...any)) (vncViewerHP string, stop, disconn *exec.Cmd) {
	// -70 -j x
	// -70
	if portV < 0 {
		// Для CGI
		return
	}
	lhp := JoinHostPort(LH, portV)
	if destination != "" {
		if isHP(lhp) {
			print(fmt.Errorf("already used - уже используется %s", lhp))
		} else {
			opts := []string{"-NL" + lhp + ":" + lhp}
			if u != "" {
				opts = append(opts, "-l", u)
			}
			if directJump {
				opts = append(opts, "-j")
			}
			forw := exec.CommandContext(ctx, repo, append(opts, destination)...)
			err := forw.Start()
			print(forw, err)
			if err != nil {
				return
			}
			go func() {
				forw.Wait()
			}()
			time.Sleep(time.Second)
		}
	}
	var start, conn, killall *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		if vncserver == "" {
			vncserver = vncserverWindows
		}
		psCount := psPrint(vncserver, "", 0, PrintNil)
		if psCount < 1 {
			start = exec.Command(vncserver, "-start")
			err := start.Run()
			print(start, err)
			if err != nil {
				return
			}
			stop = exec.Command(vncserver, "-stop")
		}
		conn = exec.CommandContext(ctx, vncserver, "-controlservice", "-connect", lhp)
		disconn = exec.Command(vncserver, "-controlservice", "-disconnectall")
	default:
		if vncserver == "" {
			vncserver = vncserverEtc
		}
		if vncSecurityTypes == "" {
			vncSecurityTypes = vncSecurityTypesEtc
		}
		optSecurityTypes := []string{"-SecurityTypes", vncSecurityTypes}
		display := ":" + strconv.Itoa(portV-PORTV)
		optDisplay := []string{"-display", display}
		start = exec.Command(vncserver, append(optSecurityTypes, display)...)
		err := start.Run()
		print(start, err)
		vncconnect, err := exec.LookPath("vncconnect")
		if err == nil {
			conn = exec.CommandContext(ctx, vncconnect, append(optDisplay, lhp)...)
		} else {
			conn = exec.CommandContext(ctx, "vncconfig", append(optDisplay, "-connect", lhp)...)
			killall = exec.Command("killall", "tigervncconfig")
		}
		disconn = exec.Command(vncserver, "-kill", display)
	}
	err := conn.Start()
	print(conn, err)
	if err != nil {
		return
	}
	go func() {
		conn.Wait()
	}()
	if killall != nil {
		print(killall, killall.Run())
	} else {
		time.Sleep(time.Second)
	}
	vncViewerHP = lhp
	return
}
