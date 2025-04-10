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

// Ожидает подключения  vnc-сервера через порт 127.0.0.1:portV или
//
//	через `dssh -l u -j destination` или
//
// `dssh -l u destination` или
// `dssh destination`.
// -077
func useVNC(portV int, u, dj string) {
	err := startViewer(portV, false)
	if err != nil {
		Println(err)
	}
	if args.Destination == "" {
		// Println(ToExitPress, Enter)
		// os.Stdin.Read([]byte{0})
		holdClose(false)
		return
	}
	lhp := JoinHostPort(LH, portV)
	s4 := lhp + ":" + lhp
	args.NoCommand = args.Command == ""
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
	if args.Command != "" {
		opts = append(opts, args.Command)
		if len(args.Argument) > 0 {
			opts = append(opts, args.Argument...)
		}
	}
	forw := strings.Join(opts, " ")
	Println(forw)
	go holdClose(true)
	// go func() {
	// 	Println(ToExitPress, Enter)
	// 	os.Stdin.Read([]byte{0})
	// 	closer.Close()
	// }()

	Println(forw, tssh.Tssh(&args), "done")

	// forw := exec.CommandContext(ctx, repo, opts...)
	// err := forw.Start()
	// Println(forw, err)
	// if err != nil {
	// 	return
	// }
	// forw.Wait()
}

// Запускает vnc-клиента и если R то перенос для CGI
func startViewer(portV int, R bool) (err error) {
	if portV < 0 {
		return fmt.Errorf("no port")
	}
	lhp := JoinHostPort(LH, portV)
	vncViewerP := strconv.Itoa(portV)
	if vncviewer == "" {
		vncviewer = vncviewerEtc
		if win {
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
		if !isHP(lhp) {
			return fmt.Errorf("not waiting for connection %s не ожидает подключения", vnc)
		}
	}
	if !R {
		return
	}
	args.Argument = append(args.Argument, "--vnc", vncViewerP)
	s4 := lhp + ":" + lhp
	Println(repo, "-R", s4, args.Destination, repo, "--vnc", vncViewerP)
	args.RemoteForward.UnmarshalText([]byte(s4))
	return
}

// Запускает vnc-сервер.
// Завершает работу по отсутствии связи с 127.0.0.1:portV.
// Завершает работу по вводу Enter.
func shareVNC(ctx context.Context, portV int, u, dj string) {
	d := args.Destination
	l := args.LoginName
	if dj != "" {
		d = dj
		l = u
	}

	vncViewerHP, stop, disconn := showVNC(ctx, portV, dj != "", d, l, Println)
	closer.Bind(func() {
		if stop != nil {
			Println(stop, stop.Run())
		} else if vncViewerHP != "" && disconn != nil {
			Println(disconn, disconn.Run())
		}
	})
	if vncViewerHP == "" {
		return
	}
	go holdClose(true)
	// go func() {
	// 	Println(ToExitPress, Enter)
	// 	os.Stdin.Read([]byte{0})
	// 	closer.Close()
	// }()

	switch runtime.GOOS {
	case "windows", "linux":
		established(ctx, vncViewerHP, true, Println)
	default:
		watchDarwin(ctx, nil, vncViewerHP, Println)
	}
}

// Показывает vnc-клиенту через порт 127.0.0.1:portV
// или через `dssh -l u -j destination`
// или `dssh -l u destination`
// или `dssh destination`.
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
			print(fmt.Errorf("already used - %s уже используется", lhp))
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
	if !isHP(lhp) {
		print(fmt.Errorf("not waiting for connection %s не ожидает подключения", lhp))
		return
	}
	var start, conn, killall *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		if vncserver == "" {
			vncserver = vncserverWindows
		}
		psCount := psPrint(vncserver, "", 0, print)
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

// Готовит команду для запуска на стороне sshd.
// Завершает работу по отсутствии связи с 127.0.0.1:portV.
// Завершает работу по вводу Enter.
func sshVNC(ctx context.Context, portV int) {
	args.Argument = []string{}
	lhp := JoinHostPort(LH, portV)
	switch goos(args.Destination) {
	case "windows":
		if vncserver == "" {
			vncserver = vncserverWindows
		}
		vncserver = strings.TrimSuffix(strings.ToLower(vncserver), ".exe")
		args.Command = fmt.Sprintf(
			"where %s&&%s -7%d||("+
				"sc query %s|findstr RUNNING&&("+
				"%s -controlservice -connect %s&set/p p=Press Enter to disconnect&%s -controlservice -disconnectall"+
				")||("+
				"%s -start&%s -controlservice -connect %s&set/p p=Press Enter to stop&%s -stop"+
				"))",
			repo, repo, portV-PORTV,
			vncserver, vncserver, lhp, vncserver,
			vncserver, vncserver, lhp, vncserver)
	default:
		if vncserver == "" {
			vncserver = vncserverEtc
		}
		if vncSecurityTypes == "" {
			vncSecurityTypes = vncSecurityTypesEtc
		}
		display := ":" + strconv.Itoa(portV-PORTV)
		args.Command = fmt.Sprintf(
			"which %s&&%s -7%d||("+
				"%s -SecurityTypes %s %s;"+
				"which vncconnect&&vncconnect -display %s %s||"+
				"which vncconfig&&vncconfig -display %s -connect %s&&killall tigervncconfig;"+
				"echo Press Enter to kill;read -rn1;%s -kill %s"+
				")",
			repo, repo, portV-PORTV,
			vncserver, vncSecurityTypes, display,
			display, lhp,
			display, lhp,
			vncserver, display)
	}
	Println(args.Command)
	time.AfterFunc(time.Second, func() {
		switch runtime.GOOS {
		case "windows", "linux":
			established(ctx, lhp, true, Println)
		default:
			watchDarwin(ctx, nil, lhp, Println)
		}
		closer.Close()
	})
}

func holdClose(close bool) {
	Println(ToExitPress, Enter)
	os.Stdin.Read([]byte{0})
	if close {
		closer.Close()
	}
}
