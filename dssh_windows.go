//go:build windows
// +build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	su "github.com/nyaosorg/go-windows-su"
	"github.com/xlab/closer"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const win = true

var (
	PuTTY       = `SOFTWARE\SimonTatham\PuTTY`        //root
	Sessions    = filepath.Join(PuTTY, "Sessions")    //dir
	SshHostCAs  = filepath.Join(PuTTY, "SshHostCAs")  //dir
	SshHostKeys = filepath.Join(PuTTY, "SshHostKeys") //file
)

// Конфиг для putty на Windows
func Conf(name, _ string, kv map[string]string) {
	rk, _, err := registry.CreateKey(registry.CURRENT_USER,
		name,
		registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		Println(err)
		return
	}
	defer rk.Close()

	for k, v := range kv {
		if i, err := strconv.Atoi(v); err == nil {
			rk.SetDWordValue(k, uint32(i))
		} else {
			rk.SetStringValue(k, v)
		}
	}
}

func GlobalSshPath() string {
	return filepath.Join(os.Getenv("ProgramData"), SSH)
}

// cmd = exec.Command("cmd", "/c", "start", "/b", bin, opt)
func createNewConsole(cmd *exec.Cmd) {
	const CREATE_NEW_CONSOLE = 0x10
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags:    CREATE_NEW_CONSOLE,
		NoInheritHandles: true,
	}
}

func isWin7() bool {
	maj, min, _ := windows.RtlGetNtVersionNumbers()
	return maj < 6 || (maj == 6 && min <= 1)
}

func ConsoleCP() {
	const CP_UTF8 uint32 = 65001
	var kernel32 = windows.NewLazyDLL("kernel32.dll")

	getConsoleCP := func() uint32 {
		result, _, _ := kernel32.NewProc("GetConsoleCP").Call()
		return uint32(result)
	}

	getConsoleOutputCP := func() uint32 {
		result, _, _ := kernel32.NewProc("GetConsoleOutputCP").Call()
		return uint32(result)
	}

	setConsoleCP := func(cp uint32) {
		kernel32.NewProc("SetConsoleCP").Call(uintptr(cp))
	}

	setConsoleOutputCP := func(cp uint32) {
		kernel32.NewProc("SetConsoleOutputCP").Call(uintptr(cp))
	}

	inCP := getConsoleCP()
	outCP := getConsoleOutputCP()
	setConsoleCP(CP_UTF8)
	setConsoleOutputCP(CP_UTF8)
	closer.Bind(func() { setConsoleCP(inCP) })
	closer.Bind(func() { setConsoleOutputCP(outCP) })
}

func sx(ctx context.Context, u, hp string) {
	x := "sftp"
	if args.Scp {
		x = "scp"
		if args.Sftp {
			// -39
			// -93
			x = "ssh"
		}
	}
	opt := fmt.Sprintf("%s://%s@%s/", x, u, hp)

	err := fmt.Errorf("not found handler - не найден обработчик %q", x)
	if tryWinSCP {
		_, err = su.ShellExecute(su.OPEN, opt, "", "")
		Println("start", opt, err)
		if err == nil {
			return
		}
	}

	bin := ""
	if x == "ssh" && tryPuTTY {
		bin = PUTTY
		opt := []string{}
		if args.LoginName != "" {
			opt = append(opt, "-l", args.LoginName)
		}
		if args.Port > 0 {
			opt = append(opt, "-P", strconv.Itoa(args.Port))
		}
		opt = append(opt, "-load", args.Destination)
		cmd := exec.CommandContext(ctx, bin, opt...)
		cmdStart(cmd)
		return
	}
	// scp
	// sftp
	if x == "scp" {
		Println(err)
		x = "sftp"
	}

	if tryFileZilla {
		bin, err = exec.LookPath(fileZillaBin)
		if err != nil {
			bin = filepath.Join(os.Getenv("ProgramFiles"), "FileZilla FTP Client", fileZillaBin)
			bin, err = exec.LookPath(bin)
		}
		if err == nil {
			ucd := ""
			ucd, err = os.UserConfigDir()
			if err == nil {
				u, err = uhp2u(u, filepath.Join(ucd, fileZillaBin, fileZillaXml))
				if err == nil {
					cmdStart(exec.CommandContext(ctx, bin, "-l", "interactive", fmt.Sprintf("%s://%s@%s/", x, u, hp)))
					return
				}
			}
		}
	}
	if tryOpenSSH {
		bin, err = exec.LookPath(x)
		if err == nil {
			opt := []string{}
			if args.ProxyJump != "" {
				opt = append(opt, "-J", args.ProxyJump)
			}
			for _, v := range args.Option.Marshal() {
				opt = append(opt, "-o", v)
			}

			cmd := exec.CommandContext(ctx, bin, append(opt, args.Destination)...)
			createNewConsole(cmd)
			cmdStart(cmd)
			return
		}
	}
	if tryPuTTY {
		bin, err = exec.LookPath("p" + x)
		if err == nil {
			opt := []string{}
			if args.LoginName != "" {
				opt = append(opt, "-l", args.LoginName)
			}
			if args.Port > 0 {
				opt = append(opt, "-P", strconv.Itoa(args.Port))
			}
			opt = append(opt, "-load", args.Destination)
			cmd := exec.CommandContext(ctx, bin, opt...)
			createNewConsole(cmd)
			cmdStart(cmd)
			return
		}
	}
	Println(err)
}
