//go:build windows
// +build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/xlab/closer"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

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
	return filepath.Join(os.Getenv("ProgramData"), "ssh")
}

// cmd = exec.Command("cmd.exe", "/C", fmt.Sprintf(`start %s %s`, bin, opt))
func createNewConsole(cmd *exec.Cmd) {
	if isWin7() {
		// В Win7 проблема запустить консольные программы в отдельном окне
		cmd = exec.Command("cmd.exe", append([]string{"/C", "start"}, cmd.Args...)...)
		return
	}
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
