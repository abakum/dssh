//go:build windows
// +build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

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

func createNewConsole(cmd *exec.Cmd) {
	const CREATE_NEW_CONSOLE = 0x10
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags:    CREATE_NEW_CONSOLE,
		NoInheritHandles: true,
	}
}
