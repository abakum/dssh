//go:build !windows
// +build !windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/abakum/winssh"
	"github.com/xlab/closer"
)

const win = false

var (
	PuTTY       = winssh.UserHomeDirs(".putty")
	Sessions    = path.Join(PuTTY, "sessions")
	SshHostCAs  = path.Join(PuTTY, "sshhostcas")
	SshHostKeys = path.Join(PuTTY, "sshhostkeys")
)

func confToMap(name, separator string) (kv map[string]string) {
	kv = make(map[string]string)
	file, err := os.Open(name)
	if err != nil {
		Println(err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()
		if s == "" {
			continue
		}
		ss := strings.Split(s, separator)
		v := ""
		if len(ss) > 1 {
			v = ss[1]
		}
		kv[ss[0]] = v
	}
	return
}

func mapToConf(name, separator string, p map[string]string) (err error) {
	os.MkdirAll(path.Dir(name), 0700)
	f, err := os.Create(name)
	if err != nil {
		return
	}
	defer f.Close()
	defer f.Chmod(FILEMODE)
	for k, v := range p {
		_, err = f.WriteString(k + separator + v + "\n")
		if err != nil {
			return
		}
	}
	return
}

// Конфиг для putty на linux и на MacOS
func Conf(name, separator string, kv map[string]string) {
	p := confToMap(name, separator)
	for k, v := range kv {
		if k == "" {
			continue
		}
		p[k] = v
	}
	mapToConf(name, separator, p)
}

func GlobalSshPath() string {
	return path.Join("/etc", SSH)
}

func createNewConsole(*exec.Cmd) {

}
func isWin7() bool { return false }

func ConsoleCP() {
	setRaw(&once)
}
func sx(ctx context.Context, u, hp string) {
	x := "sftp"
	if args.Scp {
		x = "scp"
	}
	opt := fmt.Sprintf("%s://%s@%s/", x, u, hp)
	bin, err := exec.LookPath("filezilla")
	var cmd *exec.Cmd
	if err == nil && args.Sftp {
		cmd = exec.CommandContext(ctx, bin, "-l", "interactive", opt)
	} else {
		bin = "xdg-open"
		cmd = exec.CommandContext(ctx, bin, opt)
	}
	cmd.Start()
	Println(cmd, err)
	if err == nil {
		closer.Bind(func() { cmd.Process.Release() })
	}
}
