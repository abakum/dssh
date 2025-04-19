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
	"path/filepath"
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
	bin, err := exec.LookPath(fileZillaBin)
	var cmd *exec.Cmd
	if err == nil && args.Sftp {
		ucd, err := os.UserHomeDir()
		if err != nil {
			return
		}
		fz := filepath.Join(ucd, ".config", fileZillaBin, fileZillaXml)
		uhp := strings.Split(u, ";")
		l := len(uhp)
		if l > 3 {
			err = replaceHPT(fz, x2v(uhp[l-2]), x2v(uhp[l-1]), "2")
		} else {
			err = replaceHPT(fz, "", "", "0")
		}
		if err != nil {
			return
		}
		opt = fmt.Sprintf("%s://%s@%s/", x, uhp[0], hp)
		cmd = exec.CommandContext(ctx, bin, "-l", "interactive", opt)
	} else {
		bin = "xdg-open"
		cmd = exec.CommandContext(ctx, bin, opt)
	}
	cmd.Start()
	Println(cmd, err)
	if err != nil {
		return
	}
	closer.Bind(func() { cmd.Process.Release() })

}
