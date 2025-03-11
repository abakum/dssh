package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/abakum/winssh"
)

// Время модификации
func ModTime(name string) (unix int64) {
	info, err := os.Stat(name)
	if err == nil {
		unix = info.ModTime().Unix()
	}
	return
}

// net.SplitHostPort со значениями по умолчанию host:port.
func SplitHostPort(hp, host string, port int) (h, p string) {
	sp := strconv.Itoa(port)
	h, p, err := net.SplitHostPort(hp)
	if err == nil {
		if p == "" {
			p = sp
		}
		if h == "" {
			h = host
		}
		return h, p
	}
	// Нет :
	_, err = strconv.Atoi(hp)
	if err == nil {
		return host, hp
	}
	if hp == "" {
		hp = host
	}
	return hp, sp
}

func UserHomeDir(s string) string {
	if strings.HasPrefix(s, "~") {
		s = filepath.Join(winssh.UserHomeDirs(), strings.TrimPrefix(s, "~"))
	}
	return s
}
