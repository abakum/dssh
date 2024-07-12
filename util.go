package main

import (
	"net"
	"os"
	"path/filepath"
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

// net.SplitHostPort со значениями по умолчанию
func SplitHostPort(hp, host, port string) (h, p string) {
	hp = strings.ReplaceAll(hp, "*", ALL)
	h, p, err := net.SplitHostPort(hp)
	if err == nil {
		if p == "" {
			p = port
		}
		if h == "" {
			h = host
		}
		return h, p
	}
	// Нет :
	// _, err = strconv.Atoi(hp)
	// if err == nil {
	// 	return host, hp
	// }
	if hp == "" {
		hp = host
	}
	return hp, port
}

func UserHomeDir(s string) string {
	if strings.HasPrefix(s, "~") {
		s = filepath.Join(winssh.UserHomeDirs(), strings.TrimPrefix(s, "~"))
	}
	return s
}
