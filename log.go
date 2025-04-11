package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/abakum/go-ansiterm"
	"github.com/abakum/menu"
	"github.com/xlab/closer"
)

const (
	EL                     = ansiterm.KEY_ESC_CSI + "K"
	REL                    = "\r" + EL
	DECTCEM                = ansiterm.KEY_ESC_CSI + "?25h"
	ANSI_SGR_INVISIBLE     = ansiterm.KEY_ESC_CSI + "8m"
	ANSI_SGR_INVISIBLE_OFF = ansiterm.KEY_ESC_CSI + "28m"
)

var (
	Std = menu.Std
	lef = log.New(Std, "\r"+menu.BUG, log.Lshortfile)
	le  = log.New(Std, "\r"+menu.BUG, 0)
	lf  = log.New(Std, "\r"+menu.GT, log.Lshortfile)
	l   = log.New(Std, "\r"+menu.GT, 0)
	// lt  = log.New(Std, "\t", 0)
)

// Colorable log
func SetColor() {
	bug, _, out := menu.BugGtOut()
	lef.SetOutput(out)
	le.SetOutput(out)
	bug = strings.ReplaceAll(bug, menu.BUG, "<")
	if menu.IsAnsi() {
		bug = REL + bug
		lf.SetPrefix(REL + menu.GT)
		l.SetPrefix(REL + menu.GT)
	} else {
		bug = "\r" + bug
	}
	lef.SetPrefix(bug)
	le.SetPrefix(bug)
}

// Get source of code
func src(depth int) (s string) {
	pc := make([]uintptr, 1)
	n := runtime.Callers(depth-5, pc)
	if n > 0 {
		frame, _ := runtime.CallersFrames(pc).Next()
		s = fmt.Sprintf("%s:%d:", path.Base(frame.File), frame.Line)
	}
	return
}

// Wrap source of code and message to error
func Errorf(format string, args ...any) error {
	return fmt.Errorf(src(8)+" %w", fmt.Errorf(format, args...))
}

// Wrap source of code and error to error
// func srcError(err error) error {
// 	if err == nil {
// 		return nil
// 	}
// 	return fmt.Errorf(src(8)+" %w", err)
// }

// Вывод Ok если нет ошибки
func PrintOk(s string, err error) (ok bool) {
	ok = err == nil
	if ok {
		l.Println(src(8), s, "ok")
		// fmt.Fprint(l.Writer(), "\r")
	} else {
		le.Println(src(8), s, err)
		// fmt.Fprint(le.Writer(), "\r")
	}
	return ok
}

// Вывод ошибки если она есть
func Println_(v ...any) {
	// anys := []any{src(8)}
	anys := []any{}
	ok := true
	for _, a := range v {
		switch t := a.(type) {
		case nil:
			anys = append(anys, "Ф")
		case error:
			anys = append(anys, t)
			ok = false
		case string:
			if t != "" {
				anys = append(anys, t)
			}
		default:
			anys = append(anys, t)
		}
	}
	if ok {
		lf.Output(2, fmt.Sprintln(anys...))
		// l.Println(anys...)
		// fmt.Fprint(l.Writer(), "\r")
	} else {
		lef.Output(2, fmt.Sprintln(anys...))
		// le.Println(anys...)
		// fmt.Fprint(le.Writer(), "\r")
	}
}

func Println(v ...any) {
	PrintLn(3, v...)
}

// Вывод ошибки если она есть
func PrintLn(level int, v ...any) {
	// anys := []any{src(8)}
	anys := []any{}
	ok := true
	for _, a := range v {
		switch t := a.(type) {
		case nil:
			anys = append(anys, "Ф")
		case error:
			anys = append(anys, t)
			ok = false
		case string:
			if t != "" {
				anys = append(anys, t)
			}
		default:
			anys = append(anys, t)
		}
	}
	if ok {
		lf.Output(level, fmt.Sprintln(anys...))
	} else {
		lef.Output(level, fmt.Sprintln(anys...))
	}
}

// Вывод ошибки если она есть
func Print(v ...any) {
	anys := []any{}
	ok := true
	for _, a := range v {
		switch t := a.(type) {
		case nil:
			anys = append(anys, "Ф")
		case error:
			anys = append(anys, t)
			ok = false
		case string:
			if t != "" {
				anys = append(anys, t)
			}
		default:
			anys = append(anys, t)
		}
	}
	if ok {
		lf.Output(2, fmt.Sprint(anys...))
	} else {
		lef.Output(2, fmt.Sprint(anys...))
	}
}

// Вывод ошибки и завершение приложения
func Fatal(err error) {
	if err != nil {
		le.Println(src(8), err)
		// fmt.Fprint(le.Writer(), "\r")
		closer.Exit(1)
	}
}

// Вывод ошибки и завершение приложения в случаи выполнения любого условия case
func FatalOr(s string, cases ...bool) {
	for _, c := range cases {
		if c {
			le.Println(src(8), s)
			// fmt.Fprint(le.Writer(), "\r")
			closer.Exit(1)
			break
		}
	}
}

// Вывод ошибки и завершение приложения в случаи выполнения всех условий case
func FatalAnd(s string, cases ...bool) {
	for _, c := range cases {
		if !c {
			return
		}
	}
	le.Println(src(8), s)
	// fmt.Fprint(le.Writer(), "\r")
	closer.Exit(1)
}

func base() string {
	info, ok := debug.ReadBuildInfo()
	if ok {
		return path.Base(info.Path) //info.Main.Path
	}
	exe, err := os.Executable()
	if err == nil {
		return strings.Split(filepath.Base(exe), ".")[0]
	}
	dir, err := os.Getwd()
	if err == nil {
		return filepath.Base(dir)
	}
	return "main"
}

func build(a ...any) (s string) {
	s = runtime.GOARCH + " " + runtime.GOOS
	if info, ok := debug.ReadBuildInfo(); ok {
		s += " " + info.GoVersion
		s += " " + path.Base(info.Path)
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				s += " " + setting.Value[:7]
			case "vcs.time":
				t, err := time.Parse("2006-01-02T15:04:05Z", setting.Value)
				if err != nil {
					s += " " + setting.Value
				} else {
					s += " " + t.Local().Format("20060102T150405")
				}
			}
		}
	}
	s += " " + strings.TrimSpace(fmt.Sprintln(a...))
	return
}

func revision() (s string) {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				s = setting.Value[:7]
			}
		}
	}
	if s == "" {
		s = base()
	}
	return
}
