package main

import (
	"fmt"
	"log"
	"path"
	"runtime"
	"strings"

	"github.com/abakum/menu"
	"github.com/xlab/closer"
)

var (
	lef = log.New(Std, menu.BUG, log.Lshortfile)
	le  = log.New(Std, menu.BUG, 0)
	lf  = log.New(Std, menu.GT, log.Lshortfile)
	l   = log.New(Std, menu.GT, 0)
	lt  = log.New(Std, "\t", 0)
)

// Colorable log
func SetColor() {
	bug, _, out := menu.BugGtOut()
	lef.SetOutput(out)
	le.SetOutput(out)
	bug = strings.ReplaceAll(bug, menu.BUG, "<")
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
func srcError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(src(8)+" %w", err)
}

// Вывод Ok если нет ошибки
func PrintOk(s string, err error) (ok bool) {
	ok = err == nil
	if ok {
		l.Println(src(8), s, "ok")
		fmt.Fprint(l.Writer(), "\r")
	} else {
		le.Println(src(8), s, err)
		fmt.Fprint(le.Writer(), "\r")
	}
	return ok
}

// Вывод ошибки если она есть
func Println(v ...any) (ok bool) {
	anys := []any{src(8)}
	ok = true
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
		l.Println(anys...)
		fmt.Fprint(l.Writer(), "\r")
	} else {
		le.Println(anys...)
		fmt.Fprint(le.Writer(), "\r")
	}
	return ok
}

// Вывод ошибки и завершение приложения
func Fatal(err error) {
	if err != nil {
		le.Println(src(8), err)
		fmt.Fprint(le.Writer(), "\r")
		closer.Exit(1)
	}
}

// Вывод ошибки и завершение приложения в случаи выполнения любого условия case
func FatalOr(s string, cases ...bool) {
	for _, c := range cases {
		if c {
			le.Println(src(8), s)
			fmt.Fprint(le.Writer(), "\r")
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
	fmt.Fprint(le.Writer(), "\r")
	closer.Exit(1)
}
