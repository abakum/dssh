/*
MIT License

Copyright (c) 2023-2024 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tssh

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/abakum/pageant"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Агент авторизации
type xAgent struct {
	x             string //  ForwardAgent или IdentityAgent
	extendedAgent agent.ExtendedAgent
	conn          net.Conn
	// ForwardAgent
	client  *ssh.Client
	session *ssh.Session
}

// Создаём канал и посылаем запрос на перенос агента
func (x *xAgent) Forward(addr string) {
	if x.session != nil {
		// ForwardAgent
		if err := agent.ForwardToAgent(x.client, x.extendedAgent); err != nil {
			warning("forward to agent [%s] failed: %v", addr, err)
			return
		}

		if err := agent.RequestAgentForwarding(x.session); err != nil {
			warning("request agent forwarding to [%s] failed: %v", addr, err)
			return
		}
		debug("forward to agent [%s] success", addr)
	}
}

// Закрываем канал только IdentityAgent или all и удаляем агента из списка агентов
func (x *xAgent) Close(addr string, agents xAgents, all bool) {
	if x.session == nil || all {
		// IdentityAgent || all
		debug("connection to the %s [%s] closed", x.x, addr)
		if x.conn != nil {
			x.conn.Close()
		}
		x.extendedAgent = nil
		x.client = nil
		x.session = nil
		delete(agents, addr)
	}
}

// Список агентов авторизации
type xAgents map[string]*xAgent

// Создаём каналы и посылаем запросы на перенос агентов
func (xs xAgents) Forward() {
	for addr, x := range xs {
		x.Forward(addr)
	}
}

// Закрываем каналы только IdentityAgent или all и удаляем агентов из списка агентов
func (xs xAgents) Close(all bool) {
	for addr, x := range xs {
		x.Close(addr, xs, all)
	}
}

// Если список агентов не пуст добавляем закрытие каналов в список onExitFuncs
func (xs xAgents) OnExit() {
	if len(xs) > 0 {
		onExitFuncs.Add(func() {
			xs.Close(true)
		})
	}
}

var (
	agents = make(xAgents)
)

func isResolvedExist(addr string) (string, error) {
	resolved := resolveHomeDir(addr)
	if resolved == "" {
		return "", fmt.Errorf("address is not set")
	}
	if isFileExist(resolved) {
		return resolved, nil
	}
	return "", fmt.Errorf("file [%s] is not exist", resolved)
}

func getIdentityAgentAddr(args *SshArgs, param *sshParam) (string, error) {
	const SOCK = "SSH_AUTH_SOCK"

	if addr := getOptionConfig(args, "IdentityAgent"); addr != "" {
		switch strings.ToLower(addr) {
		case "pageant":
			return pageantAddr()
		case "none", "no":
			return "", fmt.Errorf("none")
		}
		if addr == SOCK {
			addr = "$" + SOCK
		}
		addr = expandEnv(addr)
		expandedAddr, err := expandTokens(addr, args, param, "%CdhijkLlnpru")
		if err != nil {
			return "", fmt.Errorf("expand IdentityAgent [%s] failed: %v", addr, err)
		}
		return isResolvedExist(expandedAddr)
	}
	if addr := os.Getenv(SOCK); addr != "" {
		return isResolvedExist(addr)
	}
	if addr := defaultAgentAddr; addr != "" {
		// For Windows
		addr, err := isResolvedExist(addr)
		if err == nil {
			return addr, err
		}
		// Plan B - pageant
		addr, err = pageantAddr()
		if err == nil {
			return addr, err
		}
	}
	return "", fmt.Errorf("no IdentitydAgent")
}

func pageantAddr() (string, error) {
	_, err := pageant.PageantWindow()
	if err == nil {
		return "pageant", err
	}
	return "", err
}

func getForwardAgentAddr(args *SshArgs, param *sshParam) (string, error) {
	err := fmt.Errorf("no ForwardAgent")
	if args.NoForwardAgent {
		return "", err
	}
	if args.ForwardAgent {
		return getIdentityAgentAddr(args, param)
	}

	if addr := getOptionConfig(args, "ForwardAgent"); addr != "" {
		switch strings.ToLower(addr) {
		case "pageant":
			return pageantAddr()
		case "no":
			return "", err
		case "yes":
			return getIdentityAgentAddr(args, param)
		}
		return isResolvedExist(expandEnv(addr))
	}
	return "", err
}

func getAgentClient(args *SshArgs, param *sshParam, x string) agent.ExtendedAgent {
	var (
		addr string
		err  error
	)
	switch x {
	case "IdentityAgent":
		addr, err = getIdentityAgentAddr(args, param)
	case "ForwardAgent":
		addr, err = getForwardAgentAddr(args, param)
	}
	if err != nil {
		warning("get %s addr failed: %v", x, err)
		return nil
	}
	addr = filepath.Clean(addr)
	ag, ok := agents[addr]
	if ok {
		debug("old %s client [%s] success", x, addr)
		return ag.extendedAgent
	}

	conn, err := dialAgent(addr)
	if err != nil {
		warning("dial %s [%s] failed: %v", x, addr, err)
		return nil
	}

	extendedAgent := agent.NewClient(conn)
	debug("new %s client [%s] success", x, addr)

	agents[addr] = &xAgent{
		x:             x,
		conn:          conn,
		extendedAgent: extendedAgent,
	}

	return extendedAgent
}
