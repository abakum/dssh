package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/xlab/closer"
)

const (
	fileZillaBin = "filezilla"
	fileZillaXml = fileZillaBin + ".xml"
)

// https://tool.hiofd.com/en/xml-to-go/
type FileZilla3 struct {
	XMLName  xml.Name `xml:"FileZilla3"`
	Text     string   `xml:",chardata"`
	Version  string   `xml:"version,attr"`
	Platform string   `xml:"platform,attr"`
	Settings struct {
		Text    string `xml:",chardata"`
		Setting []struct {
			Text string `xml:",chardata"`
			Name string `xml:"name,attr"`
			// Platform  string `xml:"platform,attr"`
			// Sensitive string `xml:"sensitive,attr"`
		} `xml:"Setting"`
		// Tabs struct {
		// 	Text string `xml:",chardata"`
		// 	Tab  struct {
		// 		Text         string `xml:",chardata"`
		// 		Selected     string `xml:"selected,attr"`
		// 		Host         string `xml:"Host"`
		// 		Port         string `xml:"Port"`
		// 		Protocol     string `xml:"Protocol"`
		// 		Type         string `xml:"Type"`
		// 		User         string `xml:"User"`
		// 		Logontype    string `xml:"Logontype"`
		// 		EncodingType string `xml:"EncodingType"`
		// 		BypassProxy  string `xml:"BypassProxy"`
		// 		Name         string `xml:"Name"`
		// 		Site         string `xml:"Site"`
		// 		RemotePath   string `xml:"RemotePath"`
		// 		LocalPath    string `xml:"LocalPath"`
		// 	} `xml:"Tab"`
		// } `xml:"Tabs"`
	} `xml:"Settings"`
}

func replaceHPT(filePath, h, p, t string) (err error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		err = fmt.Errorf("error reading file: %v", err)
		return
	}

	var fileZilla FileZilla3
	err = xml.Unmarshal(file, &fileZilla)
	if err != nil {
		err = fmt.Errorf("error unmarshalling XML: %v", err)
		return
	}
	const (
		ph = "Proxy host"
		pp = "Proxy port"
		pt = "Proxy type"
		s  = "Setting"
		m  = `<%s name="%s">%s</%s>`
	)
	replace := func(f *string, k, o, n string) {
		if n == "" || o == n {
			return
		}
		from := fmt.Sprintf(m, s, k, o, s)
		if o == "" {
			// <Setting name="Proxy host" />
			from = fmt.Sprintf(`<%s name="%s" />`, s, k)
		}
		Println(k, "=", n)
		*f = strings.Replace(*f,
			from,
			fmt.Sprintf(m, s, k, n, s), 1)
	}
	f := string(file)
	for _, proxy := range fileZilla.Settings.Setting {
		switch proxy.Name {
		case ph:
			replace(&f, proxy.Name, proxy.Text, h)
		case pp:
			replace(&f, proxy.Name, proxy.Text, p)
		case pt:
			replace(&f, proxy.Name, proxy.Text, t)
		}
	}

	return WriteFile(filePath, []byte(f), FILEMODE)
}

func x2v(s string) string {
	i := strings.LastIndex(s, "=")
	if i > -1 {
		return s[i+1:]
	}
	return ""
}

func uhp2u(uhp, fz string) (u string, err error) {
	a := strings.Split(uhp, ";")
	u = a[0]
	if fz == "" {
		return
	}
	l := len(a)
	if l > 3 {
		err = replaceHPT(fz, x2v(a[l-2]), x2v(a[l-1]), "2")
	} else {
		err = replaceHPT(fz, "", "", "0")
	}
	return
}

func cmdStart(cmd *exec.Cmd) {
	err := cmd.Start()
	PrintLn(3, cmd, err)
	if err != nil {
		return
	}
	closer.Bind(func() { cmd.Process.Release() })
}
