package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
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
	f := string(file)
	for _, set := range fileZilla.Settings.Setting {
		replace := func(f, text string) string {
			if text == "" || set.Text == text {
				return f
			}
			return strings.Replace(f,
				fmt.Sprintf(m, s, set.Name, set.Text, s),
				fmt.Sprintf(m, s, set.Name, text, s), 1)
		}
		switch set.Name {
		case ph:
			f = replace(f, h)
		case pp:
			f = replace(f, p)
		case pt:
			f = replace(f, t)
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
