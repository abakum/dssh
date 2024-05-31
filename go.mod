module github.com/abakum/dssh

go 1.21.4

replace internal/tool => ./internal/tool

// replace github.com/abakum/winssh => ../winssh

// replace github.com/abakum/go-sshlib => ../go-sshlib

// replace github.com/abakum/putty_hosts => ../putty_hosts

replace github.com/ThalesIgnite/crypto11 v1.2.5 => github.com/blacknon/crypto11 v1.2.6

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/abakum/embed-encrypt v0.0.0-20240419131915-ba2ccee1a359
	github.com/abakum/go-ansiterm v0.0.0-20240209124652-4fc46d492442
	github.com/abakum/go-netstat v0.0.0-20240426061934-05d15dfd4d6c
	github.com/abakum/menu v0.0.0-20240516123901-df323673a8dd
	github.com/abakum/pageant v0.0.0-20240419114114-01633e0d85e4
	github.com/abakum/putty_hosts v0.0.0-20240522125805-7fdec7195277
	github.com/abakum/version v0.1.3-lw
	github.com/abakum/winssh v0.0.0-20240506170933-67061329cb4d
	github.com/alessio/shellescape v1.4.2
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/charmbracelet/bubbles v0.18.0
	github.com/charmbracelet/bubbletea v0.26.2
	github.com/charmbracelet/lipgloss v0.10.0
	github.com/chzyer/readline v1.5.1
	github.com/creack/pty v1.1.21
	github.com/gliderlabs/ssh v0.3.7
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/mattn/go-isatty v0.0.20
	github.com/mattn/go-runewidth v0.0.15
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pquerna/otp v1.4.0
	github.com/skeema/knownhosts v1.2.2
	github.com/stretchr/testify v1.8.4
	github.com/trzsz/go-arg v1.5.3
	github.com/trzsz/iterm2 v0.1.2
	github.com/trzsz/promptui v0.10.7
	github.com/trzsz/ssh_config v1.3.6
	github.com/trzsz/trzsz-go v1.1.8-0.20240303135018-b95b67671472
	github.com/xlab/closer v1.1.0
	golang.org/x/crypto v0.22.0
	golang.org/x/sys v0.20.0
	golang.org/x/term v0.20.0
	internal/tool v0.0.0-00010101000000-000000000000
)

require (
	github.com/UserExistsError/conpty v0.1.2 // indirect
	github.com/abakum/go-console v0.0.0-20240420142043-eda1cdf92473 // indirect
	github.com/akavel/rsrc v0.10.2 // indirect
	github.com/alexflint/go-scalar v1.2.0 // indirect
	github.com/andybrewer/mack v0.0.0-20220307193339-22e922cc18af // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/jsmin v0.0.0-20220218165748-59f39799265f // indirect
	github.com/eiannone/keyboard v0.0.0-20220611211555-0d226195f203 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/iamacarpet/go-winpty v1.0.4 // indirect
	github.com/josephspurrier/goversioninfo v1.4.0 // indirect
	github.com/klauspost/compress v1.17.7 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.15.2 // indirect
	github.com/ncruces/zenity v0.10.12 // indirect
	github.com/pkg/sftp v1.13.6 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/randall77/makefat v0.0.0-20210315173500-7ddd0e42c844 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/image v0.15.0 // indirect
	golang.org/x/net v0.22.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
