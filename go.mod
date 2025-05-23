module github.com/abakum/dssh

go 1.21

// replace github.com/abakum/go-ser2net => ../go-ser2net
// replace github.com/abakum/go-serial => ../go-serial

// replace github.com/abakum/embed-encrypt => ../embed-encrypt
// replace github.com/skeema/knownhosts => ../knownhosts
replace github.com/abakum/dssh/internal/tool => ./internal/tool

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/PatrickRudolph/telnet v0.0.0-20210301083732-6a03c1f7971f
	github.com/abakum/dssh/internal/tool v0.0.0-00010101000000-000000000000
	github.com/abakum/embed-encrypt v0.0.1
	github.com/abakum/go-ansiterm v0.0.1
	github.com/abakum/go-netstat v0.0.1
	github.com/abakum/go-ser2net v0.0.2-0.20250408133320-cc276657586b
	github.com/abakum/go-serial v1.6.3-0.20250320122135-eefecde49188
	github.com/abakum/go-stun v0.0.0-20250215144216-9aafc02fa8ac
	github.com/abakum/menu v0.0.2-lw
	github.com/abakum/pageant v0.0.1
	github.com/abakum/version v0.1.4-lw
	github.com/abakum/winssh v0.0.1
	github.com/alessio/shellescape v1.4.2
	github.com/charmbracelet/bubbles v0.18.0
	github.com/charmbracelet/bubbletea v0.26.4
	github.com/charmbracelet/lipgloss v0.11.0
	github.com/chzyer/readline v1.5.1
	github.com/containerd/console v1.0.4
	github.com/creack/pty v1.1.21
	github.com/gliderlabs/ssh v0.3.7
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/mattn/go-isatty v0.0.20
	github.com/mattn/go-runewidth v0.0.15
	github.com/mitchellh/go-homedir v1.1.0
	github.com/ncruces/rethinkraw v0.10.7
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c
	github.com/pquerna/otp v1.4.0
	github.com/skeema/knownhosts v1.3.0
	github.com/smeinecke/go-socks5 v0.0.0-20180316091040-4880db608f18
	github.com/stretchr/testify v1.10.0
	github.com/trzsz/go-arg v1.5.3
	github.com/trzsz/iterm2 v0.1.2
	github.com/trzsz/promptui v0.10.7
	github.com/trzsz/ssh_config v1.3.6
	github.com/trzsz/trzsz-go v1.1.7
	github.com/unixist/go-ps v0.0.0-20160415204547-177148200605
	github.com/xlab/closer v1.1.0
	golang.org/x/crypto v0.28.0
	golang.org/x/sys v0.29.0
	golang.org/x/term v0.25.0
)

require (
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/UserExistsError/conpty v0.1.2 // indirect
	github.com/abakum/cancelreader v0.0.0-20241122215017-9e298cf19164 // indirect
	github.com/abakum/go-console v0.0.1 // indirect
	github.com/abakum/go-netroute v0.0.0-20250317083818-2d043769dafc // indirect
	github.com/abakum/go-terminal-size v0.0.0-20241120142632-2e3252fa87fa // indirect
	github.com/abakum/term v0.0.1 // indirect
	github.com/akavel/rsrc v0.10.2 // indirect
	github.com/alexflint/go-scalar v1.2.0 // indirect
	github.com/andybrewer/mack v0.0.0-20220307193339-22e922cc18af // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/charmbracelet/x/ansi v0.1.2 // indirect
	github.com/charmbracelet/x/input v0.1.0 // indirect
	github.com/charmbracelet/x/term v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.1.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/creack/goselect v0.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/jsmin v0.0.0-20220218165748-59f39799265f // indirect
	github.com/eiannone/keyboard v0.0.0-20220611211555-0d226195f203 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/fvbommel/sortorder v1.1.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/iamacarpet/go-winpty v1.0.4 // indirect
	github.com/josephspurrier/goversioninfo v1.4.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.15.2 // indirect
	github.com/ncruces/jason v0.4.0 // indirect
	github.com/ncruces/zenity v0.10.10 // indirect
	github.com/nyaosorg/go-windows-su v0.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/sftp v1.13.6 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/randall77/makefat v0.0.0-20210315173500-7ddd0e42c844 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sorenisanerd/gotty v1.5.1-0.20240325190845-c69d11d17d83 // indirect
	github.com/urfave/cli/v2 v2.24.2 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	github.com/yudai/hcl v0.0.0-20151013225006-5fa2393b3552 // indirect
	golang.org/x/image v0.14.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
