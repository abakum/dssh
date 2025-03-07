package main

import "os"

const (
	vncserverWindows    = "tvnserver.exe"
	vncserverEtc        = "vncserver"
	vncSecurityTypesEtc = "None"
	vncviewerWindows    = "vncviewer.exe"
	vncviewerEtc        = "vncviewer"
)

var (
	vncserver        = os.Getenv("VNC_SERVER")
	vncSecurityTypes = os.Getenv("VNC_SECURITY_TYPES")
	display          = os.Getenv("DISPLAY")
	vncviewer        = os.Getenv("VNC_VIEWER")
)
