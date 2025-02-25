set host=-j ddns.name
set vncviewer=vncviewer.exe
set LH=127.0.0.1

echo Run `dssh` on VNC server
pause

cd /d %~dp0
start %vncviewer% -listen
start dssh _

ping %LH%
start dssh : dssh -NL%LH%:5500:%LH%:5500 %host%

:app
set control=^&tvnserver -controlapp
set start=^&tvnserver -run%control% -connect %LH%
set stop=%control% -shutdown

:service
set control=^&tvnserver -controlservice
set start=%control% -connect %LH%
set stop=%control% -disconnectall

dssh : cd /d c:\Program Files\TightVNC%start%^&pause%stop%

dssh --restart :
taskkill /F /IM %vncviewer%
dssh --stop .