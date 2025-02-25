set host=-j direct.accesible.lan.ip

set vncviewer=vncviewer.exe
set LH=127.0.0.1

echo Run `dssh _` on VNC server
pause

cd /d %~dp0
start %vncviewer% -listen

:app
set control=^&tvnserver -controlapp
set start=^&tvnserver -run%control% -connect %LH%
set stop=%control% -shutdown

:service
set control=^&tvnserver -controlservice
set start=%control% -connect %LH%
set stop=%control% -disconnectall


dssh -R%LH%:5500:%LH%:5500 %host% cd /d c:\Program Files\TightVNC%start%^&pause%stop%

taskkill /F /IM %vncviewer%