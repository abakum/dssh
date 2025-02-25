set host=-j ddns.name
set vncviewer=vncviewer.exe
set LH=127.0.0.1

echo Run `dssh _` or `dssh +` on VNC server
pause

cd /d %~dp0
start %vncviewer% -listen
start dssh _

dssh : dssh -fL%LH%:5500:%LH%:5500 %host%^&cd /d c:\Program Files\TightVNC^&tvnserver -controlservice -connect %LH%^&pause^&tvnserver -controlservice -disconnectall

taskkill /F /IM %vncviewer%
dssh --stop .