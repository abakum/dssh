set client=-j direct.accesible.wan.ip
set server=:
set listen=_
set/p p=Run `dssh` on VNC server. Press Enter

set start=vncserver -SecurityTypes None
set stop=vncserver -kill
set display=-display :2
set vncviewer=vncviewer.exe
set LH=127.0.0.1

cd /d %~dp0
start %vncviewer% -listen
start dssh %listen%

ping /n 2 %LH%
start dssh %server% dssh -NL%LH%:5500:%LH%:5500 %client%
ping /n 2 %LH%

dssh -TR%LH%:5500:%LH%:5500 %server% ^
%start% %display%;^
vncconfig %display% -connect %LH%;^
killall tigervncconfig;^
vncconnect %display% %LH%;^
echo Press Enter to kill;^
read -rn1;^
%stop% %display%

dssh --restart %server%
dssh --stop -j %listen%
taskkill /F /IM %vncviewer%