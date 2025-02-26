set server=j direct.accesible.lan.ip
set listen=_
set/p p=Run `dssh %listen%` on VNC server. Press Enter

set start=vncserver -SecurityTypes None
set stop=vncserver -kill
set display=-display :2
set vncviewer=vncviewer.exe
set LH=127.0.0.1
set ssh=dssh

cd /d %~dp0
start %vncviewer% -listen
ping /n 1 %LH%

%ssh% -TR%LH%:5500:%LH%:5500 %server% ^
%start% %display%;^
vncconfig %display% -connect %LH%;^
killall tigervncconfig;^
vncconnect %display% %LH%;^
echo Press Enter to kill;^
read -rn1;^
%stop% %display%

taskkill /F /IM %vncviewer%