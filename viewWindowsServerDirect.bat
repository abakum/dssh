set server=-j direct.accesible.dssh
:set server=-J direct.accesible.sshd -j direct.accesible.dssh
set server=-j 10.161.115.189
set listen=_
set/p p=Run `dssh %listen%` on VNC server. Press Enter

set vncserver=tvnserver
set vncpath=c:\Program Files\TightVNC
set vncviewer=vncviewer.exe
set LH=127.0.0.1
set ssh=dssh

cd /d %~dp0
start %vncviewer% -listen
ping /n 1 %LH%

%ssh% -TR%LH%:5500:%LH%:5500 %server% cd /d %vncpath%^
&sc query %vncserver%^|findstr RUNNING^&^
&(%vncserver% -controlservice -connect %LH%^
&set/p p=Press Enter to disconnect^
&%vncserver% -controlservice -disconnectall^
&exit)^
&%vncserver% -start^
&%vncserver% -controlservice -connect %LH%^
&set/p p=Press Enter to stop^
&%vncserver% -stop

taskkill /F /IM %vncviewer%