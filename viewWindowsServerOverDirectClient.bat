set client=-j direct.accesible.dssh
:set client=-J direct.accesible.sshd -j direct.accesible.dssh
set client=-j ssh.cloudns.ch
set server=:
set listen=_
set/p p=Run `dssh` on VNC server. Press Enter

set vncserver=tvnserver
set vncpath=c:\Program Files\TightVNC
set vncviewer=vncviewer.exe
set LH=127.0.0.1

cd /d %~dp0
start %vncviewer% -listen
start dssh %listen%

ping /n 2 %LH%
start dssh %server% dssh -NL%LH%:5500:%LH%:5500 %client%
ping /n 2 %LH%

dssh -T %server% cd /d %vncpath%^
&sc query %vncserver%^|findstr RUNNING^&^
&(%vncserver% -controlservice -connect %LH%^
&set/p p=Press Enter to disconnect^
&%vncserver% -controlservice -disconnectall^
&exit)^
&%vncserver% -start^
&%vncserver% -controlservice -connect %LH%^
&set/p p=Press Enter to stop^
&%vncserver% -stop

dssh --restart %server%
dssh --stop -j %listen%
taskkill /F /IM %vncviewer%