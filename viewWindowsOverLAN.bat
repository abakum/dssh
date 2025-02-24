set host=-j direct.accesible.lan.ip
set vncviewer=vncviewer.exe
set LH=127.0.0.1

cd /d %~dp0
start %vncviewer% -listen

dssh -R%LH%:5500:%LH%:5500 %host% cd /d c:\Program Files\TightVNC^&tvnserver -controlservice -connect %LH%^&pause^&tvnserver -controlservice -disconnectall

taskkill /F /IM %vncviewer%