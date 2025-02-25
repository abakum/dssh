set host=-J nat.alias -j lan.ip.behind.nat

set geometry=-geometry 1366x768
set display=-display :2
set vncviewer=vncviewer.exe
set LH=127.0.0.1

cd /d %~dp0
start %vncviewer% -listen
echo Press any key to stop view

:TightVNC
set connect=vncconnect %display% %LH%

:TigerVNC
set connect=vncconfig %display% -connect %LH%

dssh -R%LH%:5500:%LH%:5500 %host% vncserver %geometry% %display%;%connect%;read -rn1;vncserver -kill %display%

taskkill /F /IM %vncviewer%