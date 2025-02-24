set host=-J nat.alias -j lan.ip.behind.nat
set geometry=-geometry 1366x768
set display=:2
set vncviewer=vncviewer.exe
set LH=127.0.0.1

cd /d %~dp0
start %vncviewer% -listen
echo Press any key to stop view

:TightVNC
:dssh -R%LH%:5500:%LH%:5500 %host% vncserver %geometry% %display%;vncconnect -display %display% %LH%;read -rn1;vncserver -kill %display%

:TigerVNC
dssh -R%LH%:5500:%LH%:5500 %host% vncserver %geometry% %display%;vncconfig -nowin -display %display% -connect %LH%;read -rn1;vncconfig -nowin -display %display% -disconnect;vncserver -kill %display%

taskkill /F /IM %vncviewer%