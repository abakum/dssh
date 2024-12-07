# dssh

dssh:=(tssh from trzsz)+(CA key with embed-encrypt)+(sshd from gliderlabs)+(access over NAT using jumphost ssh-j.com)+(ser2net with putty or direct connect to serial console or over browser)

# 0.    Мои благодарности
    1.  Lonny Wong https://github.com/trzsz/trzsz-ssh
    2.  Paul Scheduikat https://github.com/lu4p/embed-encrypt
    3.  Glider Labs https://github.com/gliderlabs/ssh
    4.  ValdikSS https://bitbucket.org/ValdikSS/dropbear-sshj/src/master/
    5.  9elements https://github.com/9elements/go-ser2net
    6.  Patrick Rudolph https://github.com/PatrickRudolph/telnet


# 1.    Как использовать для доступа к локальной последовательной консоли:
    1.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на первом USB порту со скоростью 9600 запусти `dssh -U9600` или `dssh -U9` или `dssh -UU` или `dssh -HH` или `dssh -z`. Можно задать любую стартовую скорость на последовательной консоле а потом переключать! На Darwin 12.7.6 тоже работает. Для Linux нужно членство в группе dialout. 
    2.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на порту COM3 для Windows со скоростью 9600 `dssh -HCOM3` или `dssh -H3`. 
    3.  Вместо PuTTY, plink, microcom, screen для доступа к локальной последовательной консоли на порту /dev/ttyUSB0 со скоростью 9600 `dssh -H/dev/ttyUSB0` или `dssh -HttyUSB0` или `dssh -H0`.
    4.  Вместе с PuTTY для доступа к локальной последовательной консоли на первом найденном USB порту `dssh -u`. На Linux и Darwin используется plink если нет plink то `busybox microcom`.
    5.  Вместе с plink для доступа к локальной последовательной консоли на первом найденном USB порту `dssh -zu` (-z Для Windows в том же окне).
    6.  Вместе с telnet для доступа к локальной последовательной консоли на первом найденном USB порту через telnet://127.0.0.1:2322 `dssh -Z` (Для Windows в новом окне).
    7.  Вместе с telnet для доступа к локальной последовательной консоли на первом найденном USB порту через telnet://127.0.0.1:2322 `dssh -zZ` (-z Для Windows в том же окне). 
    8.  В окне веб браузера для доступа к локальной последовательной консоли на первом найденном USB порту через http://127.0.0.1:8088 - `dssh -8 8088` или `dssh -88`.
    9.  Как в 1.8 но через http:// 192.168.1.1:8080 `dssh -8 8080 0.0.0.0` или `dssh -80 0.0.0.0` или для Windows `dssh -80 *` или для Linux, Cygwin `dssh -80 '*'`(Где 192.168.1.1 это первый сетевой интерфейс).
    10. Как в 1.8 но через http://192.168.2.1:8089  `dssh -8 8089 192.168.2.1` или `dssh -89 192.168.2.1` или `dssh -89 _` (Где 192.168.2.1 это последний сетевой интерфейс).
    11. Как в 1.9 но через telnet://192.168.1.1:5000  `dssh -25000 0.0.0.0` или `dssh -25000 *` или `dssh -25000 '*'`.
    12. Как в 1.10 но через telnet://192.168.2.1:5000 - `dssh -25000 192.168.2.1` или  `dssh -25000 _`.
    13. Когда используется `dssh -22 -88` это всё равно, что совместно `dssh -22` и `dssh -H:2322 -88`. Режим посредника.
    14. Вообще dssh c ключом -2 работает как RFC2217 telnet сервер типа ser2net только без команд для модема.
    15. А dssh с ключом -H host:port работает как RFC2217 telnet клиент и может удалённо менять режимы работы последовательной консоли: baudRate - скорость бит/сек, dataBits - количесто бит в данных, parity - чётность, stopBits - количество стоповых бит. По умолчанию это 9600,8,N,1,N.

# 2.    Как использовать для доступа к удалённой консоли по ssh:
    1.  При наличии на хосте Сети запускаем сервер командой `dssh` (Сервер будет ждать на 127.0.0.1:2222).
    2.  При наличии у клиента Сети подключаемся к серверу командой `dssh :` Это сработает и за NAT так как подключение идёт через посредника ssh-j.com.
    3.  При отсутствии на хосте Сети запускаем сервер командами `dssh *` или `dssh _` или `dssh -d host:port` и сообщаем клиенту host:port. (Где * как в 1.9 а _ как 1.10).
    4.  При отсутствии на клиенте Сети подключаемся к серверу `dssh -j host:port`.
    5.  Если клиент находится на хосте (для теста) подключаемся к серверу без посредников комндой  `dssh .` или `dssh -j:` или через посредника командой `dssh :` 
    6.  Так же как в 1.6-1.13 но с параметром -Hcmd для Windows или -Hbash для Linux. Например `dssh -Hcmd -22 :` или `dssh -Hbash -88 :` 
    7.  Так же как в 1.6-1.13 но с параметром `:`. Например вместе с PuTTY команда `dssh -u :` или вместе c plink команда `dssh -zu :`
    8.  Вместе с ssh в отдельном окне команда `dssh -Z :` или вместе с ssh в том же окне команда `dssh -zZ :`.

# 3.    Как использовать для доступа к удалённой последовательной консоли:
    1.  Как в 2.2-2.6 только добавив параметры -z -U -H -2 -8 из раздела 1. Например `dssh -z :` или `dssh -H3 :`
    2.  Если на 192.168.0.2 запущен сервер RFC2217 telnet c доступом к последовательной консоли через порт 5000 например `dssh -25000 _` как в 1.12 или сервис ser2net или RouterOS с портом USB и адаптером USB2serial то с 192.168.0.3 можно подключиться командой `dssh -W192.168.0.2:5000` в режиме raw без управления режимом последовательной консоли или `dssh -H192.168.0.2:5000` в режиме RFC2217 c управлением режимом последовательной консоли.
    3.  Если на 192.168.0.1 запущен `dssh` и на 192.168.0.2 запущен сервер RFC2217 telnet c доступом к последовательной консоли через порт 5000 как в 3.2 то можно подключиться командами `dssh -W192.168.0.2:5000 :` или `dssh -H192.168.0.2:5000 :`. Как на 3.2 только отовсюду.
    4.  Если на 192.168.0.1 и 192.168.1.1 запущен `sshd` и на 192.168.0.2 запущен сервер RFC2217 telnet c доступом к последовательной консоли через порт 5000 как в 3.2 то присоединится к сессии можно командами `ssh -W192.168.0.2:5000 192.168.1.1` или `dssh -W192.168.0.2:5000 192.168.1.1` 
    5.  Если на хосте запущен `dssh` и на нём же запущен сервер RFC2217 telnet c доступом к последовательной консоли например `dssh -22` то можно подключиться отовсюду командами `dssh -W127.0.0.1:2322 :` или `dssh -W:2322 :` или `dssh -W2322 :` или `dssh -H127.0.0.1:2322 :` или `dssh -H:2322 :`.
    6. Когда используется `dssh -22 :` или `dssh -88 :` то telnet или web сервер запускается на стороне ssh сервера а порт указанный в -2 или -8 форвардится локально. Управление режимом последовательной консоли в этом случае ведётся не по протоколу RFC2217 а по ssh.


 
# 4.    Как использовать для совместного доступа к последовательной консоли (или консоли с интерпретатором команд) нескольких клиентов:
    1.  Запускаем на удалённом хосте сервер `dssh`.
    2.  Команда `dssh -2 2322 :` или `dssh -22 :` запускает на удалённом хосте RFC2217 telnet сервер (типа ser2net) с портом 2322. По умолчанию порт 2322 будет подключен к последовательной консоли на первом USB порту со скоростью 9600. Параметрами -H -U можно указать другой последовательный порт и другую стартовую скорость.
    3.  Присоединяемся к сессии на порту 2322 командой `dssh -22 :` (присоединиться к сессии можно и `dssh -W2322 :` и `dssh -H:2322 :`) или с вариантами параметров -u, -Z. Таких подключений может быть несколько.
    4.  Если клиенты находятся на хосте то присоединиться к сессии можно командой `dssh -22` или `dssh -22 .` (или как в 4.3 `dssh -W2322 .` или `dssh -H:2322 .` или `dssh -W2322` или `dssh -H:2322`) или `dssh -22 -j :`.
    5.  Другие клиенты в локальной сети хоста могут присоединится к сессии командой `dssh -22 -j host:port` или `dssh -Whost:2322` или `dssh -Hhost:2322` что тоже что `telnet host 2322` (Или на Windows `start telnet://host:2322`) где host:port это адрес запущенного сервера dssh
    9.  Если в пунктах 4.2-4.5 заменить -22 на -88 то вместо telnet://host:2322 будет использоваться http://host:8088 то есть будет запущен веб-сервер на порту 8088. Например `dssh -8 8088` или `dssh -88`
    10. Другие клиенты в локальной сети хоста могут присоединится к сессии командой `dssh -88 -j host:port` (Или на Windows `start http://host:8088`) где host:port это адрес запущенного сервера dssh
    11.  Если в пунктах 4.2-4.10 указать -Hcmd (для Windows) или -Hbash (для Linux) то вместо последовательной консоли будет совместно использоваться сессия интерпретатора команд.

# 5.    Как использовать на Windows 7:
    1.  Если есть Cygwin, MSYS2/MINGW, git-bash то как обычно `dssh alias`
    2.  Иначе используем вместе с PuTTY - `dssh -u alias` или `dssh alias`. Чтобы запустить без PuTTY - `dssh -T alias` или `dssh -ND:1080 alias`
    3. Иначе используем вместе с ssh - `dssh -Z alias`.
    4.  Иначе для доступа к локальной последовательной консоли через браузер `dssh -88`
    5.  Иначе для доступа к удалённой последовательной консоли через браузер `dssh -88 :`
    6.  Иначе для доступа к удалённой консоли на Linus через браузер `dssh -Hbash -88 :` или для Windows `dssh -Hcmd -88 :`.
    7.  Иначе чтоб подключиться к ser2net серверу 192.168.0.1:5000 `dssh -H192.168.0.1:5000 -88`
    8.  Иначе как в 1.13 `dssh -22 -88`

# 6.    Как устроена авторизация:
    1.  Авторизация основана на вложенном ключе Центра Сертификации `.\internal\ca`. Его можно обновлять запуском `go run cmd/main.go`.
    2.  Вложение шифруется ключом `.\key.enc`. Его можно удалить а потом создать новый запустив `go run github.com/abakum/embed-encrypt`.
    3.  Ключ расшифровки вложения извлекается не публикуемой функцией Priv из `internal\tool\tool.go`. Пример такой  функции смотри в https://github.com/abakum/eex/blob/main/public/tool/tool.go.
    4.  Доступ к экземпляру сервера в пространстве имён посредника ssh-j.com задаётся именем `59d7a68@ssh-j.com` где 59d7a68 это начало хэша комита git смотри `git log -1` или первую строку при запуске `dssh -V` - то есть без дополнительный параметров клиент `dssh :` подключится к серверу `dssh` если они одного комита.
    5.  Для доступа клиента к серверу другого комита нужно указать имя через параметр -l `dssh -l 59d7a68 :`.
    6.  Врочем вместо начала хэша комита можно использовать что-то попроще - переименовываем `dssh` в `ivanov` и посылаем Иванову. Он запускает сервер `ivanov` а мы подключаемтся как `dssh -l ivanov :`.
    7.  Если Петров умеет запускать программы с параметром то можно и не переименовывать `dssh` в `petroff`. Петров запустит `dssh -l petroff` а мы `dssh -l petroff :`.

# 7.    Что было доделанно в tssh:
    1. Вывод кастомных сообщения - DebugF и WarningF из login.go.
    2. Для красоты - type StringSet из login.go, type afterDo []func() для afterLoginFuncs, onExitFuncs, restoreStdFuncs из main.go.
    3. Глобальный конфиг для Windows - initUserConfig из config.go, resolveEtcDir, expandEnv в getHostKeyCallback из login.go, config.go.
    4. Авторизация хостов по сертификатам - caKeysCallback, caKeys в getHostKeyCallback из cert.go.
    5. Авторизация клиентов по сертификатам -  addCertSigner, args.Config.GetAllSigner, args.Config.GetAllCASigner, idKeyAlgorithms в getPublicKeysAuthMethod из login.go.
    6. Чтение HostKeyAlgorithms - setupHostKeyAlgorithmsConfig из login.go, algo.go. Смотри `ssh -Q HostKeyAlgorithms`.
    7. Перенос агента авторизации - getForwardAgentAddr, getAgentClient в sshAgentForward из login.go.
    8. Чтение ExitOnForwardFailure - dynamicForward, localForward, remoteForward, sshForward из forward.go .
    9. Запуск в Windows7 без Cygwin и MSYS2 через `-T` - setupVirtualTerminal, sttyExecutable из term_windows.go.
    10. Чтение IdentitiesOnly в getPublicKeysAuthMethod из login.go.
    11. Уникальный SecretEncodeKey и подсказка `encPassword bar` при указании `-o Password=foo` в getPasswordAuthMethod из login.go.
    12. Возможность прервать dynamicForward, localForward, remoteForward  по Ctr-C используя restoreStdFuncs.Cleanup перед ss.client.Wait в sshStart из main.go.
    13. Возможность прервать сессию по `<Enter><EscapeChar>.` newTildaReader в wrapStdIO из trzsz.go и newServerWriteCloser в sshLogin из login.go.
    14. Для системного прокси Windows нужен socks4 поэтому github.com/smeinecke/go-socks5 вместо github.com/armon/go-socks5 в forward.go.
    15. goScanHostKeys ищет все ключи хоста для добавки в known_hosts. Есть мнение, что это не безопасно.
    16. Чтение KexAlgorithms - setupKexAlgorithmsConfig из login.go, kex.go. Смотри `ssh -Q KexAlgorithms`.
    17. Исправлена опечатка в keepAlive
    18. makeStdinRaw для stdioForward в sshStart.

# 8.    Как ещё можно использовать dssh:
    1.  Если запустить на хосте `dssh` то к хосту можно подключится для удалённой разработки через `Remote - SSH extension` выбрав алиас `ssh-j` в `Connect to Host`.
    2.  Благодаря tssh можно прописать в алиасе `proxy` encPassword и DynamicForward 127.0.0.1:1080 чтоб не вводить пароль при запуске `dssh -5 proxy` для использования Socks5 прокси. (смотри 7.11)
    3.  Для системного прокси на Windows нужен Socks4 прокси поэтому команда будет`dssh proxy` (смотри 7.14).
    5.  В 4.11 можно вместо интерпретатора команд указывать команду. Например `dssh -Htop :` это почти то же что и `dssh -t : top`. Вот только строка параметра -H не должна заканчиваться на цифру - иначе это будет принято за порт последовательной консоли. Например вместо `dssh -Htest2 :` надо `dssh -H"test2 ". Если в команде есть пробелы то пробел в конец можно не добавлять. Например `dssh -H"ping 8.8.8.8"`
    6.  Команды с -Hcmd или -Hbash можно использовать для отладки когда на хосте нет последовательно порта.

# 9.    Удалённый доступ к последовательной консоли на устройстве под управлением RouterOS с портом USB:
    1.  Подключаем USB2serial переходник в USB порт устройства под управлением RouterOS.
    2.  Запускаем удалённый доступ к последовательной консоли RouterOS командой `/port remote-access add port=usb1 tcp-port=5000 protocol=raw` https://help.mikrotik.com/docs/spaces/ROS/pages/8978525/Ports. Для смены режима на консоле `/port set 0 flow-control=none stop-bits=1 parity=none baud-rate=9600` `/port set 0 baud-rate=auto`
    3.  Если LAN хоста с запущенными `dssh` это 192.168.0.1 а у устройства с RouterOS LAN это 192.168.0.2 то подключаемся `dssh -W192.168.0.2:5000 :`. Это похоже на `ssh -W192.168.0.2:5000 admin@192.168.0.1` только ssh не переводит терминал в raw режим а dssh переводит.
    4.  Иначе разрешим доступ с WAN на 22 порт tcp`/ip firewall filter add action=accept chain=input dst-port=22 protocol=tcp` для доступа по SSH с WAN.
    И разрешим доступ с lo по tcp `/ip firewall filter add action=accept chain=input in-interface=lo protocol=tcp` для туннеля с WAN на 5000 порт. (80 для управления по webfig, 8291 по winbox)  
    5.  Если WAN устройства с RouterOS это 192.168.1.2 то подключаемся `dssh -W5000 admin@192.168.1.2`.
    6.  Останавливаем удалённый доступ к последовательной консоли RouterOS командой `/port remote-access remove 0` 
    7.  Для возможности смены клиентом режима удалённой последовательной консоли через протокол RFC2217 запускаем аналог ser2net на RouterOS командой `/port remote-access add port=usb1 tcp-port=5000`
    8.  Если LAN хоста с запущенными `dssh` это 192.168.0.1 а у устройства с RouterOS LAN это 192.168.0.2 то подключаемся `dssh -H192.168.0.2:5000 :`.
    9.  Если WAN RouterOS это 192.168.1.2 то подключаемся `dssh -NL127.0.0.1:5000:127.0.0.1:5000 admin@192.168.1.2` а потом `dssh -H:5000`. Если вместо `dssh -NL...` использовать `ssh -NL...` то `dssh -H:5000` сработает только однажды потому, что после закрытия `dssh -H:5000` статус `/port remote-access` останется подключенным. Это особенность ssh.

#10.    Параметры: (где x отсутствует или локальный IP или локальный алиас типа: _ или * а X это внешний IP или алиас или . или :)
    1.  `-z`  то же что и `-U 9600` см. 1.1
    2.  `-22 x` то же что `-U 9600` плюс запуск RFC2217 telnet сервера на `x:2322` см. 1.11 
    3.  `-Z x`  то же что и `-20 x` а потом `telnet x 2320` для Windows старше 7 в новом окне см. 1.6
    4.  `-zZ x`  то же что и `-20 x` а потом `telnet x 2320` в том же окне.
        