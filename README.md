# dssh

dssh:=(tssh from trzsz)+(CA key with embed-encrypt)+(sshd from gliderlabs)+(access over NAT using jumphost ssh-j.com)+(ser2net with putty or direct connect to serial console or over browser)

# 1.    Как использовать для доступа к локальной последовательной консоли:
    1.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на первом USB порту со скоростью 9600 запусти `dssh -U9600` или `dssh -U9`. Можно задать любую стартовую скорость на последовательной консоле а потом переключать! На Darwin 12.7.6 тоже работает. Для Linux нужно членство в группе dialout.
    2.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на порту COM3 для Windows со скоростью 9600 запусти `dssh -HCOM3` или `dssh -H3`.
    3.  Вместо PuTTY, plink, microtty, screen для доступа к локальной последовательной консоли на порту /dev/ttyUSB0 со скоростью 115200 запусти `dssh -H/dev/ttyUSB0 -U115200` или `dssh -HttyUSB0 -U0` или или `dssh -H0 -U0`.
    4.  Вместе с PuTTY для доступа к локальной последовательной консоли на первом найденном USB порту со скоростью 19200 - `dssh -uU1` (На Linux и Darwin используется plink если нет plink то microtty. На Windows и Linux если нет plink то используется telnet через RFC2217).
    5.  Вместе с plink для доступа к локальной последовательной консоли на первом найденном USB порту со скоростью 2400 - `dssh -zuU2` (-z Для Windows в том же окне).
    6.  Вместе с telnet для доступа к локальной последовательной консоли на первом найденном USB порту со скоростью 57600 через telnet://127.0.0.1:2322 - `dssh -zZU5 -2 2322` или `dssh -zZU5 -22` (-z Для Windows в том же окне).
    7.  Вместе с telnet для доступа к локальной последовательной консоли на первом найденном USB порту со скоростью 38400 через telnet://127.0.0.1:2322 - `dssh -ZU3 -22` (Для Windows в новом окне).
    8.  В окне веб браузера для доступа к локальной последовательной консоли на первом найденном USB порту со скоростью 9600 через http://127.0.0.1:8088 - `dssh -8 8088` или `dssh -88`.
    9.  Как в 1.8 но через http://0.0.0.0:8080 - `dssh -8 8080 0.0.0.0` или `dssh -80 0.0.0.0` или `dssh -80 *`.
    10.  Как в 1.8 но через http://192.168.0.1:8089 - `dssh -8 8089 192.168.0.1` или `dssh -89 192.168.0.1` или `dssh -89 _` (Где 192.168.0.1 это первый сетевой интерфейс).

# 2.    Как использовать для доступа к удалённой консоли:
    1.  При наличии на хосте Сети запускаем сервер командой `dssh` (Сервер будет ждать на 127.0.0.1:2222).
    2.  При наличии у клиента Сети подключаемся к серверу командой `dssh :` Это сработает и за NAT так как подключение идёт через посредника ssh-j.com.
    3.  При отсутствии на хосте Сети запускаем сервер командами `dssh *` или `dssh _` или `dssh -d host:port` и сообщаем клиенту host:port. (Где * как в 1.9 а _ как 1.10).
    4.  При отсутствии на клиенте Сети подключаемся к серверу `dssh -j host:port`.
    5.  Если клиент находится на хосте (для теста) подключаемся к серверу без посредников комндой  `dssh .` или `dssh -j :` или через посредника командой `dssh :` 
    6.  Так же как в 1.6-1.10 но с параметром -Hcmd (для Windows) или -Hbash (для Linux). Например `dssh -Hcmd -22 :` или `dssh -Hbash -88 :` 
    7.  Так же как в 1.6-1.10 но с параметром :. Например вместе с PuTTY команда `dssh -u :` или вместе c plink команда `dssh -uz :`
    8.  Вместе с ssh в отдельном окне команда `dssh -Z :` или вместе с ssh в том же окне команда `dssh -Zz :`.

# 3.    Как использовать для доступа к удалённой последовательной консоли:
    1.  Как в 2.1-2.6 только добавив параметры -U -H -2 -8 -u -Z -z из раздела 1. Например `dssh -U9 :` или `dssh -H3 :`
    2.  Если хост на Windows и доступ к нему ведётся с параметром -u то для протоколировании действий на сервере открывается окно с PuTTY а если PuTTY не установлен то открывается окно с telnet.
 
# 4.    Как использовать для совместного доступа к последовательной консоли (или консоли с интерпретатором команд) нескольких клиентов:
    1.  Запускаем на удалённом хосте сервер `dssh`.
    2.  Команда `dssh -2 2322 :` или `dssh -22 :` запускает на удалённом хосте RFC2217 TELNET сервер (типа ser2net) с портом 2322. Выбор режима порта (скорость, количество бит,...) теперь возможен только этим клиентом. По умолчанию порт 2322 будет подключен к последовательной консоли на первом USB порту со скоростью 9600. Параметрами -H -U можно указать другой последовательный порт и другую стартовую скорость.
    3.  Присоединяемся к сессии на порту 2322 командой `dssh -22 :` или с вариантами параметров -u, -Z или `dssh -W127.0.0.1:2322 :`. (Таких подключений может быть несколько).
    4.  Если клиенты находятся на хосте то присоединится к сессии можно командой `dssh -22` или `dssh -22 .` или `dssh -W127.0.0.1:2322 .` или `dssh -22 -j :`.
    5.  Другие клиенты в локальной сети хоста могут присоединится к сессии командой `dssh -22 -j host:port` или `telnet host 2322` (Или на Windows `start telnet://host:2322`) где host:port это адрес запущенного сервера dssh
    9.  Если в пунктах 4.2-4.5 заменить -22 на -88 то вместо telnet://host:2322 будет использоваться http://host:8088 то есть будет запущен веб-сервер на порту 8088. Например `dssh -8 8088` или `dssh -88`
    10. Другие клиенты в локальной сети хоста могут присоединится к сессии командой `dssh -88 -j host:port` (Или на Windows `start http://host:8088`) где host:port это адрес запущенного сервера dssh
    11.  Если в пунктах 4.2-4.10 указать -Hcmd (для Windows) или -Hbash (для Linux) то вместо последовательной консоли будет совместно использоваться сессия шела.

# 5.    Как использовать на Windows 7:
    1.  Если есть Cygwin, MSYS2/MINGW, git-bash то как обычно `dssh alias`
    2.  Иначе используем вместе с PuTTY - `dssh -u alias` или `dssh alias`. Чтобы запустить без PuTTY - `dssh -T alias` или `dssh -ND:1080 alias`
    3. Иначе используем вместе с ssh - `dssh -Z alias`.
    4.  Иначе для доступа к локальной последовательной консоли через браузер `dssh -88`
    5.  Иначе для доступа к удалённой последовательной консоли через браузер `dssh -88 :`
    6.  Иначе для теста к локальной консоли через браузер `dssh -Hcmd -88`
    6.  Иначе для доступа к удалённой консоли через браузер `dssh -Hbash -88 :` (для Linux) или `dssh -Hcmd -88 :` (для Windows)

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
    5.  В 4.11 можно вместо шела указывать программу. Например `dssh -Htop :` это почти то же что и `dssh -t : top`. Вот только строка параметра -H не должна заканчиваться на цифру - иначе это будет принято за порт последовательной консоли. Например вместо `dssh -H"ping 8.8.8.8" :` надо `dssh -H"ping 8.8.8.8 "
    6.  Команды с -Hcmd или -Hbash можно использовать для отладки когда на хосте нет последовательно порта.

# 9.    Доступ к последовательной консоли на устройстве под управлением RouterOS с портом USB:
    1.  Подключаем USB2Serial переходник в USB порт устройства под управлением RouterOS.
    2.  Запускаем аналог ser2net на RouterOS командой `/port remote-access add port=usb1 tcp-port=23 protocol=raw` https://help.mikrotik.com/docs/spaces/ROS/pages/8978525/Ports
    3.  Если алиас хоста с запущенными `dssh` и `sshd` LANROS  а у устройства с RouterOS LAN это 192.168.0.1 то подключаемся `dssh -W192.168.0.1:23 :` или `dssh -W192.168.0.1:23 LANROS`. Это похоже на `ssh -W127.0.0.1:23 LANROS` только вместе с переводом терминала в raw режим. Для Windows это то-же что `ssh -L23:127.0.0.1:23 LANROS` а потом `plink -telnet 127.0.0.1`
    4.  Иначе разрешим доступ с WAN на 22 порт tcp`/ip firewall filter add action=accept chain=input dst-port=22 protocol=tcp` для доступа по SSH с WAN.
    5.  Иначе разрешим доступ с lo по tcp `/ip firewall filter add action=accept chain=input in-interface=lo protocol=tcp` для туннеля с WAN на 23 порт. (80 для управления по webfig, 8291 по winbox)  
    6.  Если алиас WANROS это WAN RouterOS то подключаемся `dssh -W127.0.0.1:23 WANROS`
    7.  Останавливаем аналог ser2net на RouterOS командой `/port remote-access remove 0` 
