# dssh

dssh:=(tssh from trzsz)+(CA key with embed-encrypt)+(sshd from gliderlabs)+(access over NAT using jumphost ssh-j.com)+(ser2net with putty or direct connect to serial console or over browser)

# 0. Мои благодарности
1.  [Lonny Wong](https://github.com/trzsz/trzsz-ssh).
2.  [Paul Scheduikat](https://github.com/lu4p/embed-encrypt).
3.  [Glider Labs](https://github.com/gliderlabs/ssh).
4.  [ValdikSS](https://bitbucket.org/ValdikSS/dropbear-sshj/src/master).
5.  [9elements](https://github.com/9elements/go-ser2net).
6.  [Patrick Rudolph](https://github.com/PatrickRudolph/telnet).
7.  [Simon Tatham](https://www.chiark.greenend.org.uk/~sgtatham/putty)

# 1. Как использовать для доступа к локальной консоли:<div id=1.1>
1.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на первом USB порту со скоростью 9600 `dssh -U9600` или `dssh -U9` или `dssh -UU` или `dssh -HH` или `dssh -z`. Можно задать любую стартовую скорость на последовательной консоле а потом переключать! На Darwin 12.7.6 тоже работает. Для Linux нужно членство в группе dialout.<div id=1.2>
2.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на порту COM3 для Windows со скоростью 9600 `dssh -HCOM3` или `dssh -H3`.<div id=1.3>
3.  Вместо PuTTY, plink, `busybox microcom` для доступа к локальной последовательной консоли на порту `/dev/ttyUSB0` со скоростью 9600 `dssh -H/dev/ttyUSB0` или `dssh -HttyUSB0` или `dssh -H0`.<div id=1.4>
4.  Вместе с PuTTY для доступа к локальной последовательной консоли на первом найденном USB порту `dssh -u`. На Linux и Darwin используется putty или plink если их нет то `busybox microcom`.<div id=1.5>
5.  Вместе с plink для доступа к локальной последовательной консоли на первом найденном USB порту `dssh -zu`. Ключ `-z` в том же окне.<div id=1.6>
6.  Вместе с telnet для доступа к локальной последовательной консоли на первом найденном USB порту через telnet://127.0.0.1:2320 `dssh -Z`. Для Windows в новом окне. С Сygwin на Windows 7 не работает.<div id=1.7>
7.  Вместе с telnet для доступа к локальной последовательной консоли на первом найденном USB порту через telnet://127.0.0.1:2320 `dssh -zZ`. Ключ `-z` в том же окне.<div id=1.8>
8. В окне веб браузера для доступа к локальной последовательной консоли на первом найденном USB порту через http&#65279;://127.0.0.1:8088 - `dssh -8 8088` или `dssh -88`.<div id=1.9>
9. Как в [1.8](#1.8) но через http&#65279;://192.168.1.1:8080 `dssh -8 8080 0.0.0.0` или `dssh -80 0.0.0.0` или `dssh -80 +`, где 192.168.1.1 это первый сетевой интерфейс.<div id=1.10>
10. Как в [1.9](#1.9) но через http&#65279;://192.168.2.1:8089 `dssh -8 8089 192.168.2.1` или `dssh -89 192.168.2.1` или `dssh -89 _`, где 192.168.2.1 это последний сетевой интерфейс.<div id=1.11>
11. Как в [1.9](#1.9) но через telnet://192.168.1.1:5000 `dssh -25000 0.0.0.0` или `dssh -25000 +`.<div id=1.12>
12. Как в [1.10](#1.10) но через telnet://192.168.2.1:5000 `dssh -25000 192.168.2.1` или `dssh -25000 _`.<div id=1.13>
13. Когда используется `dssh -22 -88` это всё равно, что совместно `dssh -22` и `dssh -H:2322 -88`. Режим посредника.<div id=1.14>
14. Вообще dssh c ключом `-2` работает как RFC2217 телнет-сервер типа ser2net только без команд для модема.<div id=1.15>
15. Вообще dssh с ключом `-H host:port` работает как RFC2217 телнет-клиент и может удалённо менять режимы работы последовательной консоли: baudRate - скорость бит/сек, dataBits - количесто бит в данных, parity - чётность, stopBits - количество стоповых бит. По умолчанию это 9600,8,N,1,N.<div id=1.16>
16. Чтоб поделится локальной последовательной консолью через sshd-сервер `X` `dssh -22 X`. Для подключения к этой консоли `dssh -22 X`  или `dssh -H:2322 X`.<div id=1.17>
17. Чтоб поделится локальной последовательной консолью через dssh-сервер `dssh -s22 :`. Для подключения к этой консоли `dssh -22 :` или `dssh -H:2322 :`.

# 2. Как использовать для доступа к удалённой консоли по ssh:
1.  При наличии на хосте Сети запускаем dssh-сервер `dssh`. Сервер будет ждать на 127.0.0.1:2222.<div id=2.2>
2.  При наличии у клиента Сети подключаемся к dssh-серверу `dssh :` Это сработает и за NAT так как подключение идёт через посредника `ssh-j.com`.<div id=2.3>
3.  При отсутствии на хосте Сети запускаем dssh-сервер `dssh +` или `dssh _` или `dssh -d host:port` и сообщаем клиенту `host:port`, где `+` как в [1.9](#1.9) а `_` как [1.10](#1.10).<div id=2.4>
4.  При отсутствии на клиенте Сети подключаемся к dssh-серверу `dssh -j host:port`.<div id=2.5>
5.  Если клиент находится на хосте, для теста, подключаемся к dssh-серверу без посредников комндой `dssh .` или `dssh -j:` или через посредника `dssh :`.<div id=2.6>
6.  Так же как в [1.4](#1.4) и [1.5](#1.5) но с параметром `:`. Например вместе с PuTTY `dssh -u :` или вместе c plink `dssh -zu :`. Должно выполнятся условие [6.8](#6.8).
7.  Вместе с ssh в отдельном окне `dssh -Z :` похоже на [1.6](#1.6) или вместе с ssh в том же окне `dssh -zZ :` похоже на [1.7](#1.7). Должно выполнятся условие [6.8](#6.8).
8.  Так же как в [1.8](#1.8)-[1.12](#1.12) но с параметром `-Hcmd` для Windows или `-Hbash` для Linux. Например `dssh -Hcmd -22 :` или `dssh -Hbash -88 :`.

# 3. Как использовать для доступа к удалённой консоли:
1.  Как в [2.2](#2.2)-[2.6](#2.6) только добавив ключи `-z` `-U` `-H` `-2` `-8` из раздела [1](#1.1). Например `dssh -z :` или `dssh -H3 :`<div id=3.2>
2.  Если на 192.168.2.1 запущен RFC2217 телнет-сервер c доступом к последовательной консоли через порт 5000 например `dssh -25000 _` как в [1.12](#1.12) или сервис ser2net или RouterOS с портом USB и адаптером USB2serial то с 192.168.2.2 можно подключиться `dssh -W_:5000` в режиме raw без управления режимом последовательной консоли или `dssh -H_:5000` в режиме RFC2217 c управлением режимом последовательной консоли.
3.  Если на 192.168.2.2 запущен `dssh` а на 192.168.2.1 запущен RFC2217 телнет-сервер c доступом к последовательной консоли через порт 5000 как в [3.2](#3.2) то можно подключиться `dssh -W_:5000 :` или `dssh -H_:5000 :`. Как в [3.2](#3.2) только отовсюду.
4.  Если на 192.168.2.2 и 192.168.1.1 запущен sshd-сервер а на 192.168.2.1 запущен RFC2217 телнет-сервер c доступом к последовательной консоли через порт 5000 как в [3.2](#3.2) то присоединится к консоли можно `ssh -W_:5000 192.168.1.1` или `dssh -H_:5000 192.168.1.1`.<div id=3.5>
5.  Если на хосте запущен dssh-сервер и на нём же запущен  RFC2217 телнет-сервер c доступом к последовательной консоли например `dssh -22` то можно подключиться отовсюду `dssh -W127.0.0.1:2322 :` или `dssh -W:2322 :` или `dssh -W2322 :` или `dssh -H127.0.0.1:2322 :` или `dssh -H:2322 :`.
6.  Когда используется `dssh -22 :` или `dssh -88 :` то телнет или веб-сервер запускается на хосте dssh-сервера а порт указанный в `-2` или `-8` форвардится локально. Управление режимом последовательной консоли в этом случае ведётся не по протоколу RFC2217 а по ssh с помощью эскэйп последовательности.
 
# 4. Как использовать для совместного доступа к консоли нескольких клиентов:
1.  Запускаем на удалённом хосте dssh-сервер `dssh`.<div id=4.2>
2.  Команда `dssh -2 2322 :` или `dssh -22 :` запускает на удалённом хосте RFC2217 телнет-сервер (типа ser2net) с портом 2322. По умолчанию порт 2322 будет подключен к последовательной консоли на первом USB порту со скоростью 9600. Ключами `-H` `-U` можно указать другой последовательный порт и другую стартовую скорость.<div id=4.3>
3.  Присоединяемся к консоли на порту 2322 `dssh -22 :` или `dssh -u22 :` или `dssh -Z22 :` или `dssh -W2322 :` или `dssh -H:2322 :`. Таких подключений может быть несколько.<div id=4.4>
4.  Если клиенты находятся на хосте то присоединиться к консоли можно `dssh -22 -j:` или `dssh -22` или `dssh -22 .` или  как в [4.3](#4.3) но без `:` или с параметром `.` вместо `:`.<div id=4.5>
5.  Другие клиенты в локальной сети хоста могут присоединится к консоли `dssh -22 -j host`, где `host` это адрес запущенного dssh-сервера или на Windows `telnet host 2322`.<div id=4.6>
6.  Если в пунктах [4.2](#4.2)-[4.5](#4.5) заменить `-22` на `-88` то вместо telnet://host:2322 будет использоваться http&#65279;://host:8088 то есть будет запущен веб-сервер на порту 8088. Например `dssh -8 8088` или `dssh -88`.<div id=4.7>
7.  Другие клиенты в локальной сети хоста могут присоединится к консоли `dssh -88 -j host`. или на Windows `start http&#65279;://host:8088`, где `host` это адрес запущенного dssh-сервера.
8.  Если в [4.2](#4.2)-[4.7](#4.7) добавить ключ `-Hcmd` для Windows или `-Hbash` для Linux или Cygwin то вместо последовательной консоли будет совместно использоваться интерпретатор команд.

# 5. Как использовать на Windows 7:
1.  Если есть Cygwin, MSYS2/MINGW, git-bash то как обычно `dssh alias`
2.  Иначе вместо `dssh alias` если есть PuTTY будет запущен `dssh -u alias`. Чтобы запустить без PuTTY `dssh -T alias` или `dssh -ND:1080 alias` или `dssh -Z alias` или `dssh -z alias`.
3.  Иначе используем вместе с ssh `dssh -Z alias` или `dssh -z alias`.
4.  Иначе для доступа к локальной консоли через браузер `dssh -88`
5.  Иначе для доступа к удалённой консоли через браузер `dssh -88 :`
6.  Иначе для доступа к удалённой консоли на Linux через браузер `dssh -Hbash -88 :` или для Windows `dssh -Hcmd -88 :`.
7.  Иначе чтоб подключиться к ser2net серверу 192.168.2.1:5000 `dssh -H192.168.2.1:5000 -88`
8.  Иначе как в [1.13](#1.13) `dssh -22 -88`

# 6. Как устроена авторизация:
1.  Авторизация основана на вложенном ключе Центра Сертификации `.\internal\ca`. Его можно обновлять запуском `go run cmd/main.go`.
2.  Вложение шифруется ключом `.\key.enc`. Его можно удалить а потом создать новый запустив `go run github.com/abakum/embed-encrypt`.
3.  Ключ расшифровки вложения извлекается не публикуемой функцией Priv из `internal\tool\tool.go`. Пример такой функции смотри в [eex](https://github.com/abakum/eex/blob/main/public/tool/tool.go).
4.  Доступ к экземпляру сервера в пространстве имён посредника ssh-j.com задаётся именем `59d7a68@ssh-j.com` где 59d7a68 это начало хэша комита git смотри `git log -1` или первую строку при запуске `dssh -V` то есть без дополнительный параметров клиент `dssh :` подключится к dssh-серверу через посредника если они одного комита.
5.  Для доступа клиента к dssh-серверу другого комита нужно указать имя через ключ `-l` `dssh -l 59d7a68 :`.
6.  Врочем вместо начала хэша комита можно использовать что-то попроще например переименовываем файл `dssh` в `ivanov` и посылаем Иванову. Он запускает dssh-сервер `ivanov` а мы подключаемтся как `dssh -l ivanov :`.
7.  Если Петров умеет запускать программы с параметром то можно и не переименовывать `dssh` в `petroff`. Петров запустит `dssh -l petroff` а мы `dssh -l petroff :`.<div id=6.8>
8. Для доступа к dssh-серверу через `putty`, `plink` или `ssh` важно иметь доступ к агенту ключей с хотя бы одним ключём например `id_rsa` и хоть раз запустить `dssh . exit` чтоб записать сертификаты в `~/.ssh/id_rsa-cert.pub` и `~/.ssh/dssh`. 

# 7. Что было доделанно в tssh:
1. Вывод кастомных сообщения - DebugF и WarningF из login.go.
2. Для красоты - type StringSet из login.go, type afterDo []func() для afterLoginFuncs, onExitFuncs, restoreStdFuncs из main.go.
3. Глобальный конфиг для Windows - initUserConfig из config.go, resolveEtcDir, expandEnv в getHostKeyCallback из login.go, config.go.
4. Авторизация хостов по сертификатам - caKeysCallback, caKeys в getHostKeyCallback из cert.go.
5. Авторизация клиентов по сертификатам - addCertSigner, args.Config.GetAllSigner, args.Config.GetAllCASigner, idKeyAlgorithms в getPublicKeysAuthMethod из login.go.
6. Чтение HostKeyAlgorithms - setupHostKeyAlgorithmsConfig из login.go, algo.go. Смотри `ssh -Q HostKeyAlgorithms`.
7. Перенос агента авторизации - getForwardAgentAddr, getAgentClient в sshAgentForward из login.go.
8. Чтение ExitOnForwardFailure - dynamicForward, localForward, remoteForward, sshForward из forward.go .
9. Запуск в Windows7 без Cygwin и MSYS2 через `-T` - setupVirtualTerminal, sttyExecutable из term_windows.go.
10. Чтение IdentitiesOnly в getPublicKeysAuthMethod из login.go.<div id=7.11>
11. Уникальный SecretEncodeKey и подсказка `encPassword bar` при указании `-o Password=foo` в getPasswordAuthMethod из login.go.
12. Возможность прервать dynamicForward, localForward, remoteForward по Ctr-C используя restoreStdFuncs.Cleanup перед ss.client.Wait в sshStart из main.go.
13. Возможность прервать сессию по `<Enter><EscapeChar>.` newTildaReader в wrapStdIO из trzsz.go и newServerWriteCloser в sshLogin из login.go.<div id=7.14>
14. Для системного прокси Windows нужен socks4 поэтому github.com/smeinecke/go-socks5 вместо github.com/armon/go-socks5 в forward.go.
15. goScanHostKeys ищет все ключи хоста для добавки в known_hosts. Есть мнение, что это не безопасно.
16. Чтение KexAlgorithms - setupKexAlgorithmsConfig из login.go, kex.go. Смотри `ssh -Q KexAlgorithms`.
17. Исправлена опечатка в keepAlive
18. makeStdinRaw для stdioForward в sshStart.

# 8. Как ещё можно использовать dssh:
1.  Если запустить на хосте `dssh` и проверив доступ `dssh :` потом к хосту можно подключится для удалённой разработки через `Remote - SSH extension` выбрав алиас `ssh-j` в `Connect to Host`.
2.  Благодаря tssh можно прописать в алиасе `proxy` encPassword и D`ynamicForward 127.0.0.1:1080` чтоб не вводить пароль при запуске `dssh -5 proxy` для использования Socks5 прокси [7.11](#7.11). Чтоб ssh не ругался на неизвестный параметр encPassword в начале `~/.ssh/config` вставьте `IgnoreUnknown *`
3.  Для системного прокси на Windows нужен Socks4 прокси поэтому `dssh proxy` [7.14](#7.14).
4.  В [4.11](#4.11) можно вместо интерпретатора команд указывать команду. Например `dssh -Htop :` это почти то же что и `dssh -t : top`. Вот только значение ключа `-H` не должно заканчиваться на цифру - иначе это будет принято за порт последовательной консоли. Например вместо `dssh -Htest2 :` надо `dssh -H"test2 ". Если в команде есть пробелы то пробел в конец можно не добавлять. Например `dssh -H"ping 8.8.8.8"`
5.  Команды с `-Hcmd` или `-Hbash` можно использовать для отладки когда на хосте нет последовательно порта.
6.  Можно использовать `dssh` как посредника: Если у клиента `AX` есть RFC2217 доступ к консоли по адресу host:port и доступ к sshd-серверу `X` то отдаём эту консоль  через `X` `dssh -Hhost:port -22 X` если у клиента `BXBY` есть доступ к sshd-серверам `X` и `Y` то используем её `dssh -22 X` или передаём её `dssh -H:2322 -22 Y` если у клиента `СY` есть доступ к sshd-серверу `Y` то используем её `dssh -22 Y`. Все команды управления режимом последовательной консоли передаются по цепочке посредников. Вместо последовательной консоли может быть консоль интерпретатора команд. Вместо sshd-серверов могут быть dssh-сервера для них добавляем параметр `-s` если отдаём локальную консоль.
7.  Можно использовать `dssh` в качестве посредника в `~/.ssh/config` `ProxyCommand dssh -W %h:%p :`
8.  Если для `Host overSocks5` указать `ProxyCommand plink -load %n -raw %h -P %p` и `ProxyPutty socks5://127.0.0.1:1080` то в `PuTTY\Sessions\overSocks5` будет записано, `ProxyMethod=2` `ProxyHost=127.0.0.1` `ProxyPort=1080` и `plink` сделает то же что и `ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p` или `ProxyCommand connect -S 127.0.0.1:1080 %h %p` [ssh-connect](https://github.com/gotoh/ssh-connect). Можно задать и `ProxyPutty socks4://host[:port]` как `ProxyCommand nc -X 4 -x host[:port] %h %p` и `ProxyPutty socks4a://host[:port]` как `ProxyCommand nc -X 4a -x host[:port] %h %p` и `ProxyPutty http://host[:port]` как `ProxyCommand nc -X connect -x host[:port] %h %p` и `ProxyPutty ${http_proxy}`. Если в `Host overSocks5` указан `ProxyPutty` то PuTTY не будет использовать `ProxyCommand` а ssh будет.
Можно отдельно указать для `Host D1080` `ProxyPutty socks5://127.0.0.1:1080` а для `Host overSocks5` `ProxyCommand plink -load D1080 -raw %h -P %p`.

# 9. Удалённый доступ к последовательной консоли на устройстве под управлением RouterOS с портом USB:
1.  Подключаем USB2serial переходник в USB порт устройства под управлением RouterOS.
2.  Запускаем удалённый доступ к последовательной консоли RouterOS `/port remote-access add port=usb1 tcp-port=5000 protocol=raw` [Ports](https://help.mikrotik.com/docs/spaces/ROS/pages/8978525/Ports). Для смены режима на консоле `/port set 0 flow-control=none stop-bits=1 parity=none baud-rate=9600` `/port set 0 baud-rate=auto`
3.  Если LAN хоста с запущенными `dssh` это 192.168.0.1 а у устройства с RouterOS LAN это 192.168.0.2 то подключаемся `dssh -W192.168.0.2:5000 :`. Это похоже на `ssh -W192.168.0.2:5000 admin@192.168.0.1` только ssh не переводит терминал в raw режим а dssh переводит.
4.  Иначе разрешим доступ с WAN на 22 порт tcp`/ip firewall filter add action=accept chain=input dst-port=22 protocol=tcp` для доступа по SSH с WAN.
    И разрешим доступ с lo по tcp `/ip firewall filter add action=accept chain=input in-interface=lo protocol=tcp` для туннеля с WAN на 5000 порт. (80 для управления по webfig, 8291 по winbox)  
5.  Если WAN устройства с RouterOS это 192.168.1.2 то подключаемся `dssh -W5000 admin@192.168.1.2`.
6.  Останавливаем удалённый доступ к последовательной консоли RouterOS `/port remote-access remove 0` 
7.  Для возможности смены клиентом режима удалённой последовательной консоли через протокол RFC2217 запускаем аналог ser2net на RouterOS `/port remote-access add port=usb1 tcp-port=5000`
8.  Если LAN хоста с запущенными `dssh` это 192.168.0.1 а у устройства с RouterOS LAN это 192.168.0.2 то подключаемся `dssh -H192.168.0.2:5000 :`.<div id=9.9>
9.  Если WAN RouterOS это 192.168.1.2 то подключаемся `dssh -H:5000 admin@192.168.1.2` это то же что и `dssh -NL127.0.0.1:5000:127.0.0.1:5000 admin@192.168.1.2` а потом `dssh -H:5000`.
10. Если запустить `ssh -NL127.0.0.1:5000:127.0.0.1:5000 admin@192.168.1.2` то `dssh -H:5000` сработает только однажды потому, что после закрытия `dssh -H:5000` статус `/port remote-access` останется подключенным. Это особенность ssh.

# 10. Параметры для локального доступа:
- x.    отсутствует или локальный IP или локальный алиас: `_` или `+`.
- Y.    локальная последовательная консоль на первом свободном порту USB.
- host. любой IP или адрес хоста или x.
- port. TCP порт.<div id=10.1>
1.  `-z` то же что и `-U 9600` как в [1.1](#1.1).<div id=10.2>
2.  `-22 x` то же что `-U 9600` + стартует RFC2217 телнет-сервер на `x:2322` как в [1.11](#1.11) + стартует RFC2217 телнет клиент в том же окне.<div id=10.3>
3.  `-ZH host:port` то же что и `telnet -e^Q host port` для Windows в новом окне как в [1.6](#1.6). Для Cygwin на Windows7 или Linux в том же окне.<div id=10.4>
4.  `-Z22 x` то же что и `-22 x` + `telnet -e^Q x 2322` для Windows в новом окне. Для Cygwin на Windows7 или Linux в том же окне.<div id=10.5>
5.  `-Z x` для Linux то же что и `busybox microcom -s 9600 Y`. Для Windows как в [10.4](#10.4).<div id=10.6>
6.  `-zZ x` то же что и `-20 x` + `telnet -e^Q x 2320` том же окне и без управлением режимом консоли.<div id=10.7>
7.  `-u22 x` то же что и `-22 x` + `putty -telnet x -P 2322` как в [1.4](#1.4).<div id=10.8>
8.  `-u` то же что и `putty -serial Y -sercfg 9600,8,1,N,N` и без управлением режимом консоли.<div id=10.9>
9.  `-zu` то же что и `plink -serial Y -sercfg 9600,8,1,N,N` и без управлением режимом консоли. Для Cygwin на Windows7 `putty -serial Y -sercfg 9600,8,1,N,N`.<div id=10.10>
10.  `-uH host:port` то же что и `putty -telnet host -P port` как в [1.4](#1.4).<div id=10.11>
11.  `-88 x` то же что `-U 9600` + стартует веб-сервер на `x:8088` + `chrome http&#65279;:\\x:8088`.<div id=10.12>
12.  `-22 -88 x` то же что `-U 9600` + стартует RFC2217 телнет-сервер на `x:2322` + стартует веб-сервер на `x:8088` + `chrome http&#65279;:\\x:8088`

# 11. Параметры для удалённого доступа:
- X.  внешний IP или адрес или ssh алиас.
- Y.  удалённая последовательная консоль на первом свободном порту USB.
- host.   любой IP или адрес хоста или x.
- port.   TCP порт.<div id=11.1>
1.  `-z :` как в [10.1](#10.1) только на хосте с `dssh`.<div id=11.2>
2.  `-22 :` как в [10.2](#10.2) только на хосте с `dssh` + 127.0.0.1:2322 форвардится на 127.0.0.1:2322 сервера.<div id=11.3>
3.  `-H host:port :` то же что и `dssh -W host:port :` только с управлением по RFC2217 или RFC1073 как в [3.5](#3.5).<div id=11.4>
4.  `-Z22 :` то же что и `-22 :` как в [11.2](#11.2) + `telnet -e^Q 127.0.0.1 2322` учитывая форвардинг портов управление будет консолью на хосте сервера.<div id=11.5>
5.  `-Z X` то же что и `ssh X` для Windows новом окне.<div id=11.6>
6.  `-zZ X` то же что и `ssh X` для Windows в том же окне.<div id=11.7>
7.  `-u22 :` то же что и `-22 :` + `putty -telnet 127.0.0.1 -P 2322` учитывая форвардинг портов управление будет консолью на хосте сервера.<div id=11.8>
8.  `-u X` то же что и `putty @X` для Windows новом окне как в [1.4](#1.4). Для Linux то же что и `plink -load X`. Перед стартом putty алиас X создаётся из ssh алиаса X.<div id=11.9>
9.  `-zu X` то же что и `plink -load X` как в [11.8](#11.8).<div id=11.10>
10. `-22 .` как в [11.2](#11.2) только для теста на локальном хосте с `dssh` + стартует RFC2217 телнет-сервер на 127.0.0.1:2332 + 127.0.0.1:2322 форвардится на 127.0.0.1:2332 как в [2.5](#2.5).<div id=11.11>
11. `-88 :` то же что `-U 9600` + стартует веб-сервер на хосте dssh-сервера `127.0.0.1:8088` + локальный порт 127.0.0.1:8088 форвардится на порт 127.0.0.1:8088 сервера + `chrome http&#65279;:\127.0.0.1:8088` учитывая форвардинг портов управление будет консолью на хосте сервера.<div id=11.12>
12. `-22 -88 :` то же что `-U 9600` + 127.0.0.1:2322 и 127.0.0.1:8088 форвардятся на 127.0.0.1:2322 и 127.0.0.1:8088 сервера + стартует RFC2217 телнет-сервер на `127.0.0.1:2322` + стартует веб-сервер на `127.0.0.1:8088` + `chrome http&#65279;:\127.0.0.1:8088` учитывая форвардинг портов управление будет консолью на хосте сервера.<div id=11.13>
13.  `-22 X` как в [10.2](#10.2) + 127.0.0.1:2322 sshd-сервера X форвардится на 127.0.0.1:2322 локального телнет-сервера с RFC2217. Это работает не только c dssh-сервером.<div id=11.14>
14. `-H host:port X` 127.0.0.1:port форвардится sshd-сервером X на host:port + локальный телнет клиент по RFC2217 управляет через sshd-сервер X телнет-сервером с RFC2217 на host:port как в [9.9](#9.9). Это работает не только c dssh-сервером. Отданная как в [11.3](#11.3) через sshd-сервер X консоль может использоваться как в [11.4](#11.4) так и [11.2](#11.2).<div id=11.15>
15.  `-s22 :` как в [10.2](#10.2) + 127.0.0.1:2322 sshd-сервера X форвардится на 127.0.0.1:2322 локального телнет-сервера с RFC2217. Это работает не только c dssh-сервером.

# 12. Что делать если запутались в параметрах.
1.  Читать исходники. Иногда исходники и коментарии понятней руководств.

# 13. Что делать если запутались в исходниках.
1.  Писать свою программу тщательно комментировать её и писать руководства. \8^)
