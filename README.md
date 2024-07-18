# dssh

dssh:=(tssh from trzsz)+(CA key with embed-encrypt)+(sshd from gliderlabs)+(access over NAT using jumphost ssh-j.com)+(ser2net with putty or direct connect to serial console)

# 1.    Как использовать для доступа к локальной последовательной консоли:
    1.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на первом USB порту со скоростью 9600 запусти `dssh -U9600` или `dssh -U9` (Для Маков не пробовал. Для Линуксов нужно членство в группе dialout. Можно задать любую стартовую скорость на порту а потом переключать!)
    2.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на порту COM3 со скоростью 9600 запусти `dssh -HCOM3` (Для Виндовс)
    3.  Вместо PuTTY, plink, microtty, screen для доступа к локальной последовательной консоли на порту /dev/ttyUSB0 со скоростью 115200 запусти `dssh -H/dev/ttyUSB0 -U115200` или `dssh -H/dev/ttyUSB0 -U0`
    4.  Вместе с PuTTY для доступа к локальной последовательной консоли на первом USB порту со скоростью 19200 - `dssh -uU1` (Для Линуксов и Маков используется plink если нет plink то microtty. Для Виндовс и Линуксов если нет plink то используется telnet через RFC2217)
    5.  Вместе с plink для доступа к локальной последовательной консоли на первом USB порту со скоростью 2400 - `dssh -uzU2` (Для Виндовс в том же окне)
    6.  Вместе с telnet для доступа к локальной последовательной консоли на первом USB порту со скоростью 38400 - `dssh -ZU3` (для Виндовс в новом окне)
    7.  Вместе с telnet для доступа к локальной последовательной консоли на первом USB порту со скоростью 57600 - `dssh -ZzU5` (для Виндовс в том же окне)

# 2.    Как использовать для доступа к удалённой последовательной консоли:
    1.  При наличии на хосте Сети запускаем сервер командой `dssh` (Сервер будет ждать на 127.0.0.1:2222)
    2.  При наличии у клиента Сети подключаемся к серверу командой `dssh :` Это сработает и за NAT так как подключение идёт через посредника ssh-j.com
    3.  При отсутствии на хосте Сети запускаем сервер командами `dssh *` или `dssh _` или `dssh -d host:port` и сообщаем клиенту host:port.
    4.  При отсутствии на клиенте Сети подключаемся к серверу `dssh -j host:port`
    5.  Дальше как в разделе 1. (Для Виндос через ssh используется plink или telnet)
    6.  Вместо пунктов 2. и 3. можно использовать `dssh -U9 :` и остальные варианты c параметрами -H, -u, -Z. (Для Виндос PuTTY или telnet открываются в новых окнах)
    7.  Если хост на Виндовс и доступ к нему ведётся с параметром -u то для протокола действий на сервере открывается окно с PuTTY а если PuTTY не установлен то открывается окно с telnet.

# 3.    Как использовать для совместного доступа к последовательной консоли нескольких клиентов:
    1.  Запускаем на удалённом хосте сервер `dssh`
    2.  Запускаем на удалённом хосте RFC2217 сервер (типа ser2net) с портом 22170 `dssh -2 22170` или `dssh -20` Выбор режима порта (скорость, количество бит,...) теперь возможен только с этого хоста. По умолчанию порт 22170 будет подключен к последовательной консоли на первом USB порту со скоростью 9600. Параметрами -H -U можно указать другой последовательный порт и другую стартовую скорость.
    3.  Подключаемся к порту 22170 `dssh -20 :` или с вариантами параметров -u, -Z. (Таких подключений может быть несколько)
    4.  Вместо пункта 2. любой клиент может запустить на хосте RFC2217 сервер с портом 7000 на последовательном порту COM7 на стартовой скорости 115200 командой `dssh -2 7000 -HCOM7 -U0 :` Выбор режима порта теперь возможен только этим клиентом.
    5.  Другие клиенты могут подключится к порту 7000 командой `dssh -2 7000 :` и управлять последовательной консолью на порту COM7 со скоростью 115200.
    6.  Другие клиенты в локальной сети хоста могут подключится к порту 7000 командой `dssh -2 7000 -j host:port`
    7.  Клиент на хосте может подключится к порту 7000 командой `dssh -2 7000 .`
    8.  Можно подключится и к сервису ser2net.

# 4.    Как использовать на Виндовс 7:
    1.  Если нет Cygwin, MSYS2/MINGW, git-bash то используем вместе с PuTTY - `dssh -u alias` иначе запускаем из Cygwin, MSYS2/MINGW, git-bash как обычно `dssh alias`

# 5.    Как устроена авторизация:
    1.  Авторизация основана на вложенном ключе Центра Сертификации `.\internal\ca`. Его можно обновлять запуском `go run cmd/main.go`
    2.  Вложение шифруется ключом `.\key.enc`. Его можно удалить а потом создать новый запустив `go run github.com/abakum/embed-encrypt`
    3.  Ключ расшифровки вложения извлекается не публикуемой функцией Priv из `internal\tool\tool.go`. Пример такой  функции смотри в https://github.com/abakum/eex/blob/main/public/tool/tool.go
    4.  Доступ к экземпляру сервера в пространстве имён посредника ssh-j.com задаётся именем `59d7a68a020c992ca41819553e888fad8f9684c1@ssh-j.com` где 59d7a68a020c992ca41819553e888fad8f9684c1 это хэш комита git смотри `git log -1` или первую строку при запуске `dssh -V` - то есть без дополнительный параметров клиент `dssh :` подключится к серверу `dssh` если они одного комита.
    5.  Для доступа клиента к серверу другого комита нужно указать имя через параметр -l `dssh -l 59d7a68a020c992ca41819553e888fad8f9684c1 :`
    6.  Врочем вместо хэша комита можно использовать что-то попроще - переименовываем `dssh` в `ivanov` и посылаем Иванову. Он запускает сервер `ivanov` а мы подключаемтся как `dssh -l ivanov :`.
    7.  Если Петров умеет запускать программы с параметром то можно и не переименовывать `dssh` в `petrov`. Петров запустит `dssh -l petroff` а мы `dssh -l petroff :`

# 6.    Что было доделанно в tssh:
    1. Вывод кастомных сообщения - DebugF и WarningF из login.go.
    2. Для красоты - type StringSet из login.go, type afterDo []func() для afterLoginFuncs, onExitFuncs, restoreStdFuncs из main.go.
    3. Глобальный конфиг для Windows - initUserConfig из config.go, resolveEtcDir, expandEnv в getHostKeyCallback из login.go, config.go.
    4. Авторизация хостов по сертификатам - caKeysCallback, caKeys в getHostKeyCallback из cert.go.
    5. Авторизация клиентов по сертификатам -  addCertSigner, args.Config.GetAllSigner, args.Config.GetAllCASigner, idKeyAlgorithms в getPublicKeysAuthMethod из login.go.
    6. Чтение HostKeyAlgorithms - setupHostKeyAlgorithmsConfig из login.go, algo.go. Смотри `ssh -Q HostKeyAlgorithms`.
    7. Перенос агента авторизации - getForwardAgentAddr, getAgentClient в sshAgentForward из login.go.
    8. Чтение ExitOnForwardFailure - dynamicForward, localForward, remoteForward, sshForward из forward.go 
    9. Запуск в Windows7 без Cygwin и MSYS2 через `-T` - setupVirtualTerminal, sttyExecutable из term_windows.go.
    10. Чтение IdentitiesOnly в getPublicKeysAuthMethod из login.go.
    11. Уникальный SecretEncodeKey и подсказка `encPassword bar` при указании `-o Password=foo` в getPasswordAuthMethod из login.go.
    12. Возможность прервать dynamicForward, localForward, remoteForward  по Ctr-C используя restoreStdFuncs.Cleanup перед ss.client.Wait в sshStart из main.go.
    13. Возможность прервать сессию по `<Enter><EscapeChar>.` newTildaReader в wrapStdIO из trzsz.go и newServerWriteCloser в sshLogin из login.go.
    14. Для системного прокси windows нужен socks4 поэтому github.com/smeinecke/go-socks5 вместо github.com/armon/go-socks5 в forward.go.
    15. goScanHostKeys ищет все ключи хоста для добавки в known_hosts. Есть мнение, что это не безопасно.
