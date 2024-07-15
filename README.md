# dssh

dssh:=(tssh from trzsz)+(CA key with embed-encrypt)+(sshd from gliderlabs)+(access over NAT using jumpphost ssh-j.com)+(ser2net with putty or direct connect to serial console)

Что было доделанно в tssh:

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

# Как использовать для доступа к локальной последовательной консоли
    1.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на первом USB порту со скоростью 9600 - `dssh -U9600` или `dssh -U9` (Для Маков не пробовал. Для Линуксов нужно членство в группе dialout. Можно задать любую стартовую скорость на порту а потом переключить.)
    2.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на порту COM3 со скоростью 9600 - `dssh -HCOM3` (Для Виндовс)
    3.  Вместо PuTTY, plink для доступа к локальной последовательной консоли на порту /dev/ttyUSB0 со скоростью 115200 - `dssh -H/dev/ttyUSB0 -U115200` или `dssh -H/dev/ttyUSB0 -U0`
    4.  Вместе с PuTTY для доступа к локальной последовательной консоли на первом USB порту со скоростью 19200 - `dssh -uU1` (Для Линуксов и Маков используется plink если нет plink то microtty. Для Виндовс и Линуксов если нет plink то используется telnet через RFC2217.)
    5.  Вместе с plink для доступа к локальной последовательной консоли на первом USB порту со скоростью 2400 - `dssh -uzU2` (Для Виндовс в том же окне)
    6.  Вместе с telnet для доступа к локальной последовательной консоли на первом USB порту со скоростью 38400 - `dssh -ZU3` (для Виндовс в новом окне)
    7.  Вместе с telnet для доступа к локальной последовательной консоли на первом USB порту со скоростью 57600 - `dssh -ZzU5` (для Виндовс в том же окне)

# Как использовать для доступа к удалённой последовательной консоли
    1.  Запускаем на удалённом хосте сервер `dssh`
    2.  Подключаемся к нему `dssh :` (При наличии Сети это сработает и за NAT так как подключение идёт через посредника ssh-j.com)
    3.  Дальше как в пункте `Как использовать для доступа к локальной последовательной консоли` (Для Виндос через ssh используется plink или telnet)
    4.  Вместо пунктов 2. и 3. можно использовать `dssh -U9 :` и остальные варианты c параметрами -H, -u, -Z. (Для Виндос PuTTY или telnet открываются в новых окнах)
    5.  Если хост на Виндовс и доступ к нему ведётся с  параметром -u то для протокола открывается окно с PuTTY а если PuTTY не установлен то открывается окно с telnet.

# Как использовать для совместного доступа к последовательной консоли нескольких клиентов
    1.  Запускаем на удалённом хосте сервер `dssh`
    2.  Запускаем на удалённом хосте RFC2217 сервер с портом 22170 `dssh -2 22170 .` или `dssh -20 .` Выбор скорости и порта теперь возможен только с этого хоста.
    3.  Подключаемся к нему `dssh -20 :` или с вариантами параметров -H, -u, -Z. (Таких подключений может быть несколько)
    4.  Вместо пункта 2. можно запустить RFC2217 сервер с портом 7000 от любого клиента `dssh -2 7000 -HCOM7 :` Выбор скорости и порта теперь возможен только этим клиентом.
    5.  Подключаемся к нему `dssh -2 7000 :` или с вариантами параметров -H, -u, -Z. (Таких подключений может быть несколько)

# Как использовать на Виндовс 7
    1.  Если нет Cygwin, MSYS2/MINGW, git-bash то используем вместе с PuTTY - `dssh -u alias` или запускаем из Cygwin, MSYS2/MINGW, git-bash как обычно `dssh alias`
