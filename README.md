# Copilot's review
**Purpose of the Repository**

The `dssh` repository aims to combine various functionalities and tools to create a robust SSH-based system for accessing remote and local consoles. It incorporates features from multiple sources such as `tssh`, `embed-encrypt`, `sshd from gliderlabs`, and others to provide secure and versatile access over NAT using jump hosts, and offers support for serial console connections via tools like `ser2net` and `putty`. The README provides detailed instructions on how to access local and remote consoles using different configurations and tools, along with acknowledgments to contributors and projects that inspired or contributed to `dssh`.

**Features and Technologies Used**

The `dssh` repository is implemented primarily in Go, with a small portion in Batchfile. It integrates various technologies and tools to enhance SSH and serial console access functionalities, including:
- **tssh from trzsz**: Provides foundational SSH functionalities.
- **embed-encrypt**: Adds certificate authority key management with embedded encryption.
- **gliderlabs/ssh**: Supplies the SSH server capabilities.
- **ser2net**: Facilitates serial to network connections, allowing access to serial consoles over the network.
- **ssh-j.com**: Enables access over NAT using a jump host.
- **Putty and telnet**: For direct or browser-based connections to serial consoles.
- **RouterOS and hub4com**: Support for integrating with various hardware and network configurations.

Overall, `dssh` is a comprehensive tool designed for secure and flexible access to consoles, combining multiple open-source projects and technologies to offer a wide range of connectivity options.

# dssh

dssh:=(tssh from trzsz)+(CA key with embed-encrypt)+(sshd from gliderlabs)+(access over NAT using jumphost ssh-j.com)+(ser2net with putty or direct connect to serial console or over browser)

# 0. Мои благодарности<div id=0.1>
1. [Lonny Wong](https://github.com/trzsz/trzsz-ssh).<div id=0.2>
2. [Paul Scheduikat](https://github.com/lu4p/embed-encrypt).<div id=0.3>
3. [Glider Labs](https://github.com/gliderlabs/ssh).<div id=0.4>
4. [ValdikSS](https://bitbucket.org/ValdikSS/dropbear-sshj/src/master).<div id=0.5>
5. [9elements](https://github.com/9elements/go-ser2net).<div id=0.6>
6. [Patrick Rudolph](https://github.com/PatrickRudolph/telnet).<div id=0.7>
7. [Simon Tatham](https://www.chiark.greenend.org.uk/~sgtatham/putty).<div id=0.8>
8. [Corey Minyard](https://github.com/cminyard/ser2net).<div id=0.9>
9. [Vyacheslav Frolov](https://sourceforge.net/projects/com0com/files/hub4com/2.1.0.0/).<div id=0.10>
10. [MikroTik](https://help.mikrotik.com/docs/).
11. [Cristian Maglie](https://github.com/bugst/go-serial)

# 1. Как использовать для доступа к локальной консоли:<div id=y>
- [y](#y). отсутствует зачит локальная последовательная консоль на первом свободном порту USB. Или путь к последовательному порту на Linux как /dev/ttyUSB0. Или последовательный порт на Windows как COM1. Или суффикс порта от 0 до 9.<div id=X>
- [X](#X). IP или FQDN или ssh-алиас или dssh-алиас `.` как сокращение алиаса `dssh` или dssh-алиас `:` как сокращение алиаса `ssh-j`. Вместо алиаса `:` можно использовать алиас `.` в этом случае если на хосте dssh-клиента не запущен dssh-сервер то будет использован алиас `:` для доступа к dssh-серверу через посредника ssh-j.com.<div id=x>
- [x](#x). отсутствует зачит 0.0.0.0 или локальный IP или локальный алиас: `+` как `127.0.0.1` или `_` как локальный IP 192.168.1.2 к роутеру 192.168.1.1.<div id=host>
- [host](#host). [X](#X) или [x](#x).<div id=port>
- [port](#port). TCP порт.<div id=port5000>
- [port5000](#port5000). суффикс порта 5000 от 0 до 9 значит порт от 5000 до 5009 или [port](#port).<div id=noWin7withoutCygwin>
- [noWin7withoutCygwin](#noWin7withoutCygwin). кроме Windows 7 без Cygwin.<div id=Win7withoutCygwin>
- [Win7withoutCygwin](#Win7withoutCygwin). для Windows 7 без Cygwin.<div id=Win7withCygwin>
- [Win7withCygwin](#Win7withCygwin). для Windows 7 с Cygwin.<div id=1.1>
1. Вместо PuTTY, plink [0.7](#0.7) для доступа к локальной последовательной консоли на первом USB порту [y](#y) со стартовым режимом 9600,8,N,1,N `dssh -U9600` или короче с префиксом скорости `dssh -U9` или без указания режима тогда берётся последний режим на порту `dssh -UU` или короче `dssh -z`. Можно задать любой стартовый режим на [y](#y) а потом переключать! На MacOS 12.7.6 тоже работает. Для Linux нужно членство в группе dialout.<div id=1.2>
2. Вместо PuTTY, plink для доступа к локальной последовательной консоли на порту `COM1` для Windows `dssh -HCOM1` или короче с суффиксом порта `dssh -H1`. Если символ отмены в параметре `-e` задан как `none` то для завершения ввода используется `^Z` иначе `^D`. Если параметр `-e` не задан то для завершения ввода можно использовать `^Z` или `<Enter>~.` но лучше использовать `^D`.<div id=1.3>
3. Вместо PuTTY, plink, `busybox microcom` для доступа к локальной последовательной консоли на порту `/dev/ttyUSB0` не для Windows `dssh -H/dev/ttyUSB0` или `dssh -HttyUSB0` или короче `dssh -H0`. Если символ отмены в параметре `-e` задан как `none` то для завершения ввода используется `^D`. Если параметр `-e` не задан то для завершения ввода можно использовать `<Enter>~.` но лучше использовать `^D`.<div id=1.4>
4. Вместе с PuTTY для доступа к [y](#y) `dssh -u` как в [1.1](#1.1) берётся последний режим на порту. На Linux и Darwin используется putty или plink если их нет то `busybox microcom`.<div id=1.5>
5. Вместе с plink для доступа к [y](#y) `dssh -zu` [или короче](#Win7withoutCygwin) `dssh -u`. Ключ `-z` вместе с ключами `-u` или `-Z` значит в том же окне.<div id=1.6>
6. Вместе с telnet для доступа к [y](#y) через telnet://0.0.0.0:5000 `dssh -Z`. Для Windows в новом окне.<div id=1.7>
7. Вместе с telnet для доступа к [y](#y) через telnet://0.0.0.0:5000 `dssh -zZ`.<div id=1.8>
8. В окне веб браузера для доступа к [y](#y) через http&#65279;://0.0.0.0:8000 `dssh -8 8000` или `dssh -80` [или короче](#Win7withoutCygwin) `dssh -s`. Иногда порты на 127.0.0.1 блокируется политикой безопасности. Тогда вместо `dssh -80` или `dssh -s` используем `dssh -80 _` или `dssh -s _`.<div id=1.9>
9. Как в [1.8](#1.8) но через http&#65279;://192.168.1.2:8000 `dssh -80 192.168.1.2` или если у роутера 192.168.1.1 то `dssh -80 _` [x](#x).<div id=1.10>
10. Как в [1.9](#1.9) но через http&#65279;://127.0.0.1:8009 `dssh -8 8009 127.0.0.1` или короче `dssh -89 +`. Иногда порты на 127.0.0.1 блокируется политикой безопасности. Тогда вместо (1.10)[#1.10] можно использовать (1.9)[#1.9].<div id=1.11>
11. Как в [1.9](#1.9) но через telnet://192.168.1.2:5000 `dssh -25000 192.168.1.2` или `dssh -20 192.168.1.2` [или короче](#noWin7withoutCygwin) `dssh -s _`.<div id=1.12>
12. Как в [1.10](#1.10) но через telnet://127.0.0.1:5000 `dssh -25000 127.0.0.1` [или короче](#noWin7withoutCygwin) `dssh -s +`.<div id=1.13>
13. Когда используется `dssh -20 -88` это всё равно, что совместно `dssh -20` и `dssh -H: -88`. Режим посредника.<div id=1.14>
14. Команда `dssh -2 port5000 x` работает и как RFC2217 телнет-клиент [1.15](#1.15) и как RFC2217 телнет-сервер типа [ser2net](#0.8) только без команд для модема.<div id=1.15>
15. Команда `dssh -H host:[port5000]` работает как RFC2217 телнет-клиент и может удалённо менять режимы работы последовательной консоли: baudRate - скорость в бодах, dataBits - количесто бит в символе, parity - чётность, stopBits - количество стоповых бит. Если `dssh -HH` то пробуем доступ через LAN `dssh -H 127.0.0.1:5000` или короче `dssh -H:` иначе через локальный dssh-сервер `dssh -H: .` иначе через dssh-сервер `dssh -H: :`<div id=1.16>
16. Чтоб поделиться локальной последовательной консолью через sshd-сервер [X](#X) `dssh -s20 X` [или короче](#noWin7withoutCygwin) `dssh -s X`. Для подключения к этой консоли `dssh -H127.0.0.1:5000 X` или `dssh -H5000 X` или `dssh -H: X` или короче `dssh -HH X` или без управления `dssh -W5000 X` или без управления и без перевода консоли в сырой (raw) режим `ssh -W127.0.0.1:5000 X`.<div id=1.17>
17. Чтоб поделиться локальной последовательной консолью через dssh-сервер `dssh -s20 .` [или короче](#noWin7withoutCygwin) `dssh -s .` . Для подключения к этой консоли `dssh -HH` или без управления `dssh -W5000 .` или без управления и без перевода консоли в сырой режим `ssh -W127.0.0.1:5000 :`. 
18. Чтоб поделиться через LAN локальной последовательной консолью без dssh-сервера и без sshd-сервера `dssh -20` [или короче](#noWin7withoutCygwin) `dssh -s`. Для подключения к этой консоли `dssh -H host[:port5000]` или без управления `dssh -W host[:port5000]` или `telnet host 5000`. 
19. Если sshd-сервер и dssh-сервер на одном хосте то можно поделиться локальной последовательной консолью через sshd-сервер [X](#X) `dssh -s X` а подключится через dssh-сервер `dssh -HH` и наоборот - поделиться локальной последовательной консолью через dssh-сервер `dssh -s .` а подключится через sshd-сервер [X](#X) `dssh -HH X`.
20. Команда `dssh -s host` [это то же что и](#Win7withoutCygwin) `dssh -80 host`. Чтоб управляющие последовательности ANSI обрабатывать в веб-браузере.

# 2. Как использовать для доступа к удалённой консоли интерпретатора команд по ssh:<div id=port2200>
- port2200. суффикс порта 2200 от 0 до 9 значит порт от 2200 до 2209 или [port](#port).<div id=2.1>
1. При наличии на хосте Сети запускаем dssh-сервер `dssh` или `dssh +`. Сервер будет ждать на 0.0.0.0:2200 или соответствено на 127.0.0.1:2200.<div id=2.2>
2. При наличии у клиента Сети подключаемся к dssh-серверу `dssh .` Это сработает и за NAT так как подключение к [dssh-серверу](#2.1) идёт через посредника `ssh-j.com` [0.4](#0.4). Если `dssh` на direct.accesible.dssh то можно подключится к нему `dssh -j`. Для чего через посредника узнаём direct.accesible.dssh через CGI `dssh -T : dssh --eips` а потом напрямую `dssh -j direct.accesible.dssh`. Это сработает и через LAN.<div id=2.3>
3. При отсутствии на хосте Сети запускаем dssh-сервер `dssh _` или `dssh -d x[:port2200]` и сообщаем клиенту x[:port2200].<div id=2.4>
4. При отсутствии на клиенте Сети но при наличии локальной сети к `x` подключаемся к dssh-серверу `dssh -j x[:port2200]`.<div id=2.5>
5. Если клиент находится на хосте с dssh-сервером, подключаемся к нему без посредников `dssh .` или `dssh -j :` или `dssh -j x[:port2200]` или через посредника `dssh :` .<div id=2.6>
6. Так же как в [1.4](#1.4) и [1.5](#1.5) но с параметром `.`. Например вместе с PuTTY `dssh -u .` или вместе c plink `dssh -zu .`. Должно выполняться условие [6.8](#6.8).
7. Вместе с ssh в отдельном окне `dssh -Z .` похоже на [1.6](#1.6) или вместе с ssh в том же окне `dssh -zZ .` похоже на [1.7](#1.7). Должно выполняться условие [6.8](#6.8). C Cygwin на Windows 7 `dssh -Z .` значит `dssh -zZ .`
8. Так же как в [1.8](#1.8)-[1.12](#1.12) но с параметром `-Hcmd` для Windows или `-Hbash` для Linux. Например `dssh -Hcmd -20 .` [или короче](#noWin7withoutCygwin) `dssh -0Hcmd` или через браузер и Linux `dssh -0Hbash -88`. Если через LAN то соответственно `dssh -0Hcmd -j x[:port2200]` или `dssh -0Hbash -88 -j x[:port2200]`.
9. Вместо `ssh X` как `dssh X` и наоборот вместо `dssh :` `dssh -Z :` как `ssh :`.

# 3. Как использовать для доступа к удалённой консоли:<div id=3.1>
1. Как в [2.2](#2.2)-[2.6](#2.6) только добавив ключи `-z` `-U` `-H` `-2` `-8` из раздела [1](#1.1). Например `dssh -z .` зто похоже на `dssh . dssh -z` или `ssh . dssh -z` но лучше `dssh -0` чтоб отдать и использовать удалённую консоль dssh-сервера или `dssh -0 X` чтоб отдать и использовать удалённую консоль sshd-сервера [X](#X).<div id=3.2>
2. Если на 192.168.1.2 запущен RFC2217 телнет-сервер c доступом к последовательной консоли через порт 5000 например `dssh -25000 _` [или короче](#noWin7withoutCygwin) `dssh -s _` как в [1.12](#1.12) или сервис [ser2net](#0.8) или RouterOS с портом USB и адаптером USB2serial то с 192.168.1.3 можно подключиться `dssh -W192.168.1.2:5000` в сыром режиме без управления режимом последовательной консоли или `dssh -H192.168.1.2:` в режиме RFC2217 c управлением режимом последовательной консоли.
3. Если на 192.168.1.1 запущен dssh-сервер а на 192.168.1.2 запущен RFC2217 телнет-сервер c доступом к последовательной консоли через порт 5000 как в [3.2](#3.2) то можно подключиться без управления режимом консоли `dssh -W192.168.1.2:5000 .` или с управлением`dssh -H192.168.1.2: .`. Как в [3.2](#3.2) только отовсюду.
4. Если на 192.168.1.1 запущен sshd-сервер [X](#X) а на 192.168.1.2 запущен RFC2217 телнет-сервер c доступом к последовательной консоли через порт 5000 как в [3.2](#3.2) то присоединиться к консоли можно `ssh -W192.168.1.2:5000 X` или `dssh -H192.168.1.2: X`.<div id=3.5>
5. Если на хосте запущен dssh-сервер и на нём же запущен RFC2217 телнет-сервер c доступом к последовательной консоли например `dssh -20` [или короче](#noWin7withoutCygwin) `dssh -s` то можно подключиться отовсюду `dssh -W127.0.0.1:5000 .` или `dssh -W:5000 .` или `dssh -W5000 .` или `dssh -H127.0.0.1:5000 .` или `dssh -H5000 .` или `dssh -H: .` или короче `dssh -HH`.
6. Когда используется `dssh -20 .` или `dssh -80 .` или короче `dssh -0` то телнет или веб-сервер запускается на хосте dssh-сервера а порт указанный в `-2` или `-8` переносится локально как `-L`. Управление режимом последовательной консоли по ключу `-8` ведётся не по протоколу RFC2217 а по ssh. Похоже на `dssh . dssh -20` или `dssh . dssh -80`. Можно и так `dssh -HH .` что выглядит похожим на `dssh -HH X` но при этом `dssh -HH .` запускает на dssh-сервере RFC2217 телнет клиента как `dssh -20 .` а `dssh -HH X` не запускает его там а просто использует если он запущен.
7. Когда используется `dssh -0 X` это аналог `dssh X dssh -20` [или короче](#noWin7withoutCygwin) `dssh X dssh -80`. Это работает если на [X](#X) есть `dssh`
8. Режим посредника на dssh-сервере с direct.accesible.dssh `dssh`. Приятно, что посредник ssh-j.com используется только при подключении. После подключения трафик через него не идёт. 
8.1 Отдадим локальную последовательную консоль `dssh -js`.
8.2 Используем отданную последовательную консоль `dssh -jHH` или через веб (например в Windows 7) `dssh -jHH -88`.
8.3 Отдадим локальный интерпретатора команд bash `dssh -jsHbash`.
8.4 Используем отданный интерпретатора команд `dssh -jHH` или через веб (например в Windows 7) `dssh -jHH -88`.
 

# 4. Как использовать для совместного доступа к консоли нескольких клиентов:
1. Запускаем на удалённом хосте dssh-сервер `dssh`.<div id=4.2>
2. Команда `dssh -2 5000 .` или `dssh -20 .` [или короче](#noWin7withoutCygwin) `dssh -0` запускает на хосте с dssh-сервером RFC2217 телнет-сервер с портом 5000 и локальный телнет-клиент. По умолчанию порт 5000 будет подключен к последовательной консоли на первом USB порту. Ключами `-H` `-U` можно указать другой последовательный порт и другую стартовую скорость. Если порт 5000 на хосте с dssh-сервером занят то `dssh -20 .` [или короче](#noWin7withoutCygwin) `dssh -0` запустит только локальный телнет-клиент.<div id=4.3>
3. Присоединяемся к консоли на порту 5000 `dssh -H5000 .` или короче `dssh -HH` или с PuTTY `dssh -uHH` или c telnet `dssh -ZHH`. Эти команды запускают локальный телнет-клиент. Таких подключений может быть несколько.<div id=4.4>
4. Если клиенты находятся на хосте то присоединиться к консоли можно `dssh -20 -j :` или `dssh -20` или как в [4.3](#4.3).<div id=4.5>
5. Другие клиенты в локальной сети хоста могут присоединиться к консоли `dssh -20 -j host[:port2200]`.<div id=4.6>
6. Если в пунктах [4.2](#4.2)-[4.5](#4.5) заменить `-20` на `-80` то вместо telnet://host:5000 будет использоваться http&#65279;://host:8000 то есть будет запущен веб-сервер на порту 8000. Например `dssh -8 8000` или `dssh -80`. Это используется в `dssh -0` [которая](#Win7withoutCygwin) вместо `dssh -20 .` запустит `dssh -80 .`. <div id=4.7>
7. Другие клиенты в локальной сети хоста могут присоединиться к консоли `dssh -88 -j host[:port2200]`.
8. Если в [4.2](#4.2)-[4.7](#4.7) добавить ключ `-Hcmd` для Windows или `-Hbash` для Linux или Cygwin то вместо последовательной консоли будет совместно использоваться интерпретатор команд.
9. Если RFC2217 телнет-сервер с портом 5000 запущен на sshd-сервере [X](#X) то подключится к нему можно `dssh -H:0 X` или короче `dssh -HH X`. Если вместо порта 5000 порт 5002 то `dssh -H:2 X`. Если вместо порта 5000 порт 7000 то `dssh -H7000 X`.

# 5. Как использовать на Windows 7:
1. Если через Cygwin, MSYS2/MINGW, git-bash то как обычно `dssh X`
2. Иначе вместо `dssh X` если установлен OpenSSH будет запущен `dssh -Z X`.
3. Иначе будет использоваться `start ssh://X`.
4. Иначе для доступа к удалённому интерпретатору команд через браузер `dssh -80 -0Hsh l` или `dssh -80 -0Hcmd w`
5. Иначе для доступа к локальной консоли через браузер `dssh -80`
6. Иначе для доступа к удалённой консоли dssh-сервера через браузер `dssh -0`
7. Иначе для доступа к удалённой консоли интерпретатора команд dssh-сервера через браузер когда dssh-сервер на Linux `dssh -0Hbash` или когда dssh-сервер на Windows `dssh -0Hcmd`.
8. Иначе чтоб подключиться через браузер к телнет-серверу 192.168.1.2:5000 [3.3](#3.3) через dssh-сервер `dssh -H192.168.1.2:5000 -80 .` или короче `dssh -0H192.168.1.2`
9. Иначе чтоб подключиться через браузер к телнет-серверу 192.168.1.2:5000 [3.4](#3.4) через sshd-сервер [X](#X) `dssh -H192.168.1.2:5000 -80 X` или короче `dssh -0H192.168.1.2 X`.

# 6. Как устроена авторизация:
1. Авторизация основана на вложенном ключе Центра Сертификации `.\internal\ca`. Его можно обновлять запуском `go run cmd/main.go`.
2. Вложение шифруется ключом `.\key.enc`. Его можно удалить а потом создать новый запустив `go run github.com/abakum/embed-encrypt`.
3. Ключ расшифровки вложения извлекается не публикуемой функцией Priv из `internal\tool\tool.go`. Пример такой функции смотри в [eex](https://github.com/abakum/eex/blob/main/public/tool/tool.go).
4. Доступ к экземпляру сервера в пространстве имён посредника ssh-j.com задаётся именем `59d7a68@ssh-j.com` где 59d7a68 это начало хэша комита git смотри `git log -1` или первую строку при запуске `dssh -V` то есть без дополнительный параметров клиент `dssh .` подключится к dssh-серверу через посредника если они одного комита.
5. Для доступа клиента к dssh-серверу другого комита нужно указать имя через ключ `-l` `dssh -l 59d7a68 .`.
6. Врочем вместо начала хэша комита можно использовать что-то попроще например переименовываем файл `dssh` в `ivanov` и посылаем Иванову. Он запускает dssh-сервер `ivanov` а мы подключаемся как `dssh -l ivanov .`.
7. Если Петров умеет запускать программы с параметром то можно и не переименовывать `dssh` в `petroff`. Петров запустит `dssh -l petroff` а мы `dssh -l petroff .`. Вместо фамилий можно для Linux `dssh -l $(hostname)` для Windows `dssh -l %COMPUTERNAME%` и подключаться например `dssh -l debian .` и `dssh -l windows .`. Имейте в виду что имена могут буть заняты на посреднике ssh-j.com.<div id=6.8>
8. Для доступа к dssh-серверу через `ssh`, `PuTTY`, `plink`,  или `WinSCP` важно иметь доступ к агенту ключей с хотя бы одним ключём например `id_rsa` и хоть раз запустить `dssh . exit` чтоб записать сертификат замка в `~/.ssh/id_rsa-cert.pub` и сертификат хоста в `~/.ssh/dssh`. Для PuTTY plink и WinSCP соответственно DetachedCertificate и SshHostCAs.

# 7. Что было доделанно в tssh:
1. Вывод кастомных сообщения - DebugF и WarningF из login.go.
2. Для красоты - type StringSet из login.go, type afterDo []func() для afterLoginFuncs, onExitFuncs, restoreStdFuncs из main.go.
3. Глобальный конфиг для Windows - initUserConfig из config.go, resolveEtcDir, ExpandEnv в getHostKeyCallback из login.go, config.go.
4. Авторизация хостов по сертификатам - caKeysCallback, caKeys в getHostKeyCallback из cert.go.
5. Авторизация клиентов по сертификатам - addCertSigner, args.Config.GetAllSigner, args.Config.GetAllCASigner, idKeyAlgorithms в getPublicKeysAuthMethod из login.go.
6. Чтение HostKeyAlgorithms - setupHostKeyAlgorithmsConfig из login.go, algo.go. Смотри `ssh -Q HostKeyAlgorithms`.
7. Перенос агента авторизации - getForwardAgentAddr, getAgentClient в sshAgentForward из login.go.
8. Чтение ExitOnForwardFailure - dynamicForward, localForward, remoteForward, sshForward из forward.go .
9. Запуск в Windows 7 без Cygwin и MSYS2 через `-T` - setupVirtualTerminal, sttyExecutable из term_windows.go.
10. Чтение IdentitiesOnly в getPublicKeysAuthMethod из login.go.<div id=7.11>
11. Уникальный SecretEncodeKey и подсказка `encPassword bar` при указании `-o Password=foo` в getPasswordAuthMethod из login.go.
12. Возможность прервать dynamicForward, localForward, remoteForward по Ctr-C используя restoreStdFuncs.Cleanup перед ss.client.Wait в sshStart из main.go.
13. Возможность прервать сессию по `<Enter><EscapeChar>.` newTildaReader в wrapStdIO из trzsz.go и newServerWriteCloser в sshLogin из login.go.<div id=7.14>
14. Для системного прокси Windows нужен socks4 поэтому github.com/smeinecke/go-socks5 вместо github.com/armon/go-socks5 в forward.go.
15. goScanHostKeys ищет все ключи хоста для добавки в known_hosts. Есть мнение, что это не безопасно.
16. Чтение KexAlgorithms - setupKexAlgorithmsConfig из login.go, kex.go. Смотри `ssh -Q KexAlgorithms`.
17. Исправлена опечатка в keepAlive
18. makeStdinRaw для stdioForward в sshStart.

# 8. Как ещё можно использовать dssh:<div id=Y>
- [Y](#Y). как [X](#X)
1. Если запустить на хосте `dssh` и проверив доступ `dssh :` потом к хосту можно подключиться для удалённой разработки через `Remote - SSH extension` выбрав алиас `ssh-j` или ":" в `Connect to Host`.
2. Благодаря tssh [0.1](#0.1) можно прописать в `~/.ssh/config` после `Host proxy` `encPassword bar` и `DynamicForward 127.0.0.1:1080` чтоб не вводить пароль при запуске `dssh -5 proxy` для использования Socks5 прокси [7.11](#7.11). Чтоб `ssh` не ругался на неизвестный параметр `encPassword` в начале `~/.ssh/config` вставьте `IgnoreUnknown *`
3. Для системного прокси на Windows нужен Socks4 прокси поэтому `dssh proxy` [7.14](#7.14).
4. В [4.11](#4.11) можно вместо интерпретатора команд указывать команду или посредника. Например `dssh -Htop .` это почти то же что и `dssh -t . top`. Вот только значение ключа `-H` если не содержит ` ` или `:` не должно заканчиваться на цифру - иначе это будет принято за порт последовательной консоли. Например вместо `dssh -Htest2 .` надо `dssh -H"test2 " .` Если в значение ключа `-H` есть пробелы то пробел в конец можно не добавлять. Например `dssh -H"ping 8.8.8.8"`. Если в значение ключа `-H` есть `:` то это посредник и может заканчиваться на цифру.
5. Команды с `-Hcmd` или `-Hbash` можно использовать для отладки когда на хосте нет последовательно порта.
6. Можно использовать `dssh` как посредника: Если у клиента `AX` есть доступ к телнет-серверу по адресу host:port и доступ к sshd-серверу [X](#X) то отдаём эту консоль через [X](#X) `dssh -Hhost:[port5000] -20 X` [или короче](#noWin7withoutCygwin) `dssh -sHhost X` если у клиента `BXBY` есть доступ к sshd-серверам [X](#X) и [Y](#Y) то используем её `dssh -HH X` или заходим на [X](#X) `dssh X` и передаём её на [Y](#Y) `dssh -sHH Y` или короче `dssh -t X dssh -sHH Y` если у клиента `СY` есть доступ к sshd-серверу [Y](#Y) то используем её `dssh -HH Y`. Все команды управления режимом последовательной консоли передаются по цепочке посредников. Вместо последовательной консоли может быть консоль интерпретатора команд. Вместо sshd-серверов могут быть dssh-сервера: Если у клиента `A` есть доступ к телнет-серверу по адресу host:[port5000] и доступ к dssh-серверу то отдаём эту консоль `dssh -sH host:[port5000]` если у клиента `BY` есть доступ к dssh-серверу и к sshd-серверу [Y](#Y) то используем её `dssh -HH` или передаём её на [Y](#Y) `dssh . dssh -sHH Y` если у клиента `СY` есть доступ к sshd-серверу [Y](#Y) то используем её `dssh -HH Y`.
7. Можно использовать `dssh` в качестве посредника в `~/.ssh/config` `ProxyCommand dssh -W %h:%p .` как `ProxyCommand ssh -W %h:%p ssh-j`. Например `dssh -J ssh-j X` как `Host X` и `ProxyCommand dssh -W %h:%p .`
8. Если для `Host overSocks5` указать `ProxyCommand plink -load %n -raw %h -P %p` и `ProxyPutty socks5://127.0.0.1:1080` то в `PuTTY\Sessions\overSocks5` будет записано, `ProxyMethod=2` `ProxyHost=127.0.0.1` `ProxyPort=1080` и `plink` сделает то же что и `ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p` или `ProxyCommand connect -S 127.0.0.1:1080 %h %p` [ssh-connect](https://github.com/gotoh/ssh-connect). Можно задать и `ProxyPutty socks4://host[:port]` как `ProxyCommand nc -X 4 -x host[:port] %h %p` и `ProxyPutty socks4a://host[:port]` и `ProxyPutty http://host[:port]` как `ProxyCommand nc -X connect -x host[:port] %h %p` и `ProxyPutty ${http_proxy}`. Если в `Host overSocks5` указан `ProxyPutty` то PuTTY не будет использовать `ProxyCommand` а ssh будет.
Можно отдельно указать для `Host D1080` `ProxyPutty socks5://127.0.0.1:1080` а для `Host overSocks5` `ProxyCommand plink -load D1080 -raw %h -P %p`. Приятно, что это сработает и на Windows и на Linux если установлен plink.
9. Можно использовать dssh-клиента в качестве посредника для доступа к dssh-серверу через `socks5://127.0.0.1:1080` как `dssh -45ND1080 .`
10. Чтоб перезапустить dssh-сервер используйте ключ `-r` или `--restart`. Сервер остановится и запустится через 15 секунд.
11. Чтоб остановить dssh-сервер используйте ключ `--stop`.<div id=8.12>
12. Если невозможно подключиться к dssh-серверу командой `dssh -j host` но возможно с алиаса `jh` то подключаемся `dssh -J jh -j host`. Если на dssh.sshd.host запущен и dssh-сервер и sshd-сервер и невозможно подключиться `dssh -j host` то можно `dssh -J dssh.sshd.host -j :` или короче `dssh -J dssh.sshd.host`. Смотри [2.2](#2.2).
13. Если невозможно подключиться к dssh-серверу командой `dssh -j host` но возможно с `dssh.host` на котором установлен `dssh` то подключаемся `dssh dssh.host dssh -j host`.

# 9. Удалённый доступ к последовательной консоли на хосте с [RouterOS](#0.10) или с [ser2net](#0.8) или с [hub4com](#0.9):
1. Подключаем USB2serial переходник в USB порт устройства под управлением RouterOS.
2. Запускаем удалённый доступ к последовательной консоли RouterOS `/port remote-access add port=usb1 tcp-port=5000 protocol=raw` [Ports](https://help.mikrotik.com/docs/spaces/ROS/pages/8978525/Ports). Для смены режима на консоле `/port set 0 flow-control=none stop-bits=1 parity=none baud-rate=9600` `/port set 0 baud-rate=auto`
3. Если LAN dssh-сервера это 192.168.0.1 а у устройства с RouterOS LAN это 192.168.0.2 то подключаемся `dssh -W192.168.0.2:5000 .` или `dssh . dssh -W192.168.0.2:5000`. Это похоже на `ssh -W192.168.0.2:5000 ssh-j` только ssh не переводит консоль в сырой режим а dssh переводит.
4. Иначе разрешим доступ с WAN на 22 порт tcp `/ip firewall filter add action=accept chain=input dst-port=22 protocol=tcp` для доступа по SSH с WAN.
 И разрешим доступ с lo по tcp `/ip firewall filter add action=accept chain=input in-interface=lo protocol=tcp` для туннеля с WAN на 5000 порт. (80 для управления по webfig, 8291 по winbox) 
5. Если алиас RouterOS это X то подключаемся `dssh -W5000 X`.
6. Останавливаем удалённый доступ к последовательной консоли RouterOS `/port remote-access remove 0` 
7. Для возможности смены клиентом режима удалённой последовательной консоли через протокол RFC2217 запускаем аналог [ser2net](#0.8) на RouterOS `/port remote-access add port=usb1 tcp-port=5000`
8. Если LAN хоста с запущенными `dssh` это 192.168.0.1 а у устройства с RouterOS LAN это 192.168.0.2 то подключаемся `dssh -H192.168.0.2:5000 .` или короче `dssh -H192.168.0.2: .`.<div id=9.9>
9. Если алиас RouterOS это [X](#X) то подключаемся `dssh -H127.0.0.1:5000 X` или `dssh -H: X` или короче `dssh -HH X` это то же что и `dssh -NL127.0.0.1:5000:127.0.0.1:5000 X` а потом `dssh -H:`.
10. Если запустить `ssh -NL127.0.0.1:5000:127.0.0.1:5000 X` то `dssh -H:` сработает только однажды потому, что после закрытия `dssh -H:` статус `/port remote-access` останется подключенным. Это особенность ssh.
11. Если алиас хоста с sshd-сервером [X](#X) и на нём запущен `ser2net -C "5000:telnet:0:/dev/ttyUSB1:115200 8DATABITS NONE 1STOPBIT LOCAL -XONXOFF remctl"` или [hub4com](#0.9) как `com2tcp-rfc2217 com1 5000` типа `dssh -H1 -20 +` то подключаемся `dssh -H127.0.0.1:5000 X` или `dssh -H: X` или короче `dssh -HH X`. 
12. Если на хосте с dssh-сервером запущен `ser2net -C "127.0.0.1,5000:telnet:0:/dev/ttyUSB1:115200 8DATABITS NONE 1STOPBIT LOCAL -XONXOFF remctl"` или [hub4com](#0.9) как `com2tcp-rfc2217 --interface 127.0.0.1 com1 5000` типа `dssh -H1 -20` то подключаемся `dssh -H127.0.0.1:5000 .` или `dssh -H: .` или короче `dssh -HH`. 
13. Если [ser2net](#0.8) или [hub4com](#0.9) доступен по LAN как `x` и на нём запущен `ser2net -C "x,5000:telnet:0:/dev/ttyUSB1:115200 8DATABITS NONE 1STOPBIT LOCAL -XONXOFF remctl"` или `com2tcp-rfc2217 --interface x com1 5000` типа `dssh -H1 -20 x` то подключаемся `dssh -Hx:5000` или `dssh -Hx:`. 

# 10. Параметры для локального доступа:
1. `-z` то же что и `-UU` как в [1.1](#1.1).<div id=10.2>
2. `-20 x` то же что `-UU` + стартует RFC2217 телнет-сервер на `x:5000` как в [1.11](#1.11) + стартует RFC2217 телнет-клиент в том же окне.<div id=10.3>
3. `-ZH host:port5000` то же что и `telnet -e^Q host port5000` для Windows в новом окне как в [1.6](#1.6). Для Cygwin на Windows 7 или Linux в том же окне.<div id=10.4>
4. `-Z20 x` то же что и `-20 x` + `telnet -e^Q x 5000` для Windows в новом окне. Для Cygwin на Windows 7 или Linux в том же окне.<div id=10.5>
5. `-Z x` как в [10.4](#10.4).<div id=10.6>
6. `-zZ x` то же что и `-20 x` + `telnet -e^Q x 5000` в том же окне и без управлением режимом консоли.<div id=10.7>
7. `-u20 x` то же что и `-20 x` + `putty -telnet x -P 5000` как в [1.4](#1.4).<div id=10.8>
8. `-u` как и `-uUU` это `putty -serial y -sercfg 9600,8,N,1,N` если перед этим режим был задан как `-U9` и без управлением режимом консоли.<div id=10.9>
9. `-zu` как и `-zuUU` это `plink -serial y -sercfg 9600,8,N,1,N` если перед этим режим был задан как `-U9` и без управлением режимом консоли. Для Cygwin на Windows 7 `putty -serial y -sercfg 9600,8,N,1,N`.<div id=10.10>
10. `-uH host:port5000` то же что и `putty -telnet host -P port5000` как в [1.4](#1.4).<div id=10.11>
11. `-88 x` то же что `-UU` + стартует веб-сервер на `x:8008` + `chrome http://x:8008`.<div id=10.12>
12. `-22 -88 x` то же что `-UU` + стартует RFC2217 телнет-сервер на `x:5002` + стартует веб-сервер на `x:8008` + `chrome http://x:8008`

# 11. Параметры для удалённого доступа:
1. `-z .` как в [10.1](#10.1) только на хосте с `dssh`. Как `ssh : dssh -z`.<div id=11.2>
2. `-20 .` или `-HH .` или короче `-0` как в [10.2](#10.2) только на хосте с `dssh` + 127.0.0.1:5000 переносится локально как `-L` на 127.0.0.1:5000 сервера.<div id=11.3>
3. `-H host:port5000 .` то же что и `dssh -W host:port5000 .` только с управлением по RFC2217 или RFC1073 как в [3.5](#3.5).<div id=11.4>
4. `-Z20 .` или короче `-Z0` то же что и `-20 .` как в [11.2](#11.2) + `telnet -e^Q 127.0.0.1 5000` учитывая перенос портов управление будет консолью на хосте сервера.<div id=11.5>
5. `-Z X` то же что и `ssh X` для Windows новом окне.<div id=11.6>
6. `-zZ X` то же что и `ssh X` для Windows в том же окне.<div id=11.7>
7. `-u20 .` или короче `-u0` то же что и `-20 .` + `putty -telnet 127.0.0.1 -P 5000` учитывая перенос портов управление будет консолью на хосте сервера.<div id=11.8>
8. `-u X` то же что и `putty @X` для Windows новом окне как в [1.4](#1.4). Для Linux то же что и `plink -load X`. Перед стартом putty алиас X создаётся из ssh алиаса X.<div id=11.9>
9. `-zu X` то же что и `plink -load X` как в [11.8](#11.8).<div id=11.10>
10. `-s .` как в [10.2](#10.2).<div id=11.11>
11. `-88 .` то же что `-UU` + стартует веб-сервер на хосте dssh-сервера `127.0.0.1:8008` + локальный порт 127.0.0.1:8008 переносится на порт 127.0.0.1:8008 сервера + `chrome http://127.0.0.1:8008` учитывая перенос портов управление консолью будет на хосте сервера.<div id=11.12>
12. `-22 -88 .` то же что `-UU` + 127.0.0.1:5002 и 127.0.0.1:8008 переносятся на 127.0.0.1:5002 и 127.0.0.1:8008 сервера + стартует RFC2217 телнет-сервер на `127.0.0.1:5002` + стартует веб-сервер на `127.0.0.1:8008` + `chrome http://127.0.0.1:8008` учитывая перенос портов управление консолью будет на хосте сервера.<div id=11.13>
13. `-s20 X` или короче `-s X` как в [10.2](#10.2) + 127.0.0.1:5000 sshd-сервера X переносится как `-R` на 127.0.0.1:5000 локального телнет-сервера с RFC2217. Это работает не только c dssh-сервером.<div id=11.14>
14. `-H host:[port5000] X` 127.0.0.1:port5000 переносится sshd-сервером X на host:port5000 + локальный телнет-клиент по RFC2217 управляет через sshd-сервер X телнет-сервером с RFC2217 на host:port5000 как в [9.9](#9.9). Это работает не только c dssh-сервером. Отданная как в [11.3](#11.3) через sshd-сервер X консоль может использоваться как в [11.4](#11.4) так и [11.2](#11.2).<div id=11.15>
15. `-s` как в [10.2](#10.2).
16. `dssh -t X dssh -22` или `ssh -t X dssh -22` как [11.2](#11.2) только через sshd-сервер [X](#X).

# 12. Параметры для VNC доступа. Передавать VNC трафик можно и через посредника ssh-j.com, но не будем злоупотреблять его добротой - лучше использовать VNC напрямую:

- sshd.lan на хосте запущен sshd и он доступен через LAN. Локальный sshd-сервер.
- sshd.wan на хосте запущен sshd, роутер настроен для переноса порта 22 с sshd.wan на sshd.lan:22 и он доступен через WAN. Глобальный dssh-сервер.
- dssh.lan на хосте запущен `dssh _` и он доступен через LAN. Локальный dssh-сервер.
- dssh.wan на хосте запущен `dssh` или `dssh +`, роутер настроен для переноса порта 2200 с dssh.wan на dssh.lan:2200 и он доступен через WAN. Глобальный dssh-сервер.
- dssh.x на хосте запущен `dssh` и он доступен и c LAN и с WAN.
- vncserver.lan - на хосте установлен vnc-сервер и он доступен через LAN. Показывающий локально.
- vncserver.sshd.wan - на хосте установлен vnc-сервер и он доступен через WAN как sshd.wan. Показывающий глобально через sshd.
- vncserver.dssh.wan - на хосте установлен vnc-сервер и он доступен через WAN как dssh.wan. Показывающий глобально через dssh.
- vncviewer.lan - на хосте установлен vnc-клиент и он доступен через LAN. Наблюдатель локально.
- vncviewer.sshd.wan - на хосте установлен vnc-клиент и он доступен через WAN как sshd.wan. Наблюдатель глобально через sshd.
- vncviewer.dssh.wan - на хосте установлен vnc-клиент и он доступен через WAN как dssh.wan. Наблюдатель глобально через dssh.

1. Увидеть рабочий стол vncserver.sshd.lan можно с vncviewer.lan командой `dssh -77 vncserver.sshd.lan`. Если на vncserver.sshd.lan установлен dssh то используется `dssh -077 vncserver.sshd.lan dssh -77`. 
2. Увидеть рабочий стол vncserver.dssh.lan можно с vncviewer.lan командой `dssh -077 -j vncserver.dssh.lan dssh -77` или короче `dssh -77 -j vncserver.dssh.lan`.
3. Если роутер настроен для переноса порта 22 c vncserver.sshd.wan на vncserver.sshd.lan:22 то увидеть его рабочий стол c vncviewer.wan можно командой `dssh -77 vncserver.sshd.wan`.
4. Если роутер настроен для переноса порта 2200 c vncserver.dssh.wan на vncserver.dssh.lan:2200 то увидеть его рабочий стол c vncviewer.wan можно командой `dssh -77 .`. Примерно как в [viewWindowsServerDirect](viewWindowsServerDirect.bat) [viewLinuxServerDirect](viewLinuxServerDirect.bat).
5. Если роутер настроен для переноса порта 2200 c vncviewer.dssh.wan на vncviewer.dssh.lan:2200, а на vncserver.dssh.wan запущен `dssh` то увидеть его рабочий стол можно c vncviewer.lan командой `dssh -77 .` - магия. Примерно как в [viewWindowsServerOverDirectClient](viewWindowsServerOverDirectClient.bat) [viewLinuxServerOverDirectClient](viewLinuxServerOverDirectClient.bat).
6. Чтоб увидеть рабочий стол vncserver.lan c vncviewer.lan запустите на vncviewer.lan `dssh -077 sshd.lan` а на vncserver.lan `dssh -s77 sshd.lan`. Режим локального sshd посредника.
7. Чтоб увидеть рабочий стол vncserver.dssh.wan c vncviewer.wan запустите на vncviewer.wan `dssh -077 .` а на vncserver.wan `dssh -s77 .`. Режим глобального dssh посредника.
8. Если на vncviewer.sshd.lan запущен sshd то чтоб с vncserver.lan показать свой рабочий стол запустите `dssh vncviewer.sshd.lan dssh -077` а потом `dssh -s77 vncviewer.sshd.lan`. 
9. Чтоб с vncserver.lan показать свой рабочий стол локальному наблюдателю vncviewer.dssh.lan запустите `dssh -j vncviewer.dssh.lan dssh -077` а потом `dssh -s77 -j vncviewer.dssh.lan`.
10. Чтоб с vncserver.wan показать свой рабочий стол глобальному наблюдателю vncviewer.dssh.wan запустите `dssh . dssh -077` а потом `dssh -s77 .`.

# 13. Параметры для SFTP доступа. Передавать SFTP трафик можно и через посредника ssh-j.com, но не будем злоупотреблять его добротой - лучше использовать SFTP напрямую:

- sftp.lan - на хосте установлен sftp-клиент WinSCP или FileZilla и он доступен через LAN.
- sftp.sshd.wan - на хосте установлен sftp-клиент и он доступен через WAN как sshd.wan.
- sftp.dssh.wan - на хосте установлен sftp-клиент и он доступен через WAN как dssh.wan.

1. Увидеть файлы sshd.lan можно с sftp.lan командой `dssh -9 sshd.lan`. 
2. Увидеть файлы dssh.lan можно с sftp.lan командой `dssh -9 -j dssh.lan`.
3. Если роутер настроен для переноса порта 22 c sshd.wan на sshd.lan:22 то увидеть его файлы c sftp.wan можно командой `dssh -9 sshd.wan`.
4. Если роутер настроен для переноса порта 2200 c dssh.wan на dssh.lan:2200 то увидеть его файлы c sftp.wan можно командой `dssh -9`.
5. Если невозможно подключиться напрямую к dssh-серверу на dssh.sshd.host командой `dssh -9j dssh.sshd.host` но возможно через посредника `jh` командой `dssh -J jh dssh.sshd.host` то подключаемся `dssh -9J jh,dssh.sshd.host -j :` или короче `dssh -9J jh,host.dssh.sshd`. 
6. Возможность авторизоваться по [сертификату ЦС](#6.8) имеет WinSCP, но не FileZilla. Чтоб сертификат хоста `dssh` заимствовался у PuTTY для этого в реестр WinSCP заносится признак "SshHostCAsFromPuTTY"=dword:00000001. Если конфигурация WinSCP хранится не в реестре сделайте это сами.

# 14. Что делать если запутались в параметрах.
1. Читать исходники. Иногда исходники и коментарии понятней руководств.

# 15. Что делать если запутались в исходниках.
1. Писать свою программу тщательно комментировать её и писать руководства. \8^)
