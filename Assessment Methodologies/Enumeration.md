wordlists on the web attack box
- /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
- /root/Desktop/wordlists/common-passwords.txt

### TL;DR 

>[!tip] SMB LESSON
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
<br>
<br>

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
<br>
<br>

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
<br>
<br>

>[!tip] HTTP
- IIS
```bash
nmap
whatweb $IP
http $IP     # for header info #httpie.io site
dirb http://$IP
browsh --startup-url http://$IP  #tries to simulate a copy of the site interminal


=NSE SCRIPTS= 
--script http-enum             #finds a small amount of dir
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
<br>
<br>

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



## servers + services
basically enumerating a very few set of common services on servers.
FTP, SSH, SQL, SMB, HTTP

What is a server & Services
A server is a special piece of hardware that provides a functionality specialized to that machine that can be utilized by a device/devices.

SMB 
- the smb-protocols script basically tells you what dialects and version the server is using.
- the smb-security-mode basically enumerates the account that exists - "guest", if message signing is enaled or disabled.
- enum-sessions script enumerates for logged in sessions.
- The IPC$ share is also known as a **null session connection**. By using this session, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares. The IPC$ share is created by the Windows Server service.


ERRATUM
smbmap mistake
![[Pasted image 20230925021339.png]]