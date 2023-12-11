DONT FORGET UDP SERVICES


### TL;DR
```
- arp-scan + fping - grab live hosts, probe each -> enumerate ports
- Never forget UDP.
- use NSE scripts
```
#### Live Host enumeration / Host idetificaion :
fping
arp requests
type 8 - echo req

>arp scan 
```bash
sudo arp-scan -I tun0 -g 10.142.111.0/24
```
>Ping

>Fping 
```bash
fping -I tun0 -g 10.142.111.0/24 -a 2>dev/null
```
>nmap
```bash
nmap -sn 10.142.111.0/24
```

```

3-way handshake with nmap
I send syn
it replies Syn-ack
I reply with ack
and send a rst-ack to close the connection

if port is closed
I send a syn
it replies with rst+ack

If TCP-stealth scan
I send a syn
It rpelies a syn-ack
and I kill the connection with rst.

if serivce version
I send syn
it rreplies a syn+ack
I send an ack but grab its banner
and then end he connection with rst+ack 

>scan list
nmap -iL ip.list -sV -O


nmap --script=discovery
shows a lot of info that might help
```
