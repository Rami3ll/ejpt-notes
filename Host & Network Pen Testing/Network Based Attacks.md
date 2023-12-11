 ARP
 IP -> MAC resolution
 
ARP Poisoning ; broadcasting ARP packets that tell other computers that you are another on the network. - this would mean traffic meant for that computer would come to you

Promiscuous mode : listen to all traffic on a network.

 
>live host scan 
```bash
nmap $IP/CIDR -sn
```

## Tshark usage
clli version of wireshark 
`-i `select iface
`-D` list iface and exit
`-r` input from a fiile - PCAP files and all.
`-`z for stats
`-Y` to apply a filter
`-e `tells what field/column in the capture output to display

>run tshark on a pcap file :-
```bash
tshark -r file.pcap

wc -l 
```

>statistic switches :-
```bash
tshark -r file.pcap -z io,phs -q
```
io, phs outputs the protocol hierarchy and frames and bytes. in the capture file.

FILTERING
```bash
filter only http traffic 
> tshark -r file.pcap -Y "http" | more

Filter to show only HTTP GET requests
> tshark -r file.pcap -Y "http.request.method==GET" | more

Filter to show only Source and Dest IP
> tshark -r file.pcap -Y 'ip.src==$IP && ip.dst==$IP' | more

Look xat specific fields in the capture 
> tshark -r file.pcap -Y 'http.request.method==GET' -Tfields -e frame.time -e ip.src -e http.request.full_uri

Filter with REGEXP if "password" is in any request packet
> tshark -r file.pcap -Y 'http contains password'

Filter to see only GET and POST reqs and if request to a website "nytimes.com" was made 
> tshark -r file.pcap -Y "http.request.method==GET && http.host==www.nytimes.com" -Tfield -e ip.dst

Filter to see the IP address of amazon and the ip addresses that made requests to the site with their cookie
> tshark -r file.pcap -Y 'ip contains amazon.in && ip.src==$IP' -Tfields -e ip.src -e http.cookie

Filter to see the user agent along with an IP address 
tshark -r file.pcap -Y 'ip.src==$IP && http' -Tfield -e http.user_agent
```

****
### ARP Poisoning
```bash
redirect stdin to ip_forward
> echo 1> /proc/sys/net/ipv4/ip_forward

spoof our IP into another on the network 
> arpspoof -i eth1 -t $SPOOF_IP -r $TARGET_SENDING_CONN
> arpspoof -i eth1 -t 10.100.13.37 -r 10.100.13.36
```
.36 runs telnet
.37 is a host on the network w/no services - a client

Here, basically we are pretending to be the Telnet server, and the client on .36 tries to connect to us .140,  instead of .37

### Wifi Traffic Analysis
```bash

```