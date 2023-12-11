## Types of info gathering

2 types of  : 
```txt
- Passive info gathering
gathering as much without actively engaging target using publicly available sources.
what we are looking for :  ip & DNS info, domain names and domain ownership, emails & social profiles, web tech on target site, subdomains etc.

- Active info gathering
gathering as much as possible by actively engaging target system
what we are looking for : open ports, internal infrastructure, information enum from target system
```

KEY : Difference between footprinting & Recon
``` txt
footprinting is essentially the same as recon, only difference is youre identifying more important information that is pertinent to a single target.
```
### Passive recon techniques
```txt
GENERAL IP/ASN recon
>use host command :

host google.com
host -t txt google.com

- a site having 2 ipv4 address usually indicates its behnd a proxy or firewall like cloudflare and the rest. 

## WEB RECON
>/robots.txt

>httrack.com / webhttrack - copies a site to a local directory.

>whatweb

>whois - can be used to also get the nameservers of a domain along with other domain specific info.

DNSSEC prevents sensitive information e.g email address of the registrant,name from being shown by redacting it, when a whois lookup is done on the server/domain, when its enabled its DNSSEC: unsigned

>Netcraft 
- netcraft.com - used to gather info about a target domain, e.g registrar email, tech running on the server etc.

Services -> Internet Data mining -> Internet Research Tools(at the bottom)



## DNS RECON
dnsrecon, dnsdumpster.com
- dnsrecon 
dnsrecon -d hackersploit.org



## WAF RECON
web application firewall detection with wafw00f
wafw00f -l   
wafw00f rami.com
wafw00f -a rami.com



## SUBDOMAIN RECON
- sublist3r
basically uses multiple search engines and websites like netcraft, dnsdumptser etc to gather subdomains passively, it does have a bruteforce variant "subbrute" for active recon.

nb : google does request limiting and sublist3r generates a lot of requests via google.

sublist3r -h
sublist3r -d hackersploit.org -e google,yahoo



## GOOGLE DORKS
>limit search results to only one domain, find admin panels or urls related to an administrative function, find subdomains

site:ine.com
site:ine.com employee
site:ine.com inurl:admin
site:*.ine.com
site:*.ine.com intitle:admin
site:*ine.com filetype:pdf

intitle:index of
cache:ine.com   #how a site looked previously like wayback


## EMAIL HARVESTING
>theHarvester : similar to sublist3r because it uses a host of search engines and websites like linkedin,censys,crt.sh etc to scrape the internet for email addresses. - It can do subdomain enum and zonetransfers.
- If no source is specified with -b itll use all sources.- It supports company names.
- An email is important because essentially during a test if phishing is in scope, you can craft a malicious link/attachments which when clicked can give you a foothold.
NB : Checkout "spyse" search engine.

theHarvester -d hackersploit.org -b google,linkedin
theHarvester -d hackersploit.org -b google,linkedin,yahoo,dnsdumpster,duckduckgo,crtsh

NB : if you found emails you can check with haveibeenpwned.com to see if a password has been part of a breach and its still being used, we can do a password spray and all.
```


### Active Recon techniques
```

## DNS RECORDS
not so familiar ones lol
HINFO - Host info
SOA - start of authority, regulates a list of servers for zone transfers where there are server clusters from slave to master.
SRV - service records
PTR - IP to host name

>DNS interrogation is the proces of probing/enum DNS records for a specific domain.

>DNS zone transfer is the process when a DNS zone file is copied or transfered from one DNS server to another. - It can be disabled, and when its enabled and improperly configured it can be abused. When you do a zonetransfer is leaks all the possible records being hosted on a DNS server.

- dnsenum automatically does zonetransfers on a specific nameserver.
dnsenum zonetransfer.me

- can also do a zone transfer with DIG (with an asynchronous zone transfer: axfr)

dig axfr @nsztm1.digi.ninja zonetransfer.me

- FIERCE
uses (default)wordlists and can also do zone transfers if it finds nothing it defaults to a dns bruteforce 
fierce -dns zonetransfer.me


```