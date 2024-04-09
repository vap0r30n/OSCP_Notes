# intial enumeration
fuck fuck fuck (heavily adapted from: 
https://blog.adithyanak.com/oscp-preparation-guide/enumeration
https://0xdf.gitlab.io/2024/03/21/smb-cheat-sheet.html#
and others that I can't remember
, thanks!)

## // port scan
```
rustscan -a <tgt_ip> --ulimit 5000
ports=<ports>
nmap -Pn -p$port -A -T5 -oN scan.txt <tgt_ip>
sudo nmap -sV -p$ports--script "vuln"
```

## // DNS enum
```
dnsrecon -d megacorpone.com -t std
dnsrecon -d megacorpone.com -D ~/list.txt -t brt        // bruteforce domain names
nslookup mail.megacorptwo.com                           // ip resolution
nslookup -type=TXT info.megacorptwo.com 192.168.50.151  // query the dns server for the TXT record of the specified host
```

## // FTP anonymous login
```
ftp <tgt_ip>
anonymous
anonymous
```

## // SMTP veryify username
```
nc -nv <tgt_ip> 25
VRFY <user>
```

## // RPC Bind - 111
```
rpcclient --user="" --command=enumprivs -N 10.10.10.10
rpcinfo –p 10.10.10.10
rpcbind -p 10.10.10.10 
```

## // RPC - 135
```
rpcdump.py 10.11.1.121 -p 135
rpcdump.py 10.11.1.121 -p 135 | grep ncacn_np // get pipe names
rpcmap.py ncacn_ip_tcp:10.11.1.121[135]
```

## // SMB - 139 & 445
```
nmap --script smb-protocols <tgt_ip>
nmap --script smb-vuln* -p 139,445 <tgt_ip>

// basic enum
netexec smb <tgt_ip>

// get share info
crackmapexec smb <tgt_ip> -u <user> -p '<pass>' --shares
netexec smb <tgt_ip> --shares
netexec smb <tgt_ip> --shares -u '0xdf' -p '0xdf'
netexec smb <tgt_ip> --shares -u 'guest' -p ''
echo exit | smbclient -L //<tgt_ip>
smbclient -N -L //<tgt_ip>

// enumerate files
smbclient //<tgt_ip>/<share_name> -U <username> <password>
netexec smb <tgt_ip> -u oxdf -p '' -M spider_plus

// kerberos auth
smbclient.py '<domain>/<username>:<password>@<target_hn>' -k -no-pass

// user / object enumeration .. guest is decent account to attempt
rpcclient 10.10.11.222 -U 'guest%'
lookupsid.py guest@10.10.11.222 -no-pass
netexec smb <tgt_ip> -u guest -p '' --rid brute
impacket-samrdump <domain>/<admin>:<password>@<tgt_ip

```

## // SNMP
```
snmpwalk -c public -v1 10.0.0.0
snmpcheck -t 192.168.1.X -c public
onesixtyone -c names -i hosts
nmap -sT -p 161 192.168.X.X -oG snmp_results.txt
snmpenum -t 192.168.1.X
```

## // IRC
```
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 <tgt_ip>
```

## // MSQL
```
nmap -sV -Pn -vv 10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122
```

## // HTTP, HTTPS
```
whatweb <url>
nikto -h <url>
nmap --script http-enum <url>


gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -u http://<url>
gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 100 -x txt,php,csv,md,json,js,html,py,sh -u http://<url>
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,csv,md,json,js,html,py,sh -t 100 -u http://<url>
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 100 -x txt,php,csv,md,json,js,html,py,sh -u http://<url>
gobuster -s 200,204,301,302,307,403 -w /usr/share/seclists/Discovery/Web_Content/big.txt -t 100 -x txt,php,csv,md,json,js,html,py,sh -u http://<url>

wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 --hw 12 http://192.168.0.119/index.php?FUZZ=id

```
