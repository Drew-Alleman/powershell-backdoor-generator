# powershell-backdoor
A Powershell Reverse Backdoor

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
usage: listen.py [-h] [--ip-address IP_ADDRESS] [--port PORT] [--out-file OUT_FILE] [--verbose]

Powershell Backdoor

options:
  -h, --help            show this help message and exit
  --ip-address IP_ADDRESS, -I IP_ADDRESS
                        IP Address to bind to default: xxx.xxx.x.xx (your local ip)
  --port PORT, -p PORT  Port to connect over default:4444
  --out-file OUT_FILE, -O OUT_FILE
                        Generated backdoor filename
  --verbose             Show verbose output
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
