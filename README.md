# 🛡️ CyberRecon Arsenal

> **The Ultimate Cybersecurity Reconnaissance & Penetration Testing Platform**

A comprehensive, production-ready cybersecurity suite featuring advanced reconnaissance, vulnerability assessment, exploitation tools, and AI-powered assistance. Built with enterprise-grade security, performance, and usability in mind.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)
![Status](https://img.shields.io/badge/status-production-success.svg)

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for legitimate cybersecurity professionals, penetration testers, and security researchers. Unauthorized access to computer systems is illegal. Always ensure you have explicit written permission before testing any systems you don't own.

## 🚀 Features

### 🤖 AI Assistant
- **AI Pentesting Chat** - Intelligent assistant for penetration testing guidance
- **Telegram Bot Integration** - Remote control and monitoring
- **Contextual Recommendations** - Smart suggestions based on scan results

### 🔍 Reconnaissance
- **Network Scanner** - Comprehensive network discovery and mapping
- **Port Scanner** - Fast, accurate port scanning with service detection
- **Domain Intel** - WHOIS, DNS enumeration, subdomain discovery
- **OSINT Toolkit** - Email harvesting, social media recon, metadata extraction

### 🌐 Web Application Security
- **Web Scanner** - Automated web vulnerability detection
- **SQL Injection** - Advanced SQLi detection and exploitation
- **XSS Scanner** - Cross-site scripting vulnerability finder
- **Directory Bruteforce** - Hidden directory and file discovery

### 📱 Mobile Security
- **APK Analyzer** - Android application security analysis
- **Mobile Scanner** - Comprehensive mobile app vulnerability assessment
- **iOS Security** - iOS application security testing
- **Mobile Forensics** - Device artifact extraction and analysis

### 💣 Exploitation
- **Exploit Database** - Searchable CVE and exploit repository
- **Payload Generator** - Multi-platform payload creation
- **Metasploit Integration** - Access to Metasploit framework
- **Custom Exploits** - Custom exploit code generation

### 🔓 Post-Exploitation
- **Privilege Escalation** - OS-specific privilege escalation techniques
- **Persistence** - Methods for maintaining access
- **Data Exfiltration** - Secure data extraction techniques
- **Lateral Movement** - Network propagation strategies

### 🔎 Intelligence
- **IP Reputation** - Check IP addresses against threat databases
- **Email Validator** - Verify email deliverability and security
- **Breach Checker** - Search for compromised credentials
- **Phone Lookup** - Phone number intelligence gathering
- **Temp Mail** - Disposable email generation

### 🗄️ Stealerlo.gs Integration (NEW!)
- **Breach Search** - Access 12B+ stealerlog records
- **Hash Cracking** - MD5, SHA1, SHA256, NTLM plaintext lookup
- **Phone Intelligence** - Reverse phone lookup with caller details
- **IP Geolocation** - Advanced IP information and network data
- **Machine Forensics** - System information and file retrieval
- **Domain Employee Search** - Find company credentials by domain
- **Social Media Analysis** - Cross-platform account discovery
- **OSINT Proxy** - Access Snusbase, Shodan, OSINTDog APIs
- **Async Jobs** - UUID generation, logs search, domain scanning

See [Stealerlo.gs API Documentation](./docs/STEALERLOGS_API.md) for complete integration details.

### 🔐 Obfuscation
- **Script Editor Pro** - Advanced code editor with obfuscation
- **EXE Obfuscator** - Windows executable obfuscation
- **PS1 to EXE** - PowerShell to executable conversion
- **Code Obfuscator** - Multi-language code obfuscation
- **Payload Encoder** - Multiple encoding schemes (base64, hex, unicode)

### ⚙️ Management
- **API Manager** - RESTful API for all features
- **Webhook Configuration** - Real-time event notifications
- **Automation** - Scheduled scans and automated workflows

## 📋 Prerequisites

- **Node.js** >= 18.0.0
- **npm** >= 9.0.0
- **Operating System**: Linux, macOS, or Windows

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/cyberrecon-arsenal.git
cd cyberrecon-arsenal
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
nano .env
```

### 4. Start the Server

```bash
# Production mode
npm start

# Development mode with auto-reload
npm run dev
```

The application will be available at `http://localhost:3001`

## 🌐 API Documentation

### Base URL
```
http://localhost:3001/api
```

### Authentication
Currently, the API is open for development. Production deployments should implement authentication.

### Rate Limiting
- **Window**: 15 minutes
- **Max Requests**: 100 per window
- Configurable via `RATE_LIMIT_MAX_REQUESTS` in `.env`

## 📚 API Endpoints

### Domain Intelligence

#### Get WHOIS Information
```http
GET /api/domain/whois/:domain
```

**Example:**
```bash
curl http://localhost:3001/api/domain/whois/example.com
```

**Response:**
```json
{
  "domain": "example.com",
  "registrar": "Example Registrar",
  "creationDate": "1995-08-14",
  "expirationDate": "2024-08-13",
  "nameServers": ["ns1.example.com", "ns2.example.com"]
}
```

#### DNS Records Lookup
```http
GET /api/domain/dns/:domain
```

#### Subdomain Discovery
```http
GET /api/domain/subdomains/:domain
```

#### Domain Reputation Check
```http
GET /api/domain/reputation/:domain
```

### Network Scanning

#### Port Scan
```http
POST /api/network/scan
Content-Type: application/json

{
  "host": "192.168.1.1",
  "startPort": 1,
  "endPort": 1000,
  "options": {
    "timeout": 3000,
    "serviceDetection": true
  }
}
```

#### Quick Scan (Common Ports)
```http
GET /api/network/quick-scan/:host
```

#### Service Detection
```http
POST /api/network/service-detection
Content-Type: application/json

{
  "host": "192.168.1.1",
  "ports": [80, 443, 22, 3306]
}
```

#### Network Mapping
```http
POST /api/network/map
Content-Type: application/json

{
  "host": "192.168.1.1",
  "options": {
    "serviceDetection": true
  }
}
```

### Web Analysis

#### SSL/TLS Analysis
```http
GET /api/web/ssl/:url
```

#### HTTP Headers
```http
GET /api/web/headers/:url
```

#### Security Headers Check
```http
GET /api/web/security-headers/:url
```

#### Technology Detection
```http
GET /api/web/technology/:url
```

### OSINT

#### Email Harvesting
```http
GET /api/osint/emails/:domain
```

#### Social Media Reconnaissance
```http
GET /api/osint/social-media/:username
```

#### Metadata Extraction
```http
GET /api/osint/metadata/:url
```

#### Data Breach Check
```http
GET /api/osint/breaches/:email
```

### Vulnerability Assessment

#### Search CVEs
```http
GET /api/vulnerability/cve/search?keyword=apache&limit=10
```

#### Get CVE Details
```http
GET /api/vulnerability/cve/:cveId
```

#### Vulnerability Scan
```http
POST /api/vulnerability/scan
Content-Type: application/json

{
  "target": "example.com",
  "scanType": "comprehensive"
}
```

### Web Application Security

#### SQL Injection Scan
```http
POST /api/vulnerability/webapp/sql-injection
Content-Type: application/json

{
  "url": "http://example.com/page",
  "params": {}
}
```

#### XSS Scan
```http
POST /api/vulnerability/webapp/xss
Content-Type: application/json

{
  "url": "http://example.com/search"
}
```

#### Directory Bruteforce
```http
POST /api/vulnerability/webapp/directory-bruteforce
Content-Type: application/json

{
  "url": "http://example.com",
  "wordlist": "common"
}
```

### Intelligence

#### IP Reputation Check
```http
GET /api/vulnerability/intelligence/ip/:ip
```

#### Email Validation
```http
GET /api/vulnerability/intelligence/email/:email
```

#### Phone Lookup
```http
GET /api/vulnerability/intelligence/phone/:number
```

#### Generate Temporary Email
```http
GET /api/vulnerability/intelligence/temp-mail
```

### Exploitation

#### Generate Payload
```http
POST /api/vulnerability/exploitation/payload
Content-Type: application/json

{
  "type": "reverse-shell-bash",
  "options": {
    "lhost": "10.10.10.10",
    "lport": 4444
  }
}
```

**Available Payload Types:**
- `reverse-shell-bash`
- `reverse-shell-python`
- `reverse-shell-php`
- `reverse-shell-powershell`
- `web-shell-php`
- `sql-injection-union`
- `xss-basic`

#### List Exploits
```http
GET /api/vulnerability/exploitation/exploits?category=remote&platform=linux
```

#### Generate Custom Exploit
```http
POST /api/vulnerability/exploitation/custom
Content-Type: application/json

{
  "target": "Apache 2.4.49",
  "vulnerability": "Path Traversal"
}
```

### Mobile Security

#### Analyze APK
```http
POST /api/vulnerability/mobile/apk-analyze
Content-Type: application/json

{
  "file": {
    "name": "app.apk",
    "size": 5242880
  }
}
```

#### Mobile App Scan
```http
POST /api/vulnerability/mobile/scan
Content-Type: application/json

{
  "platform": "android",
  "appId": "com.example.app"
}
```

### Obfuscation

#### Obfuscate Script
```http
POST /api/vulnerability/obfuscation/script
Content-Type: application/json

{
  "code": "console.log('Hello World');",
  "language": "javascript"
}
```

#### Encode Payload
```http
POST /api/vulnerability/obfuscation/encode
Content-Type: application/json

{
  "payload": "malicious code here",
  "encodingType": "base64"
}
```

**Encoding Types:** `base64`, `hex`, `url`, `unicode`

### Post-Exploitation

#### Privilege Escalation
```http
GET /api/vulnerability/post-exploit/privesc/linux?method=auto
```

#### Persistence Techniques
```http
GET /api/vulnerability/post-exploit/persistence/windows
```

#### Data Exfiltration
```http
POST /api/vulnerability/post-exploit/exfiltration
Content-Type: application/json

{
  "method": "http"
}
```

**Methods:** `http`, `dns`, `ftp`, `icmp`

### AI Assistant

#### Chat with AI
```http
POST /api/vulnerability/ai/chat
Content-Type: application/json

{
  "message": "How do I test for SQL injection?",
  "sessionId": "user-session-123"
}
```

#### Get Conversation History
```http
GET /api/vulnerability/ai/history/:sessionId
```

#### Clear Conversation
```http
DELETE /api/vulnerability/ai/history/:sessionId
```

## 🔒 Security Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```env
# Server Configuration
PORT=3001
NODE_ENV=production
HOST=0.0.0.0

# Security
API_KEY_SECRET=your_secure_random_string_here
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# External API Keys (Optional)
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
HUNTER_IO_API_KEY=your_hunter_key

# CORS Settings
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
```

### Security Features

- ✅ **Helmet.js** - Security headers
- ✅ **CORS** - Cross-origin resource sharing control
- ✅ **Rate Limiting** - Request throttling
- ✅ **Input Validation** - Comprehensive input sanitization
- ✅ **Error Handling** - Secure error responses
- ✅ **Logging** - Detailed security logging

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm test -- --coverage
```

## 📊 Performance

- Optimized for high-concurrency scanning
- Asynchronous operations for non-blocking I/O
- Connection pooling for database operations
- Caching for frequently accessed data

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Change PORT in .env file
PORT=3002
```

### Permission Denied on Linux
```bash
# Some scans require elevated privileges
sudo npm start
```

### Module Not Found
```bash
# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Use ES6+ features
- Follow ESLint configuration
- Add JSDoc comments for functions
- Write tests for new features

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security best practices
- The cybersecurity community for tools and techniques
- Open source contributors

## 📞 Support

- **Documentation**: [API Docs](http://localhost:3001/api)
- **Issues**: [GitHub Issues](https://github.com/yourusername/cyberrecon-arsenal/issues)
- **Security**: Report security vulnerabilities privately

## 🗺️ Roadmap

- [ ] Database integration for scan history
- [ ] User authentication and authorization
- [ ] Advanced reporting (PDF, HTML, JSON)
- [ ] Webhook integrations
- [ ] Scheduled automated scans
- [ ] Integration with SIEM systems
- [ ] Machine learning for anomaly detection
- [ ] Mobile app for iOS/Android
- [ ] Kubernetes deployment support

## ⭐ Star History

If you find this project useful, please consider giving it a star!

---

**Built with ❤️ by the CyberRecon Arsenal Team**

*Making cybersecurity accessible to everyone*
