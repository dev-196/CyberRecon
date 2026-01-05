# COMPLETE CYBERRECON PROJECT - FUNCTION-BY-FUNCTION ANALYSIS
**Analysis Date**: January 5, 2024
**Total Services**: 13
**Total Lines**: 3,840 (backend services only)

---

## PROJECT STRUCTURE

```
CyberRecon/
├── backend/
│   ├── services/           (13 services)
│   ├── routes/            (6 route files)
│   ├── middleware/        (1 error handler)
│   ├── config/            (1 logger)
│   └── utils/             (1 validation)
├── templates/
│   └── telegram-stealer.ps1  (3,895 lines)
└── frontend/              (React compiled)
```

---

# SERVICE-BY-SERVICE DEEP ANALYSIS

=== Analyzing aiAssistantService.js ===

**File**: backend/services/aiAssistantService.js
**Lines**: 138

### Functions:
29:  async chat(message, sessionId = 'default') {
106:  async getConversationHistory(sessionId) {
122:  async clearConversation(sessionId) {

---

=== Analyzing domainService.js ===

**File**: backend/services/domainService.js
**Lines**: 201

### Functions:
16:  async getWhoisInfo(domain) {
39:  async getDNSRecords(domain) {
98:  async discoverSubdomains(domain) {
140:  async getDomainReputation(domain) {

---

=== Analyzing exploitationService.js ===

**File**: backend/services/exploitationService.js
**Lines**: 351

### Functions:
206:  async generatePayload(type, options = {}) {
277:  async listExploits(category = 'all', platform = 'all') {
331:  async generateCustomExploit(target, vulnerability) {

---

=== Analyzing intelligenceService.js ===

**File**: backend/services/intelligenceService.js
**Lines**: 164

### Functions:
7:  async checkIPReputation(ip) {
47:  async validateEmail(email) {
82:  async checkBreaches(email) {
113:  async phoneLookup(phoneNumber) {
141:  async generateTempMail() {

---

=== Analyzing mobileSecurityService.js ===

**File**: backend/services/mobileSecurityService.js
**Lines**: 161

### Functions:
5:  async analyzeAPK(apkFile) {
57:  async scanMobileApp(platform, appId) {
92:  async iosSecurityAnalysis(ipaFile) {
127:  async mobileForensics(deviceType, options = {}) {

---

=== Analyzing networkService.js ===

**File**: backend/services/networkService.js
**Lines**: 222

### Functions:
29:  async scanPort(host, port, timeout = 3000) {
74:  async scanPorts(host, startPort, endPort, options = {}) {
105:  async quickScan(host) {
110:  async grabBanner(host, port, timeout = 5000) {
168:  async serviceDetection(host, ports) {
187:  async networkMap(host, options = {}) {

---

=== Analyzing obfuscationService.js ===

**File**: backend/services/obfuscationService.js
**Lines**: 145

### Functions:
61:  async encodePayload(payload, encodingType = 'base64') {
98:  async ps1ToExe(scriptContent, outputName = 'payload.exe') {
118:  async obfuscateExecutable(file, level = 'medium') {

---

=== Analyzing osintService.js ===

**File**: backend/services/osintService.js
**Lines**: 211

### Functions:
7:  async harvestEmails(domain) {
51:  async socialMediaRecon(target) {
64:        platforms.map(async (platform) => {
102:  async extractMetadata(url) {
165:  async dataBreachCheck(email) {
184:  async comprehensiveOSINT(target, type = 'domain') {

---

=== Analyzing postExploitationService.js ===

**File**: backend/services/postExploitationService.js
**Lines**: 982

### Functions:
5:  async privilegeEscalation(platform, method = 'auto') {
77:  async persistenceTechniques(platform) {
823:  async dataExfiltration(method = 'http', options = {}) {
937:  async lateralMovement(network, technique = 'pass-the-hash') {

---

=== Analyzing stealerLogsService.js ===

**File**: backend/services/stealerLogsService.js
**Lines**: 590

### Functions:
21:  async search(query, type, options = {}) {
61:  async multiSearch(terms, types, options = {}) {
95:  async hashSearch(hashes) {
120:  async ipLookup(ips) {
145:  async phoneLookup(phones, countryCode = null) {
171:  async getCount(query = null, type = null) {
207:  async getDetailedCount(query, type, options = {}) {
239:  async getMachineInfo(uuid) {
266:  async getMachineFiles(machineId, fileType) {
304:  async socialMediaAnalysis(query, platform = 'all') {
331:  async proxySearch(provider, action, query) {
364:  async searchLogs(query, filePattern = null) {
391:  async getLogsSearchStatus(jobId, cursor = null) {
420:  async generateUUIDSearch(count = 10, filters = {}) {
451:  async getUUIDSearchStatus(jobId) {
477:  async searchDomainFiles(domain, fileTypes = [], options = {}) {
518:  async getDomainFilesStatus(jobId) {
544:  async getIngestionLogs(options = {}) {
572:  async healthCheck() {

---

=== Analyzing vulnerabilityService.js ===

**File**: backend/services/vulnerabilityService.js
**Lines**: 177

### Functions:
11:  async searchCVE(keyword, limit = 10) {
47:  async getCVEDetails(cveId) {
88:  async searchExploits(keyword, limit = 20) {
127:  async vulnerabilityScan(target, scanType = 'basic') {

---

=== Analyzing webAppService.js ===

**File**: backend/services/webAppService.js
**Lines**: 245

### Functions:
6:  async sqlInjectionScan(url, params = {}) {
82:  async xssScan(url) {
144:  async directoryBruteforce(url, wordlist = 'common') {
196:  async comprehensiveWebScan(url) {

---

=== Analyzing webService.js ===

**File**: backend/services/webService.js
**Lines**: 253

### Functions:
8:  async getSSLCertificate(hostname, port = 443) {
46:  async analyzeSSL(url) {
74:  async getHTTPHeaders(url) {
98:  async checkSecurityHeaders(url) {
186:  async detectTechnology(url) {

---

