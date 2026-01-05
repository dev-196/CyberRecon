import axios from 'axios';
import { logger } from '../config/logger.js';
import { AppError } from '../middleware/errorHandler.js';

export class WebAppService {
  async sqlInjectionScan(url, params = {}) {
    try {
      logger.info(`Running SQL injection scan on ${url}`);
      
      const payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2"
      ];

      const vulnerabilities = [];
      const testResults = [];

      for (const payload of payloads) {
        try {
          // Test each parameter with payload
          const testUrl = `${url}?test=${encodeURIComponent(payload)}`;
          const response = await axios.get(testUrl, {
            timeout: 5000,
            validateStatus: () => true
          });

          const indicators = [
            'SQL syntax',
            'mysql_fetch',
            'Warning: mysql',
            'pg_query',
            'ORA-',
            'Microsoft SQL',
            'ODBC Error'
          ];

          const hasIndicator = indicators.some(ind => 
            response.data?.toString().includes(ind)
          );

          testResults.push({
            payload,
            vulnerable: hasIndicator,
            statusCode: response.status
          });

          if (hasIndicator) {
            vulnerabilities.push({
              type: 'SQL Injection',
              payload,
              severity: 'HIGH',
              description: 'Potential SQL injection vulnerability detected'
            });
          }
        } catch (error) {
          // Continue with next payload
        }
      }

      return {
        url,
        timestamp: new Date().toISOString(),
        vulnerabilities,
        testResults,
        summary: {
          totalTests: payloads.length,
          potentialVulnerabilities: vulnerabilities.length
        }
      };
    } catch (error) {
      logger.error(`SQL injection scan failed: ${error.message}`);
      throw new AppError(`SQL injection scan failed: ${error.message}`, 500);
    }
  }

  async xssScan(url) {
    try {
      logger.info(`Running XSS scan on ${url}`);
      
      const payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<body onload=alert("XSS")>'
      ];

      const vulnerabilities = [];
      const testResults = [];

      for (const payload of payloads) {
        try {
          const testUrl = `${url}?q=${encodeURIComponent(payload)}`;
          const response = await axios.get(testUrl, {
            timeout: 5000,
            validateStatus: () => true
          });

          // Check if payload is reflected in response
          const reflected = response.data?.toString().includes(payload.substring(0, 20));

          testResults.push({
            payload: payload.substring(0, 50) + '...',
            reflected,
            statusCode: response.status
          });

          if (reflected) {
            vulnerabilities.push({
              type: 'Cross-Site Scripting (XSS)',
              payload: payload.substring(0, 50) + '...',
              severity: 'HIGH',
              description: 'Potential XSS vulnerability - payload reflected in response'
            });
          }
        } catch (error) {
          // Continue with next payload
        }
      }

      return {
        url,
        timestamp: new Date().toISOString(),
        vulnerabilities,
        testResults,
        summary: {
          totalTests: payloads.length,
          potentialVulnerabilities: vulnerabilities.length
        }
      };
    } catch (error) {
      logger.error(`XSS scan failed: ${error.message}`);
      throw new AppError(`XSS scan failed: ${error.message}`, 500);
    }
  }

  async directoryBruteforce(url, wordlist = 'common') {
    try {
      logger.info(`Running directory bruteforce on ${url}`);
      
      const commonDirs = [
        'admin', 'administrator', 'login', 'wp-admin', 'dashboard',
        'api', 'backup', 'config', 'database', 'uploads',
        'images', 'includes', 'js', 'css', 'assets',
        'test', 'dev', 'staging', 'tmp', 'temp',
        'old', 'backup', 'backups', 'db', 'sql'
      ];

      const foundDirs = [];
      const baseUrl = url.replace(/\/$/, '');

      for (const dir of commonDirs) {
        try {
          const testUrl = `${baseUrl}/${dir}`;
          const response = await axios.head(testUrl, {
            timeout: 3000,
            maxRedirects: 0,
            validateStatus: () => true
          });

          if (response.status === 200 || response.status === 301 || response.status === 302) {
            foundDirs.push({
              path: `/${dir}`,
              statusCode: response.status,
              redirectTo: response.headers.location || null
            });
          }
        } catch (error) {
          // Directory doesn't exist or error, continue
        }
      }

      return {
        url,
        wordlist,
        timestamp: new Date().toISOString(),
        foundDirectories: foundDirs,
        summary: {
          totalTested: commonDirs.length,
          totalFound: foundDirs.length
        }
      };
    } catch (error) {
      logger.error(`Directory bruteforce failed: ${error.message}`);
      throw new AppError(`Directory bruteforce failed: ${error.message}`, 500);
    }
  }

  async comprehensiveWebScan(url) {
    try {
      logger.info(`Running comprehensive web scan on ${url}`);
      
      const results = {
        url,
        timestamp: new Date().toISOString(),
        scans: {}
      };

      // Run all scans
      try {
        results.scans.sqlInjection = await this.sqlInjectionScan(url);
      } catch (error) {
        results.scans.sqlInjection = { error: error.message };
      }

      try {
        results.scans.xss = await this.xssScan(url);
      } catch (error) {
        results.scans.xss = { error: error.message };
      }

      try {
        results.scans.directories = await this.directoryBruteforce(url);
      } catch (error) {
        results.scans.directories = { error: error.message };
      }

      // Calculate overall risk
      const totalVulns = 
        (results.scans.sqlInjection?.vulnerabilities?.length || 0) +
        (results.scans.xss?.vulnerabilities?.length || 0);

      results.summary = {
        totalVulnerabilities: totalVulns,
        riskLevel: totalVulns === 0 ? 'LOW' : 
                   totalVulns < 3 ? 'MEDIUM' : 'HIGH',
        foundDirectories: results.scans.directories?.foundDirectories?.length || 0
      };

      return results;
    } catch (error) {
      logger.error(`Comprehensive web scan failed: ${error.message}`);
      throw new AppError(`Comprehensive web scan failed: ${error.message}`, 500);
    }
  }
}

export default new WebAppService();
