import https from 'https';
import http from 'http';
import axios from 'axios';
import { logger } from '../config/logger.js';
import { AppError } from '../middleware/errorHandler.js';

export class WebService {
  async getSSLCertificate(hostname, port = 443) {
    return new Promise((resolve, reject) => {
      const options = {
        host: hostname,
        port: port,
        method: 'GET',
        rejectUnauthorized: false,
        agent: false
      };

      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        
        if (cert && Object.keys(cert).length > 0) {
          resolve({
            subject: cert.subject,
            issuer: cert.issuer,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            serialNumber: cert.serialNumber,
            fingerprint: cert.fingerprint,
            altNames: cert.subjectaltname,
            protocol: res.socket.getProtocol(),
            cipher: res.socket.getCipher()
          });
        } else {
          reject(new Error('No certificate found'));
        }
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.end();
    });
  }

  async analyzeSSL(url) {
    try {
      logger.info(`Analyzing SSL/TLS for ${url}`);
      
      const hostname = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
      const certInfo = await this.getSSLCertificate(hostname);
      
      const validTo = new Date(certInfo.validTo);
      const now = new Date();
      const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

      return {
        hostname,
        certificate: certInfo,
        validation: {
          isValid: validTo > now,
          daysUntilExpiry,
          expiryStatus: daysUntilExpiry < 0 ? 'expired' :
                        daysUntilExpiry < 30 ? 'expiring-soon' : 'valid'
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`SSL analysis failed for ${url}: ${error.message}`);
      throw new AppError(`SSL analysis failed: ${error.message}`, 500);
    }
  }

  async getHTTPHeaders(url) {
    try {
      logger.info(`Fetching HTTP headers for ${url}`);
      
      const fullUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await axios.get(fullUrl, {
        maxRedirects: 5,
        timeout: 10000,
        validateStatus: () => true
      });

      return {
        url: fullUrl,
        statusCode: response.status,
        statusText: response.statusText,
        headers: response.headers,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`HTTP headers fetch failed for ${url}: ${error.message}`);
      throw new AppError(`Failed to fetch HTTP headers: ${error.message}`, 500);
    }
  }

  async checkSecurityHeaders(url) {
    try {
      logger.info(`Checking security headers for ${url}`);
      
      const headerData = await this.getHTTPHeaders(url);
      const headers = headerData.headers;

      const securityHeaders = {
        'strict-transport-security': headers['strict-transport-security'] || null,
        'content-security-policy': headers['content-security-policy'] || null,
        'x-frame-options': headers['x-frame-options'] || null,
        'x-content-type-options': headers['x-content-type-options'] || null,
        'x-xss-protection': headers['x-xss-protection'] || null,
        'referrer-policy': headers['referrer-policy'] || null,
        'permissions-policy': headers['permissions-policy'] || null
      };

      const score = Object.values(securityHeaders).filter(v => v !== null).length;
      const maxScore = Object.keys(securityHeaders).length;

      return {
        url,
        securityHeaders,
        score: {
          current: score,
          maximum: maxScore,
          percentage: Math.round((score / maxScore) * 100)
        },
        recommendations: this.getSecurityRecommendations(securityHeaders),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Security headers check failed for ${url}: ${error.message}`);
      throw new AppError(`Security headers check failed: ${error.message}`, 500);
    }
  }

  getSecurityRecommendations(headers) {
    const recommendations = [];

    if (!headers['strict-transport-security']) {
      recommendations.push({
        header: 'Strict-Transport-Security',
        severity: 'high',
        description: 'HSTS header is missing. This helps prevent man-in-the-middle attacks.',
        recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
      });
    }

    if (!headers['content-security-policy']) {
      recommendations.push({
        header: 'Content-Security-Policy',
        severity: 'high',
        description: 'CSP header is missing. This helps prevent XSS attacks.',
        recommendation: 'Implement a Content-Security-Policy appropriate for your application'
      });
    }

    if (!headers['x-frame-options']) {
      recommendations.push({
        header: 'X-Frame-Options',
        severity: 'medium',
        description: 'X-Frame-Options header is missing. This helps prevent clickjacking attacks.',
        recommendation: 'Add: X-Frame-Options: DENY or SAMEORIGIN'
      });
    }

    if (!headers['x-content-type-options']) {
      recommendations.push({
        header: 'X-Content-Type-Options',
        severity: 'medium',
        description: 'X-Content-Type-Options header is missing.',
        recommendation: 'Add: X-Content-Type-Options: nosniff'
      });
    }

    if (!headers['referrer-policy']) {
      recommendations.push({
        header: 'Referrer-Policy',
        severity: 'low',
        description: 'Referrer-Policy header is missing.',
        recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin'
      });
    }

    return recommendations;
  }

  async detectTechnology(url) {
    try {
      logger.info(`Detecting technology for ${url}`);
      
      const fullUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await axios.get(fullUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const headers = response.headers;
      const body = response.data;
      const technologies = [];

      // Server detection
      if (headers['server']) {
        technologies.push({
          name: 'Server',
          value: headers['server'],
          category: 'Web Server'
        });
      }

      // Powered-by detection
      if (headers['x-powered-by']) {
        technologies.push({
          name: 'Powered By',
          value: headers['x-powered-by'],
          category: 'Backend'
        });
      }

      // Framework detection from HTML
      if (typeof body === 'string') {
        if (body.includes('wp-content') || body.includes('wordpress')) {
          technologies.push({ name: 'WordPress', category: 'CMS' });
        }
        if (body.includes('Joomla')) {
          technologies.push({ name: 'Joomla', category: 'CMS' });
        }
        if (body.includes('Drupal')) {
          technologies.push({ name: 'Drupal', category: 'CMS' });
        }
        if (body.includes('react')) {
          technologies.push({ name: 'React', category: 'Frontend Framework' });
        }
        if (body.includes('vue.js') || body.includes('Vue')) {
          technologies.push({ name: 'Vue.js', category: 'Frontend Framework' });
        }
        if (body.includes('angular')) {
          technologies.push({ name: 'Angular', category: 'Frontend Framework' });
        }
      }

      return {
        url: fullUrl,
        technologies,
        totalDetected: technologies.length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Technology detection failed for ${url}: ${error.message}`);
      throw new AppError(`Technology detection failed: ${error.message}`, 500);
    }
  }
}

export default new WebService();
