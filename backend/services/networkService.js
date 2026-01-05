import net from 'net';
import { logger } from '../config/logger.js';
import { AppError } from '../middleware/errorHandler.js';

export class NetworkService {
  constructor() {
    this.commonPorts = {
      21: 'FTP',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      143: 'IMAP',
      443: 'HTTPS',
      445: 'SMB',
      3306: 'MySQL',
      3389: 'RDP',
      5432: 'PostgreSQL',
      5900: 'VNC',
      6379: 'Redis',
      8080: 'HTTP-Proxy',
      8443: 'HTTPS-Alt',
      27017: 'MongoDB'
    };
  }

  async scanPort(host, port, timeout = 3000) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let isResolved = false;

      const cleanup = () => {
        if (!isResolved) {
          isResolved = true;
          socket.destroy();
        }
      };

      socket.setTimeout(timeout);

      socket.on('connect', () => {
        cleanup();
        resolve({
          port,
          status: 'open',
          service: this.commonPorts[port] || 'unknown'
        });
      });

      socket.on('timeout', () => {
        cleanup();
        resolve({
          port,
          status: 'filtered',
          service: this.commonPorts[port] || 'unknown'
        });
      });

      socket.on('error', () => {
        cleanup();
        resolve({
          port,
          status: 'closed',
          service: this.commonPorts[port] || 'unknown'
        });
      });

      socket.connect(port, host);
    });
  }

  async scanPorts(host, startPort, endPort, options = {}) {
    try {
      logger.info(`Scanning ports ${startPort}-${endPort} on ${host}`);
      
      const timeout = options.timeout || 3000;
      const results = [];
      const scanPromises = [];

      for (let port = startPort; port <= endPort; port++) {
        scanPromises.push(this.scanPort(host, port, timeout));
      }

      const scanResults = await Promise.all(scanPromises);
      
      return {
        host,
        startPort,
        endPort,
        timestamp: new Date().toISOString(),
        totalScanned: scanResults.length,
        openPorts: scanResults.filter(r => r.status === 'open'),
        closedPorts: scanResults.filter(r => r.status === 'closed').length,
        filteredPorts: scanResults.filter(r => r.status === 'filtered').length,
        results: options.serviceDetection !== false ? scanResults.filter(r => r.status === 'open') : scanResults
      };
    } catch (error) {
      logger.error(`Port scan failed for ${host}: ${error.message}`);
      throw new AppError(`Port scan failed: ${error.message}`, 500);
    }
  }

  async quickScan(host) {
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080];
    return this.scanPorts(host, commonPorts[0], commonPorts[commonPorts.length - 1], { serviceDetection: true });
  }

  async grabBanner(host, port, timeout = 5000) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = '';
      let isResolved = false;

      const cleanup = () => {
        if (!isResolved) {
          isResolved = true;
          socket.destroy();
        }
      };

      socket.setTimeout(timeout);

      socket.on('connect', () => {
        // Send a generic request to trigger a banner
        socket.write('HEAD / HTTP/1.0\r\n\r\n');
      });

      socket.on('data', (data) => {
        banner += data.toString();
        // Give some time for more data, then resolve
        setTimeout(() => {
          cleanup();
          resolve({
            port,
            banner: banner.trim(),
            service: this.commonPorts[port] || 'unknown',
            success: true
          });
        }, 500);
      });

      socket.on('timeout', () => {
        cleanup();
        resolve({
          port,
          banner: banner.trim() || 'No banner received',
          service: this.commonPorts[port] || 'unknown',
          success: false
        });
      });

      socket.on('error', (error) => {
        cleanup();
        resolve({
          port,
          banner: `Error: ${error.message}`,
          service: this.commonPorts[port] || 'unknown',
          success: false
        });
      });

      socket.connect(port, host);
    });
  }

  async serviceDetection(host, ports) {
    try {
      logger.info(`Detecting services on ${host} for ports: ${ports.join(', ')}`);
      
      const detectionPromises = ports.map(port => this.grabBanner(host, port));
      const results = await Promise.all(detectionPromises);

      return {
        host,
        timestamp: new Date().toISOString(),
        services: results.filter(r => r.success),
        totalDetected: results.filter(r => r.success).length
      };
    } catch (error) {
      logger.error(`Service detection failed for ${host}: ${error.message}`);
      throw new AppError(`Service detection failed: ${error.message}`, 500);
    }
  }

  async networkMap(host, options = {}) {
    try {
      logger.info(`Creating network map for ${host}`);
      
      // Quick port scan
      const portScan = await this.quickScan(host);
      
      // Service detection on open ports
      const openPorts = portScan.openPorts.map(p => p.port);
      let services = { services: [], totalDetected: 0 };
      
      if (openPorts.length > 0 && options.serviceDetection !== false) {
        services = await this.serviceDetection(host, openPorts);
      }

      return {
        host,
        timestamp: new Date().toISOString(),
        portScan,
        serviceDetection: services,
        summary: {
          totalOpenPorts: portScan.openPorts.length,
          totalServices: services.totalDetected,
          criticalServices: services.services.filter(s => 
            [21, 23, 3389, 5900].includes(s.port)
          ).length
        }
      };
    } catch (error) {
      logger.error(`Network mapping failed for ${host}: ${error.message}`);
      throw new AppError(`Network mapping failed: ${error.message}`, 500);
    }
  }
}

export default new NetworkService();
