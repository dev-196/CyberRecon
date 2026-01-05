import whois from 'whois-json';
import dns from 'dns';
import { promisify } from 'util';
import { logger } from '../config/logger.js';
import { AppError } from '../middleware/errorHandler.js';

const dnsResolve = promisify(dns.resolve);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveCname = promisify(dns.resolveCname);

export class DomainService {
  async getWhoisInfo(domain) {
    try {
      logger.info(`Fetching WHOIS information for ${domain}`);
      const whoisData = await whois(domain);
      
      return {
        domain,
        registrar: whoisData.registrar || 'Unknown',
        creationDate: whoisData.creationDate || null,
        expirationDate: whoisData.expirationDate || null,
        registrantOrganization: whoisData.registrantOrganization || 'Unknown',
        registrantCountry: whoisData.registrantCountry || 'Unknown',
        nameServers: whoisData.nameServers || [],
        status: whoisData.status || [],
        dnssec: whoisData.dnssec || 'unsigned',
        raw: whoisData
      };
    } catch (error) {
      logger.error(`WHOIS lookup failed for ${domain}: ${error.message}`);
      throw new AppError(`WHOIS lookup failed: ${error.message}`, 500);
    }
  }

  async getDNSRecords(domain) {
    try {
      logger.info(`Fetching DNS records for ${domain}`);
      
      const results = {
        domain,
        timestamp: new Date().toISOString(),
        records: {}
      };

      // A records (IPv4)
      try {
        results.records.A = await dnsResolve4(domain);
      } catch (error) {
        results.records.A = [];
      }

      // AAAA records (IPv6)
      try {
        results.records.AAAA = await dnsResolve6(domain);
      } catch (error) {
        results.records.AAAA = [];
      }

      // MX records
      try {
        results.records.MX = await dnsResolveMx(domain);
      } catch (error) {
        results.records.MX = [];
      }

      // NS records
      try {
        results.records.NS = await dnsResolveNs(domain);
      } catch (error) {
        results.records.NS = [];
      }

      // TXT records
      try {
        results.records.TXT = await dnsResolveTxt(domain);
      } catch (error) {
        results.records.TXT = [];
      }

      // CNAME records
      try {
        results.records.CNAME = await dnsResolveCname(domain);
      } catch (error) {
        results.records.CNAME = [];
      }

      return results;
    } catch (error) {
      logger.error(`DNS lookup failed for ${domain}: ${error.message}`);
      throw new AppError(`DNS lookup failed: ${error.message}`, 500);
    }
  }

  async discoverSubdomains(domain) {
    try {
      logger.info(`Discovering subdomains for ${domain}`);
      
      // Common subdomain prefixes
      const commonSubdomains = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'cpanel', 'whm', 'webdisk', 'ns', 'admin', 'blog', 'shop',
        'api', 'dev', 'staging', 'test', 'portal', 'vpn', 'remote',
        'cloud', 'git', 'cdn', 'static', 'assets', 'img', 'images',
        'mobile', 'm', 'support', 'help', 'secure', 'dashboard'
      ];

      const discoveredSubdomains = [];

      for (const subdomain of commonSubdomains) {
        const fullDomain = `${subdomain}.${domain}`;
        try {
          const addresses = await dnsResolve4(fullDomain);
          if (addresses && addresses.length > 0) {
            discoveredSubdomains.push({
              subdomain: fullDomain,
              addresses
            });
          }
        } catch (error) {
          // Subdomain doesn't exist, continue
        }
      }

      return {
        domain,
        totalFound: discoveredSubdomains.length,
        subdomains: discoveredSubdomains,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Subdomain discovery failed for ${domain}: ${error.message}`);
      throw new AppError(`Subdomain discovery failed: ${error.message}`, 500);
    }
  }

  async getDomainReputation(domain) {
    try {
      logger.info(`Checking domain reputation for ${domain}`);
      
      // Basic reputation checks
      const reputation = {
        domain,
        timestamp: new Date().toISOString(),
        checks: {}
      };

      // Check if domain resolves
      try {
        const addresses = await dnsResolve4(domain);
        reputation.checks.resolvable = addresses.length > 0;
      } catch (error) {
        reputation.checks.resolvable = false;
      }

      // Check for MX records (email capability)
      try {
        const mx = await dnsResolveMx(domain);
        reputation.checks.hasEmail = mx.length > 0;
      } catch (error) {
        reputation.checks.hasEmail = false;
      }

      // Check for SPF record
      try {
        const txt = await dnsResolveTxt(domain);
        reputation.checks.hasSPF = txt.some(record => 
          record.join('').includes('v=spf1')
        );
      } catch (error) {
        reputation.checks.hasSPF = false;
      }

      // Check for DMARC record
      try {
        const dmarc = await dnsResolveTxt(`_dmarc.${domain}`);
        reputation.checks.hasDMARC = dmarc.some(record => 
          record.join('').includes('v=DMARC1')
        );
      } catch (error) {
        reputation.checks.hasDMARC = false;
      }

      // Calculate basic reputation score
      const score = Object.values(reputation.checks).filter(v => v === true).length;
      reputation.score = (score / Object.keys(reputation.checks).length) * 100;
      reputation.rating = reputation.score >= 75 ? 'Good' : 
                          reputation.score >= 50 ? 'Fair' : 'Poor';

      return reputation;
    } catch (error) {
      logger.error(`Domain reputation check failed for ${domain}: ${error.message}`);
      throw new AppError(`Domain reputation check failed: ${error.message}`, 500);
    }
  }
}

export default new DomainService();
