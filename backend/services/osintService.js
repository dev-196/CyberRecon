import axios from 'axios';
import * as cheerio from 'cheerio';
import { logger } from '../config/logger.js';
import { AppError } from '../middleware/errorHandler.js';

export class OSINTService {
  async harvestEmails(domain) {
    try {
      logger.info(`Harvesting emails for domain ${domain}`);
      
      const emails = new Set();
      const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

      // Try to fetch and parse the website
      try {
        const url = domain.startsWith('http') ? domain : `https://${domain}`;
        const response = await axios.get(url, {
          timeout: 10000,
          validateStatus: () => true
        });

        if (response.data) {
          const matches = response.data.match(emailRegex);
          if (matches) {
            matches.forEach(email => emails.add(email.toLowerCase()));
          }
        }
      } catch (error) {
        logger.warn(`Could not fetch website for email harvesting: ${error.message}`);
      }

      // Common email patterns
      const commonPrefixes = ['info', 'contact', 'support', 'admin', 'hello', 'sales'];
      commonPrefixes.forEach(prefix => {
        emails.add(`${prefix}@${domain}`);
      });

      return {
        domain,
        totalFound: emails.size,
        emails: Array.from(emails),
        timestamp: new Date().toISOString(),
        note: 'Results include common email patterns. Verify before use.'
      };
    } catch (error) {
      logger.error(`Email harvesting failed for ${domain}: ${error.message}`);
      throw new AppError(`Email harvesting failed: ${error.message}`, 500);
    }
  }

  async socialMediaRecon(target) {
    try {
      logger.info(`Performing social media reconnaissance for ${target}`);
      
      const platforms = [
        { name: 'Twitter', url: `https://twitter.com/${target}`, checkMethod: 'profile' },
        { name: 'LinkedIn', url: `https://www.linkedin.com/in/${target}`, checkMethod: 'profile' },
        { name: 'GitHub', url: `https://github.com/${target}`, checkMethod: 'profile' },
        { name: 'Instagram', url: `https://www.instagram.com/${target}`, checkMethod: 'profile' },
        { name: 'Facebook', url: `https://www.facebook.com/${target}`, checkMethod: 'profile' }
      ];

      const results = await Promise.all(
        platforms.map(async (platform) => {
          try {
            const response = await axios.head(platform.url, {
              timeout: 5000,
              maxRedirects: 5,
              validateStatus: (status) => status < 500
            });

            return {
              platform: platform.name,
              url: platform.url,
              exists: response.status === 200,
              status: response.status
            };
          } catch (error) {
            return {
              platform: platform.name,
              url: platform.url,
              exists: false,
              status: 'error',
              error: error.message
            };
          }
        })
      );

      return {
        target,
        foundProfiles: results.filter(r => r.exists).length,
        profiles: results,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Social media recon failed for ${target}: ${error.message}`);
      throw new AppError(`Social media reconnaissance failed: ${error.message}`, 500);
    }
  }

  async extractMetadata(url) {
    try {
      logger.info(`Extracting metadata from ${url}`);
      
      const fullUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await axios.get(fullUrl, {
        timeout: 10000,
        validateStatus: () => true
      });

      const $ = cheerio.load(response.data);
      
      const metadata = {
        url: fullUrl,
        title: $('title').text() || null,
        description: $('meta[name="description"]').attr('content') || null,
        keywords: $('meta[name="keywords"]').attr('content') || null,
        author: $('meta[name="author"]').attr('content') || null,
        ogTitle: $('meta[property="og:title"]').attr('content') || null,
        ogDescription: $('meta[property="og:description"]').attr('content') || null,
        ogImage: $('meta[property="og:image"]').attr('content') || null,
        ogType: $('meta[property="og:type"]').attr('content') || null,
        twitterCard: $('meta[name="twitter:card"]').attr('content') || null,
        twitterSite: $('meta[name="twitter:site"]').attr('content') || null,
        canonical: $('link[rel="canonical"]').attr('href') || null,
        robots: $('meta[name="robots"]').attr('content') || null,
        generator: $('meta[name="generator"]').attr('content') || null,
        viewport: $('meta[name="viewport"]').attr('content') || null
      };

      // Extract all links
      const links = [];
      $('a').each((i, elem) => {
        const href = $(elem).attr('href');
        if (href) links.push(href);
      });

      // Extract all scripts
      const scripts = [];
      $('script').each((i, elem) => {
        const src = $(elem).attr('src');
        if (src) scripts.push(src);
      });

      return {
        metadata,
        links: {
          total: links.length,
          external: links.filter(l => l.startsWith('http')).length,
          internal: links.filter(l => !l.startsWith('http') && !l.startsWith('//')).length
        },
        scripts: {
          total: scripts.length,
          list: scripts.slice(0, 20) // First 20 scripts
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Metadata extraction failed for ${url}: ${error.message}`);
      throw new AppError(`Metadata extraction failed: ${error.message}`, 500);
    }
  }

  async dataBreachCheck(email) {
    try {
      logger.info(`Checking data breaches for ${email}`);
      
      // Note: This is a placeholder. In production, you would integrate with
      // services like Have I Been Pwned API
      return {
        email,
        breachesFound: 0,
        breaches: [],
        timestamp: new Date().toISOString(),
        note: 'This is a placeholder. Integrate with Have I Been Pwned API for real data.'
      };
    } catch (error) {
      logger.error(`Data breach check failed for ${email}: ${error.message}`);
      throw new AppError(`Data breach check failed: ${error.message}`, 500);
    }
  }

  async comprehensiveOSINT(target, type = 'domain') {
    try {
      logger.info(`Performing comprehensive OSINT for ${target}`);
      
      const results = {
        target,
        type,
        timestamp: new Date().toISOString()
      };

      if (type === 'domain') {
        results.emails = await this.harvestEmails(target);
        results.metadata = await this.extractMetadata(target);
      } else if (type === 'username') {
        results.socialMedia = await this.socialMediaRecon(target);
      } else if (type === 'email') {
        results.breaches = await this.dataBreachCheck(target);
      }

      return results;
    } catch (error) {
      logger.error(`Comprehensive OSINT failed for ${target}: ${error.message}`);
      throw new AppError(`Comprehensive OSINT failed: ${error.message}`, 500);
    }
  }
}

export default new OSINTService();
