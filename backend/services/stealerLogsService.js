import axios from 'axios';
import { logger } from '../config/logger.js';
import { AppError } from '../middleware/errorHandler.js';

export class StealerLogsService {
  constructor() {
    this.baseUrl = 'https://api.stealerlo.gs';
    this.apiKey = process.env.STEALERLOG_API_KEY || null;
  }

  getHeaders() {
    if (!this.apiKey) {
      throw new AppError('Stealerlo.gs API key not configured. Set STEALERLOG_API_KEY in .env', 500);
    }
    return {
      'X-API-Key': this.apiKey,
      'Content-Type': 'application/json'
    };
  }

  async search(query, type, options = {}) {
    try {
      logger.info(`Stealerlo.gs search: ${type} - ${query}`);
      
      const payload = {
        query,
        type,
        limit: options.limit || 100,
        offset: options.offset || 0,
        useRegex: options.useRegex || false,
        wildcard: options.wildcard || false,
        ...((options.dateFrom || options.dateTo) && {
          dateFrom: options.dateFrom,
          dateTo: options.dateTo
        })
      };

      const response = await axios.post(`${this.baseUrl}/search`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        data: response.data,
        query,
        type,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs search failed: ${error.message}`);
      
      if (error.response?.status === 429) {
        throw new AppError('Rate limit exceeded on Stealerlo.gs API', 429);
      }
      
      throw new AppError(`Stealerlo.gs search failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async multiSearch(terms, types, options = {}) {
    try {
      logger.info(`Stealerlo.gs multi-search: ${terms.length} terms across ${types.length} types`);
      
      const payload = {
        terms,
        types,
        operator: options.operator || 'OR',
        limit: options.limit || 100,
        offset: options.offset || 0,
        ...((options.dateFrom || options.dateTo) && {
          dateFrom: options.dateFrom,
          dateTo: options.dateTo
        })
      };

      const response = await axios.post(`${this.baseUrl}/search`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        data: response.data,
        terms,
        types,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs multi-search failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs multi-search failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async hashSearch(hashes) {
    try {
      logger.info(`Stealerlo.gs hash search: ${hashes.length} hashes`);
      
      const payload = {
        terms: hashes
      };

      const response = await axios.post(`${this.baseUrl}/hashsearch`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        data: response.data,
        hashCount: hashes.length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs hash search failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs hash search failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async ipLookup(ips) {
    try {
      logger.info(`Stealerlo.gs IP lookup: ${ips.length} IPs`);
      
      const payload = {
        terms: ips
      };

      const response = await axios.post(`${this.baseUrl}/iplookup`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        data: response.data,
        ipCount: ips.length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs IP lookup failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs IP lookup failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async phoneLookup(phones, countryCode = null) {
    try {
      logger.info(`Stealerlo.gs phone lookup: ${phones.length} phones`);
      
      const payload = {
        terms: phones,
        ...(countryCode && { countryCode })
      };

      const response = await axios.post(`${this.baseUrl}/phonelookup`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        data: response.data,
        phoneCount: phones.length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs phone lookup failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs phone lookup failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async getCount(query = null, type = null) {
    try {
      if (!query && !type) {
        // Get total database count
        const response = await axios.get(`${this.baseUrl}/count`, {
          headers: this.getHeaders(),
          timeout: 10000
        });
        
        return {
          success: true,
          totalRecords: response.data.count,
          timestamp: new Date().toISOString()
        };
      }

      // Get count for specific query
      const payload = { query, type };
      const response = await axios.post(`${this.baseUrl}/count`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        count: response.data.count,
        query,
        type,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs count failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs count failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async getDetailedCount(query, type, options = {}) {
    try {
      logger.info(`Stealerlo.gs detailed count: ${type} - ${query}`);
      
      const payload = {
        query,
        type,
        useRegex: options.useRegex || false,
        ...((options.dateFrom || options.dateTo) && {
          dateFrom: options.dateFrom,
          dateTo: options.dateTo
        })
      };

      const response = await axios.post(`${this.baseUrl}/count/detailed`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        data: response.data,
        query,
        type,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs detailed count failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs detailed count failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async getMachineInfo(uuid) {
    try {
      logger.info(`Stealerlo.gs machine info: ${uuid}`);
      
      const response = await axios.get(`${this.baseUrl}/machineinfo`, {
        params: { uuid },
        headers: this.getHeaders(),
        timeout: 20000
      });

      return {
        success: true,
        data: response.data,
        uuid,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs machine info failed: ${error.message}`);
      
      if (error.response?.status === 404) {
        throw new AppError('Machine not found', 404);
      }
      
      throw new AppError(`Stealerlo.gs machine info failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async getMachineFiles(machineId, fileType) {
    try {
      logger.info(`Stealerlo.gs machine files: ${machineId} - ${fileType}`);
      
      const validTypes = ['common_files', 'passwords', 'all_passwords', 'all_txt_files'];
      if (!validTypes.includes(fileType)) {
        throw new AppError(`Invalid file type. Must be one of: ${validTypes.join(', ')}`, 400);
      }

      const response = await axios.get(`${this.baseUrl}/machine-files`, {
        params: {
          machine_id: machineId,
          type: fileType
        },
        headers: this.getHeaders(),
        timeout: 30000,
        responseType: fileType === 'common_files' ? 'arraybuffer' : 'json'
      });

      return {
        success: true,
        data: response.data,
        machineId,
        fileType,
        contentType: response.headers['content-type'],
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs machine files failed: ${error.message}`);
      
      if (error.response?.status === 404) {
        throw new AppError('Files not found for this machine', 404);
      }
      
      throw new AppError(`Stealerlo.gs machine files failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async socialMediaAnalysis(query, platform = 'all') {
    try {
      logger.info(`Stealerlo.gs social media analysis: ${query}`);
      
      const payload = {
        query,
        platform
      };

      const response = await axios.post(`${this.baseUrl}/analyze`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        data: response.data,
        query,
        platform,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs social media analysis failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs social media analysis failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async proxySearch(provider, action, query) {
    try {
      logger.info(`Stealerlo.gs proxy: ${provider} - ${action}`);
      
      const validProviders = ['snusbase', 'shodan', 'osintdog'];
      if (!validProviders.includes(provider.toLowerCase())) {
        throw new AppError(`Unsupported provider. Available: ${validProviders.join(', ')}`, 400);
      }

      const payload = {
        provider,
        action,
        query
      };

      const response = await axios.post(`${this.baseUrl}/source`, payload, {
        headers: this.getHeaders(),
        timeout: 45000
      });

      return {
        success: true,
        provider,
        action,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs proxy search failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs proxy search failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async searchLogs(query, filePattern = null) {
    try {
      logger.info(`Stealerlo.gs logs search: ${query}`);
      
      const payload = {
        query,
        ...(filePattern && { filePattern })
      };

      const response = await axios.post(`${this.baseUrl}/search/logs`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        jobId: response.data.jobId,
        status: response.data.status,
        message: response.data.message,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs logs search failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs logs search failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async getLogsSearchStatus(jobId, cursor = null) {
    try {
      logger.info(`Stealerlo.gs logs search status: ${jobId}`);
      
      const params = { jobId };
      if (cursor) params.cursor = cursor;

      const response = await axios.get(`${this.baseUrl}/search/logs`, {
        params,
        headers: this.getHeaders(),
        timeout: 20000
      });

      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs logs search status failed: ${error.message}`);
      
      if (error.response?.status === 404) {
        throw new AppError('Job not found', 404);
      }
      
      throw new AppError(`Stealerlo.gs logs search status failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async generateUUIDSearch(count = 10, filters = {}) {
    try {
      logger.info(`Stealerlo.gs generate UUID search: ${count} UUIDs`);
      
      if (count < 1 || count > 100) {
        throw new AppError('Count must be between 1 and 100', 400);
      }

      const payload = {
        count,
        ...(Object.keys(filters).length > 0 && { filters })
      };

      const response = await axios.post(`${this.baseUrl}/generate-uuid-search`, payload, {
        headers: this.getHeaders(),
        timeout: 30000
      });

      return {
        success: true,
        jobId: response.data.jobId,
        status: response.data.status,
        count,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs generate UUID search failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs generate UUID search failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async getUUIDSearchStatus(jobId) {
    try {
      logger.info(`Stealerlo.gs UUID search status: ${jobId}`);
      
      const response = await axios.get(`${this.baseUrl}/generate-uuid-search`, {
        params: { jobId },
        headers: this.getHeaders(),
        timeout: 20000
      });

      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs UUID search status failed: ${error.message}`);
      
      if (error.response?.status === 404) {
        throw new AppError('Job not found', 404);
      }
      
      throw new AppError(`Stealerlo.gs UUID search status failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async searchDomainFiles(domain, fileTypes = [], options = {}) {
    try {
      logger.info(`Stealerlo.gs domain files search: ${domain}`);
      
      const payload = {
        domain,
        ...(fileTypes.length > 0 && { fileTypes }),
        limit: options.limit || 100,
        async: options.async !== false // Default to async
      };

      const response = await axios.post(`${this.baseUrl}/search-domain-files`, payload, {
        headers: this.getHeaders(),
        timeout: options.async === false ? 60000 : 30000
      });

      // Check if response is immediate (synchronous) or job-based (async)
      if (response.data.status === 'completed') {
        return {
          success: true,
          mode: 'synchronous',
          data: response.data,
          timestamp: new Date().toISOString()
        };
      }

      return {
        success: true,
        mode: 'asynchronous',
        jobId: response.data.jobId,
        status: response.data.status,
        domain,
        fileTypes,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs domain files search failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs domain files search failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async getDomainFilesStatus(jobId) {
    try {
      logger.info(`Stealerlo.gs domain files status: ${jobId}`);
      
      const response = await axios.get(`${this.baseUrl}/search-domain-files`, {
        params: { jobId },
        headers: this.getHeaders(),
        timeout: 20000
      });

      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs domain files status failed: ${error.message}`);
      
      if (error.response?.status === 404) {
        throw new AppError('Job not found', 404);
      }
      
      throw new AppError(`Stealerlo.gs domain files status failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async getIngestionLogs(options = {}) {
    try {
      logger.info('Stealerlo.gs ingestion logs');
      
      const params = {
        limit: options.limit || 50,
        offset: options.offset || 0,
        ...(options.dateFrom && { dateFrom: options.dateFrom }),
        ...(options.dateTo && { dateTo: options.dateTo })
      };

      const response = await axios.get(`${this.baseUrl}/ingestlog`, {
        params,
        headers: this.getHeaders(),
        timeout: 20000
      });

      return {
        success: true,
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs ingestion logs failed: ${error.message}`);
      throw new AppError(`Stealerlo.gs ingestion logs failed: ${error.message}`, error.response?.status || 500);
    }
  }

  async healthCheck() {
    try {
      const response = await axios.get(`${this.baseUrl}/health`, {
        timeout: 5000
      });

      return {
        success: true,
        status: response.data.status,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Stealerlo.gs health check failed: ${error.message}`);
      throw new AppError('Stealerlo.gs API is unavailable', 503);
    }
  }
}

export default new StealerLogsService();
