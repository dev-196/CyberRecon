import express from 'express';
import stealerLogsService from '../services/stealerLogsService.js';
import { validateEmail } from '../utils/validation.js';

const router = express.Router();

// POST /api/stealerlogs/search - Main search endpoint
router.post('/search', async (req, res, next) => {
  try {
    const { query, type, limit, offset, useRegex, wildcard, dateFrom, dateTo } = req.body;
    
    if (!query || !type) {
      return res.status(400).json({ error: 'query and type are required' });
    }

    const validTypes = ['email', 'username', 'password', 'site', 'website', 'domain', 'phone', 'name', 'ip', 'uuid'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `Invalid type. Allowed: ${validTypes.join(', ')}` });
    }

    const result = await stealerLogsService.search(query, type, {
      limit,
      offset,
      useRegex,
      wildcard,
      dateFrom,
      dateTo
    });
    
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/multi-search - Multi-term/multi-type search
router.post('/multi-search', async (req, res, next) => {
  try {
    const { terms, types, operator, limit, offset, dateFrom, dateTo } = req.body;
    
    if (!terms || !Array.isArray(terms) || terms.length === 0) {
      return res.status(400).json({ error: 'terms array is required' });
    }

    if (!types || !Array.isArray(types) || types.length === 0) {
      return res.status(400).json({ error: 'types array is required' });
    }

    const result = await stealerLogsService.multiSearch(terms, types, {
      operator,
      limit,
      offset,
      dateFrom,
      dateTo
    });
    
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/hash-search - Search for hash plaintexts
router.post('/hash-search', async (req, res, next) => {
  try {
    const { hashes, terms } = req.body;
    const hashList = hashes || terms;
    
    if (!hashList || !Array.isArray(hashList) || hashList.length === 0) {
      return res.status(400).json({ error: 'hashes array is required' });
    }

    if (hashList.length > 100) {
      return res.status(400).json({ error: 'Maximum 100 hashes per request' });
    }

    const result = await stealerLogsService.hashSearch(hashList);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/ip-lookup - IP geolocation lookup
router.post('/ip-lookup', async (req, res, next) => {
  try {
    const { ips, terms } = req.body;
    const ipList = ips || terms;
    
    if (!ipList || !Array.isArray(ipList) || ipList.length === 0) {
      return res.status(400).json({ error: 'ips array is required' });
    }

    if (ipList.length > 100) {
      return res.status(400).json({ error: 'Maximum 100 IPs per request' });
    }

    const result = await stealerLogsService.ipLookup(ipList);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/phone-lookup - Reverse phone lookup
router.post('/phone-lookup', async (req, res, next) => {
  try {
    const { phones, terms, phone, countryCode, country_code } = req.body;
    let phoneList = phones || terms;
    
    if (phone && !phoneList) {
      phoneList = [phone];
    }
    
    if (!phoneList || !Array.isArray(phoneList) || phoneList.length === 0) {
      return res.status(400).json({ error: 'phones array is required' });
    }

    if (phoneList.length > 10) {
      return res.status(400).json({ error: 'Maximum 10 phone numbers per request' });
    }

    const code = countryCode || country_code;
    const result = await stealerLogsService.phoneLookup(phoneList, code);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/stealerlogs/count - Get total record count
router.get('/count', async (req, res, next) => {
  try {
    const result = await stealerLogsService.getCount();
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/count - Count search results
router.post('/count', async (req, res, next) => {
  try {
    const { query, type } = req.body;
    
    if (!query || !type) {
      return res.status(400).json({ error: 'query and type are required' });
    }

    const result = await stealerLogsService.getCount(query, type);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/count/detailed - Detailed count by source
router.post('/count/detailed', async (req, res, next) => {
  try {
    const { query, type, useRegex, dateFrom, dateTo } = req.body;
    
    if (!query || !type) {
      return res.status(400).json({ error: 'query and type are required' });
    }

    const result = await stealerLogsService.getDetailedCount(query, type, {
      useRegex,
      dateFrom,
      dateTo
    });
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/stealerlogs/machine-info/:uuid - Get machine information
router.get('/machine-info/:uuid', async (req, res, next) => {
  try {
    const { uuid } = req.params;
    
    if (!uuid) {
      return res.status(400).json({ error: 'UUID is required' });
    }

    const result = await stealerLogsService.getMachineInfo(uuid);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/stealerlogs/machine-files/:machineId/:fileType - Get machine files
router.get('/machine-files/:machineId/:fileType', async (req, res, next) => {
  try {
    const { machineId, fileType } = req.params;
    
    if (!machineId || !fileType) {
      return res.status(400).json({ error: 'machineId and fileType are required' });
    }

    const result = await stealerLogsService.getMachineFiles(machineId, fileType);
    
    // Handle binary data (common_files returns compressed archive)
    if (fileType === 'common_files' && Buffer.isBuffer(result.data)) {
      res.set('Content-Type', result.contentType);
      res.set('Content-Disposition', `attachment; filename="${machineId}_common_files.7z"`);
      return res.send(result.data);
    }
    
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/social-media - Social media analysis
router.post('/social-media', async (req, res, next) => {
  try {
    const { query, username, email, platform } = req.body;
    const searchQuery = query || username || email;
    
    if (!searchQuery) {
      return res.status(400).json({ error: 'query, username, or email is required' });
    }

    const result = await stealerLogsService.socialMediaAnalysis(searchQuery, platform || 'all');
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/proxy - OSINT provider proxy
router.post('/proxy', async (req, res, next) => {
  try {
    const { provider, action, query } = req.body;
    
    if (!provider || !action || !query) {
      return res.status(400).json({ error: 'provider, action, and query are required' });
    }

    const result = await stealerLogsService.proxySearch(provider, action, query);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/logs-search - Start async logs search
router.post('/logs-search', async (req, res, next) => {
  try {
    const { query, term, filePattern, pattern } = req.body;
    const searchQuery = query || term;
    const searchPattern = filePattern || pattern;
    
    if (!searchQuery) {
      return res.status(400).json({ error: 'query is required' });
    }

    const result = await stealerLogsService.searchLogs(searchQuery, searchPattern);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/stealerlogs/logs-search/:jobId - Poll logs search status
router.get('/logs-search/:jobId', async (req, res, next) => {
  try {
    const { jobId } = req.params;
    const { cursor } = req.query;
    
    if (!jobId) {
      return res.status(400).json({ error: 'jobId is required' });
    }

    const result = await stealerLogsService.getLogsSearchStatus(jobId, cursor);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/generate-uuid-search - Generate and search UUIDs
router.post('/generate-uuid-search', async (req, res, next) => {
  try {
    const { count, filters } = req.body;
    
    const result = await stealerLogsService.generateUUIDSearch(count || 10, filters || {});
    res.status(202).json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/stealerlogs/generate-uuid-search/:jobId - Poll UUID search status
router.get('/generate-uuid-search/:jobId', async (req, res, next) => {
  try {
    const { jobId } = req.params;
    
    if (!jobId) {
      return res.status(400).json({ error: 'jobId is required' });
    }

    const result = await stealerLogsService.getUUIDSearchStatus(jobId);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/stealerlogs/domain-files - Search domain files
router.post('/domain-files', async (req, res, next) => {
  try {
    const { domain, fileTypes, file_types, limit, async } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'domain is required' });
    }

    const types = fileTypes || file_types || [];
    const result = await stealerLogsService.searchDomainFiles(domain, types, {
      limit,
      async
    });
    
    // Return appropriate status code based on mode
    if (result.mode === 'synchronous') {
      res.json(result);
    } else {
      res.status(202).json(result);
    }
  } catch (error) {
    next(error);
  }
});

// GET /api/stealerlogs/domain-files/:jobId - Poll domain files search status
router.get('/domain-files/:jobId', async (req, res, next) => {
  try {
    const { jobId } = req.params;
    
    if (!jobId) {
      return res.status(400).json({ error: 'jobId is required' });
    }

    const result = await stealerLogsService.getDomainFilesStatus(jobId);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/stealerlogs/ingestion-logs - Get ingestion pipeline logs
router.get('/ingestion-logs', async (req, res, next) => {
  try {
    const { limit, offset, dateFrom, dateTo } = req.query;
    
    const result = await stealerLogsService.getIngestionLogs({
      limit: limit ? parseInt(limit) : undefined,
      offset: offset ? parseInt(offset) : undefined,
      dateFrom,
      dateTo
    });
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/stealerlogs/health - Health check
router.get('/health', async (req, res, next) => {
  try {
    const result = await stealerLogsService.healthCheck();
    res.json(result);
  } catch (error) {
    next(error);
  }
});

export default router;
