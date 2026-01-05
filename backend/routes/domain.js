import express from 'express';
import domainService from '../services/domainService.js';
import { validateDomain } from '../utils/validation.js';

const router = express.Router();

// GET /api/domain/whois/:domain
router.get('/whois/:domain', async (req, res, next) => {
  try {
    const domain = validateDomain(req.params.domain);
    const result = await domainService.getWhoisInfo(domain);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/domain/dns/:domain
router.get('/dns/:domain', async (req, res, next) => {
  try {
    const domain = validateDomain(req.params.domain);
    const result = await domainService.getDNSRecords(domain);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/domain/subdomains/:domain
router.get('/subdomains/:domain', async (req, res, next) => {
  try {
    const domain = validateDomain(req.params.domain);
    const result = await domainService.discoverSubdomains(domain);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/domain/reputation/:domain
router.get('/reputation/:domain', async (req, res, next) => {
  try {
    const domain = validateDomain(req.params.domain);
    const result = await domainService.getDomainReputation(domain);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

export default router;
