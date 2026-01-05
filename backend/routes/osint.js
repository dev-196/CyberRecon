import express from 'express';
import osintService from '../services/osintService.js';
import { validateDomain, validateEmail } from '../utils/validation.js';

const router = express.Router();

// GET /api/osint/emails/:domain
router.get('/emails/:domain', async (req, res, next) => {
  try {
    const domain = validateDomain(req.params.domain);
    const result = await osintService.harvestEmails(domain);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/osint/social-media/:target
router.get('/social-media/:target', async (req, res, next) => {
  try {
    const target = req.params.target;
    const result = await osintService.socialMediaRecon(target);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/osint/metadata/:url
router.get('/metadata/:url', async (req, res, next) => {
  try {
    const url = req.params.url;
    const result = await osintService.extractMetadata(url);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/osint/breaches/:email
router.get('/breaches/:email', async (req, res, next) => {
  try {
    const email = validateEmail(req.params.email);
    const result = await osintService.dataBreachCheck(email);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/osint/comprehensive
router.post('/comprehensive', async (req, res, next) => {
  try {
    const { target, type } = req.body;
    const result = await osintService.comprehensiveOSINT(target, type);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

export default router;
