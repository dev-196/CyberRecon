import express from 'express';
import webService from '../services/webService.js';
import { validateURL } from '../utils/validation.js';

const router = express.Router();

// GET /api/web/ssl/:url
router.get('/ssl/:url', async (req, res, next) => {
  try {
    const url = validateURL(req.params.url);
    const result = await webService.analyzeSSL(url);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/web/headers/:url
router.get('/headers/:url', async (req, res, next) => {
  try {
    const url = validateURL(req.params.url);
    const result = await webService.getHTTPHeaders(url);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/web/security-headers/:url
router.get('/security-headers/:url', async (req, res, next) => {
  try {
    const url = validateURL(req.params.url);
    const result = await webService.checkSecurityHeaders(url);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/web/technology/:url
router.get('/technology/:url', async (req, res, next) => {
  try {
    const url = validateURL(req.params.url);
    const result = await webService.detectTechnology(url);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

export default router;
