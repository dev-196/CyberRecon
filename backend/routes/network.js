import express from 'express';
import networkService from '../services/networkService.js';
import { validateIP, validatePortRange } from '../utils/validation.js';

const router = express.Router();

// POST /api/network/scan
router.post('/scan', async (req, res, next) => {
  try {
    const { host, startPort, endPort, options } = req.body;
    const validatedHost = req.body.host.match(/^\d+\.\d+\.\d+\.\d+$/) 
      ? validateIP(host) 
      : host; // Allow domain names too
    
    const ports = validatePortRange(startPort, endPort);
    const result = await networkService.scanPorts(validatedHost, ports.start, ports.end, options);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// GET /api/network/quick-scan/:host
router.get('/quick-scan/:host', async (req, res, next) => {
  try {
    const host = req.params.host;
    const result = await networkService.quickScan(host);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/network/service-detection
router.post('/service-detection', async (req, res, next) => {
  try {
    const { host, ports } = req.body;
    const result = await networkService.serviceDetection(host, ports);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// POST /api/network/map
router.post('/map', async (req, res, next) => {
  try {
    const { host, options } = req.body;
    const result = await networkService.networkMap(host, options);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

export default router;
