import validator from 'validator';
import { AppError } from '../middleware/errorHandler.js';

export const validateDomain = (domain) => {
  if (!domain || typeof domain !== 'string') {
    throw new AppError('Domain is required and must be a string', 400);
  }

  // Remove protocol if present
  domain = domain.replace(/^https?:\/\//, '').split('/')[0];

  if (!validator.isFQDN(domain)) {
    throw new AppError('Invalid domain format', 400);
  }

  return domain;
};

export const validateIP = (ip) => {
  if (!ip || typeof ip !== 'string') {
    throw new AppError('IP address is required and must be a string', 400);
  }

  if (!validator.isIP(ip)) {
    throw new AppError('Invalid IP address format', 400);
  }

  return ip;
};

export const validateURL = (url) => {
  if (!url || typeof url !== 'string') {
    throw new AppError('URL is required and must be a string', 400);
  }

  if (!validator.isURL(url, { require_protocol: false })) {
    throw new AppError('Invalid URL format', 400);
  }

  return url;
};

export const validateEmail = (email) => {
  if (!email || typeof email !== 'string') {
    throw new AppError('Email is required and must be a string', 400);
  }

  if (!validator.isEmail(email)) {
    throw new AppError('Invalid email format', 400);
  }

  return validator.normalizeEmail(email);
};

export const validatePort = (port) => {
  const portNum = parseInt(port);
  
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    throw new AppError('Invalid port number. Must be between 1 and 65535', 400);
  }

  return portNum;
};

export const validatePortRange = (startPort, endPort) => {
  const start = validatePort(startPort);
  const end = validatePort(endPort);

  if (start > end) {
    throw new AppError('Start port must be less than or equal to end port', 400);
  }

  const maxPorts = parseInt(process.env.MAX_PORTS_PER_SCAN) || 1000;
  if (end - start + 1 > maxPorts) {
    throw new AppError(`Port range too large. Maximum ${maxPorts} ports per scan`, 400);
  }

  return { start, end };
};

export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  // Remove potential XSS attempts
  return validator.escape(input);
};

export const validateScanOptions = (options) => {
  const validOptions = {
    timeout: options.timeout ? parseInt(options.timeout) : 5000,
    aggressive: options.aggressive === true,
    serviceDetection: options.serviceDetection !== false,
    osDetection: options.osDetection === true
  };

  if (validOptions.timeout < 1000 || validOptions.timeout > 60000) {
    throw new AppError('Timeout must be between 1000 and 60000 ms', 400);
  }

  return validOptions;
};
