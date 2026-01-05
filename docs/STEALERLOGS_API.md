# Stealerlo.gs API Integration Guide

Complete documentation for the Stealerlo.gs API integration in CyberRecon Arsenal.

## Overview

Access to 12B+ stealerlog records and multiple OSINT providers through a unified API interface.

## Quick Start

1. Get API key from [search.stealerlo.gs](https://search.stealerlo.gs)
2. Add to `.env`: `STEALERLOG_API_KEY=slgs_your_key`
3. Start using the API endpoints at `/api/stealerlogs/*`

## Main Endpoints

### Search Records
`POST /api/stealerlogs/search`

Search 12B+ records by email, username, password, domain, phone, IP, etc.

### Hash Search
`POST /api/stealerlogs/hash-search`

Find plaintext passwords from hash values (MD5, SHA1, SHA256, NTLM).

### Phone Lookup
`POST /api/stealerlogs/phone-lookup`

Reverse phone number lookup with caller information.

### Domain Files Search
`POST /api/stealerlogs/domain-files`

Find employee credentials and files for a specific domain.

### Machine Info
`GET /api/stealerlogs/machine-info/:uuid`

Get comprehensive system information for a machine.

For complete API documentation with examples, see the inline code comments and README.md.

## Legal Notice

For authorized security testing and research only. Unauthorized access is illegal.
