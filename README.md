# SEC//SCAN — Web Security Checker

A web-based security diagnostic tool that analyzes websites across 6 security points.

**Live demo:** [https://hasegawaan-securitycheck.com/](https://hasegawaan-securitycheck.com/)

## Overview

Built as a personal project to learn web security and infrastructure hands-on. The tool scans any URL and generates a security score based on common vulnerability indicators.

## Security Checks

| Check | Description |
|-------|-------------|
| HTTPS | Whether encrypted communication is enabled |
| SSL Certificate | Certificate validity and expiry |
| HSTS | HTTP Strict Transport Security header |
| X-Frame-Options | Clickjacking protection |
| CSP | Content Security Policy (XSS mitigation) |
| X-Content-Type-Options | MIME sniffing protection |

## Tech Stack

- Python (Flask) — backend API
- HTML / CSS / JavaScript — frontend
- Azure — hosting and deployment

## Background

Developed to learn security concepts through practice. After deploying, I ran the tool against itself and discovered it scored 0/6. I then identified and fixed each vulnerability until achieving a perfect score — experiencing the full cycle of vulnerability discovery and remediation firsthand.

## What I Learned

- HTTPS / SSL/TLS mechanisms
- Types and roles of security headers
- Attack methods: XSS, clickjacking, downgrade attacks
- Python HTTP request/response handling
- Azure server setup and deployment
