# SEC//SCAN — Web Security Checker

A web-based security diagnostic tool that analyzes websites across 6 security points.

---

## v3.0 Update

Expanded from 6 checks to **15 checks** across 4 categories, added OWASP Top 10 mapping, and integrated AI-generated test points.

**New in v3.0:**

| Feature | Description |
|---------|-------------|
| Cookie security | HttpOnly, Secure, SameSite attribute checks per cookie |
| Form analysis | CSRF token detection, autocomplete, insecure action URLs |
| Extended headers | Referrer-Policy, Permissions-Policy, X-XSS-Protection, Server/X-Powered-By info leak, Cache-Control |
| Risk levels | Each finding classified as Critical / High / Medium / Low |
| OWASP Top 10 mapping | Findings mapped to OWASP 2021 categories (A01–A10) |
| AI test points | Gemini-powered additional test point generation |
| Score dashboard | Animated score ring with risk count breakdown |
| JSON export | Full diagnostic report download |
| PDF print | Print-optimized layout |
| Auto-deploy | GitHub Actions → Azure on every push |

---

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
