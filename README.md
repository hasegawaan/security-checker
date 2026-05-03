# SEC//SCAN — Web Security Checker

A web-based security diagnostic tool that analyzes websites across 6 security points.

---

## v3.0 アップデート

チェック項目を6項目から**15項目**に拡充し、OWASP Top 10マッピングとAI生成テスト観点機能を追加しました。

**v3.0 新機能一覧：**

| 機能 | 内容 |
|------|------|
| Cookie セキュリティ | HttpOnly・Secure・SameSite 属性をCookieごとに確認 |
| フォーム解析 | CSRFトークン検出・autocomplete属性・HTTP送信先チェック |
| ヘッダー拡充 | Referrer-Policy・Permissions-Policy・X-XSS-Protection・Server/X-Powered-By情報漏洩・Cache-Control |
| リスクレベル | 各チェック結果を Critical / High / Medium / Low で分類 |
| OWASP Top 10 マッピング | 検出した問題をOWASP 2021カテゴリ（A01〜A10）に対応付け |
| AI テスト観点生成 | Gemini APIによる追加テスト観点の自動生成 |
| スコアダッシュボード | アニメーション付きスコアリングとリスク件数の可視化 |
| JSON エクスポート | 診断レポートのダウンロード |
| PDF 印刷 | 印刷最適化レイアウト |
| 自動デプロイ | GitHub Actions → Azure（push のたびに自動反映） |

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
