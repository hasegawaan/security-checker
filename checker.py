import ssl
import socket
import urllib.parse
import datetime
import re
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
from html.parser import HTMLParser

import requests
from requests.exceptions import RequestException

OWASP_NAMES = {
    "A01": "アクセス制御の不備",
    "A02": "暗号化の失敗",
    "A03": "インジェクション",
    "A04": "安全でない設計",
    "A05": "セキュリティの設定ミス",
    "A06": "脆弱・古いコンポーネントの使用",
    "A07": "認証・認可の失敗",
    "A08": "データ整合性の欠如",
    "A09": "ログ・監視の欠如",
    "A10": "SSRF",
}

RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class CheckResult:
    id: str
    category: str
    name: str
    ok: bool
    detail: str
    risk_level: str  # critical | high | medium | low | info
    owasp: List[str]
    suggestion: str

    def to_dict(self):
        return asdict(self)


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._current = {
                "action": a.get("action", ""),
                "method": a.get("method", "get").upper(),
                "inputs": [],
            }
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append({
                "type": a.get("type", "text").lower(),
                "name": a.get("name", ""),
                "autocomplete": a.get("autocomplete", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


class SecurityChecker:
    def __init__(self, url: str):
        raw = url.strip()
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        self.url = raw
        parsed = urllib.parse.urlparse(self.url)
        self.hostname = parsed.hostname or ""
        self._resp: Optional[requests.Response] = None
        self._headers: Dict[str, str] = {}
        self._html = ""
        self._ssl_info: Optional[Dict] = None
        self._error: Optional[str] = None

    # ------------------------------------------------------------------ fetch

    def _fetch(self):
        if self._resp is not None or self._error:
            return
        try:
            self._resp = requests.get(
                self.url,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 SecurityChecker/3.0"},
                allow_redirects=True,
                verify=True,
            )
            self._headers = {k.lower(): v for k, v in self._resp.headers.items()}
            self._html = self._resp.text[:60000]
        except RequestException as e:
            self._error = str(e)
            self._headers = {}

    def _check_ssl(self):
        if self._ssl_info is not None:
            return
        if not self.url.startswith("https://"):
            self._ssl_info = {"valid": False, "error": "HTTPS未使用", "days_left": 0}
            return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    expire = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days = (expire - datetime.datetime.utcnow()).days
                    self._ssl_info = {
                        "valid": True,
                        "days_left": days,
                        "expire_date": cert["notAfter"],
                        "protocol": ssock.version(),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                    }
        except ssl.SSLCertVerificationError as e:
            self._ssl_info = {"valid": False, "error": f"証明書検証エラー: {e}", "days_left": 0}
        except ssl.SSLError as e:
            self._ssl_info = {"valid": False, "error": f"SSLエラー: {e}", "days_left": 0}
        except Exception as e:
            self._ssl_info = {"valid": False, "error": str(e), "days_left": 0}

    # ------------------------------------------------------------------ checks

    def check_protocol(self) -> List[CheckResult]:
        is_https = self.url.startswith("https://")
        return [CheckResult(
            id="protocol",
            category="ssl",
            name="HTTPS プロトコル",
            ok=is_https,
            detail="HTTPS通信を使用しています" if is_https else "HTTP通信のため通信内容が暗号化されていません",
            risk_level="info" if is_https else "critical",
            owasp=[] if is_https else ["A02"],
            suggestion="" if is_https else "サーバーでHTTPSを有効にし、HTTPからHTTPSへの強制リダイレクトを設定してください",
        )]

    def check_ssl(self) -> List[CheckResult]:
        self._check_ssl()
        results = []
        info = self._ssl_info or {}

        if not info.get("valid"):
            results.append(CheckResult(
                id="ssl_cert",
                category="ssl",
                name="SSL/TLS 証明書",
                ok=False,
                detail=f"証明書エラー: {info.get('error', '不明')[:100]}",
                risk_level="critical",
                owasp=["A02"],
                suggestion="有効なSSL/TLS証明書を設置し、証明書チェーンが完全であることを確認してください",
            ))
            return results

        days = info["days_left"]
        if days > 30:
            results.append(CheckResult(
                id="ssl_cert", category="ssl", name="SSL/TLS 証明書",
                ok=True, detail=f"証明書有効（残り{days}日）",
                risk_level="info", owasp=[], suggestion="",
            ))
        elif days > 0:
            results.append(CheckResult(
                id="ssl_cert", category="ssl", name="SSL/TLS 証明書",
                ok=False, detail=f"証明書の期限が近づいています（残り{days}日）",
                risk_level="medium", owasp=["A02"],
                suggestion="早急に証明書を更新してください",
            ))
        else:
            results.append(CheckResult(
                id="ssl_cert", category="ssl", name="SSL/TLS 証明書",
                ok=False, detail="証明書の期限が切れています",
                risk_level="critical", owasp=["A02"],
                suggestion="証明書を今すぐ更新してください",
            ))

        proto = info.get("protocol", "")
        if proto == "TLSv1.3":
            results.append(CheckResult(
                id="tls_version", category="ssl", name="TLS バージョン",
                ok=True, detail=f"最新の{proto}を使用しています",
                risk_level="info", owasp=[], suggestion="",
            ))
        elif proto == "TLSv1.2":
            results.append(CheckResult(
                id="tls_version", category="ssl", name="TLS バージョン",
                ok=True, detail=f"{proto}を使用（TLS 1.3へのアップグレードを推奨）",
                risk_level="low", owasp=[], suggestion="TLS 1.3へのアップグレードを検討してください",
            ))
        else:
            results.append(CheckResult(
                id="tls_version", category="ssl", name="TLS バージョン",
                ok=False, detail=f"古いプロトコル {proto} を使用しています",
                risk_level="high", owasp=["A02"],
                suggestion="TLS 1.2以上を有効にし、TLS 1.0/1.1/SSLを無効化してください",
            ))

        return results

    def check_headers(self) -> List[CheckResult]:
        self._fetch()
        results = []
        h = self._headers

        HEADER_DEFS = [
            dict(
                id="hsts", name="HSTS (Strict-Transport-Security)",
                header="strict-transport-security",
                ok_detail=lambda: f"HSTS設定済み: {h.get('strict-transport-security','')}",
                ng_detail="HSTSが未設定。ブラウザはHTTPSを強制しません",
                risk="high", owasp=["A02", "A05"],
                suggestion="Strict-Transport-Security: max-age=31536000; includeSubDomains を設定してください",
            ),
            dict(
                id="csp", name="Content-Security-Policy",
                header="content-security-policy",
                ok_detail=lambda: "CSP設定済み（XSS対策有効）",
                ng_detail="CSPが未設定。XSS攻撃のリスクが高まります",
                risk="high", owasp=["A03", "A05"],
                suggestion="Content-Security-Policy を設定し、スクリプトの読み込み元を制限してください",
            ),
            dict(
                id="xframe", name="X-Frame-Options",
                header="x-frame-options",
                ok_detail=lambda: f"クリックジャッキング対策済み: {h.get('x-frame-options','')}",
                ng_detail="X-Frame-Optionsが未設定。クリックジャッキング攻撃のリスクがあります",
                risk="medium", owasp=["A04", "A05"],
                suggestion="X-Frame-Options: DENY または SAMEORIGIN を設定してください",
            ),
            dict(
                id="xcontent", name="X-Content-Type-Options",
                header="x-content-type-options",
                ok_detail=lambda: f"MIMEスニッフィング対策済み: {h.get('x-content-type-options','')}",
                ng_detail="X-Content-Type-Optionsが未設定。MIMEタイプスニッフィングのリスクがあります",
                risk="medium", owasp=["A05"],
                suggestion="X-Content-Type-Options: nosniff を設定してください",
            ),
            dict(
                id="referrer", name="Referrer-Policy",
                header="referrer-policy",
                ok_detail=lambda: f"Referrer-Policy設定済み: {h.get('referrer-policy','')}",
                ng_detail="Referrer-Policyが未設定。URL内の機密情報が外部に漏洩する可能性があります",
                risk="low", owasp=["A05"],
                suggestion="Referrer-Policy: strict-origin-when-cross-origin を設定してください",
            ),
            dict(
                id="permissions", name="Permissions-Policy",
                header="permissions-policy",
                ok_detail=lambda: "Permissions-Policy設定済み",
                ng_detail="Permissions-Policyが未設定。不要なブラウザ機能へのアクセスが許可される可能性があります",
                risk="low", owasp=["A05"],
                suggestion="Permissions-Policy でカメラ・マイク等の不要な機能を制限してください",
            ),
            dict(
                id="xxss", name="X-XSS-Protection",
                header="x-xss-protection",
                ok_detail=lambda: f"X-XSS-Protection設定済み: {h.get('x-xss-protection','')}",
                ng_detail="X-XSS-Protectionが未設定（レガシーブラウザでのXSS対策なし）",
                risk="low", owasp=["A03"],
                suggestion="X-XSS-Protection: 1; mode=block を設定してください（CSPが優先）",
            ),
        ]

        for d in HEADER_DEFS:
            present = d["header"] in h
            results.append(CheckResult(
                id=d["id"], category="headers", name=d["name"],
                ok=present,
                detail=d["ok_detail"]() if present else d["ng_detail"],
                risk_level="info" if present else d["risk"],
                owasp=[] if present else d["owasp"],
                suggestion="" if present else d["suggestion"],
            ))

        # Server header version disclosure
        server = h.get("server", "")
        version_leak = bool(server and re.search(r"\d", server))
        results.append(CheckResult(
            id="server_ver", category="headers", name="Serverヘッダー情報漏洩",
            ok=not version_leak,
            detail=f"Serverヘッダーにバージョン情報: {server}" if version_leak else "Serverヘッダーのバージョン情報は適切に制限されています",
            risk_level="low" if version_leak else "info",
            owasp=["A05", "A06"] if version_leak else [],
            suggestion="Serverヘッダーからバージョン情報を削除してください" if version_leak else "",
        ))

        # X-Powered-By
        has_xpb = "x-powered-by" in h
        results.append(CheckResult(
            id="xpoweredby", category="headers", name="X-Powered-By 情報漏洩",
            ok=not has_xpb,
            detail=f"X-Powered-By: {h.get('x-powered-by','')}" if has_xpb else "X-Powered-Byヘッダーなし（良好）",
            risk_level="low" if has_xpb else "info",
            owasp=["A05", "A06"] if has_xpb else [],
            suggestion="X-Powered-Byヘッダーを削除し、使用技術スタックの情報漏洩を防いでください" if has_xpb else "",
        ))

        # Cache-Control on sensitive paths (basic check)
        cache = h.get("cache-control", "")
        has_nocache = any(x in cache.lower() for x in ["no-store", "no-cache", "private"])
        results.append(CheckResult(
            id="cache", category="headers", name="Cache-Control",
            ok=has_nocache,
            detail=f"Cache-Control: {cache}" if cache else "Cache-Controlヘッダーが未設定。機密データがキャッシュされる可能性があります",
            risk_level="info" if has_nocache else "low",
            owasp=[] if has_nocache else ["A05"],
            suggestion="" if has_nocache else "機密ページにCache-Control: no-store, private を設定してください",
        ))

        return results

    def check_cookies(self) -> List[CheckResult]:
        self._fetch()
        results = []

        raw_cookies = []
        if self._resp is not None:
            # requests stores cookies but raw Set-Cookie headers are more informative
            for k, v in self._resp.headers.items():
                if k.lower() == "set-cookie":
                    raw_cookies.append(v)

        if not raw_cookies:
            results.append(CheckResult(
                id="cookie_none", category="cookies", name="Cookie 設定確認",
                ok=True, detail="Set-Cookieヘッダーは検出されませんでした",
                risk_level="info", owasp=[], suggestion="",
            ))
            return results

        for i, cstr in enumerate(raw_cookies[:5]):
            cl = cstr.lower()
            parts = [p.strip() for p in cstr.split(";")]
            name = parts[0].split("=")[0].strip() if parts else f"Cookie#{i+1}"

            # HttpOnly
            has_ho = "httponly" in cl
            results.append(CheckResult(
                id=f"cookie_{i}_httponly", category="cookies",
                name=f"{name}: HttpOnly",
                ok=has_ho,
                detail="HttpOnly設定済み（JSからアクセス不可）" if has_ho else "HttpOnly未設定。XSS経由でのCookie窃取リスクがあります",
                risk_level="info" if has_ho else "high",
                owasp=[] if has_ho else ["A07"],
                suggestion="" if has_ho else "HttpOnly属性を追加し、JavaScriptからCookieへのアクセスを禁止してください",
            ))

            # Secure
            has_sec = "secure" in cl
            results.append(CheckResult(
                id=f"cookie_{i}_secure", category="cookies",
                name=f"{name}: Secure",
                ok=has_sec,
                detail="Secure設定済み（HTTPS専用）" if has_sec else "Secure未設定。HTTP通信でもCookieが送信されます",
                risk_level="info" if has_sec else "high",
                owasp=[] if has_sec else ["A02", "A07"],
                suggestion="" if has_sec else "Secure属性を追加し、HTTPS接続のみでCookieを送信するよう設定してください",
            ))

            # SameSite
            ss_part = next((p for p in parts if "samesite" in p.lower()), "")
            has_ss = bool(ss_part)
            results.append(CheckResult(
                id=f"cookie_{i}_samesite", category="cookies",
                name=f"{name}: SameSite",
                ok=has_ss,
                detail=f"SameSite設定済み: {ss_part.strip()}" if has_ss else "SameSite未設定。CSRF攻撃のリスクがあります",
                risk_level="info" if has_ss else "medium",
                owasp=[] if has_ss else ["A01", "A07"],
                suggestion="" if has_ss else "SameSite=Strict または SameSite=Lax を設定してCSRF対策を強化してください",
            ))

        return results

    def check_forms(self) -> List[CheckResult]:
        self._fetch()
        results = []

        if self._error or not self._html:
            results.append(CheckResult(
                id="form_fetch_err", category="forms", name="フォーム解析",
                ok=False, detail="HTMLコンテンツの取得に失敗しました",
                risk_level="info", owasp=[], suggestion="",
            ))
            return results

        parser = FormParser()
        try:
            parser.feed(self._html)
        except Exception:
            pass

        forms = parser.forms
        if not forms:
            results.append(CheckResult(
                id="form_none", category="forms", name="フォーム検出",
                ok=True, detail="ページ内にフォームは検出されませんでした",
                risk_level="info", owasp=[], suggestion="",
            ))
            return results

        results.append(CheckResult(
            id="form_count", category="forms", name="フォーム検出",
            ok=True, detail=f"{len(forms)}個のフォームを検出しました",
            risk_level="info", owasp=[], suggestion="",
        ))

        for i, form in enumerate(forms[:4]):
            action = form.get("action", "")
            inputs = form.get("inputs", [])

            if action.startswith("http://"):
                results.append(CheckResult(
                    id=f"form_{i}_action", category="forms",
                    name=f"フォーム#{i+1}: 送信先URL",
                    ok=False,
                    detail=f"HTTP URLに送信されます: {action[:60]}",
                    risk_level="high", owasp=["A02"],
                    suggestion="フォームの送信先をHTTPSに変更してください",
                ))

            has_pw = any(inp["type"] == "password" for inp in inputs)
            has_csrf = any(
                "csrf" in inp["name"].lower() or "token" in inp["name"].lower()
                for inp in inputs
            )

            if has_pw:
                results.append(CheckResult(
                    id=f"form_{i}_csrf", category="forms",
                    name=f"フォーム#{i+1}: CSRF対策",
                    ok=has_csrf,
                    detail="CSRFトークンを検出しました" if has_csrf else "パスワードフォームにCSRFトークンが見つかりません",
                    risk_level="info" if has_csrf else "medium",
                    owasp=[] if has_csrf else ["A01"],
                    suggestion="" if has_csrf else "CSRFトークンをフォームに追加してください",
                ))

                for inp in inputs:
                    if inp["type"] == "password":
                        ac = inp.get("autocomplete", "")
                        ok_ac = ac in ("off", "new-password", "current-password")
                        results.append(CheckResult(
                            id=f"form_{i}_autocomplete", category="forms",
                            name=f"フォーム#{i+1}: パスワードautocomplete",
                            ok=ok_ac,
                            detail=f'autocomplete="{ac}"（適切）' if ok_ac else "パスワードフィールドのautocomplete属性が未設定または不適切です",
                            risk_level="info" if ok_ac else "low",
                            owasp=[] if ok_ac else ["A04"],
                            suggestion="" if ok_ac else 'autocomplete="current-password" または "new-password" を設定してください',
                        ))
                        break

        return results

    # ------------------------------------------------------------------ main

    def run_all(self) -> List[CheckResult]:
        results = []
        results += self.check_protocol()
        results += self.check_ssl()
        results += self.check_headers()
        results += self.check_cookies()
        results += self.check_forms()
        return results

    def get_summary(self, results: List[CheckResult]) -> Dict:
        total = len(results)
        passed = sum(1 for r in results if r.ok)
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results:
            if not r.ok and r.risk_level in risk_counts:
                risk_counts[r.risk_level] += 1

        # ペナルティ方式（リスクに応じて減点、最低10点）
        penalties = {"critical": 15, "high": 8, "medium": 4, "low": 1}
        deduction = sum(penalties.get(r.risk_level, 0) for r in results if not r.ok)
        score = max(10, 100 - deduction)

        if risk_counts["critical"] > 0:
            grade, grade_color = "CRITICAL", "critical"
        elif risk_counts["high"] > 0:
            grade, grade_color = "HIGH RISK", "high"
        elif risk_counts["medium"] > 0:
            grade, grade_color = "MEDIUM RISK", "medium"
        elif risk_counts["low"] > 0:
            grade, grade_color = "LOW RISK", "low"
        else:
            grade, grade_color = "SECURE", "info"

        owasp_issues: Dict[str, List[str]] = {}
        for r in results:
            if not r.ok:
                for o in r.owasp:
                    owasp_issues.setdefault(o, []).append(r.name)

        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "score": score,
            "grade": grade,
            "grade_color": grade_color,
            "risk_counts": risk_counts,
            "owasp_issues": owasp_issues,
        }
