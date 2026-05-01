from flask import Flask, request, render_template_string
import sys
import ssl
import socket
import urllib.request
import datetime

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SEC//SCAN — Webセキュリティチェッカー</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #060910;
            --surface: #0d1117;
            --border: #1a2332;
            --accent: #00ff88;
            --accent2: #00c8ff;
            --danger: #ff3a5c;
            --text: #c8d8e8;
            --muted: #3a5070;
            --mono: 'Share Tech Mono', monospace;
            --sans: 'Rajdhani', sans-serif;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--mono);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* scanline overlay */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                rgba(0,0,0,0.07) 2px,
                rgba(0,0,0,0.07) 4px
            );
            pointer-events: none;
            z-index: 100;
        }

        /* noise grain */
        body::after {
            content: '';
            position: fixed;
            inset: -50%;
            width: 200%;
            height: 200%;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
            opacity: 0.4;
            pointer-events: none;
            z-index: 99;
            animation: grain 0.5s steps(2) infinite;
        }

        @keyframes grain {
            0%, 100% { transform: translate(0, 0); }
            25% { transform: translate(-1%, 1%); }
            50% { transform: translate(1%, -1%); }
            75% { transform: translate(-1%, -1%); }
        }

        .container {
            max-width: 780px;
            margin: 0 auto;
            padding: 60px 24px 80px;
        }

        /* header */
        .header {
            margin-bottom: 52px;
            animation: fadeDown 0.6s ease both;
        }

        .header-tag {
            font-family: var(--mono);
            font-size: 11px;
            letter-spacing: 0.25em;
            color: var(--accent);
            text-transform: uppercase;
            margin-bottom: 12px;
            opacity: 0.8;
        }

        .header-tag::before {
            content: '> ';
            color: var(--muted);
        }

        h1 {
            font-family: var(--sans);
            font-weight: 700;
            font-size: clamp(32px, 6vw, 54px);
            letter-spacing: -0.02em;
            line-height: 1;
            color: #fff;
        }

        h1 span {
            color: var(--accent);
        }

        .header-sub {
            font-size: 12px;
            color: var(--muted);
            margin-top: 10px;
            letter-spacing: 0.1em;
        }

        /* form */
        .scan-form {
            display: flex;
            gap: 0;
            margin-bottom: 48px;
            border: 1px solid var(--border);
            background: var(--surface);
            animation: fadeDown 0.6s 0.1s ease both;
            position: relative;
            overflow: hidden;
        }

        .scan-form::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--accent), transparent);
            animation: scanLine 3s ease-in-out infinite;
        }

        @keyframes scanLine {
            0%, 100% { opacity: 0; transform: translateX(-100%); }
            50% { opacity: 1; transform: translateX(100%); }
        }

        .prompt-label {
            display: flex;
            align-items: center;
            padding: 0 16px;
            color: var(--accent);
            font-size: 14px;
            border-right: 1px solid var(--border);
            white-space: nowrap;
            user-select: none;
        }

        input[type=text] {
            flex: 1;
            background: transparent;
            border: none;
            outline: none;
            padding: 16px 18px;
            font-family: var(--mono);
            font-size: 14px;
            color: var(--text);
            caret-color: var(--accent);
        }

        input[type=text]::placeholder { color: var(--muted); }

        button {
            background: var(--accent);
            color: #000;
            border: none;
            padding: 0 28px;
            font-family: var(--sans);
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            cursor: pointer;
            transition: background 0.15s, box-shadow 0.15s;
            white-space: nowrap;
        }

        button:hover {
            background: #00ffaa;
            box-shadow: 0 0 20px rgba(0,255,136,0.4);
        }

        button:active { transform: scale(0.98); }

        /* results */
        .result-panel {
            border: 1px solid var(--border);
            background: var(--surface);
            animation: fadeUp 0.5s ease both;
        }

        .result-header {
            border-bottom: 1px solid var(--border);
            padding: 14px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .result-header-label {
            font-size: 11px;
            letter-spacing: 0.2em;
            color: var(--muted);
            text-transform: uppercase;
        }

        .result-target {
            font-size: 12px;
            color: var(--accent2);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 55%;
        }

        .check-list {
            list-style: none;
        }

        .check-item {
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 13px 20px;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
            animation: fadeUp 0.4s ease both;
        }

        .check-item:last-child { border-bottom: none; }

        {% for i in range(10) %}
        .check-item:nth-child({{ i + 1 }}) { animation-delay: {{ i * 0.06 }}s; }
        {% endfor %}

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .ok .status-dot {
            background: var(--accent);
            box-shadow: 0 0 8px var(--accent);
        }

        .ng .status-dot {
            background: var(--danger);
            box-shadow: 0 0 8px var(--danger);
        }

        .check-text { flex: 1; color: var(--text); }
        .ok .check-text { color: #a0f0c8; }
        .ng .check-text { color: #ff8099; }

        .check-badge {
            font-size: 10px;
            letter-spacing: 0.1em;
            padding: 2px 8px;
            border-radius: 2px;
            text-transform: uppercase;
            font-family: var(--sans);
            font-weight: 700;
        }

        .ok .check-badge {
            background: rgba(0,255,136,0.12);
            color: var(--accent);
            border: 1px solid rgba(0,255,136,0.25);
        }

        .ng .check-badge {
            background: rgba(255,58,92,0.12);
            color: var(--danger);
            border: 1px solid rgba(255,58,92,0.25);
        }

        /* score */
        .score-bar-wrap {
            padding: 20px 20px 10px;
            border-top: 1px solid var(--border);
        }

        .score-meta {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            margin-bottom: 10px;
        }

        .score-label {
            font-size: 11px;
            letter-spacing: 0.2em;
            color: var(--muted);
            text-transform: uppercase;
        }

        .score-num {
            font-family: var(--sans);
            font-weight: 700;
            font-size: 28px;
            color: #fff;
        }

        .score-num span { font-size: 14px; color: var(--muted); }

        .progress-track {
            height: 4px;
            background: var(--border);
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent2), var(--accent));
            width: {{ (score / total * 100) | int if total else 0 }}%;
            transition: width 1s cubic-bezier(0.16, 1, 0.3, 1);
            box-shadow: 0 0 12px rgba(0,255,136,0.5);
            animation: growBar 1s cubic-bezier(0.16, 1, 0.3, 1) both;
        }

        @keyframes growBar {
            from { width: 0; }
        }

        .verdict {
            padding: 14px 20px;
            font-family: var(--sans);
            font-weight: 500;
            font-size: 14px;
            letter-spacing: 0.05em;
            border-top: 1px solid var(--border);
            color: var(--muted);
        }

        .verdict strong {
            {% if score == total %}color: var(--accent);
            {% elif score >= 4 %}color: #ffd700;
            {% else %}color: var(--danger);{% endif %}
        }

        /* animations */
        @keyframes fadeDown {
            from { opacity: 0; transform: translateY(-12px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(10px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        /* corner decoration */
        .corner-deco {
            position: fixed;
            bottom: 24px;
            right: 24px;
            font-size: 10px;
            color: var(--muted);
            letter-spacing: 0.15em;
            opacity: 0.4;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-tag">security scan tool v1.0</div>
            <h1>SEC<span>//</span>SCAN</h1>
            <p class="header-sub">WEB セキュリティ診断システム &nbsp;|&nbsp; 6-POINT ANALYSIS</p>
        </header>

        <form method="post" class="scan-form">
            <span class="prompt-label">TARGET://</span>
            <input type="text" name="url" placeholder="https://example.com" value="{{ url }}" autocomplete="off" spellcheck="false">
            <button type="submit">SCAN</button>
        </form>

        {% if results %}
        <div class="result-panel">
            <div class="result-header">
                <span class="result-header-label">SCAN RESULTS</span>
                <span class="result-target">{{ url }}</span>
            </div>
            <ul class="check-list">
                {% for r in results %}
                <li class="check-item {{ 'ok' if r.ok else 'ng' }}">
                    <div class="status-dot"></div>
                    <span class="check-text">{{ r.text }}</span>
                    <span class="check-badge">{{ 'PASS' if r.ok else 'FAIL' }}</span>
                </li>
                {% endfor %}
            </ul>
            <div class="score-bar-wrap">
                <div class="score-meta">
                    <span class="score-label">SECURITY SCORE</span>
                    <span class="score-num">{{ score }}<span> / {{ total }}</span></span>
                </div>
                <div class="progress-track">
                    <div class="progress-fill"></div>
                </div>
            </div>
            <div class="verdict"><strong>{{ 評価 }}</strong></div>
        </div>
        {% endif %}
    </div>
    <div class="corner-deco">SEC//SCAN &copy; 2025</div>
</body>
</html>
"""

def check_https(url):
    return url.startswith("https://")

def check_ssl_certificate(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.datetime.utcnow()).days
                return True, days_left
    except Exception:
        return False, 0

def get_response_headers(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return dict(response.headers)
    except Exception:
        return {}

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    score = 0
    total = 6
    url = ""
    評価 = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

        if check_https(url):
            results.append({"ok": True, "text": "HTTPS 有効"})
            score += 1
        else:
            results.append({"ok": False, "text": "HTTPS 無効（危険）"})

        valid, days_left = check_ssl_certificate(hostname)
        if valid and days_left > 0:
            results.append({"ok": True, "text": f"SSL証明書有効（残り{days_left}日）"})
            score += 1
        else:
            results.append({"ok": False, "text": "SSL証明書が無効または期限切れ"})

        headers = get_response_headers(url)
        headers_lower = {k.lower(): v for k, v in headers.items()}

        if "strict-transport-security" in headers_lower:
            results.append({"ok": True, "text": "HSTS 設定済み"})
            score += 1
        else:
            results.append({"ok": False, "text": "HSTS 未設定"})

        if "x-frame-options" in headers_lower:
            results.append({"ok": True, "text": "X-Frame-Options 設定済み"})
            score += 1
        else:
            results.append({"ok": False, "text": "X-Frame-Options 未設定"})

        if "content-security-policy" in headers_lower:
            results.append({"ok": True, "text": "CSP 設定済み"})
            score += 1
        else:
            results.append({"ok": False, "text": "CSP 未設定"})

        if "x-content-type-options" in headers_lower:
            results.append({"ok": True, "text": "X-Content-Type-Options 設定済み"})
            score += 1
        else:
            results.append({"ok": False, "text": "X-Content-Type-Options 未設定"})

        if score == total:
            評価 = "評価: 優秀 ✅"
        elif score >= 4:
            評価 = "評価: 良好、改善の余地あり ⚠️"
        else:
            評価 = "評価: セキュリティリスクあり ❌"

    return render_template_string(HTML, results=results, score=score, total=total, url=url, 評価=評価)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
