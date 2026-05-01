from flask import Flask, request, render_template_string
import sys
import ssl
import socket
import urllib.request
import datetime

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Webセキュリティチェッカー</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 700px; margin: 50px auto; padding: 0 20px; background: #f5f5f5; }
        h1 { color: #333; }
        input[type=text] { width: 70%; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 20px; font-size: 16px; background: #0078d4; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #005fa3; }
        .result { background: white; padding: 20px; border-radius: 8px; margin-top: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .ok { color: green; }
        .ng { color: red; }
        .score { font-size: 24px; font-weight: bold; margin-top: 10px; }
    </style>
</head>
<body>
    <h1>🔒 Webセキュリティチェッカー</h1>
    <form method="post">
        <input type="text" name="url" placeholder="https://example.com" value="{{ url }}">
        <button type="submit">チェック</button>
    </form>
    {% if results %}
    <div class="result">
        <h2>チェック結果: {{ url }}</h2>
        {% for r in results %}
            <p class="{{ 'ok' if r.ok else 'ng' }}">{{ '✅' if r.ok else '❌' }} {{ r.text }}</p>
        {% endfor %}
        <p class="score">スコア: {{ score }} / {{ total }}</p>
        <p>{{評価 }}</p>
    </div>
    {% endif %}
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
