import sys
import ssl
import socket
import urllib.request
import urllib.error
import datetime

def check_https(url):
    # URLがHTTPSで始まっているか確認
    return url.startswith("https://")

def check_ssl_certificate(hostname):
    try:
        # SSL証明書を取得して有効期限を確認
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # 有効期限の文字列を日付に変換
                expire_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.datetime.utcnow()).days
                return True, days_left
    except Exception:
        return False, 0

def get_response_headers(url):
    try:
        # URLにリクエストを送ってレスポンスヘッダーを取得
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return dict(response.headers)
    except Exception:
        return {}

def main():
    # コマンドライン引数からURLを受け取る
    if len(sys.argv) < 2:
        print("使い方: python3 checker.py <URL>")
        print("例:     python3 checker.py https://google.com")
        sys.exit(1)

    url = sys.argv[1]

    # URLからホスト名だけを取り出す（例: https://google.com → google.com）
    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

    print()
    print("=" * 40)
    print(f"  安全检查报告 / セキュリティチェック")
    print(f"  目标 / 対象: {url}")
    print("=" * 40)

    score = 0
    total = 6

    # ① HTTPSチェック
    if check_https(url):
        print("[✅] HTTPS 已启用 / HTTPS 有効")
        score += 1
    else:
        print("[❌] HTTPS 未启用 / HTTPS 無効（危険）")

    # ② SSL証明書チェック
    valid, days_left = check_ssl_certificate(hostname)
    if valid and days_left > 0:
        print(f"[✅] SSL证书有效，还有 {days_left} 天过期 / SSL証明書有効（残り{days_left}日）")
        score += 1
    else:
        print("[❌] SSL证书无效或已过期 / SSL証明書が無効または期限切れ")

    # レスポンスヘッダーを取得
    headers = get_response_headers(url)
    # ヘッダー名を小文字に統一して比較しやすくする
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # ③ HSTSチェック
    if "strict-transport-security" in headers_lower:
        print("[✅] HSTS 已设置 / HSTS 設定済み")
        score += 1
    else:
        print("[❌] HSTS 未设置 / HSTS 未設定")

    # ④ X-Frame-Optionsチェック
    if "x-frame-options" in headers_lower:
        print("[✅] X-Frame-Options 已设置 / X-Frame-Options 設定済み")
        score += 1
    else:
        print("[❌] X-Frame-Options 未设置 / X-Frame-Options 未設定")

    # ⑤ CSP（Content-Security-Policy）チェック
    if "content-security-policy" in headers_lower:
        print("[✅] CSP 已设置 / CSP 設定済み")
        score += 1
    else:
        print("[❌] CSP 未设置 / CSP 未設定")

    # ⑥ X-Content-Type-Optionsチェック
    if "x-content-type-options" in headers_lower:
        print("[✅] X-Content-Type-Options 已设置 / X-Content-Type-Options 設定済み")
        score += 1
    else:
        print("[❌] X-Content-Type-Options 未设置 / X-Content-Type-Options 未設定")

    # 最終スコアを表示
    print("=" * 40)
    print(f"  安全评分 / セキュリティスコア: {score} / {total}")
    if score == total:
        print("  评价 / 評価: 优秀 ✅")
    elif score >= 4:
        print("  评价 / 評価: 良好，有改善空间 ⚠️")
    else:
        print("  评价 / 評価: 存在安全隐患 ❌")
    print("=" * 40)
    print()

if __name__ == "__main__":
    main()
