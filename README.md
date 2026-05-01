# Web Security Checker / Webセキュリティチェッカー

URLを入力するだけで、Webサイトのセキュリティ設定を自動チェックするPythonツールです。

## チェック項目

| 項目 | 説明 |
|---|---|
| HTTPS | 暗号化通信が有効かどうか |
| SSL証明書 | 証明書の有効性と残り日数 |
| HSTS | HTTPSを強制するヘッダーの有無 |
| X-Frame-Options | クリックジャッキング対策 |
| CSP | XSS攻撃対策（スクリプト読み込み制限）|
| X-Content-Type-Options | MIMEスニッフィング対策 |

## 使い方

```bash
python3 checker.py <URL>
```

### 実行例

```bash
python3 checker.py https://github.com
```

### 出力例

```
========================================
  安全检查报告 / セキュリティチェック
  目标 / 対象: https://github.com
========================================
[✅] HTTPS 已启用 / HTTPS 有効
[✅] SSL证书有效，还有 33 天过期 / SSL証明書有効（残り33日）
[✅] HSTS 已设置 / HSTS 設定済み
[✅] X-Frame-Options 已设置 / X-Frame-Options 設定済み
[✅] CSP 已设置 / CSP 設定済み
[✅] X-Content-Type-Options 已设置 / X-Content-Type-Options 設定済み
========================================
  安全评分 / セキュリティスコア: 6 / 6
  评价 / 評価: 优秀 ✅
========================================
```

## 必要環境

- Python 3.x
- 外部ライブラリ不要（標準ライブラリのみ使用）

## 学んだこと

- HTTPSとSSL/TLSの仕組み
- セキュリティヘッダーの種類と役割
- XSS・クリックジャッキング・ダウングレード攻撃などの攻撃手法
- PythonによるHTTPリクエストとレスポンスの処理
