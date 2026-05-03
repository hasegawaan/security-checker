from flask import Flask, request, render_template_string, jsonify
import json
import datetime
import os

try:
    from google import genai
    from google.genai import types as genai_types
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False

from checker import SecurityChecker, OWASP_NAMES

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SEC//SCAN — AI セキュリティ診断</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:       #060910;
            --surface:  #0d1117;
            --surface2: #111820;
            --border:   #1a2332;
            --border2:  #243040;
            --accent:   #00ff88;
            --accent2:  #00c8ff;
            --danger:   #ff1a4b;
            --high:     #ff6b35;
            --medium:   #ffd700;
            --low:      #4da6ff;
            --text:     #c8d8e8;
            --muted:    #3a5070;
            --muted2:   #567090;
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
        body::before {
            content: '';
            position: fixed; inset: 0;
            background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.06) 2px, rgba(0,0,0,0.06) 4px);
            pointer-events: none; z-index: 200;
        }
        .container { max-width: 900px; margin: 0 auto; padding: 52px 24px 100px; }

        /* ── Header ── */
        .header { margin-bottom: 44px; animation: fadeDown .6s ease both; }
        .header-tag { font-size: 11px; letter-spacing: .25em; color: var(--accent); text-transform: uppercase; margin-bottom: 10px; opacity: .8; }
        .header-tag::before { content: '> '; color: var(--muted); }
        h1 { font-family: var(--sans); font-weight: 700; font-size: clamp(28px,5vw,48px); letter-spacing: -.02em; color: #fff; }
        h1 span { color: var(--accent); }
        .header-sub { font-size: 11px; color: var(--muted); margin-top: 8px; letter-spacing: .12em; }

        /* ── Form ── */
        .scan-form {
            display: flex; gap: 0; margin-bottom: 44px;
            border: 1px solid var(--border); background: var(--surface);
            animation: fadeDown .6s .1s ease both; position: relative; overflow: hidden;
        }
        .scan-form::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
            background: linear-gradient(90deg, transparent, var(--accent), transparent);
            animation: scanLine 3s ease-in-out infinite;
        }
        @keyframes scanLine { 0%,100%{opacity:0;transform:translateX(-100%)} 50%{opacity:1;transform:translateX(100%)} }
        .prompt-label { display:flex; align-items:center; padding:0 16px; color:var(--accent); font-size:14px; border-right:1px solid var(--border); white-space:nowrap; user-select:none; }
        input[type=text] { flex:1; background:transparent; border:none; outline:none; padding:16px 18px; font-family:var(--mono); font-size:14px; color:var(--text); caret-color:var(--accent); }
        input[type=text]::placeholder { color:var(--muted); }
        .scan-btn { background:var(--accent); color:#000; border:none; padding:0 28px; font-family:var(--sans); font-weight:700; font-size:13px; letter-spacing:.15em; text-transform:uppercase; cursor:pointer; transition:background .15s,box-shadow .15s; white-space:nowrap; }
        .scan-btn:hover { background:#00ffaa; box-shadow:0 0 20px rgba(0,255,136,.4); }
        .scan-btn:active { transform:scale(.98); }

        /* ── Loading ── */
        .loading-bar { display:none; height:3px; background:var(--border); margin-bottom:24px; overflow:hidden; border-radius:2px; }
        .loading-bar.active { display:block; }
        .loading-bar::after { content:''; display:block; height:100%; width:30%; background:linear-gradient(90deg,transparent,var(--accent),transparent); animation:loadingMove 1.2s ease-in-out infinite; }
        @keyframes loadingMove { 0%{transform:translateX(-100%)} 100%{transform:translateX(400%)} }

        /* ── Section header ── */
        .section-hd {
            display:flex; align-items:center; gap:10px;
            padding:12px 18px; border-bottom:1px solid var(--border);
            font-size:11px; letter-spacing:.2em; color:var(--muted2); text-transform:uppercase;
        }
        .section-hd .dot { width:6px; height:6px; border-radius:50%; background:var(--accent); box-shadow:0 0 8px var(--accent); }

        /* ── Summary dashboard ── */
        .summary-grid { display:grid; grid-template-columns:auto 1fr; gap:16px; margin-bottom:24px; animation:fadeUp .5s ease both; }
        @media(max-width:600px){ .summary-grid { grid-template-columns:1fr; } }

        .score-card { background:var(--surface); border:1px solid var(--border); padding:24px 28px; display:flex; flex-direction:column; align-items:center; justify-content:center; min-width:200px; }
        .score-ring-wrap { position:relative; width:130px; height:130px; margin-bottom:12px; }
        .score-ring-wrap svg { transform:rotate(-90deg); }
        .score-track { fill:none; stroke:var(--border2); stroke-width:10; }
        .score-fill  { fill:none; stroke-width:10; stroke-linecap:round; transition:stroke-dashoffset 1.2s cubic-bezier(.16,1,.3,1); }
        .score-center { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
        .score-num { font-family:var(--sans); font-weight:700; font-size:38px; color:#fff; line-height:1; }
        .score-pct { font-size:12px; color:var(--muted2); }
        .grade-badge { font-family:var(--sans); font-weight:700; font-size:14px; letter-spacing:.12em; padding:4px 14px; border-radius:2px; margin-top:4px; }
        .grade-info     { background:rgba(0,255,136,.12); color:var(--accent);   border:1px solid rgba(0,255,136,.3); }
        .grade-low      { background:rgba(77,166,255,.12); color:var(--low);     border:1px solid rgba(77,166,255,.3); }
        .grade-medium   { background:rgba(255,215,0,.12);  color:var(--medium);  border:1px solid rgba(255,215,0,.3); }
        .grade-high     { background:rgba(255,107,53,.12); color:var(--high);    border:1px solid rgba(255,107,53,.3); }
        .grade-critical { background:rgba(255,26,75,.12);  color:var(--danger);  border:1px solid rgba(255,26,75,.3); }
        .score-sub { font-size:11px; color:var(--muted); margin-top:6px; }

        .risk-panel { background:var(--surface); border:1px solid var(--border); display:grid; grid-template-columns:1fr 1fr; }
        .risk-tile { padding:20px; display:flex; flex-direction:column; align-items:center; justify-content:center; border-right:1px solid var(--border); border-bottom:1px solid var(--border); }
        .risk-tile:nth-child(2n){ border-right:none; }
        .risk-tile:nth-child(3),.risk-tile:nth-child(4){ border-bottom:none; }
        .risk-count-num { font-family:var(--sans); font-weight:700; font-size:32px; line-height:1; }
        .risk-lbl { font-size:10px; letter-spacing:.15em; margin-top:4px; text-transform:uppercase; }
        .rt-critical .risk-count-num { color:var(--danger); }  .rt-critical .risk-lbl { color:var(--danger); opacity:.7; }
        .rt-high     .risk-count-num { color:var(--high); }    .rt-high     .risk-lbl { color:var(--high);   opacity:.7; }
        .rt-medium   .risk-count-num { color:var(--medium); }  .rt-medium   .risk-lbl { color:var(--medium); opacity:.7; }
        .rt-low      .risk-count-num { color:var(--low); }     .rt-low      .risk-lbl { color:var(--low);    opacity:.7; }

        /* ── Tabs ── */
        .tab-nav { display:flex; gap:0; margin-bottom:0; border:1px solid var(--border); border-bottom:none; background:var(--surface); animation:fadeUp .5s .05s ease both; overflow-x:auto; }
        .tab-btn {
            flex:1; min-width:0; background:transparent; border:none; border-right:1px solid var(--border); padding:11px 8px;
            font-family:var(--mono); font-size:11px; letter-spacing:.1em; color:var(--muted2); cursor:pointer;
            text-transform:uppercase; transition:color .15s, background .15s; white-space:nowrap;
        }
        .tab-btn:last-child { border-right:none; }
        .tab-btn:hover { color:var(--text); background:rgba(255,255,255,.02); }
        .tab-btn.active { color:var(--accent); background:rgba(0,255,136,.05); border-bottom:2px solid var(--accent); margin-bottom:-1px; }
        .tab-badge { display:inline-block; font-size:9px; background:var(--border2); padding:1px 5px; border-radius:2px; margin-left:5px; vertical-align:middle; }
        .tab-btn.active .tab-badge { background:rgba(0,255,136,.2); color:var(--accent); }

        /* ── Tab panels ── */
        .tab-panel { display:none; border:1px solid var(--border); background:var(--surface); animation:fadeUp .4s ease both; margin-bottom:20px; }
        .tab-panel.active { display:block; }

        /* ── Check items ── */
        .check-item { display:flex; flex-direction:column; gap:4px; padding:13px 18px; border-bottom:1px solid var(--border); animation:fadeUp .4s ease both; }
        .check-item:last-child { border-bottom:none; }
        .check-row { display:flex; align-items:center; gap:12px; }
        .check-indicator { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
        .ci-ok       { background:var(--accent); box-shadow:0 0 8px var(--accent); }
        .ci-info     { background:var(--accent); box-shadow:0 0 8px var(--accent); }
        .ci-low      { background:var(--low);    box-shadow:0 0 8px var(--low); }
        .ci-medium   { background:var(--medium); box-shadow:0 0 8px var(--medium); }
        .ci-high     { background:var(--high);   box-shadow:0 0 8px var(--high); }
        .ci-critical { background:var(--danger); box-shadow:0 0 8px var(--danger); }
        .check-name { flex:1; font-size:12px; color:var(--text); }
        .check-detail { font-size:11px; color:var(--muted2); padding-left:20px; }
        .check-suggestion { font-size:11px; color:#6a9bb8; padding-left:20px; padding-top:2px; }
        .check-suggestion::before { content:'→ '; color:var(--accent2); }
        .risk-badge { font-size:9px; letter-spacing:.1em; padding:2px 7px; border-radius:2px; font-family:var(--sans); font-weight:700; text-transform:uppercase; flex-shrink:0; }
        .rb-ok       { background:rgba(0,255,136,.1);  color:var(--accent); border:1px solid rgba(0,255,136,.2); }
        .rb-info     { background:rgba(0,255,136,.1);  color:var(--accent); border:1px solid rgba(0,255,136,.2); }
        .rb-low      { background:rgba(77,166,255,.1); color:var(--low);    border:1px solid rgba(77,166,255,.2); }
        .rb-medium   { background:rgba(255,215,0,.1);  color:var(--medium); border:1px solid rgba(255,215,0,.2); }
        .rb-high     { background:rgba(255,107,53,.1); color:var(--high);   border:1px solid rgba(255,107,53,.2); }
        .rb-critical { background:rgba(255,26,75,.12); color:var(--danger); border:1px solid rgba(255,26,75,.25); }
        .owasp-tag { font-size:9px; padding:1px 6px; border:1px solid var(--border2); color:var(--muted2); border-radius:2px; margin-left:4px; }

        /* ── OWASP section ── */
        .owasp-section { border:1px solid var(--border); background:var(--surface); margin-bottom:20px; animation:fadeUp .5s .15s ease both; }
        .owasp-row { display:grid; grid-template-columns:56px 1fr auto; gap:0; padding:11px 18px; border-bottom:1px solid var(--border); align-items:center; }
        .owasp-row:last-child { border-bottom:none; }
        .owasp-row.has-issue { background:rgba(255,26,75,.03); }
        .owasp-code { font-size:12px; color:var(--accent2); font-weight:bold; }
        .owasp-name { font-size:12px; color:var(--text); }
        .owasp-count-badge { font-size:10px; font-family:var(--sans); font-weight:700; padding:2px 8px; border-radius:2px; margin-left:12px; }
        .obc-ok   { background:rgba(0,255,136,.1);  color:var(--accent); border:1px solid rgba(0,255,136,.2); }
        .obc-bad  { background:rgba(255,26,75,.12); color:var(--danger); border:1px solid rgba(255,26,75,.25); }
        .owasp-items { grid-column:2; font-size:10px; color:var(--muted2); margin-top:3px; }

        /* ── AI section ── */
        .ai-section { border:1px solid var(--border); background:var(--surface); margin-bottom:20px; animation:fadeUp .5s .2s ease both; }
        .ai-trigger-btn {
            display:block; width:100%; background:transparent; border:none; padding:18px;
            font-family:var(--mono); font-size:12px; color:var(--accent2); cursor:pointer;
            letter-spacing:.08em; transition:background .15s; text-align:center;
        }
        .ai-trigger-btn:hover { background:rgba(0,200,255,.05); }
        .ai-loading { padding:24px; text-align:center; display:none; }
        .ai-spinner { display:inline-block; width:20px; height:20px; border:2px solid var(--border2); border-top-color:var(--accent2); border-radius:50%; animation:spin .8s linear infinite; }
        @keyframes spin { to { transform:rotate(360deg); } }
        .ai-loading-txt { font-size:11px; color:var(--muted2); margin-top:10px; letter-spacing:.1em; }
        .ai-result { padding:20px; display:none; }
        .ai-error { padding:18px; color:var(--muted2); font-size:12px; display:none; }
        .ai-error::before { content:'⚠ '; color:var(--medium); }
        .md-h2 { font-family:var(--sans); font-size:15px; font-weight:700; color:#fff; margin:16px 0 8px; padding-bottom:6px; border-bottom:1px solid var(--border); }
        .md-h3 { font-family:var(--sans); font-size:13px; font-weight:700; color:var(--accent2); margin:14px 0 6px; }
        .md-li { font-size:12px; color:var(--text); padding:3px 0 3px 14px; position:relative; line-height:1.6; }
        .md-li::before { content:'—'; position:absolute; left:0; color:var(--muted); }
        .md-strong { color:#fff; }
        .md-code { font-family:var(--mono); background:var(--surface2); padding:1px 5px; border:1px solid var(--border); font-size:11px; color:var(--accent); }
        .ai-footer { padding:10px 18px; border-top:1px solid var(--border); font-size:10px; color:var(--muted); letter-spacing:.1em; }

        /* ── Export ── */
        .export-bar { display:flex; gap:10px; margin-bottom:20px; animation:fadeUp .5s .25s ease both; }
        .export-btn {
            flex:1; background:var(--surface); border:1px solid var(--border2); padding:12px;
            font-family:var(--mono); font-size:11px; letter-spacing:.1em; color:var(--muted2);
            cursor:pointer; text-transform:uppercase; transition:color .15s, border-color .15s, background .15s;
        }
        .export-btn:hover { color:var(--accent); border-color:var(--accent); background:rgba(0,255,136,.04); }

        /* ── Result header ── */
        .result-meta { display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; animation:fadeUp .4s ease both; }
        .result-target { font-size:13px; color:var(--accent2); word-break:break-all; }
        .result-date { font-size:11px; color:var(--muted); flex-shrink:0; margin-left:12px; }

        /* ── Animations ── */
        @keyframes fadeDown { from{opacity:0;transform:translateY(-12px)} to{opacity:1;transform:translateY(0)} }
        @keyframes fadeUp   { from{opacity:0;transform:translateY(10px)}  to{opacity:1;transform:translateY(0)} }

        /* ── Corner deco ── */
        .corner-deco { position:fixed; bottom:20px; right:20px; font-size:10px; color:var(--muted); letter-spacing:.15em; opacity:.3; pointer-events:none; }

        /* ── Print styles ── */
        @media print {
            * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; animation: none !important; transition: none !important; }
            html, body { height: auto !important; overflow: visible !important; min-height: 0 !important; }
            .container { padding-bottom: 0 !important; }
            .export-bar { margin-bottom: 0 !important; }
            body { background:#fff !important; color:#111 !important; font-family: Arial, sans-serif; }
            body::before, body::after, .corner-deco, .scan-form, .loading-bar,
            .export-bar, .ai-trigger-btn, #ai-body, #ai-loading { display:none !important; }
            .container { max-width:100%; padding:16px; }
            h1 { color:#111 !important; font-size:24px; }
            h1 span { color:#007a40 !important; }
            .header-tag { color:#007a40 !important; }
            .header-sub { color:#555 !important; }
            .result-target { color:#0066cc !important; }
            .result-date { color:#555 !important; }
            .summary-grid { display:grid; grid-template-columns:auto 1fr; gap:12px; }
            .score-card { background:#f5f5f5 !important; border:1px solid #ccc !important; }
            .score-num { color:#111 !important; }
            .score-pct, .score-sub { color:#555 !important; }
            .grade-badge { border:1px solid #999 !important; }
            .grade-info     { background:#e6fff2 !important; color:#007a40 !important; }
            .grade-low      { background:#e6f0ff !important; color:#0055aa !important; }
            .grade-medium   { background:#fff8e0 !important; color:#996600 !important; }
            .grade-high     { background:#fff0e6 !important; color:#cc4400 !important; }
            .grade-critical { background:#ffe6ea !important; color:#cc0022 !important; }
            .risk-panel { background:#f5f5f5 !important; border:1px solid #ccc !important; }
            .risk-tile { border-color:#ddd !important; }
            .rt-critical .risk-count-num { color:#cc0022 !important; }
            .rt-high     .risk-count-num { color:#cc4400 !important; }
            .rt-medium   .risk-count-num { color:#996600 !important; }
            .rt-low      .risk-count-num { color:#0055aa !important; }
            .rt-critical .risk-lbl { color:#cc0022 !important; }
            .rt-high     .risk-lbl { color:#cc4400 !important; }
            .rt-medium   .risk-lbl { color:#996600 !important; }
            .rt-low      .risk-lbl { color:#0055aa !important; }
            .tab-nav { display:none !important; }
            .tab-panel { display:block !important; border:1px solid #ccc !important; background:#fff !important; margin-bottom:12px; page-break-inside:avoid; }
            .section-hd { background:#f0f0f0 !important; color:#333 !important; border-bottom:1px solid #ccc !important; }
            .section-hd .dot { background:#007a40 !important; box-shadow:none !important; }
            .check-item { border-bottom:1px solid #eee !important; }
            .check-name { color:#111 !important; }
            .check-detail { color:#444 !important; }
            .check-suggestion { color:#0055aa !important; }
            .check-indicator { box-shadow:none !important; }
            .ci-ok, .ci-info { background:#007a40 !important; }
            .ci-low         { background:#0055aa !important; }
            .ci-medium      { background:#996600 !important; }
            .ci-high        { background:#cc4400 !important; }
            .ci-critical    { background:#cc0022 !important; }
            .risk-badge { border:1px solid #ccc !important; }
            .rb-ok, .rb-info { background:#e6fff2 !important; color:#007a40 !important; }
            .rb-low          { background:#e6f0ff !important; color:#0055aa !important; }
            .rb-medium       { background:#fff8e0 !important; color:#996600 !important; }
            .rb-high         { background:#fff0e6 !important; color:#cc4400 !important; }
            .rb-critical     { background:#ffe6ea !important; color:#cc0022 !important; }
            .owasp-tag { color:#555 !important; border-color:#ccc !important; }
            .owasp-section { border:1px solid #ccc !important; background:#fff !important; page-break-inside:avoid; }
            .owasp-row { border-bottom:1px solid #eee !important; }
            .owasp-row.has-issue { background:#fff8f8 !important; }
            .owasp-code { color:#0055aa !important; }
            .owasp-name { color:#111 !important; }
            .owasp-items { color:#555 !important; }
            .obc-ok  { background:#e6fff2 !important; color:#007a40 !important; border:1px solid #ccc !important; }
            .obc-bad { background:#ffe6ea !important; color:#cc0022 !important; border:1px solid #ccc !important; }
            .ai-section { border:1px solid #ccc !important; background:#fff !important; page-break-inside:avoid; }
            .ai-result { display:block !important; color:#111 !important; }
            .md-h2 { color:#111 !important; border-bottom:1px solid #ccc !important; }
            .md-h3 { color:#0055aa !important; }
            .md-li { color:#111 !important; }
            .md-strong { color:#111 !important; }
            .ai-footer { color:#555 !important; border-top:1px solid #eee !important; }
            .score-fill { stroke:#007a40 !important; }
            .score-track { stroke:#ddd !important; }
        }
    </style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <header class="header">
        <div class="header-tag">AI × Security Diagnostics v3.0</div>
        <h1>SEC<span>//</span>SCAN</h1>
        <p class="header-sub">
            OWASP Top 10 対応 &nbsp;|&nbsp; AI テスト観点生成 &nbsp;|&nbsp; SSL / Headers / Cookie / Form 診断
        </p>
    </header>

    <!-- Scan form -->
    <form method="post" class="scan-form" id="scanForm">
        <span class="prompt-label">TARGET://</span>
        <input type="text" name="url" placeholder="https://example.com" value="{{ url }}" autocomplete="off" spellcheck="false" required>
        <button type="submit" class="scan-btn">SCAN</button>
    </form>

    <div class="loading-bar" id="loadingBar"></div>

    {% if has_results %}

    <!-- Result metadata -->
    <div class="result-meta">
        <span class="result-target">{{ url }}</span>
        <span class="result-date">{{ scan_date }}</span>
    </div>

    <!-- Summary dashboard -->
    <div class="summary-grid">
        <div class="score-card">
            <div class="score-ring-wrap">
                <svg width="130" height="130" viewBox="0 0 130 130">
                    <circle class="score-track" cx="65" cy="65" r="54"/>
                    <circle class="score-fill" cx="65" cy="65" r="54"
                        id="scoreFill"
                        stroke-dasharray="339.3"
                        stroke-dashoffset="339.3"/>
                </svg>
                <div class="score-center">
                    <div class="score-num" id="scoreNum">0</div>
                    <div class="score-pct">/ 100</div>
                </div>
            </div>
            <div class="grade-badge grade-{{ summary.grade_color }}">{{ summary.grade }}</div>
            <div class="score-sub">{{ summary.passed }} / {{ summary.total }} チェック通過</div>
        </div>

        <div class="risk-panel">
            <div class="risk-tile rt-critical">
                <div class="risk-count-num">{{ summary.risk_counts.critical }}</div>
                <div class="risk-lbl">Critical</div>
            </div>
            <div class="risk-tile rt-high">
                <div class="risk-count-num">{{ summary.risk_counts.high }}</div>
                <div class="risk-lbl">High</div>
            </div>
            <div class="risk-tile rt-medium">
                <div class="risk-count-num">{{ summary.risk_counts.medium }}</div>
                <div class="risk-lbl">Medium</div>
            </div>
            <div class="risk-tile rt-low">
                <div class="risk-count-num">{{ summary.risk_counts.low }}</div>
                <div class="risk-lbl">Low</div>
            </div>
        </div>
    </div>

    <!-- Tabs -->
    {% set cats = [
        ('ssl',     'SSL/TLS'),
        ('headers', 'HTTP Headers'),
        ('cookies', 'Cookie'),
        ('forms',   'フォーム'),
    ] %}

    <div class="tab-nav">
        {% for cat_id, cat_label in cats %}
        {% set cat_results = results_by_cat[cat_id] %}
        {% set fail_count = cat_results | selectattr('ok', 'equalto', false) | list | length %}
        <button class="tab-btn {% if loop.first %}active{% endif %}"
                onclick="switchTab('{{ cat_id }}')" id="tabbtn-{{ cat_id }}">
            {{ cat_label }}
            {% if fail_count > 0 %}
            <span class="tab-badge">{{ fail_count }}</span>
            {% endif %}
        </button>
        {% endfor %}
    </div>

    <!-- Tab panels -->
    {% for cat_id, cat_label in cats %}
    <div class="tab-panel {% if loop.first %}active{% endif %}" id="tab-{{ cat_id }}">
        <div class="section-hd">
            <span class="dot"></span>{{ cat_label }} チェック結果
        </div>
        {% for r in results_by_cat[cat_id] %}
        {% set badge_cls = 'rb-ok' if r.ok else ('rb-' + r.risk_level) %}
        {% set ind_cls   = 'ci-ok' if r.ok else ('ci-' + r.risk_level) %}
        <div class="check-item">
            <div class="check-row">
                <div class="check-indicator {{ ind_cls }}"></div>
                <span class="check-name">{{ r.name }}</span>
                <span class="risk-badge {{ badge_cls }}">{{ 'PASS' if r.ok else r.risk_level }}</span>
                {% for o in r.owasp %}<span class="owasp-tag">{{ o }}</span>{% endfor %}
            </div>
            <div class="check-detail">{{ r.detail }}</div>
            {% if r.suggestion %}
            <div class="check-suggestion">{{ r.suggestion }}</div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endfor %}

    <!-- OWASP Top 10 mapping -->
    <div class="owasp-section">
        <div class="section-hd">
            <span class="dot"></span>OWASP Top 10 マッピング（2021）
        </div>
        {% for code, name in OWASP_NAMES.items() %}
        {% set issues = summary.owasp_issues.get(code, []) %}
        <div class="owasp-row {% if issues %}has-issue{% endif %}">
            <div class="owasp-code">{{ code }}</div>
            <div>
                <div class="owasp-name">{{ name }}</div>
                {% if issues %}<div class="owasp-items">{{ issues | join(' / ') }}</div>{% endif %}
            </div>
            <div class="owasp-count-badge {% if issues %}obc-bad{% else %}obc-ok{% endif %}">
                {% if issues %}{{ issues | length }} issue{% else %}OK{% endif %}
            </div>
        </div>
        {% endfor %}
    </div>

    <!-- AI test points -->
    <div class="ai-section">
        <div class="section-hd">
            <span class="dot"></span>AI 追加テスト観点生成
        </div>
        <div id="ai-body">
            <button class="ai-trigger-btn" onclick="loadAI()">
                ⬡ &nbsp; AI テスト観点を生成する &nbsp;（Gemini powered）
            </button>
        </div>
        <div class="ai-loading" id="ai-loading">
            <div class="ai-spinner"></div>
            <div class="ai-loading-txt">AI が診断結果を分析中...</div>
        </div>
        <div class="ai-result" id="ai-result"></div>
        <div class="ai-error" id="ai-error"></div>
    </div>

    <!-- Export -->
    <div class="export-bar">
        <button class="export-btn" onclick="exportJSON()">
            ↓ &nbsp; JSON レポートをダウンロード
        </button>
        <button class="export-btn" onclick="window.print()">
            ⎙ &nbsp; 印刷 / PDF 保存
        </button>
    </div>

    <!-- Inline data for JS -->
    <script>
    const SCAN_URL = {{ url | tojson }};
    const SCAN_SCORE = {{ summary.score }};
    const SCAN_GRADE_COLOR = {{ summary.grade_color | tojson }};
    const SCAN_DATA_JSON = {{ results_json | safe }};
    const SCAN_FINDINGS = {{ findings_json | safe }};
    </script>

    {% endif %}
</div>
<div class="corner-deco">SEC//SCAN &copy; 2025</div>

<script>
// ── Score ring animation ──────────────────────────────────────────
(function(){
    var fill = document.getElementById('scoreFill');
    if (!fill) return;
    var score = typeof SCAN_SCORE !== 'undefined' ? SCAN_SCORE : 0;
    var circ = 339.3;
    var gradeColors = {
        'info':     '#00ff88',
        'low':      '#4da6ff',
        'medium':   '#ffd700',
        'high':     '#ff6b35',
        'critical': '#ff1a4b',
    };
    fill.style.stroke = gradeColors[SCAN_GRADE_COLOR] || '#00ff88';
    setTimeout(function(){
        fill.style.strokeDashoffset = circ * (1 - score / 100);
    }, 100);
    var numEl = document.getElementById('scoreNum');
    if (numEl) {
        var start = 0, end = score, dur = 1000;
        var t0 = performance.now();
        function animate(now) {
            var p = Math.min((now - t0) / dur, 1);
            var ease = 1 - Math.pow(1 - p, 3);
            numEl.textContent = Math.round(ease * end);
            if (p < 1) requestAnimationFrame(animate);
        }
        requestAnimationFrame(animate);
    }
})();

// ── Loading bar ───────────────────────────────────────────────────
document.getElementById('scanForm').addEventListener('submit', function(){
    document.getElementById('loadingBar').classList.add('active');
});

// ── Tab switching ─────────────────────────────────────────────────
function switchTab(id) {
    document.querySelectorAll('.tab-panel').forEach(function(p){ p.classList.remove('active'); });
    document.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); });
    var panel = document.getElementById('tab-' + id);
    var btn   = document.getElementById('tabbtn-' + id);
    if (panel) panel.classList.add('active');
    if (btn)   btn.classList.add('active');
}

// ── AI test points ────────────────────────────────────────────────
function loadAI() {
    document.getElementById('ai-body').style.display = 'none';
    document.getElementById('ai-loading').style.display = 'block';
    document.getElementById('ai-result').style.display  = 'none';
    document.getElementById('ai-error').style.display   = 'none';

    fetch('/api/ai-points', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: SCAN_URL, findings: SCAN_FINDINGS})
    })
    .then(function(r){ return r.json(); })
    .then(function(data){
        document.getElementById('ai-loading').style.display = 'none';
        if (data.error) {
            var e = document.getElementById('ai-error');
            e.textContent = data.error;
            e.style.display = 'block';
        } else {
            var r = document.getElementById('ai-result');
            r.innerHTML = renderMarkdown(data.text);
            r.style.display = 'block';
        }
        // footer note
        var footer = document.createElement('div');
        footer.className = 'ai-footer';
        footer.textContent = 'Generated by Gemini (Google) · ' + new Date().toLocaleTimeString('ja-JP');
        document.querySelector('.ai-section').appendChild(footer);
    })
    .catch(function(err){
        document.getElementById('ai-loading').style.display = 'none';
        var e = document.getElementById('ai-error');
        e.textContent = 'AI通信エラー: ' + err.message;
        e.style.display = 'block';
    });
}

function renderMarkdown(text) {
    var escaped = text
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return escaped
        .replace(/^## (.+)$/gm, '<div class="md-h2">$1</div>')
        .replace(/^### (.+)$/gm, '<div class="md-h3">$1</div>')
        .replace(/\*\*(.+?)\*\*/g, '<span class="md-strong">$1</span>')
        .replace(/`([^`]+)`/g, '<code class="md-code">$1</code>')
        .replace(/^[-*] (.+)$/gm, '<div class="md-li">$1</div>')
        .replace(/\n{2,}/g, '<br><br>')
        .replace(/\n/g, '\n');
}

// ── JSON export ───────────────────────────────────────────────────
function exportJSON() {
    var data = typeof SCAN_DATA_JSON !== 'undefined' ? SCAN_DATA_JSON : {};
    var blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'secscan_' + new Date().toISOString().replace(/[:.]/g,'-').slice(0,19) + '.json';
    a.click();
}
</script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    results_by_cat = {"ssl": [], "headers": [], "cookies": [], "forms": []}
    all_results = []
    summary = {}
    url = ""
    scan_date = ""
    results_json = "null"
    findings_json = "[]"

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        checker = SecurityChecker(url)
        all_results = checker.run_all()
        summary = checker.get_summary(all_results)
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for r in all_results:
            cat = r.category if r.category in results_by_cat else "ssl"
            results_by_cat[cat].append(r)

        report = {
            "target": url,
            "scan_date": scan_date,
            "summary": summary,
            "results": [r.to_dict() for r in all_results],
        }
        results_json = json.dumps(report, ensure_ascii=False, indent=2)
        findings_json = json.dumps([r.to_dict() for r in all_results], ensure_ascii=False)

    return render_template_string(
        HTML,
        url=url,
        results_by_cat=results_by_cat,
        summary=summary,
        scan_date=scan_date,
        results_json=results_json,
        findings_json=findings_json,
        OWASP_NAMES=OWASP_NAMES,
        has_results=bool(all_results),
    )


@app.route("/api/ai-points", methods=["POST"])
def ai_points():
    referer = request.headers.get("Referer", "")
    host = request.headers.get("Host", "")
    if not (referer.startswith(f"https://{host}") or referer.startswith(f"http://{host}") or host in ("127.0.0.1:8888", "localhost:8888")):
        return jsonify({"error": "不正なリクエスト"}), 403

    if not HAS_GEMINI:
        return jsonify({"error": "google-generativeaiライブラリが未インストールです。pip install google-generativeai を実行してください。"})

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return jsonify({"error": "GEMINI_API_KEYが設定されていません。https://aistudio.google.com/app/apikey でキーを取得後、export GEMINI_API_KEY=AIza... を実行してください。"})

    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    findings = data.get("findings", [])

    failed_lines = "\n".join(
        f"- [{f['risk_level'].upper()}] {f['name']}: {f['detail']}"
        for f in findings if not f.get("ok")
    ) or "重大な問題は検出されませんでした"

    prompt = f"""あなたはWebセキュリティ診断の専門家（SHIFT Security レベル）です。
自動スキャン結果を基に、手動テストが必要な追加テスト観点を生成してください。

対象URL: {url}

自動スキャン検出問題:
{failed_lines}

以下の形式で回答してください（日本語・簡潔・実践的に）:

## 🔴 Critical / High Priority テスト観点
（緊急度の高い手動テスト観点を4-6個。具体的なテスト手順を含む）

## 🟡 Medium Priority テスト観点
（中程度の優先度のテスト観点を3-5個）

## 🟢 確認推奨事項
（追加確認事項・設定確認を3-4個）

## 推奨テストツール
（このサイトに適したツール名・コマンド例を2-3個）

## 品質保証観点
（QAエンジニアとして特に注目すべきテスト設計観点を2-3個）"""

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction="あなたはWebセキュリティ診断と品質保証の専門家です。会社名は絶対に出さず、簡潔で実践的な回答をしてください。",
                max_output_tokens=2000,
            ),
        )
        return jsonify({"text": response.text})
    except Exception as e:
        return jsonify({"error": f"AI生成エラー: {str(e)}"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
