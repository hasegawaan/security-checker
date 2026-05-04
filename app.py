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
    <title>SecScan — AI セキュリティ診断</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:       #f0f4f8;
            --surface:  #ffffff;
            --surface2: #f8fafc;
            --border:   #e2e8f0;
            --border2:  #cbd5e1;
            --navy:     #1e3a5f;
            --navy2:    #2d5282;
            --blue:     #2563eb;
            --danger:   #dc2626;
            --high:     #ea580c;
            --medium:   #d97706;
            --low:      #2563eb;
            --pass:     #16a34a;
            --text:     #1e293b;
            --muted:    #94a3b8;
            --muted2:   #64748b;
            --sans: 'DM Sans', system-ui, sans-serif;
            --mono: 'DM Mono', monospace;
            --shadow-sm: 0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.05);
            --shadow:    0 4px 6px rgba(0,0,0,.07), 0 2px 4px rgba(0,0,0,.05);
            --shadow-md: 0 10px 15px rgba(0,0,0,.08), 0 4px 6px rgba(0,0,0,.05);
        }
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:var(--bg); color:var(--text); font-family:var(--sans); min-height:100vh; font-size:14px; line-height:1.6; }
        .container { max-width:960px; margin:0 auto; padding:0 24px 80px; }

        /* ── Top bar ── */
        .topbar { background:var(--navy); padding:0 32px; margin-bottom:40px; display:flex; align-items:center; justify-content:space-between; height:60px; box-shadow:var(--shadow); }
        .topbar-logo { display:flex; align-items:center; gap:10px; }
        .topbar-logo svg { width:28px; height:28px; }
        .topbar-title { font-size:17px; font-weight:700; color:#fff; letter-spacing:-.01em; }
        .topbar-title span { color:#60a5fa; }
        .topbar-badge { font-size:10px; background:rgba(96,165,250,.2); color:#93c5fd; padding:2px 8px; border-radius:20px; border:1px solid rgba(96,165,250,.3); font-weight:500; }

        /* ── Page header ── */
        .header { padding:36px 0 32px; animation:fadeDown .5s ease both; }
        .header-tag { font-size:12px; font-weight:600; color:var(--blue); text-transform:uppercase; letter-spacing:.08em; margin-bottom:10px; }
        h1 { font-size:clamp(26px,4vw,38px); font-weight:700; color:var(--navy); letter-spacing:-.02em; line-height:1.15; }
        h1 span { color:var(--blue); }
        .header-sub { font-size:13px; color:var(--muted2); margin-top:8px; }

        /* ── Form ── */
        .scan-form { display:flex; background:var(--surface); border:1.5px solid var(--border2); border-radius:10px; overflow:hidden; box-shadow:var(--shadow-md); margin-bottom:32px; animation:fadeDown .5s .08s ease both; transition:border-color .2s, box-shadow .2s; }
        .scan-form:focus-within { border-color:var(--blue); box-shadow:0 0 0 3px rgba(37,99,235,.12), var(--shadow-md); }
        .prompt-label { display:flex; align-items:center; padding:0 16px; color:var(--muted2); font-size:13px; font-weight:500; border-right:1.5px solid var(--border); background:var(--surface2); white-space:nowrap; user-select:none; }
        input[type=text] { flex:1; background:transparent; border:none; outline:none; padding:15px 18px; font-family:var(--sans); font-size:14px; color:var(--text); }
        input[type=text]::placeholder { color:var(--muted); }
        .scan-btn { background:var(--navy); color:#fff; border:none; padding:0 28px; font-family:var(--sans); font-weight:600; font-size:13px; letter-spacing:.03em; cursor:pointer; transition:background .15s; white-space:nowrap; }
        .scan-btn:hover { background:var(--navy2); }
        .scan-btn:active { transform:scale(.99); }

        /* ── Loading ── */
        .loading-bar { display:none; height:3px; background:var(--border); margin-bottom:24px; overflow:hidden; border-radius:2px; }
        .loading-bar.active { display:block; }
        .loading-bar::after { content:''; display:block; height:100%; width:30%; background:linear-gradient(90deg,transparent,var(--blue),transparent); animation:loadingMove 1.2s ease-in-out infinite; }
        @keyframes loadingMove { 0%{transform:translateX(-100%)} 100%{transform:translateX(400%)} }

        /* ── Section header ── */
        .section-hd { display:flex; align-items:center; gap:8px; padding:12px 18px; border-bottom:1px solid var(--border); font-size:11px; letter-spacing:.08em; color:var(--muted2); text-transform:uppercase; font-weight:600; background:var(--surface2); }
        .section-hd .dot { width:6px; height:6px; border-radius:50%; background:var(--blue); }

        /* ── Summary dashboard ── */
        .summary-grid { display:grid; grid-template-columns:auto 1fr; gap:16px; margin-bottom:24px; animation:fadeUp .4s ease both; }
        @media(max-width:600px){ .summary-grid { grid-template-columns:1fr; } }

        .score-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:28px; display:flex; flex-direction:column; align-items:center; justify-content:center; min-width:200px; box-shadow:var(--shadow); }
        .score-ring-wrap { position:relative; width:130px; height:130px; margin-bottom:14px; }
        .score-ring-wrap svg { transform:rotate(-90deg); }
        .score-track { fill:none; stroke:var(--border); stroke-width:10; }
        .score-fill  { fill:none; stroke-width:10; stroke-linecap:round; transition:stroke-dashoffset 1.2s cubic-bezier(.16,1,.3,1); }
        .score-center { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
        .score-num { font-weight:700; font-size:38px; color:var(--navy); line-height:1; }
        .score-pct { font-size:12px; color:var(--muted); }
        .grade-badge { font-weight:700; font-size:12px; letter-spacing:.05em; padding:4px 14px; border-radius:20px; margin-top:8px; }
        .grade-info     { background:#dcfce7; color:#15803d; border:1px solid #bbf7d0; }
        .grade-low      { background:#dbeafe; color:#1d4ed8; border:1px solid #bfdbfe; }
        .grade-medium   { background:#fef3c7; color:#92400e; border:1px solid #fde68a; }
        .grade-high     { background:#ffedd5; color:#9a3412; border:1px solid #fed7aa; }
        .grade-critical { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
        .score-sub { font-size:12px; color:var(--muted2); margin-top:4px; }

        .risk-panel { background:var(--surface); border:1px solid var(--border); border-radius:12px; display:grid; grid-template-columns:1fr 1fr; overflow:hidden; box-shadow:var(--shadow); }
        .risk-tile { padding:22px 16px; display:flex; flex-direction:column; align-items:center; justify-content:center; border-right:1px solid var(--border); border-bottom:1px solid var(--border); transition:background .15s; }
        .risk-tile:nth-child(2n){ border-right:none; }
        .risk-tile:nth-child(3),.risk-tile:nth-child(4){ border-bottom:none; }
        .risk-tile:hover { background:var(--surface2); }
        .risk-count-num { font-weight:700; font-size:34px; line-height:1; }
        .risk-lbl { font-size:10px; letter-spacing:.1em; margin-top:4px; text-transform:uppercase; font-weight:600; opacity:.75; }
        .rt-critical .risk-count-num,.rt-critical .risk-lbl { color:var(--danger); }
        .rt-high     .risk-count-num,.rt-high     .risk-lbl { color:var(--high); }
        .rt-medium   .risk-count-num,.rt-medium   .risk-lbl { color:var(--medium); }
        .rt-low      .risk-count-num,.rt-low      .risk-lbl { color:var(--low); }

        /* ── Tabs ── */
        .tab-nav { display:flex; gap:4px; margin-bottom:12px; overflow-x:auto; padding-bottom:2px; animation:fadeUp .4s .05s ease both; }
        .tab-btn { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:8px 16px; font-family:var(--sans); font-size:12px; font-weight:500; color:var(--muted2); cursor:pointer; transition:all .15s; white-space:nowrap; }
        .tab-btn:hover { color:var(--navy); border-color:var(--border2); background:var(--surface2); }
        .tab-btn.active { color:var(--blue); background:#eff6ff; border-color:#bfdbfe; font-weight:600; }
        .tab-badge { display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; font-size:10px; background:var(--border); color:var(--muted2); border-radius:10px; margin-left:6px; font-weight:600; }
        .tab-btn.active .tab-badge { background:#dbeafe; color:var(--blue); }

        /* ── Tab panels ── */
        .tab-panel { display:none; background:var(--surface); border:1px solid var(--border); border-radius:12px; overflow:hidden; margin-bottom:20px; box-shadow:var(--shadow-sm); animation:fadeUp .3s ease both; }
        .tab-panel.active { display:block; }

        /* ── Check items ── */
        .check-item { padding:12px 18px 12px 14px; border-bottom:1px solid var(--border); border-left:3px solid transparent; display:flex; flex-direction:column; gap:3px; transition:background .1s; }
        .check-item:last-child { border-bottom:none; }
        .check-item:hover { background:var(--surface2); }
        .check-item.is-ok     { border-left-color:var(--pass); }
        .check-item.is-info   { border-left-color:var(--pass); }
        .check-item.is-low    { border-left-color:var(--low); }
        .check-item.is-medium { border-left-color:var(--medium); }
        .check-item.is-high   { border-left-color:var(--high); }
        .check-item.is-critical { border-left-color:var(--danger); }
        .check-row { display:flex; align-items:center; gap:10px; }
        .check-indicator { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
        .ci-ok,.ci-info { background:var(--pass); }
        .ci-low         { background:var(--low); }
        .ci-medium      { background:var(--medium); }
        .ci-high        { background:var(--high); }
        .ci-critical    { background:var(--danger); }
        .check-name { flex:1; font-size:13px; color:var(--text); font-weight:500; }
        .check-detail { font-size:12px; color:var(--muted2); padding-left:17px; }
        .check-suggestion { font-size:12px; color:#2563eb; padding-left:17px; }
        .check-suggestion::before { content:'→ '; color:var(--blue); opacity:.6; }
        .risk-badge { font-size:10px; font-weight:600; padding:2px 8px; border-radius:20px; flex-shrink:0; text-transform:uppercase; letter-spacing:.04em; }
        .rb-ok,.rb-info { background:#dcfce7; color:#15803d; }
        .rb-low         { background:#dbeafe; color:#1d4ed8; }
        .rb-medium      { background:#fef3c7; color:#92400e; }
        .rb-high        { background:#ffedd5; color:#9a3412; }
        .rb-critical    { background:#fee2e2; color:#991b1b; }
        .owasp-tag { font-size:10px; padding:1px 6px; border:1px solid var(--border2); color:var(--muted2); border-radius:4px; margin-left:4px; font-family:var(--mono); }

        /* ── OWASP section ── */
        .owasp-section { background:var(--surface); border:1px solid var(--border); border-radius:12px; overflow:hidden; margin-bottom:20px; box-shadow:var(--shadow-sm); animation:fadeUp .4s .15s ease both; }
        .owasp-row { display:grid; grid-template-columns:56px 1fr auto; gap:0; padding:11px 18px; border-bottom:1px solid var(--border); align-items:center; transition:background .1s; }
        .owasp-row:last-child { border-bottom:none; }
        .owasp-row:hover { background:var(--surface2); }
        .owasp-row.has-issue { background:#fff8f8; }
        .owasp-row.has-issue:hover { background:#fff0f0; }
        .owasp-code { font-size:12px; color:var(--blue); font-weight:700; font-family:var(--mono); }
        .owasp-name { font-size:13px; color:var(--text); font-weight:500; }
        .owasp-count-badge { font-size:10px; font-weight:700; padding:2px 10px; border-radius:20px; margin-left:12px; }
        .obc-ok  { background:#dcfce7; color:#15803d; }
        .obc-bad { background:#fee2e2; color:#991b1b; }
        .owasp-items { grid-column:2; font-size:11px; color:var(--muted2); margin-top:2px; }

        /* ── AI section ── */
        .ai-section { background:#eff6ff; border:1px solid #bfdbfe; border-radius:12px; overflow:hidden; margin-bottom:20px; box-shadow:var(--shadow-sm); animation:fadeUp .4s .2s ease both; }
        .ai-section .section-hd { background:#dbeafe; border-bottom:1px solid #bfdbfe; color:#1d4ed8; }
        .ai-section .section-hd .dot { background:var(--blue); }
        .ai-trigger-btn { display:block; width:100%; background:transparent; border:none; padding:20px; font-family:var(--sans); font-size:13px; font-weight:500; color:var(--blue); cursor:pointer; transition:background .15s; text-align:center; }
        .ai-trigger-btn:hover { background:rgba(37,99,235,.06); }
        .ai-loading { padding:28px; text-align:center; display:none; }
        .ai-spinner { display:inline-block; width:22px; height:22px; border:2.5px solid #bfdbfe; border-top-color:var(--blue); border-radius:50%; animation:spin .8s linear infinite; }
        @keyframes spin { to { transform:rotate(360deg); } }
        .ai-loading-txt { font-size:12px; color:var(--muted2); margin-top:12px; }
        .ai-result { padding:20px; display:none; background:#fff; }
        .ai-error { padding:18px; color:var(--high); font-size:13px; display:none; background:#fff7ed; }
        .md-h2 { font-size:15px; font-weight:700; color:var(--navy); margin:16px 0 8px; padding-bottom:6px; border-bottom:1px solid var(--border); }
        .md-h3 { font-size:13px; font-weight:600; color:var(--blue); margin:12px 0 6px; }
        .md-li { font-size:13px; color:var(--text); padding:3px 0 3px 16px; position:relative; line-height:1.6; }
        .md-li::before { content:'•'; position:absolute; left:4px; color:var(--blue); }
        .md-strong { color:var(--navy); font-weight:600; }
        .md-code { font-family:var(--mono); background:#f1f5f9; padding:1px 5px; border:1px solid var(--border); font-size:11px; color:var(--navy); border-radius:3px; }
        .ai-footer { padding:10px 18px; border-top:1px solid var(--border); font-size:11px; color:var(--muted); background:var(--surface2); }

        /* ── Export ── */
        .export-bar { display:flex; gap:10px; margin-bottom:20px; animation:fadeUp .4s .25s ease both; }
        .export-btn { flex:1; background:var(--surface); border:1.5px solid var(--border2); border-radius:8px; padding:11px; font-family:var(--sans); font-size:12px; font-weight:500; color:var(--muted2); cursor:pointer; transition:all .15s; }
        .export-btn:hover { color:var(--navy); border-color:var(--navy); background:var(--surface2); }

        /* ── Result header ── */
        .result-meta { display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; animation:fadeUp .3s ease both; }
        .result-target { font-size:13px; color:var(--blue); word-break:break-all; font-family:var(--mono); }
        .result-date { font-size:12px; color:var(--muted); flex-shrink:0; margin-left:12px; }

        /* ── Animations ── */
        @keyframes fadeDown { from{opacity:0;transform:translateY(-10px)} to{opacity:1;transform:translateY(0)} }
        @keyframes fadeUp   { from{opacity:0;transform:translateY(8px)}  to{opacity:1;transform:translateY(0)} }

        /* ── Corner deco ── */
        .corner-deco { position:fixed; bottom:20px; right:20px; font-size:10px; color:var(--muted); opacity:.4; pointer-events:none; }

        /* ── Guide section ── */
        .guide-section { margin-bottom:32px; animation:fadeUp .5s .1s ease both; }
        .guide-steps { display:flex; align-items:stretch; gap:0; margin-bottom:16px; background:var(--surface); border:1px solid var(--border); border-radius:12px; overflow:hidden; box-shadow:var(--shadow-sm); }
        .guide-step { flex:1; padding:20px 16px; text-align:center; }
        .guide-arrow { color:var(--border2); font-size:20px; display:flex; align-items:center; padding:0 2px; }
        .step-num { font-weight:700; font-size:24px; color:var(--blue); line-height:1; margin-bottom:6px; }
        .step-text { font-size:13px; color:var(--navy); font-weight:600; margin-bottom:4px; }
        .step-sub { font-size:11px; color:var(--muted2); }
        .guide-step:not(:last-child) { border-right:1px solid var(--border); }

        .risk-legend { display:flex; gap:0; margin-bottom:16px; background:var(--surface); border:1px solid var(--border); border-radius:10px; overflow:hidden; box-shadow:var(--shadow-sm); }
        .legend-item { flex:1; display:flex; align-items:center; gap:8px; padding:10px 12px; font-size:11px; font-weight:500; border-right:1px solid var(--border); white-space:nowrap; }
        .legend-item:last-child { border-right:none; }
        .legend-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
        .li-critical .legend-dot { background:var(--danger); }
        .li-high     .legend-dot { background:var(--high); }
        .li-medium   .legend-dot { background:var(--medium); }
        .li-low      .legend-dot { background:var(--low); }
        .li-pass     .legend-dot { background:var(--pass); }
        .li-critical { color:var(--danger); } .li-high { color:var(--high); } .li-medium { color:var(--medium); } .li-low { color:var(--low); } .li-pass { color:var(--pass); }

        .check-cats { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:16px; }
        @media(max-width:600px){ .check-cats { grid-template-columns:repeat(2,1fr); } }
        .cat-card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:16px; box-shadow:var(--shadow-sm); transition:box-shadow .15s, transform .15s; }
        .cat-card:hover { box-shadow:var(--shadow); transform:translateY(-1px); }
        .cat-icon { font-size:22px; margin-bottom:8px; }
        .cat-name { font-weight:700; font-size:13px; color:var(--navy); margin-bottom:4px; }
        .cat-desc { font-size:11px; color:var(--muted2); line-height:1.5; }

        /* ── Ethics notice ── */
        .ethics-notice { display:flex; gap:12px; align-items:flex-start; padding:14px 18px; border:1px solid #fde68a; background:#fffbeb; border-radius:10px; margin-bottom:20px; }
        .ethics-icon { color:var(--medium); font-size:16px; flex-shrink:0; margin-top:2px; }
        .ethics-text { font-size:12px; color:#78350f; line-height:1.7; }
        .ethics-text strong { color:#92400e; display:block; margin-bottom:3px; font-weight:700; }

        /* ── Test design table ── */
        .test-table-wrap { overflow-x:auto; margin:4px 0; border-radius:8px; border:1px solid var(--border); }
        .test-table { width:100%; border-collapse:collapse; font-size:12px; }
        .test-table th { background:#f8fafc; color:var(--muted2); padding:9px 12px; text-align:left; border-bottom:1px solid var(--border); font-weight:700; font-size:10px; letter-spacing:.08em; text-transform:uppercase; white-space:nowrap; }
        .test-table td { padding:9px 12px; border-bottom:1px solid var(--border); color:var(--text); vertical-align:top; line-height:1.6; }
        .test-table tr:last-child td { border-bottom:none; }
        .test-table tr:hover td { background:#f8fafc; }
        .test-table td:first-child { font-weight:700; color:var(--navy); white-space:nowrap; font-family:var(--mono); font-size:11px; }
        .prio-high   { color:var(--danger) !important; font-weight:700; }
        .prio-medium { color:var(--medium) !important; font-weight:600; }
        .prio-low    { color:var(--low) !important; }

        /* ── Print styles ── */
        @media print {
            * { -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important; animation:none !important; transition:none !important; box-shadow:none !important; }
            html, body { height:auto !important; overflow:visible !important; background:#fff !important; }
            .container { padding-bottom:0 !important; }
            .topbar, .scan-form, .loading-bar, .export-bar, .ai-trigger-btn, #ai-body, #ai-loading, .guide-section, .corner-deco { display:none !important; }
            .tab-nav { display:none !important; }
            .tab-panel { display:block !important; border:1px solid #ddd !important; margin-bottom:12px; page-break-inside:avoid; }
            .ai-result { display:block !important; }
            .ai-section { background:#f0f7ff !important; border:1px solid #bcd !important; }
            .owasp-row.has-issue { background:#fff5f5 !important; }
        }
    </style>
</head>
<body>

    <!-- Top bar -->
    <div class="topbar">
        <div class="topbar-logo">
            <svg viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect width="28" height="28" rx="6" fill="#2563eb"/>
                <path d="M14 5L6 9v6c0 4.4 3.4 8.5 8 9.5 4.6-1 8-5.1 8-9.5V9L14 5z" fill="white" opacity=".9"/>
                <path d="M11 14l2 2 4-4" stroke="#2563eb" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span class="topbar-title">Sec<span>Scan</span></span>
        </div>
        <span class="topbar-badge">AI × Security v3.0</span>
    </div>

<div class="container">

    <!-- Header -->
    <header class="header">
        <div class="header-tag">Web セキュリティ診断ツール</div>
        <h1>AIで強化された<span>セキュリティ診断</span></h1>
        <p class="header-sub">OWASP Top 10 対応 &nbsp;·&nbsp; SSL / HTTP Headers / Cookie / Form &nbsp;·&nbsp; AI テスト設計表生成</p>
    </header>

    <!-- Scan form -->
    <form method="post" class="scan-form" id="scanForm">
        <span class="prompt-label">URL</span>
        <input type="text" name="url" placeholder="https://example.com" value="{{ url }}" autocomplete="off" spellcheck="false" required>
        <button type="submit" class="scan-btn">診断開始</button>
    </form>

    <div class="loading-bar" id="loadingBar"></div>

    {% if not has_results %}
    <!-- Usage guide (shown only before first scan) -->
    <div class="guide-section">
        <div class="guide-steps">
            <div class="guide-step">
                <div class="step-num">01</div>
                <div class="step-text">URLを入力</div>
                <div class="step-sub">https:// から始まるURLを入力</div>
            </div>
            <div class="guide-arrow">→</div>
            <div class="guide-step">
                <div class="step-num">02</div>
                <div class="step-text">SCAN を実行</div>
                <div class="step-sub">15項目を自動チェック（約5〜10秒）</div>
            </div>
            <div class="guide-arrow">→</div>
            <div class="guide-step">
                <div class="step-num">03</div>
                <div class="step-text">結果を確認</div>
                <div class="step-sub">レポート出力・AI テスト観点生成</div>
            </div>
        </div>

        <div class="risk-legend">
            <div class="legend-item li-critical"><span class="legend-dot"></span>Critical — 即時対応必須</div>
            <div class="legend-item li-high"><span class="legend-dot"></span>High — 早急に対応</div>
            <div class="legend-item li-medium"><span class="legend-dot"></span>Medium — 計画的に対応</div>
            <div class="legend-item li-low"><span class="legend-dot"></span>Low — 余裕があれば対応</div>
            <div class="legend-item li-pass"><span class="legend-dot"></span>Pass — 問題なし</div>
        </div>

        <div class="check-cats">
            <div class="cat-card">
                <div class="cat-icon">🔒</div>
                <div class="cat-name">SSL / TLS</div>
                <div class="cat-desc">HTTPS・証明書の有効期限・TLSバージョン（3項目）</div>
            </div>
            <div class="cat-card">
                <div class="cat-icon">📋</div>
                <div class="cat-name">HTTP Headers</div>
                <div class="cat-desc">セキュリティヘッダー・バージョン情報漏洩など（9項目）</div>
            </div>
            <div class="cat-card">
                <div class="cat-icon">🍪</div>
                <div class="cat-name">Cookie</div>
                <div class="cat-desc">HttpOnly・Secure・SameSite 属性をCookieごとに確認</div>
            </div>
            <div class="cat-card">
                <div class="cat-icon">📝</div>
                <div class="cat-name">フォーム</div>
                <div class="cat-desc">CSRF対策・autocomplete属性・送信先URL</div>
            </div>
        </div>
    </div>
    {% endif %}

    <!-- Ethics notice (always visible) -->
    <div class="ethics-notice">
        <div class="ethics-icon">⚠</div>
        <div class="ethics-text">
            <strong>安全・倫理面の制限</strong>
            本ツールはHTTPヘッダーの受動的な確認のみ行い、攻撃・改ざん・不正アクセスは一切行いません。
            自身が管理するサイト、または診断許可を得たサイトのみに使用してください。
            本ツールはプロフェッショナルなペネトレーションテストの代替ではありません。
        </div>
    </div>

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
        {% set item_cls  = 'is-ok' if r.ok else ('is-' + r.risk_level) %}
        <div class="check-item {{ item_cls }}">
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
        'info':     '#16a34a',
        'low':      '#2563eb',
        'medium':   '#d97706',
        'high':     '#ea580c',
        'critical': '#dc2626',
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
            r.innerHTML = data.html;
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
    var lines = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').split('\n');
    var html = [];
    var i = 0;
    while (i < lines.length) {
        var line = lines[i];
        var trimmed = line.trim();
        if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
            var tableLines = [];
            while (i < lines.length && lines[i].trim().startsWith('|')) {
                tableLines.push(lines[i]);
                i++;
            }
            html.push(renderTable(tableLines));
            continue;
        }
        if (trimmed.match(/^## /))
            html.push('<div class="md-h2">' + trimmed.slice(3) + '</div>');
        else if (trimmed.match(/^### /))
            html.push('<div class="md-h3">' + trimmed.slice(4) + '</div>');
        else if (trimmed.match(/^[-*] /))
            html.push('<div class="md-li">' + inlineFormat(trimmed.slice(2)) + '</div>');
        else if (trimmed === '')
            html.push('<br>');
        else
            html.push('<p style="font-size:12px;color:var(--text);margin:3px 0">' + inlineFormat(trimmed) + '</p>');
        i++;
    }
    return html.join('\n');
}

function inlineFormat(s) {
    return s.replace(/\*\*(.+?)\*\*/g, '<span class="md-strong">$1</span>')
            .replace(/`([^`]+)`/g, '<code class="md-code">$1</code>');
}

function renderTable(lines) {
    var html = '<div class="test-table-wrap"><table class="test-table">';
    var inBody = false;
    lines.forEach(function(line) {
        var cells = line.trim().split('|').slice(1,-1);
        if (cells.every(function(c){ return /^[-: ]+$/.test(c); })) {
            html += '</thead><tbody>';
            inBody = true;
            return;
        }
        if (!inBody && html.indexOf('<thead>') === -1) html += '<thead>';
        html += '<tr>';
        cells.forEach(function(c, idx) {
            var v = c.trim();
            if (inBody) {
                var cls = v === '高' ? ' class="prio-high"' : v === '中' ? ' class="prio-medium"' : v === '低' ? ' class="prio-low"' : '';
                html += '<td' + cls + '>' + inlineFormat(v) + '</td>';
            } else {
                html += '<th>' + v + '</th>';
            }
        });
        html += '</tr>';
    });
    html += '</tbody></table></div>';
    return html;
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


def md_to_html(text: str) -> str:
    import html as html_lib
    import re as re_mod
    lines = text.split("\n")
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        # Table detection
        if stripped.startswith("|") and stripped.endswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i])
                i += 1
            out.append(_render_table(table_lines))
            continue
        # Headings
        if stripped.startswith("## "):
            out.append(f'<div class="md-h2">{html_lib.escape(stripped[3:])}</div>')
        elif stripped.startswith("### "):
            out.append(f'<div class="md-h3">{html_lib.escape(stripped[4:])}</div>')
        elif stripped.startswith("- ") or stripped.startswith("* "):
            out.append(f'<div class="md-li">{_inline(stripped[2:])}</div>')
        elif stripped == "":
            out.append("<br>")
        else:
            out.append(f'<p style="font-size:12px;color:var(--text);margin:3px 0">{_inline(stripped)}</p>')
        i += 1
    return "\n".join(out)


def _inline(s: str) -> str:
    import html as html_lib, re as re_mod
    s = html_lib.escape(s)
    s = re_mod.sub(r"\*\*(.+?)\*\*", r'<span class="md-strong">\1</span>', s)
    s = re_mod.sub(r"`([^`]+)`", r'<code class="md-code">\1</code>', s)
    return s


def _render_table(lines: list) -> str:
    import html as html_lib, re
    rows = []
    sep_idx = None
    for idx, line in enumerate(lines):
        cells = [c.strip() for c in line.strip().split("|")[1:-1]]
        if all(re.match(r"^[-: ]+$", c) for c in cells):
            sep_idx = idx
        else:
            rows.append(cells)
    if sep_idx is None or len(rows) == 0:
        return ""
    header = rows[0]
    body = rows[1:]
    def th(c): return f"<th>{html_lib.escape(c)}</th>"
    def td(c):
        prio = {"高": "prio-high", "中": "prio-medium", "低": "prio-low"}.get(c, "")
        cls = f' class="{prio}"' if prio else ""
        return f"<td{cls}>{_inline(c)}</td>"
    head_html = "<thead><tr>" + "".join(th(c) for c in header) + "</tr></thead>"
    body_html = "<tbody>" + "".join(
        "<tr>" + "".join(td(c) for c in row) + "</tr>" for row in body
    ) + "</tbody>"
    return f'<div class="test-table-wrap"><table class="test-table">{head_html}{body_html}</table></div>'


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

    prompt = f"""あなたはWebセキュリティ診断と品質保証の専門家です。
自動スキャン結果を基に、手動テスト設計表を日本語で作成してください。

対象URL: {url}

自動スキャン検出問題:
{failed_lines}

以下のmarkdown表形式で10〜15件のテストケースを作成してください。
表の前後に余分な文章は不要です。表と補足メモのみ出力してください。

## テスト設計表

| ID | テスト観点 | 確認手順 | 期待結果 | 優先度 | OWASP |
|----|----------|---------|--------|------|-------|
| T-001 | （テスト観点名） | （具体的な確認手順1〜2文） | （期待される正常な結果） | 高/中/低 | A0X |

優先度の基準：高＝Critical/High、中＝Medium、低＝Low

## 補足メモ
- （テスト実施上の注意点を3個以内、箇条書き）"""

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
        return jsonify({"html": md_to_html(response.text)})
    except Exception as e:
        return jsonify({"error": f"AI生成エラー: {str(e)}"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
