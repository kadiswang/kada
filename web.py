"""网页接口模块（模块化拆分 Step 3）。

集中存放：后台管理面板的 HTML 模板（LOGIN_HTML / INDEX_HTML）、
会话与鉴权辅助（active_sessions 及 CSRF / 登录限流）、会话清理循环。
这些资产与主程序运行态解耦，仅依赖 common 常量与标准库。
"""

import time
import uuid
import threading

from common import (
    SESSION_CLEANUP_INTERVAL,
    LOGIN_RATE_LIMIT_WINDOW,
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
    CSRF_TOKEN_EXPIRY,
)
active_sessions: dict[str, float] = {}

def _cleanup_expired_sessions() -> None:
    now = time.time()
    expired = [t for t, exp in active_sessions.items() if exp <= now]
    for t in expired:
        active_sessions.pop(t, None)


def _get_or_cleanup_sessions() -> dict[str, float]:
    _cleanup_expired_sessions()
    return active_sessions

_login_attempts: dict[str, list[float]] = {}
_login_attempts_lock = threading.Lock()

_csrf_tokens: dict[str, tuple[float, str]] = {}
_csrf_lock = threading.Lock()

def _check_login_rate_limit(ip: str) -> bool:
    now = time.time()
    with _login_attempts_lock:
        if ip not in _login_attempts:
            _login_attempts[ip] = []
        timestamps = [_t for _t in _login_attempts[ip] if now - _t < LOGIN_RATE_LIMIT_WINDOW]
        _login_attempts[ip] = timestamps
        return len(timestamps) < LOGIN_RATE_LIMIT_MAX_ATTEMPTS


def _record_login_attempt(ip: str) -> None:
    now = time.time()
    with _login_attempts_lock:
        if ip not in _login_attempts:
            _login_attempts[ip] = []
        _login_attempts[ip].append(now)


def _clear_login_attempts(ip: str) -> None:
    """登录成功后清空该 IP 的失败记录。"""
    with _login_attempts_lock:
        _login_attempts.pop(ip, None)


def _cleanup_login_attempts() -> None:
    """回收过期的限流记录。

    面板默认监听所有网卡，公网扫描器会持续用不同源 IP 打 /api/login；
    若只裁剪列表而不删除空的 IP 键，_login_attempts 会无上限增长（内存泄漏）。
    """
    now = time.time()
    with _login_attempts_lock:
        for ip in list(_login_attempts.keys()):
            kept = [t for t in _login_attempts[ip] if now - t < LOGIN_RATE_LIMIT_WINDOW]
            if kept:
                _login_attempts[ip] = kept
            else:
                _login_attempts.pop(ip, None)


def _cleanup_expired_csrf_tokens() -> None:
    """回收过期 CSRF 令牌。

    原逻辑只在"校验时发现过期"才删除；从未被使用过的令牌（每次刷新页面都会
    新发一个）会永久驻留内存。长期运行的服务需要定期清理。
    """
    now = time.time()
    with _csrf_lock:
        for token in [t for t, (exp, _) in _csrf_tokens.items() if exp <= now]:
            _csrf_tokens.pop(token, None)


def _generate_csrf_token() -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    with _csrf_lock:
        _csrf_tokens[token] = (time.time() + CSRF_TOKEN_EXPIRY, token)
    return token


def _validate_csrf_token(token: str | None) -> bool:
    if not token:
        return False
    with _csrf_lock:
        entry = _csrf_tokens.get(token)
        if not entry:
            return False
        expiry, _ = entry
        if time.time() > expiry:
            _csrf_tokens.pop(token, None)
            return False
        _csrf_tokens[token] = (time.time() + CSRF_TOKEN_EXPIRY, token)
        return True

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KADA - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      overflow: hidden;
      background: linear-gradient(135deg, #eef2ff 0%, #fdf2f8 50%, #ecfeff 100%);
      position: relative;
    }
    [data-theme="dark"] body {
      background: radial-gradient(ellipse at 25% 20%, #152038 0%, #0d1117 60%);
    }

    /* Blob decorations */
    .login-blob {
      position: fixed;
      border-radius: 50%;
      filter: blur(80px);
      opacity: 0.6;
      pointer-events: none;
      z-index: 0;
    }
    .login-blob:nth-child(1) { width: 400px; height: 400px; background: rgba(99,102,241,0.35); top: -120px; left: -80px; animation: blobFloat1 12s ease-in-out infinite; }
    .login-blob:nth-child(2) { width: 320px; height: 320px; background: rgba(236,72,153,0.30); top: 60%; right: -60px; animation: blobFloat2 10s ease-in-out infinite; }
    .login-blob:nth-child(3) { width: 280px; height: 280px; background: rgba(20,184,166,0.25); bottom: -80px; left: 30%; animation: blobFloat3 14s ease-in-out infinite; }
    .login-blob:nth-child(4) { width: 200px; height: 200px; background: rgba(251,191,36,0.20); top: 30%; left: 15%; animation: blobFloat4 9s ease-in-out infinite; }
    .login-blob:nth-child(5) { width: 240px; height: 240px; background: rgba(56,189,248,0.25); top: 10%; right: 20%; animation: blobFloat5 11s ease-in-out infinite; }
    [data-theme="dark"] .login-blob { opacity: 0.35; }
    [data-theme="dark"] .login-blob:nth-child(1) { background: rgba(99,102,241,0.25); }
    [data-theme="dark"] .login-blob:nth-child(2) { background: rgba(236,72,153,0.20); }
    [data-theme="dark"] .login-blob:nth-child(3) { background: rgba(20,184,166,0.18); }
    [data-theme="dark"] .login-blob:nth-child(4) { background: rgba(251,191,36,0.15); }
    [data-theme="dark"] .login-blob:nth-child(5) { background: rgba(56,189,248,0.18); }

    @keyframes blobFloat1 { 0%,100%{transform:translate(0,0)scale(1)} 33%{transform:translate(60px,-40px)scale(1.08)} 66%{transform:translate(-30px,20px)scale(0.95)} }
    @keyframes blobFloat2 { 0%,100%{transform:translate(0,0)scale(1)} 50%{transform:translate(-50px,-60px)scale(1.05)} }
    @keyframes blobFloat3 { 0%,100%{transform:translate(0,0)scale(1)} 33%{transform:translate(40px,30px)scale(1.1)} 66%{transform:translate(-20px,-20px)scale(0.9)} }
    @keyframes blobFloat4 { 0%,100%{transform:translate(0,0)} 50%{transform:translate(30px,-30px)} }
    @keyframes blobFloat5 { 0%,100%{transform:translate(0,0)scale(1)} 50%{transform:translate(-30px,20px)scale(0.9)} }

    .login-grid {
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background-image: radial-gradient(circle, rgba(99,102,241,0.04) 1px, transparent 1px);
      background-size: 32px 32px;
      -webkit-mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
      mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
    }

    .login-container {
      position: relative; z-index: 1;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
    }

    .login-toolbar {
      position: fixed; top: 20px; right: 24px; z-index: 10;
      display: inline-flex; align-items: center; gap: 10px;
    }
    .login-toolbar button {
      width: 40px; height: 40px; min-width: 40px;
      border-radius: 50%; padding: 0;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer; border: 1px solid rgba(255,255,255,0.6);
      background: rgba(255,255,255,0.7);
      backdrop-filter: blur(8px);
      color: #64748b; font-size: 16px;
      transition: all .2s;
    }
    [data-theme="dark"] .login-toolbar button {
      background: rgba(30,41,59,0.9);
      border-color: rgba(255,255,255,0.2);
      color: #f8fafc;
      box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    .login-toolbar button:hover { background: #fff; color: #6366f1; box-shadow: 0 2px 8px rgba(99,102,241,0.15); }
    [data-theme="dark"] .login-toolbar button:hover { background: rgba(51,65,85,0.95); color: #fff; }

    .login-card {
      position: relative;
      width: 100%;
      max-width: 400px;
      background: rgba(255,255,255,0.72);
      -webkit-backdrop-filter: blur(24px) saturate(180%);
      backdrop-filter: blur(24px) saturate(180%);
      border: 1px solid rgba(255,255,255,0.6);
      border-radius: 20px;
      padding: 40px 32px 32px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 18px 50px rgba(99,102,241,0.18);
      z-index: 2;
    }
    [data-theme="dark"] .login-card {
      background: rgba(28,30,36,0.55);
      border-color: rgba(255,255,255,0.10);
      box-shadow: 0 1px 3px rgba(0,0,0,0.4), 0 20px 60px rgba(59,130,246,0.22);
    }

    .brand {
      text-align: center;
      margin-bottom: 28px;
    }
    .brand-name {
      font-size: 28px;
      font-weight: 800;
      background: linear-gradient(135deg, #6366f1, #ec4899);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    [data-theme="dark"] .brand-name {
      background: linear-gradient(135deg, #60a5fa, #1d4ed8);
      -webkit-background-clip: text;
      background-clip: text;
    }
    .brand-sub {
      font-size: 14px;
      color: #94a3b8;
      margin-top: 6px;
    }
    [data-theme="dark"] .brand-sub { color: #64748b; }

    .welcome {
      text-align: center;
      font-size: 30px;
      font-weight: 700;
      margin-bottom: 28px;
      color: #1e293b;
    }
    [data-theme="dark"] .welcome { color: #f1f5f9; }

    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #64748b;
      margin-bottom: 8px;
    }
    [data-theme="dark"] label { color: #94a3b8; }
    .input-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }
    .input-wrap .input-icon {
      position: absolute;
      left: 14px;
      color: #94a3b8;
      font-size: 15px;
      pointer-events: none;
    }
    [data-theme="dark"] .input-wrap .input-icon { color: #64748b; }
    .input-wrap input {
      width: 100%;
      height: 46px;
      padding: 0 14px 0 42px;
      background: #fff;
      border: 1.5px solid #e2e8f0;
      border-radius: 10px;
      color: #1e293b;
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: border-color .2s, box-shadow .2s;
    }
    [data-theme="dark"] .input-wrap input {
      background: #1a1b1f;
      border-color: #334155;
      color: #f1f5f9;
    }
    .input-wrap input:focus {
      border-color: #6366f1;
      box-shadow: 0 0 0 3px rgba(99,102,241,0.1);
    }
    .input-wrap input::placeholder { color: #cbd5e1; }
    [data-theme="dark"] .input-wrap input::placeholder { color: #475569; }

    .error-message {
      color: #ef4444;
      font-size: 13px;
      margin-top: 8px;
      display: none;
    }
    .error-message.show { display: block; }

    .login-btn {
      width: 100%;
      height: 46px;
      border: none;
      border-radius: 10px;
      background: linear-gradient(135deg, #6366f1, #7c3aed);
      color: #fff;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity .2s, transform .1s;
      margin-top: 4px;
    }
    .login-btn:hover { opacity: 0.9; }
    .login-btn:active { transform: scale(0.98); }
    .login-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  </style>
</head>
  <body>
    <div class="login-blob"></div>
    <div class="login-blob"></div>
    <div class="login-blob"></div>
    <div class="login-blob"></div>
    <div class="login-blob"></div>
    <div class="login-grid"></div>

    <div class="login-toolbar">
      <button id="login_theme_btn" onclick="toggleLoginTheme()" title="切换主题">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
      </button>
    </div>

    <div class="login-container">
      <div class="login-card">
      <div class="brand">
        <div class="brand-name">KADA</div>
        <div class="brand-sub">VPN 节点管理系统</div>
      </div>
      <div class="welcome">欢迎回来</div>

      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label for="username">管理账号</label>
          <div class="input-wrap">
            <span class="input-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            </span>
            <input type="text" id="username" name="username" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group">
          <label for="password">安全密码</label>
          <div class="input-wrap">
            <span class="input-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </span>
            <input type="password" id="password" name="password" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        <button type="submit" class="login-btn" id="submit_btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    const THEME_KEY = 'kada_theme';
    var themeLabels = { light: '明亮模式', dark: '暗黑模式', system: '跟随系统' };
    var themeIcons = {
      light: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />',
      dark: '<path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" />',
      system: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />'
    };
    function getThemeIcon(theme) {
      var path = themeIcons[theme] || themeIcons.light;
      return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' + path + '</svg>';
    }
    function setLoginTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme);
      var btn = document.getElementById('login_theme_btn');
      if (btn) btn.innerHTML = getThemeIcon(theme);
      localStorage.setItem(THEME_KEY, theme);
    }
    function toggleLoginTheme() {
      var saved = localStorage.getItem(THEME_KEY) || 'light';
      var next = saved === 'light' ? 'dark' : (saved === 'dark' ? 'system' : 'light');
      setLoginTheme(next);
    }
    
    // 应用保存的主题
    (function() {
      var saved = localStorage.getItem(THEME_KEY) || 'light';
      setLoginTheme(saved);
    })();

    async function handleLogin(e) {
      e.preventDefault();
      var uname = document.getElementById("username").value.trim();
      var pwd = document.getElementById("password").value.trim();
      var errorText = document.getElementById("error_text");
      var submitBtn = document.getElementById("submit_btn");

      errorText.classList.remove("show");
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";

      try {
        var response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        });
        var data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确";
          errorText.classList.add("show");
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.classList.add("show");
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>

  <!-- 悬停风控情报卡片（由 showRiskIntel / hideRiskIntel 控制显隐） -->
  <div id="risk_intel_popover" class="risk-popover" style="display:none;"></div>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KADA 节点池管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    * { margin: 0; padding: 0; box-sizing: border-box; }

    :root {
      --bg: #e6e8ec;
      --surface: #ffffff;
      --surface-2: #f8fafc;
      --border: #e2e8f0;
      --border-light: #cbd5e1;
      --border-color: #e2e8f0;
      --text: #1e293b;
      --text-primary: #1e293b;
      --text-secondary: #64748b;
      --text-muted: #94a3b8;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --success: #10b981;
      --success-bg: rgba(16,185,129,0.08);
      --danger: #ef4444;
      --danger-bg: rgba(239,68,68,0.08);
      --warning: #f59e0b;
      --warning-bg: rgba(245,158,11,0.08);
      --success-gradient: linear-gradient(135deg, #059669, #10b981);
      --shadow-sm: 0 1px 3px rgba(0,0,0,0.04);
      --shadow: 0 1px 4px rgba(0,0,0,0.06), 0 2px 12px rgba(0,0,0,0.04);
      --bg-surface: #f8fafc;
    }

    [data-theme="dark"] {
      --bg: #0a0e17;
      --surface: #111827;
      --surface-2: #1a2236;
      --border: #1e293b;
      --border-light: #273548;
      --border-color: #1e293b;
      --text: #f1f5f9;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --success-bg: rgba(16,185,129,0.12);
      --danger-bg: rgba(239,68,68,0.12);
      --warning-bg: rgba(245,158,11,0.12);
      --shadow-sm: none;
      --shadow: none;
      --bg-surface: #1a2236;
    }

    [data-theme="dark"] .active-card-icon { background: #1a2236; }
    [data-theme="dark"] .stat-icon { background: #1a2236; }
    [data-theme="dark"] th { background: rgba(10,14,23,0.4); }
    [data-theme="dark"] .log-container { background: #05080f; border-color: var(--border); }
    [data-theme="dark"] .badge-info { background: rgba(99,102,241,0.15); color: #a5b4fc; }
    [data-theme="dark"] .tag-green { background: rgba(16,185,129,0.12); color: #10b981; }
    [data-theme="dark"] .tag-blue { background: rgba(99,102,241,0.15); color: #a5b4fc; }
    [data-theme="dark"] .vps-card { background: var(--bg); }
    [data-theme="dark"] .vps-item { background: var(--bg); }
    [data-theme="dark"] .option-card { background: var(--bg); }
    [data-theme="dark"] .form-input { background: var(--bg); }
    [data-theme="dark"] .form-select { background: var(--bg); }
    [data-theme="dark"] .input-field { background: var(--bg); }
    [data-theme="dark"] [style*="background: #f8fafc"] { background: var(--surface) !important; }
    [data-theme="dark"] tr:hover td { background: rgba(255,255,255,0.015); }
    [data-theme="dark"] .row-active td { background: rgba(16,185,129,0.06) !important; }
    [data-theme="dark"] .modal-close:hover { background: var(--surface-2); }
    [data-theme="dark"] #log_terminal_container { background: #05080f !important; border-color: var(--border) !important; color: #a5b4fc !important; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8) !important; }
    [data-theme="dark"] [style*="background: #f8fafc"] { background: var(--surface) !important; }
    [data-theme="dark"] .active-card-icon, 
    [data-theme="dark"] .stat-icon { background: #1a2236; }
    [data-theme="dark"] .card { background: var(--bg); }

    /* === 动态背景 Blob === */
    .main-blob {
      position: fixed;
      border-radius: 50%;
      filter: blur(80px);
      opacity: 0.5;
      pointer-events: none;
      z-index: 0;
    }
    [data-theme="dark"] .main-blob { opacity: 0.3; }
    .main-blob:nth-child(1) { width: 400px; height: 400px; background: rgba(99,102,241,0.35); top: -120px; left: -80px; animation: blobFloat1 12s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(1) { background: rgba(99,102,241,0.25); }
    .main-blob:nth-child(2) { width: 320px; height: 320px; background: rgba(236,72,153,0.30); top: 60%; right: -60px; animation: blobFloat2 10s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(2) { background: rgba(236,72,153,0.20); }
    .main-blob:nth-child(3) { width: 280px; height: 280px; background: rgba(20,184,166,0.25); bottom: -80px; left: 30%; animation: blobFloat3 14s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(3) { background: rgba(20,184,166,0.18); }
    .main-blob:nth-child(4) { width: 200px; height: 200px; background: rgba(251,191,36,0.20); top: 30%; left: 15%; animation: blobFloat4 9s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(4) { background: rgba(251,191,36,0.15); }
    .main-blob:nth-child(5) { width: 240px; height: 240px; background: rgba(56,189,248,0.25); top: 10%; right: 20%; animation: blobFloat5 11s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(5) { background: rgba(56,189,248,0.18); }

    .main-grid {
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background-image: radial-gradient(circle, rgba(99,102,241,0.04) 1px, transparent 1px);
      background-size: 32px 32px;
      -webkit-mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
      mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
    }

    /* 毛玻璃卡片 */
    .active-card {
      background: rgba(255,255,255,0.75);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      backdrop-filter: blur(16px) saturate(180%);
    }
    [data-theme="dark"] .active-card {
      background: rgba(17,24,39,0.75);
    }
    .table-wrapper {
      background: rgba(255,255,255,0.75);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      backdrop-filter: blur(16px) saturate(180%);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      overflow-x: auto;
    }
    [data-theme="dark"] .table-wrapper {
      background: rgba(17,24,39,0.75);
    }
    .stats-row .stat-card {
      background: rgba(255,255,255,0.75);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      backdrop-filter: blur(16px) saturate(180%);
    }
    [data-theme="dark"] .stats-row .stat-card {
      background: rgba(17,24,39,0.75);
    }
    .option-card {
      background: rgba(255,255,255,0.75);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      backdrop-filter: blur(16px) saturate(180%);
      border: 1px solid rgba(0,0,0,0.04);
    }
    [data-theme="dark"] .option-card {
      background: rgba(17,24,39,0.75);
      border: 1px solid rgba(255,255,255,0.08);
    }

    /* === 3x-UI 侧边栏布局 === */
    .app-layout { display: flex; min-height: 100vh; }

    .sidebar {
      width: 220px; min-width: 220px;
      background: #ffffff;
      border-right: 1px solid #e2e8f0;
      display: flex; flex-direction: column;
      position: fixed; top: 0; left: 0; bottom: 0;
      z-index: 200;
    }
    [data-theme="dark"] .sidebar { background: #15161a; border-right-color: #1e293b; }

    .sidebar-brand {
      padding: 18px 20px;
      border-bottom: 1px solid #e2e8f0;
      display: flex; align-items: center; gap: 10px;
    }
    [data-theme="dark"] .sidebar-brand { border-bottom-color: rgba(255,255,255,0.06); }
    .sidebar-brand-name {
      font-size: 20px; font-weight: 800;
      background: linear-gradient(135deg, #6366f1, #ec4899);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    [data-theme="dark"] .sidebar-brand-name {
      background: linear-gradient(135deg, #60a5fa, #818cf8);
      -webkit-background-clip: text;
      background-clip: text;
    }
    .sidebar-brand-dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: #10b981;
      animation: online-blink 1.1s ease-in-out infinite;
    }
    @keyframes online-blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

    .sidebar-nav {
      flex: 1;
      min-height: 0;
      padding: 12px 10px;
      display: flex; flex-direction: column; gap: 2px;
      overflow-y: auto;
    }
    .nav-item {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 14px;
      border-radius: 8px;
      color: #64748b;
      font-size: 13px; font-weight: 500;
      text-decoration: none;
      transition: all .15s;
      cursor: pointer;
    }
    .nav-item:hover { background: #f1f5f9; color: #1e293b; }
    .nav-item.active {
      background: #eef2ff;
      color: #6366f1;
    }
    [data-theme="dark"] .nav-item { color: rgba(255,255,255,0.6); }
    [data-theme="dark"] .nav-item:hover { background: rgba(255,255,255,0.06); color: #fff; }
    [data-theme="dark"] .nav-item.active { background: rgba(99,102,241,0.2); color: #818cf8; }
    .nav-item svg { width: 18px; height: 18px; flex-shrink: 0; }

    .sidebar-divider {
      height: 1px; margin: 8px 12px;
      background: #e2e8f0;
    }
    [data-theme="dark"] .sidebar-divider { background: rgba(255,255,255,0.08); }
    .nav-item-danger { color: #ef4444 !important; }
    .nav-item-danger:hover { background: #fef2f2 !important; color: #dc2626 !important; }
    [data-theme="dark"] .nav-item-danger { color: #f87171 !important; }
    [data-theme="dark"] .nav-item-danger:hover { background: rgba(239,68,68,0.15) !important; color: #fca5a5 !important; }

    .submenu-toggle { position: relative; justify-content: flex-start; }
    .submenu-arrow { width: 16px; height: 16px; margin-left: auto; transition: transform .2s; }
    .submenu-toggle.open .submenu-arrow { transform: rotate(180deg); }
    .sub-item { padding-left: 40px !important; font-size: 13px; }

    .sidebar-footer {
      padding: 12px 10px 16px;
      border-top: 1px solid #e2e8f0;
      flex-shrink: 0;
    }
    [data-theme="dark"] .sidebar-footer { border-top-color: rgba(255,255,255,0.06); }
    .sidebar-theme-btn {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 14px; border-radius: 8px;
      color: #475569; font-size: 13px; font-weight: 500;
      cursor: pointer; border: 1px solid #e2e8f0; background: #f8fafc;
      width: 100%; font-family: inherit;
      transition: all .15s;
    }
    .sidebar-theme-btn:hover { background: #eef2ff; color: #6366f1; border-color: #c7d2fe; }
    [data-theme="dark"] .sidebar-theme-btn { color: #cbd5e1; border-color: #334155; background: #1e293b; }
    [data-theme="dark"] .sidebar-theme-btn:hover { background: #334155; color: #fff; border-color: #475569; }

    .content {
      flex: 1;
      margin-left: 220px;
      background: transparent;
      min-height: 100vh;
      position: relative;
      z-index: 1;
    }

    /* 移动端侧边栏 */
    .mobile-menu-btn {
      position: fixed; top: 12px; left: 12px; z-index: 300;
      width: 38px; height: 38px; border-radius: 10px;
      background: var(--surface); border: 1px solid var(--border);
      color: var(--text); cursor: pointer;
      display: none; align-items: center; justify-content: center;
      box-shadow: var(--shadow);
    }
    .sidebar-overlay {
      display: none;
      position: fixed; inset: 0; background: rgba(0,0,0,0.4); z-index: 199;
    }

    @media (max-width: 768px) {
      .sidebar { transform: translateX(-100%); transition: transform .25s ease; }
      .sidebar.open { transform: translateX(0); }
      .sidebar-overlay.open { display: block; }
      .content { margin-left: 0; }
      .mobile-menu-btn { display: flex; }
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 20px 28px;
      background: transparent;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
    }

.brand h1 {
      font-size: 18px;
      font-weight: 700;
      color: var(--text);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand h1 svg { color: var(--primary); }

    .status-bar {
      font-size: 13px;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 4px;
    }

    .status-dot {
      width: 7px; height: 7px;
      border-radius: 50%;
      background: var(--success);
      display: inline-block;
    }

    .header-actions {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    button, .btn {
      height: 34px;
      padding: 0 14px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--surface);
      color: var(--text-secondary);
      white-space: nowrap;
      text-decoration: none;
      box-shadow: var(--shadow-sm);
    }

    button:hover { border-color: var(--border-light); color: var(--text); }

    .btn-primary {
      background: var(--primary);
      color: #fff;
      border: none;
    }

    .btn-primary:hover { background: var(--primary-hover); }

    .btn-success {
      background: var(--success);
      color: #fff;
      border: none;
    }

    .btn-success:hover { opacity: 0.9; }

    .btn-danger {
      background: var(--danger);
      color: #fff;
      border: none;
    }

    .btn-danger:hover { opacity: 0.9; }

    .btn-ghost {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-secondary);
      box-shadow: none;
    }

    .btn-ghost:hover { background: var(--surface-2); }

    button:disabled { opacity: 0.35; cursor: not-allowed; }

    .content-body {
      padding: 28px 36px;
      max-width: 1300px;
      margin: 0 auto;
    }

    .page-content { display: block; }

    .active-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
      margin-bottom: 20px;
      box-shadow: var(--shadow-sm);
    }

    .active-card-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .active-card-icon {
      width: 42px; height: 42px;
      background: #eef2ff;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .active-card-icon svg { width: 20px; height: 20px; color: var(--primary); }

    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .active-card-row1 {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .active-card-row2 {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-muted);
      flex-wrap: wrap;
    }

    .active-card-row2 strong { color: var(--text); font-weight: 600; }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid transparent;
    }

    .badge-ok { background: var(--success-bg); color: var(--success); border-color: rgba(16,185,129,0.2); }
    .badge-err { background: var(--danger-bg); color: var(--danger); border-color: rgba(239,68,68,0.2); }
    .badge-warn { background: var(--warning-bg); color: var(--warning); border-color: rgba(245,158,11,0.2); }
    .badge-info { background: #eef2ff; color: #6366f1; border-color: rgba(99,102,241,0.2); }

    .pulse { width: 6px; height: 6px; border-radius: 50%; background: currentColor; animation: pulse 1.5s infinite; display: inline-block; }
    @keyframes pulse { 0%{opacity:1;transform:scale(.9)} 50%{opacity:.4;transform:scale(1.5)} 100%{opacity:1;transform:scale(.9)} }

    .stats-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }

    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--shadow-sm);
    }

    .stat-card:hover { border-color: var(--border-light); }

    .stat-num {
      font-size: 28px;
      font-weight: 700;
      color: var(--text);
      line-height: 1;
      margin-bottom: 4px;
    }

    .stat-label {
      font-size: 13px;
      color: var(--text-muted);
    }

    .stat-icon {
      width: 36px; height: 36px;
      background: #eef2ff;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .stat-icon svg { width: 18px; height: 18px; color: var(--primary); }
    .stat-card:nth-child(2) .stat-icon { background: #fef3c7; }
    .stat-card:nth-child(2) .stat-icon svg { color: #f59e0b; }
    .stat-card:nth-child(3) .stat-icon { background: #d1fae5; }
    .stat-card:nth-child(3) .stat-icon svg { color: #10b981; }

    .toolbar {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 16px;
      margin-bottom: 16px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      box-shadow: var(--shadow-sm);
    }

    .toolbar select, .toolbar input {
      height: 36px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0 10px;
      color: var(--text);
      font-family: inherit;
      font-size: 13px;
      outline: none;
      cursor: pointer;
    }

    .toolbar select { width: 150px; }
    .toolbar select:focus, .toolbar input:focus { border-color: var(--primary); }

    .toolbar input { flex: 1; min-width: 200px; }

    .toolbar-spacer { margin-left: auto; }

    .table-wrap {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
    }

    .table-scroll { overflow-x: auto; }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    th {
      text-align: left;
      padding: 12px 16px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .6px;
      color: var(--text-muted);
      background: var(--surface-2);
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }

    td {
      padding: 8px 12px;
      background: var(--danger-bg);
      border: 1px solid rgba(239,68,68,0.2);
      border-radius: 6px;
      color: #dc2626;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }

    .msg-success {
      padding: 8px 12px;
      background: var(--success-bg);
      border: 1px solid rgba(16,185,129,0.2);
      border-radius: 6px;
      color: #059669;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }

    .msg-error.show, .msg-success.show { display: block; }

    .option-group {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-top: 4px;
    }

    .option-card {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      cursor: pointer;
      transition: all .15s;
      user-select: none;
    }

    .option-card:hover { border-color: var(--border-light); }
    .option-card.active {
      border-color: var(--primary);
      background: #eef2ff;
    }

    .option-card-title { font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 2px; }
    .option-card-desc { font-size: 11px; color: var(--text-muted); }
    [data-theme="dark"] .option-card-desc { color: #cbd5e1; }

    .favorites-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 16px;
      box-shadow: var(--shadow-sm);
    }

    .checkbox-row {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      cursor: pointer;
      user-select: none;
    }

    .checkbox-row input[type="checkbox"] { margin-top: 3px; }

    .checkbox-text {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .checkbox-text strong { font-size: 14px; font-weight: 600; color: var(--text); }
    .checkbox-text span { font-size: 12px; color: var(--text-muted); line-height: 1.4; }

    .vps-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 14px;
    }

    @media (max-width: 576px) { .vps-grid { grid-template-columns: 1fr; } }

    .vps-card {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .vps-tag {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 5px;
      width: fit-content;
      text-transform: uppercase;
      letter-spacing: .5px;
    }

    .tag-green { background: var(--success-bg); color: #059669; border: 1px solid rgba(16,185,129,0.2); }
    .tag-blue { background: #eef2ff; color: #6366f1; border: 1px solid rgba(99,102,241,0.2); }

    .vps-desc { font-size: 13px; color: var(--text-muted); line-height: 1.5; flex: 1; }

    .vps-link {
      display: block;
      text-align: center;
      padding: 8px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all .15s;
    }

    .vps-link:hover { border-color: var(--primary); color: var(--primary); }

    .log-container {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      height: 380px;
      padding: 16px;
      overflow-y: auto;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      line-height: 1.6;
      white-space: pre-wrap;
      word-break: break-all;
      color: #6366f1;
      margin-bottom: 16px;
    }

    @media (max-width: 768px) {
      header { flex-direction: column; align-items: flex-start; padding: 12px 20px; }
      .header-actions { width: 100%; flex-wrap: wrap; }
      main { padding: 12px 12px; }
      .active-card { flex-direction: column; align-items: flex-start; }
      .option-group { grid-template-columns: 1fr; }
    }

    /* backward-compatible aliases for legacy template references */
    .stat-icon-wrapper { width: 42px; height: 42px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }

    /* ============== 出站管理卡片样式（与 active-card / stat-card 视觉一致） ============== */
    .egress-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 14px;
      margin-top: 4px;
    }
    .egress-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 20px;
      display: flex;
      align-items: center;
      gap: 14px;
      box-shadow: var(--shadow-sm);
      transition: border-color .15s ease, box-shadow .15s ease;
    }
    .egress-card:hover { border-color: var(--border-light); box-shadow: 0 4px 12px rgba(0,0,0,0.04); }
    .egress-card .egress-icon {
      width: 42px; height: 42px;
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0;
      background: rgba(99, 102, 241, 0.12);
      border: 1px solid rgba(99, 102, 241, 0.25);
    }
    .egress-card .egress-icon svg { width: 20px; height: 20px; color: var(--primary, #6366f1); }
    .egress-card.is-default .egress-icon {
      background: rgba(16, 185, 129, 0.12);
      border-color: rgba(16, 185, 129, 0.25);
    }
    .egress-card.is-default .egress-icon svg { color: #10b981; }
    .egress-card.is-down .egress-icon {
      background: rgba(244, 63, 94, 0.10);
      border-color: rgba(244, 63, 94, 0.20);
    }
    .egress-card.is-down .egress-icon svg { color: var(--danger, #ef4444); }
    .egress-card .egress-body { flex: 1; min-width: 0; }
    .egress-card .egress-title {
      font-size: 15px; font-weight: 600;
      color: var(--text);
      display: flex; align-items: center; gap: 8px;
      margin-bottom: 6px;
    }
    .egress-card .egress-title .port-num {
      font-family: ui-monospace, "SF Mono", Menlo, monospace;
      font-size: 14px;
      color: var(--primary, #6366f1);
      background: rgba(99, 102, 241, 0.08);
      padding: 2px 8px; border-radius: 6px;
    }
    .egress-card .egress-meta {
      display: flex; flex-wrap: wrap; gap: 6px 10px;
      font-size: 12px; color: var(--text-muted);
    }
    .egress-card .egress-meta .meta-item {
      display: inline-flex; align-items: center; gap: 4px;
    }
    .egress-card .egress-meta .meta-key { color: var(--text-muted); }
    .egress-card .egress-meta .meta-val { color: var(--text); font-weight: 500; }
    .egress-card .egress-actions { flex-shrink: 0; }
    .egress-card .egress-actions .btn-danger {
      height: 32px; padding: 0 12px; font-size: 12px;
      border-radius: 8px;
      display: inline-flex; align-items: center; gap: 4px;
    }
    .egress-card .egress-actions .btn-danger svg { width: 14px; height: 14px; }
    .egress-empty {
      padding: 28px 20px;
      text-align: center;
      background: var(--surface);
      border: 1px dashed var(--border);
      border-radius: 12px;
      color: var(--text-muted);
      font-size: 13px;
    }
    .egress-default-row {
      margin-top: 18px;
      padding-top: 14px;
      border-top: 1px dashed var(--border, #e5e7eb);
      display: flex; align-items: center; gap: 10px;
      color: var(--text-muted);
      font-size: 12px;
    }
    .egress-default-row .dot {
      width: 6px; height: 6px; border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 0 3px rgba(16,185,129,0.18);
    }
    @media (max-width: 640px) {
      .egress-grid { grid-template-columns: 1fr; }
      .egress-card { padding: 14px 16px; }
    }
    .active-card-info { display: flex; align-items: center; gap: 16px; }
    .active-card-value { font-size: 24px; font-weight: 700; color: var(--text); }
    .badge-pulse { width: 6px; height: 6px; border-radius: 50%; background: currentColor; animation: pulse 1.5s infinite; display: inline-block; }
    .available { background: var(--success-bg); color: #059669; border-color: rgba(16,185,129,0.2); }
    .unavailable { background: var(--danger-bg); color: #dc2626; border-color: rgba(239,68,68,0.2); }
    .not_checked { background: var(--warning-bg); color: #d97706; border-color: rgba(245,158,11,0.2); }
    .connect-btn { height: 28px; padding: 0 10px; font-size: 12px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all .15s; border: 1px solid var(--border); background: transparent; color: var(--text-secondary); display: inline-flex; align-items: center; gap: 4px; }
    .connect-btn:hover { border-color: var(--primary); color: var(--primary); }
    .test-btn { height: 28px; padding: 0 10px; font-size: 12px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all .15s; border: 1px solid var(--border); background: transparent; color: var(--success); display: inline-flex; align-items: center; gap: 4px; }
    .test-btn:hover { background: var(--success); color: #fff; border-color: transparent; }
    .connect-btn:disabled, .test-btn:disabled { opacity: 0.35; cursor: not-allowed; }
    .modal-content {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      width: 90%;
      max-width: 480px;
      padding: 28px;
      box-shadow: 0 25px 60px rgba(0,0,0,0.25);
      animation: modalFadeIn .2s ease;
      max-height: 85vh;
      overflow-y: auto;
    }
    .modal {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      z-index: 9999;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, 0.5);
      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);
      padding: 16px;
    }
    .modal-content .btn-primary { height: 38px; padding: 0 18px; }
    
    /* 代理设置弹窗暗黑模式文字颜色覆盖 */
    [data-theme="dark"] .modal-content .form-hint,
    [data-theme="dark"] .modal-content .option-card-desc {
      color: #cbd5e1 !important;
    }
    [data-theme="dark"] .modal-content .option-card.active {
      background: rgba(99,102,241,0.15) !important;
    }
    
    /* 所有弹窗暗黑模式通用覆盖 */
    [data-theme="dark"] .modal-content {
      background: rgba(17,24,39,0.95);
      border: 1px solid rgba(255,255,255,0.08);
    }
    [data-theme="dark"] .modal {
      background: rgba(0,0,0,0.6);
    }
    [data-theme="dark"] .modal-content button[onmouseover],
    [data-theme="dark"] .modal-content button[onmouseout] {
      color: var(--text-secondary) !important;
    }
    [data-theme="dark"] .modal-content button[onmouseover]:hover {
      background: rgba(255,255,255,0.08) !important;
      color: #60a5fa !important;
    }
    [data-theme="dark"] .modal-content .form-label {
      color: var(--text-primary) !important;
    }
    [data-theme="dark"] .modal-content .input-field {
      background: var(--bg) !important;
      border-color: var(--border) !important;
      color: var(--text) !important;
    }
    [data-theme="dark"] .modal-content select {
      background: var(--bg) !important;
      border-color: var(--border) !important;
      color: var(--text) !important;
    }
    [data-theme="dark"] .modal-content .btn-ghost,
    [data-theme="dark"] .modal-content button[style*="background: transparent"] {
      color: var(--text-secondary) !important;
      border-color: var(--border) !important;
    }
    [data-theme="dark"] .modal-content .btn-ghost:hover,
    [data-theme="dark"] .modal-content button[style*="background: transparent"]:hover {
      background: rgba(255,255,255,0.06) !important;
      color: var(--text) !important;
    }
    [data-theme="dark"] .modal-content .btn-primary {
      background: var(--primary) !important;
      color: #fff !important;
    }
    [data-theme="dark"] #log_terminal_container {
      background: #05080f !important;
      border-color: var(--border) !important;
      color: #a5b4fc !important;
      box-shadow: inset 0 4px 20px rgba(0,0,0,0.8) !important;
    }
    .input-field { width: 100%; height: 40px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 0 12px; color: var(--text); font-family: inherit; font-size: 14px; outline: none; }
    .input-field:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99,102,241,0.1); }
    .vps-links { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
    .vps-item { background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
    .vps-tag { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 5px; width: fit-content; text-transform: uppercase; letter-spacing: .5px; }
    .tag-normal { background: #eef2ff; color: #6366f1; border: 1px solid rgba(99,102,241,0.2); }
    .tag-premium { background: var(--success-bg); color: #059669; border: 1px solid rgba(16,185,129,0.2); }
    .vps-desc { font-size: 13px; color: var(--text-muted); line-height: 1.5; flex: 1; }
    .vps-btn { display: block; text-align: center; padding: 8px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; color: var(--text-secondary); text-decoration: none; font-size: 12px; font-weight: 600; transition: all .15s; }
    .vps-btn:hover { border-color: var(--primary); color: var(--primary); }
    .vps-footer { padding-top: 12px; font-size: 13px; color: var(--text-muted); text-align: center; }
    .forum-link { color: var(--primary); font-weight: 600; text-decoration: none; }
    .forum-link:hover { color: #4f46e5; text-decoration: underline; }
    .latency-val { font-weight: 600; font-size: 12px; padding: 2px 6px; border-radius: 4px; }
    .latency-good { background: var(--success-bg); color: #059669; }
    .latency-medium { background: var(--warning-bg); color: #d97706; }
    .latency-poor { background: var(--danger-bg); color: #dc2626; }
    .health-badge { font-weight: 600; font-size: 12px; padding: 2px 6px; border-radius: 4px; display: inline-block; }
    .health-excellent { background: rgba(16, 185, 129, 0.15); color: #059669; }
    .health-good { background: rgba(59, 130, 246, 0.15); color: #2563eb; }
    .health-fair { background: rgba(245, 158, 11, 0.15); color: #d97706; }
    .health-poor { background: rgba(239, 68, 68, 0.15); color: #dc2626; }
    .health-critical { background: rgba(127, 29, 29, 0.15); color: #991b1b; }
    .health-unknown { background: rgba(148, 163, 184, 0.18); color: #64748b; }

    /* 风控分列 + 悬停风控情报卡片 */
    .risk-cell { font-weight: 600; font-size: 12px; padding: 2px 6px; border-radius: 4px; display: inline-block; cursor: help; vertical-align: middle; }
    .risk-safe { background: rgba(16, 185, 129, 0.15); color: #059669; }
    .risk-warn { background: rgba(245, 158, 11, 0.15); color: #d97706; }
    .risk-bad  { background: rgba(239, 68, 68, 0.15); color: #dc2626; }
    .risk-unknown { background: rgba(148, 163, 184, 0.18); color: #64748b; }
    /* 风控分单元格内的"风控异常"标记（属于风控分系统，不在健康度列） */
    .risk-cell-wrap { display: inline-flex; align-items: center; gap: 8px; flex-wrap: nowrap; white-space: nowrap; vertical-align: middle; }
    .risk-anomaly-badge {
      padding: 1px 7px; border-radius: 999px;
      font-size: 11px; font-weight: 700; white-space: nowrap;
      background: rgba(239, 68, 68, 0.16); color: #dc2626;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }
    .table-actions { display: flex; align-items: center; gap: 8px; flex-wrap: nowrap; white-space: nowrap; }
    .risk-col { min-width: 150px; }
    .risk-popover {
      position: fixed; z-index: 9999; width: 286px;
      background: var(--surface, #fff); border: 1px solid var(--border-color, #e2e8f0);
      border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.18);
      padding: 14px 16px; font-size: 12px; color: var(--text-primary, #1e293b);
      pointer-events: none;
    }
    .risk-popover h4 { margin: 0 0 10px; font-size: 13px; display: flex; align-items: center; gap: 6px; }
    .ri-row { display: flex; justify-content: space-between; gap: 10px; padding: 5px 0; border-bottom: 1px dashed var(--border-color, #e2e8f0); }
    .ri-row:last-child { border-bottom: none; }
    .ri-k { color: var(--text-secondary, #64748b); white-space: nowrap; }
    .ri-v { font-weight: 600; text-align: right; }
    .ri-v.ri-muted { color: var(--text-muted, #94a3b8); font-weight: 400; }
    .ri-ok { color: #059669; }
    .ri-danger { color: #dc2626; }
    .ri-note { margin-top: 10px; font-size: 11px; color: var(--text-muted, #94a3b8); line-height: 1.5; }

    @media (max-width: 576px) { .vps-links { grid-template-columns: 1fr; } }
    @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    @keyframes modalFadeIn { from { transform: scale(0.97); opacity: 0; } to { transform: scale(1); opacity: 1; } }
    @keyframes toastIn { from { transform: translateX(16px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    
    /* 表格样式 - 覆盖login页面遗留的danger-bg */
    table { border-collapse: collapse; table-layout: fixed; min-width: 1080px; }
    th { padding: 10px 14px; background: var(--surface-2); border-bottom: 1px solid var(--border); font-size: 12px; color: var(--text-secondary); font-weight: 600; }
    td { padding: 10px 14px; background: var(--surface); border-bottom: 1px solid var(--border); color: var(--text-primary); font-size: 13px; }
    tbody tr:hover td { background: var(--surface-2); }
    tbody tr:last-child td { border-bottom: none; }
    
    @media (max-width: 768px) {
      .modal { padding: 12px; align-items: flex-end; }
      .modal-content { width: 100%; max-width: none; border-radius: 16px 16px 0 0; max-height: 90vh; }
    }
  </style>
</head>
<body>
<div class="main-blob"></div>
<div class="main-blob"></div>
<div class="main-blob"></div>
<div class="main-blob"></div>
<div class="main-blob"></div>
<div class="main-grid"></div>

<div class="app-layout">

  <button class="mobile-menu-btn" id="mobile_menu_btn" onclick="toggleSidebar()">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
  </button>
  <div class="sidebar-overlay" id="sidebar_overlay" onclick="toggleSidebar()"></div>

  <aside class="sidebar" id="sidebar">
    <div class="sidebar-brand">
      <div class="sidebar-brand-name">KADA</div>
    </div>
    <nav class="sidebar-nav">
      <a class="nav-item active" id="nav_overview" href="javascript:void(0)" onclick="switchPage('overview')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>
        主页
      </a>
      <a class="nav-item" id="nav_nodes" href="javascript:void(0)" onclick="switchPage('nodes')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
        节点管理
      </a>
      <a class="nav-item" id="nav_egress" href="javascript:void(0)" onclick="switchPage('egress')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h18M3 6h18M3 18h18"/><circle cx="12" cy="12" r="9"/></svg>
        出站管理
      </a>
      <a class="nav-item" id="sidebar_refresh" href="javascript:void(0)" onclick="doRefreshNodes()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
        更新节点
      </a>

      <div class="sidebar-divider"></div>

      <div class="sidebar-submenu">
        <button class="nav-item submenu-toggle" id="settings_toggle" onclick="toggleSettingsSubmenu()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
          设置
          <svg class="submenu-arrow" id="settings_arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
        </button>
        <div class="submenu-items" id="settings_submenu" style="display:none;">
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openCredentialsModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            网页安全
          </a>
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openNetworkModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
            代理设置
          </a>
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openIntelModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l7 4v5c0 4.4-3 8.4-7 9-4-.6-7-4.6-7-9V7l7-4z"/><path d="M9 12l2 2 4-4"/></svg>
            风控情报
          </a>
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openGatewayModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
            网关设置
          </a>
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openLogsModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            日志
          </a>
          <a class="nav-item sub-item nav-item-danger" href="javascript:void(0)" onclick="event.stopPropagation(); logoutAdmin();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
            退出
          </a>
        </div>
      </div>

      <div class="sidebar-divider"></div>

      <a class="nav-item" href="https://github.com/kadiswang/kada" target="_blank">
        <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GitHub
      </a>
      <a class="nav-item" href="https://t.me/arestemple" target="_blank">
        <svg viewBox="0 0 16 16" fill="currentColor"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336-.063.065-.129.13-.19.193-.34.347-.597.609-.043.974.265.175.474.319.684.457.228.15.457.301.765.503.074.049.143.098.207.143.297.206.58.404.916.373.195-.018.398-.2.502-.754.25-1.332.74-4.22.842-5.281.01-.088.001-.22-.103-.312-.104-.092-.252-.09-.323-.087a1.52 1.52 0 0 0-.254.04z"/></svg>
        Telegram
      </a>
    </nav>
    <div class="sidebar-footer">
      <button class="sidebar-theme-btn" id="sidebar_theme_btn" onclick="toggleSidebarTheme()">
        <svg id="sidebar_theme_icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
        <span id="sidebar_theme_label">明亮模式</span>
      </button>
    </div>
  </aside>

  <main class="content">
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      KADA 节点管理系统
    </h1>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>服务加载中...</div>
  </div>
</header>
<div class="content-body">

    <div id="page_overview" class="page-content">
    <!-- 主页：当前连接状态卡 -->
    <section class="active-node-section" id="home_active_node_card" style="margin-bottom: 24px;">
      <!-- 主页专用：按主页选中出口渲染当前活动节点卡。 -->
    </section>
    <!-- 主页：出口实例概览（紧凑模式，点击可切换查看详情，不含路由配置和操作按钮） -->
    <section id="home_egress_module" style="background: var(--surface, #ffffff); border: 1px solid var(--border-color, #e2e8f0); border-radius: 12px; padding: 16px 20px; margin-bottom: 24px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <div style="display:flex;align-items:center;gap:8px;">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;color:var(--text-muted);"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
          <strong style="font-size:14px;color:var(--text-primary);">出口实例</strong>
        </div>
        <span id="home_egress_count" style="font-size:12px;color:var(--text-muted);"></span>
      </div>
      <div id="home_egress_blocks" style="display:flex;flex-direction:column;gap:8px;"></div>
    </section>
    </div>

    <!--
      ============================================================
      主页 / 出站管理 拆分说明（v3）：
      之前两个页面共享同一组 DOM (#egress_status_blocks / #overview_node_section)
      和同一套渲染函数 + 同一份 selectedEgressSlotId 状态，导致：
        1. 主页点切换 → 出站管理页的选中态被同步切走
        2. 出站管理页删除一个出口 → 主页的"已选中"指向已删除对象
        3. 出站管理页点添加 → 主页和出站管理同步刷新，互相影响
      拆分为两套完全独立的模块：
        主页：home_egress_blocks + home_active_node_card + homeEgressStatusList +
              homeSelectedEgressSlotId + renderHomeEgressCards + renderHomeActiveNodeCard
        出站管理：egress_status_blocks + egress_active_node_card + egressStatusList +
                   egressSelectedEgressSlotId + renderEgressCards + renderEgressActiveNodeCard +
                   renderEgressNodeList
      各自的状态、DOM、函数互不引用。switchPage 时分别控制显隐。
      ============================================================
    -->

    <div id="page_nodes" class="page-content" style="display:none;">

  <section class="toolbar">
    <select id="status_filter">
      <option value="all">全部节点</option>
      <option value="available">可用节点</option>
      <option value="unavailable">失效节点</option>
    </select>
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="hosting">机房IP</option>
      <option value="unknown">未知IP</option>
    </select>
    <select id="health_filter">
      <option value="all">全部健康度</option>
      <option value="excellent">优秀 (90+)</option>
      <option value="good">良好 (70+)</option>
      <option value="fair">一般 (50+)</option>
      <option value="poor">较差 (30+)</option>
      <option value="critical">极差 (0-29)</option>
    </select>
    <span id="node_count_label" style="font-size: 13px; color: var(--text-secondary); align-self: center; padding: 0 8px; white-space: nowrap;">
      共 <strong id="node_count_total" style="color: var(--text-primary); font-weight: 600;">0</strong> 个节点
    </span>
    <button id="btn_batch_test" class="toolbar-btn" type="button" onclick="batchTestFiltered()" style="height: 42px; gap: 6px; background: var(--primary); color: #fff; border: none;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
      一键检测
    </button>
    <button id="btn_favorites" class="toolbar-btn" type="button" onclick="toggleFavoritesView()" style="margin-left: auto; height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.907c.961 0 1.371 1.24.588 1.81l-3.97 2.883a1 1 0 00-.364 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.971-2.883a1 1 0 00-1.175 0l-3.97 2.883c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.364-1.118l-3.97-2.883c-.783-.57-.372-1.81.588-1.81h4.906a1 1 0 00.951-.69l1.519-4.674z" />
      </svg>
      收藏菜单
    </button>
  </section>
  <div id="batch_test_progress" style="display: none; margin: 12px 0; padding: 12px 16px; background: var(--surface); border: 1px solid var(--border-color); border-radius: 8px;">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
      <svg style="animation: spin 1s linear infinite; width: 16px; height: 16px; color: var(--primary);" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
      <span id="batch_test_status" style="font-size: 13px; color: var(--text-primary); font-weight: 500;">正在检测节点...</span>
      <span id="batch_test_count" style="font-size: 12px; color: var(--text-secondary); margin-left: auto;">0/0</span>
    </div>
    <div style="height: 4px; background: var(--surface-2); border-radius: 2px; overflow: hidden;">
      <div id="batch_test_bar" style="height: 100%; width: 0%; background: var(--primary); border-radius: 2px; transition: width 0.3s ease;"></div>
    </div>
  </div>
  <div id="favorites_panel" style="display: none; background: var(--surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: var(--shadow-sm);">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 15px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px;">
            ⭐ 收藏专属管理面板
          </span>
          <span style="font-size: 13px; color: var(--text-secondary);">
            在这里管理您的收藏节点过滤，以及设置出站连接漂移策略。
          </span>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
          <button id="btn_toggle_fav_routing" type="button" class="toolbar-btn" style="height: 36px; padding: 0 14px; font-size: 13px; border-radius: 6px;" onclick="toggleFavRouting()">
            启用仅用收藏出站
          </button>
        </div>
      </div>
      
      <div style="border-top: 1px solid var(--border); padding-top: 16px;">
        <label style="display: flex; align-items: flex-start; gap: 10px; cursor: pointer; user-select: none;">
          <input type="checkbox" id="fav_fail_fallback_checkbox" style="margin-top: 3px; cursor: pointer;" onchange="handleFavFallbackChange(this.checked)" checked />
          <div style="display: flex; flex-direction: column; gap: 2px;">
            <span style="font-size: 14px; font-weight: 500; color: var(--text-primary);">收藏节点失效后自动切换其他（非收藏）可用节点</span>
            <span style="font-size: 12px; color: var(--text-secondary);">勾选此项，当所有收藏节点不可用时，系统将自动使用其他最快的非收藏可用节点，保障网络连接不中断。</span>
          </div>
        </label>
        <div id="fav_fallback_warning" style="display: none; margin-top: 12px; padding: 10px 14px; background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.25); border-radius: 8px; font-size: 12px; color: var(--danger); line-height: 1.4; animation: modalFadeIn 0.2s ease-out;">
          ⚠️ <strong>警告</strong>：您已取消勾选此项。如果当前收藏的节点均不可用，系统将<strong>无法切换</strong>到其他可用节点，可能导致网络<strong>彻底断开连接</strong>！
        </div>
      </div>
    </div>
  </div>

  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 90px;">状态</th>
            <th style="width: 160px;">IP 地址 : 端口</th>
            <th style="width: 150px;">物理位置</th>
            <th style="width: 210px;">运营主体 / ISP</th>
            <th style="width: 80px;">IP 类型</th>
            <th style="width: 80px;">延迟</th>
            <th style="width: 80px;">健康度</th>
            <th class="risk-col" style="width: 150px;">风控分</th>
            <th style="width: 160px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows" style="display: table-row-group !important;"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: none; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div> <!-- end table-wrapper -->

  </div> <!-- end page_nodes -->

  <!-- Credentials Modal (网页安全设置) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </h3>
        <button type="button" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="credentials_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_username">管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入管理账号">
        </div>
        
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_password">安全密码</label>
          <input type="password" id="cred_password" class="input-field" placeholder="留空则保留当前密码">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_port">网页管理端口</label>
          <input type="number" id="cred_port" class="input-field" required min="1" max="65535" placeholder="8790">
        </div>
        
        <div class="form-group" style="margin-bottom: 20px;">
          <label class="form-label" for="cred_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="cred_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </h3>
        <button type="button" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="network_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label" for="net_egress">配置出口（每个出口独立保存）</label>
            <select id="net_egress" class="input-field" onchange="setNetEgress()" style="background: var(--surface-2); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="__default__">默认出口（7928）</option>
            </select>
            <p class="form-hint" style="font-size: 11px; color: var(--text-muted); margin-top: 6px; line-height: 1.4;">下方"上游代理"为全局（所有出口共用节点池）；路由/国家/IP类型/健康度逐出口独立保存。</p>
            <div id="net_egress_status" style="display:none; margin-top:10px; padding:10px 12px; border-radius:8px; font-size:12px; line-height:1.5;"></div>
          </div>
          <div class="form-group" style="margin-bottom: 16px; display:none;">
            <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理出站端口</label>
            <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
          </div>

        <div style="border-top: 1px dashed var(--border); padding-top: 16px; margin-bottom: 4px;">
          <label style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;color:var(--primary)"><path d="M16 7a4 4 0 11-8 0 4 4 0 018 0z"/><path d="M12 14v7m-3-3h6"/></svg>
            上游代理（拉取节点用）
          </label>
          <p class="form-hint" style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px; line-height: 1.4;">配置后通过代理访问 vpngate.net 拉取节点列表。留空则不启用。</p>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="net_upstream_enabled">启用上游代理</label>
            <input type="checkbox" id="net_upstream_enabled" style="width:16px;height:16px;accent-color:var(--primary);" onchange="toggleUpstreamFields()">
          </div>
          
          <div id="upstream_proxy_fields" style="display:none;">
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label">代理类型</label>
              <input type="hidden" id="net_upstream_type" value="socks">
              <div class="option-group" id="upstream_type_group">
                <div class="option-card active" data-value="socks" onclick="setUpstreamType('socks')">
                  <div class="option-card-title">SOCKS5</div>
                  <div class="option-card-desc">通用代理</div>
                </div>
                <div class="option-card" data-value="http" onclick="setUpstreamType('http')">
                  <div class="option-card-title">HTTP</div>
                  <div class="option-card-desc">HTTP代理</div>
                </div>
              </div>
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label" for="net_upstream_host">代理地址</label>
              <input type="text" id="net_upstream_host" class="input-field" placeholder="127.0.0.1">
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label" for="net_upstream_port">代理端口</label>
              <input type="number" id="net_upstream_port" class="input-field" min="1" max="65535" placeholder="1080">
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label" for="net_upstream_user">用户名（可选）</label>
              <input type="text" id="net_upstream_user" class="input-field" placeholder="留空则不认证">
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label" for="net_upstream_pass">密码（可选）</label>
              <input type="password" id="net_upstream_pass" class="input-field" placeholder="留空则不认证">
            </div>
          </div>
        </div>

        <div style="border-top: 1px dashed var(--border); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站路由模式</label>
            <input type="hidden" id="net_routing_mode" value="auto">
            <div class="option-group" id="routing_mode_group">
              <div class="option-card active" data-value="auto" onclick="setRoutingMode('auto')">
                <div class="option-card-title">自动配置</div>
                <div class="option-card-desc">智能切换，最稳定</div>
              </div>
              <div class="option-card" data-value="fixed_ip" onclick="setRoutingMode('fixed_ip')">
                <div class="option-card-title">固定 IP</div>
                <div class="option-card-desc">锁定IP，不自动切换</div>
              </div>
              <div class="option-card" data-value="fixed_region" onclick="setRoutingMode('fixed_region')">
                <div class="option-card-title">固定地区</div>
                <div class="option-card-desc">锁定特定国家地区</div>
              </div>
            </div>
          </div>
          
          <div id="net_force_country_group" class="form-group" style="margin-bottom: 16px; display: none;">
            <label class="form-label" for="net_force_country">锁定国家地区</label>
            <select id="net_force_country" class="input-field" style="background: var(--surface-2); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="">正在加载节点国家...</option>
            </select>
          </div>
          
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站类型过滤</label>
            <input type="hidden" id="net_routing_ip_type" value="all">
            <div class="option-group" id="routing_ip_type_group">
              <div class="option-card active" data-value="all" onclick="setRoutingIpType('all')">
                <div class="option-card-title">所有IP</div>
                <div class="option-card-desc">机房 + 住宅</div>
              </div>
              <div class="option-card" data-value="residential" onclick="setRoutingIpType('residential')">
                <div class="option-card-title">住宅IP</div>
                <div class="option-card-desc">静态家宽</div>
              </div>
              <div class="option-card" data-value="hosting" onclick="setRoutingIpType('hosting')">
                <div class="option-card-title">机房IP</div>
                <div class="option-card-desc">普通机房</div>
              </div>
            </div>
          </div>
          
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label" style="display: flex; justify-content: space-between; align-items: center;">
              <span>IP 健康度最低阈值</span>
              <span id="health_score_label" style="font-weight: 600; color: var(--primary);">不限</span>
            </label>
            <input type="range" id="net_min_health" style="width: 100%; height: 6px; appearance: none; background: var(--border-color); border-radius: 3px; outline: none; cursor: pointer; margin-top: 4px;" 
              min="0" max="100" value="0" step="5"
              oninput="$('health_score_label').textContent = this.value > 0 ? '&ge; ' + this.value + ' 分' : '不限'">
            <div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); margin-top: 2px;">
              <span>不限</span><span>50</span><span>100</span>
            </div>
          </div>
          
          <div id="net_routing_warning" class="form-hint" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; margin-top: 8px;">
            ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>


  <!-- 风控情报 Modal (proxycheck.io) -->
  <div id="intel_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3l7 4v5c0 4.4-3 8.4-7 9-4-.6-7-4.6-7-9V7l7-4z"/><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4" /></svg>
          风控情报（proxycheck.io）
        </h3>
        <button type="button" onclick="closeIntelModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <div id="intel_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="intel_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="intel_form" onsubmit="saveIntel(event)">
        <p class="form-hint" style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px; line-height: 1.5;">
          额外查询节点 IP 是否已被各大网站的风控库拉黑，以及同网段有多少人在挤。
          开启后「健康度」会同时参考这项，被标记的节点分数会自动降下来。<br>
          不填密钥也能用（约 100 次/天）；到
          <a href="https://proxycheck.io/" target="_blank" rel="noopener noreferrer" style="color: var(--primary);">proxycheck.io</a>
          免费注册可提升到 1000 次/天。自部署环境密钥会显示在下方，方便你确认是否填对。
        </p>

        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="intel_enabled">启用风控情报</label>
          <input type="checkbox" id="intel_enabled" style="width:16px;height:16px;accent-color:var(--primary);" onchange="toggleIntelFields()">
        </div>

        <div id="intel_fields" style="display:none;">
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="intel_key">API 密钥</label>
            <input type="text" id="intel_key" class="input-field" placeholder="留空则匿名调用（免费 100 次/天）" autocomplete="off" spellcheck="false">
            <p class="form-hint" id="intel_key_hint" style="font-size: 11px; color: var(--text-muted); margin-top: 6px; line-height: 1.4;">已保存的密钥会显示在上面，可直接核对；清空后保存即删除密钥。</p>
            <input type="hidden" id="intel_key_cleared" value="0">
            <a href="javascript:void(0)" onclick="clearIntelKey()" style="font-size: 12px; color: var(--danger); margin-top: 6px; display: inline-block;">清除已保存的密钥</a>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end; margin-top: 8px;">
          <button type="button" onclick="closeIntelModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="intel_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存</button>
        </div>
      </form>
    </div>
  </div>


  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal">
    <div class="modal-content" style="max-width: 600px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置与自检
        </h3>
        <button type="button" onclick="closeGatewayModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list" style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px;">
        <div style="text-align: center; color: var(--text-secondary); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 分割线 -->
      <div style="border-top: 1px dashed var(--border); margin: 20px 0;"></div>

      <!-- 本地代理出口检测 -->
      <div style="background: var(--surface-2); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
          <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2); width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary); width: 18px; height: 18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
          </div>
          <div>
            <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">本地代理出口检测</h4>
            <p style="margin: 2px 0 0 0; font-size: 12px; color: var(--text-secondary);">检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>
        
        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary); text-align: right;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测
          </button>
        </div>
      </div>
      
      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal">
    <div class="modal-content" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>
        
        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选:</label>
          <select id="log_filter_select" class="input-field" style="width: 140px; height: 32px; font-size: 12px; border-radius: 6px; padding: 0 8px; background: var(--surface-2);" onchange="filterAndRenderLogs()">
            <option value="all">全部日志</option>
            <option value="proxy">代理相关 (Proxy)</option>
            <option value="vpn">VPN 连接 (VPN)</option>
            <option value="system">系统运行 (Main/Route)</option>
          </select>
        </div>
        
        <button type="button" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #6366f1; box-shadow: inset 0 2px 8px rgba(0,0,0,0.04); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
<button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: var(--surface-2); color: var(--text-primary); border: 1px solid var(--border-color);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
          复制日志
        </button>
        <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: var(--surface-2); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>
  <div id="page_egress" class="page-content" style="display:none;">
    <!-- 添加出站管理弹窗：让用户给新实例起名（备注/用途）+ 选端口（留空自动顺延） -->
    <div id="add_egress_modal" style="display:none; position:fixed; inset:0; background:rgba(15,23,42,0.45); z-index:1000; align-items:center; justify-content:center;">
      <div style="background:var(--bg-card,#fff); border:1px solid var(--border-color,#e2e8f0); border-radius:12px; padding:24px; width:min(420px, 90vw); box-shadow:0 20px 50px rgba(15,23,42,0.25);">
        <h3 style="margin:0 0 4px; font-size:18px; font-weight:600; color:var(--text-primary,#0f172a);">添加出站管理实例</h3>
        <p style="margin:0 0 16px; font-size:12px; color:var(--text-secondary,#64748b); line-height:1.6;">为新实例起个名字（留空自动生成）。端口默认自动顺延（7929 起），如有冲突可手动指定空闲端口。</p>
        <label style="display:block; font-size:12px; color:var(--text-secondary,#64748b); margin-bottom:6px;">实例名称 <span style="color:var(--text-muted,#94a3b8);">（可选）</span></label>
        <input id="add_egress_name" type="text" maxlength="40" placeholder="例如：东京-住宅IP" style="width:100%; box-sizing:border-box; height:36px; padding:0 12px; border-radius:8px; border:1px solid var(--border-color,#cbd5e1); background:var(--bg-surface,#f8fafc); color:var(--text-primary,#0f172a); font-size:13px; outline:none;" />
        <label style="display:block; font-size:12px; color:var(--text-secondary,#64748b); margin:14px 0 6px;">本地监听端口 <span style="color:var(--text-muted,#94a3b8);">（留空自动顺延）</span></label>
        <input id="add_egress_port" type="number" min="1024" max="65535" placeholder="7929 / 7930 / ..." style="width:100%; box-sizing:border-box; height:36px; padding:0 12px; border-radius:8px; border:1px solid var(--border-color,#cbd5e1); background:var(--bg-surface,#f8fafc); color:var(--text-primary,#0f172a); font-size:13px; outline:none;" />
        <label style="display:block; font-size:12px; color:var(--text-secondary,#64748b); margin:14px 0 6px;">锁定国家/地区 <span style="color:var(--text-muted,#94a3b8);">（可选，留空则自动选最快）</span></label>
        <select id="add_egress_country" style="width:100%; box-sizing:border-box; height:36px; padding:0 12px; border-radius:8px; border:1px solid var(--border-color,#cbd5e1); background:var(--bg-surface,#f8fafc); color:var(--text-primary,#0f172a); font-size:13px; outline:none; cursor:pointer;">
          <option value="">不锁定（自动选最快）</option>
        </select>
        <div id="add_egress_error" style="display:none; margin-top:10px; padding:8px 10px; font-size:12px; color:#dc2626; background:rgba(220,38,38,0.08); border:1px solid rgba(220,38,38,0.20); border-radius:6px;"></div>
        <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:18px;">
          <button class="btn-ghost" onclick="closeAddEgressModal()" style="height:36px; padding:0 14px; border-radius:8px;">取消</button>
          <button class="btn-primary" id="add_egress_submit_btn" onclick="submitAddEgress()" style="height:36px; padding:0 16px; border-radius:8px; font-weight:600;">添加</button>
        </div>
      </div>
    </div>
    <section class="toolbar" style="flex-direction:column; align-items:stretch; gap:14px;">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <div>
          <h2 style="margin:0 0 4px;font-size:20px;font-weight:600;">出站管理</h2>
          <p style="color:var(--text-muted);margin:0;font-size:13px;line-height:1.6;">这里只决定要几个出站管理实例，每个实例是一套独立的 <strong style="color:var(--text);">HTTP/SOCKS5 代理端口</strong>。端口自动顺延（默认 7928，新增从 7929 起）。所有出站管理<strong style="color:var(--text);">共用同一份节点池</strong>（只拉取一次，不重复抓）。</p>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
          <button class="btn-primary" onclick="openAddEgressModal()" style="height:36px;padding:0 14px;border-radius:8px;font-weight:600;display:inline-flex;align-items:center;gap:6px;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:14px;height:14px;"><path d="M12 5v14M5 12h14"/></svg>
            添加出站管理
          </button>
          <button class="btn-ghost" id="btn_refresh_egress" onclick="loadEgressWithFeedback()" style="height:36px;padding:0 14px;border-radius:8px;display:inline-flex;align-items:center;gap:6px;">
            <svg id="refresh_egress_icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px;"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
            <span id="refresh_egress_text">刷新状态</span>
          </button>
        </div>
      </div>
      <div id="page_egress_hint" style="color: var(--text-muted); font-size: 12px; text-align: right;">点击下方任一卡片查看其可用节点列表；点击卡片右侧"删除"按钮可移除该出站管理实例。新添加的实例会出现在列表顶部。</div>
    </section>
    <!-- 出站管理专用：顶部活动节点卡（按出站管理页选中出口渲染，与主页独立） -->
    <section class="active-node-section" id="egress_active_node_card" style="margin-bottom: 24px;"></section>
    <!-- 出站模块：出口实例卡片区（与主页"出口实例"模块视觉完全一致：铺满 + 扁平标题 + 8px 间距） -->
    <div id="egress_module_card" style="background: var(--surface, #ffffff); border: 1px solid var(--border-color, #e2e8f0); border-radius: 12px; padding: 16px 20px; margin-bottom: 24px; box-shadow: var(--shadow-sm);">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <div style="display:flex;align-items:center;gap:8px;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;color:var(--text-muted);"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
          <strong style="font-size:14px;color:var(--text-primary);">出口实例</strong>
        </div>
        <span id="egress_card_count_label" style="font-size:12px;color:var(--text-muted);"></span>
      </div>
      <div id="egress_status_blocks" style="display:flex;flex-direction:column;gap:8px;"></div>
      <div id="egress_empty_hint" style="display:none;padding:16px 0;text-align:center;color:var(--text-muted);font-size:13px;">
        暂无出口实例。<br><span style="font-size:12px;color:var(--text-secondary);">点击上方「添加出站管理」创建第一个实例。</span>
      </div>
    </div>
    <!-- 出站管理专用：节点列表区（按选中出口过滤共享节点池，仅在该页内显示） -->
    <div id="egress_node_section" style="display:none; margin-bottom: 24px;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; flex-wrap: wrap; gap: 8px;">
        <span style="font-size: 15px; font-weight: 600; color: var(--text-primary);">节点列表</span>
        <span id="egress_filter_label" style="font-size: 12px; color: var(--text-secondary);"></span>
      </div>
      <div class="table-wrapper" style="margin-top: 0;">
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th style="width: 90px;">状态</th>
                <th style="width: 160px;">IP 地址 : 端口</th>
                <th style="width: 150px;">物理位置</th>
                <th style="width: 80px;">IP 类型</th>
                <th style="width: 80px;">延迟</th>
                <th style="width: 80px;">健康度</th>
                <th class="risk-col" style="width: 150px;">风控分</th>
                <th style="width: 160px;">操作</th>
              </tr>
            </thead>
            <tbody id="egress_rows"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
let nodes=[], state={}, testingNodeIds = new Set(), batchTesting = false;
let currentPage = 1;
const pageSize = 99999;
let currentPageNodes = [];
let countryDict = {};
let csrfToken = "";

async function fetchWithCsrf(url, options = {}) {
  if (!options.method || options.method === "GET") {
    options.method = options.method || "GET";
  }
  // Ensure headers object exists
  if (!options.headers || typeof options.headers !== "object") {
    options.headers = {};
  }
  options.headers = { ...options.headers };
  options.credentials = options.credentials || "same-origin";
  // Auto-fetch CSRF token if missing for write operations
  if (!csrfToken && (!options.method || options.method !== "GET")) {
    try {
      const csrfResp = await fetch("./api/csrf_token", { credentials: "same-origin" });
      if (csrfResp.ok) {
        const csrfData = await csrfResp.json();
        if (csrfData.csrf_token) {
          csrfToken = csrfData.csrf_token;
        }
      }
    } catch(e) {}
  }
  if (csrfToken) {
    options.headers["X-CSRF-Token"] = csrfToken;
  }
  const resp = await fetch(url, options);
  if (resp.ok) {
    try {
      const data = await resp.json();
      if (data.csrf_token) {
        csrfToken = data.csrf_token;
      }
      return data;
    } catch {
      return {};
    }
  }
  let errMsg = resp.statusText;
  try {
    const errBody = await resp.clone().json();
    errMsg = errBody.error || resp.statusText;
  } catch(e) {}
  throw new Error(errMsg);
}

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

// 健康度（0-100，越高越好）= net.coffee 信誉分（trust_score）。
// 注意：健康度与"风控分(proxycheck risk_score)"是两套相互独立的指标，刻意解耦——
// 健康度只反映节点本身的信誉/质量，风控分单独在"风控分"列展示。
// 这里优先用 health_score，旧数据回退 trust_score。
function getHealthScore(n) {
  if (!n) return 0;
  var v = (n.health_score === null || n.health_score === undefined || n.health_score === "")
    ? n.trust_score : n.health_score;
  var s = parseInt(v);
  if (isNaN(s)) return 0;
  return Math.max(0, Math.min(100, s));
}

// 风控分异常阈值：proxycheck 风险分 >= 此值视为高风险（0 最安全 / 100 最危险）。
const RISK_ANOMALY_THRESHOLD = 70;

// 风控异常判定（独立于健康度）：风险分过高，或已被风控库标记为代理。
function isRiskAnomaly(n) {
  if (!n) return false;
  var risk = parseInt(n.risk_score);
  if (!isNaN(risk) && risk >= RISK_ANOMALY_THRESHOLD) return true;
  if (n.is_flagged_proxy) return true;
  return false;
}

function riskAnomalyTitle(n) {
  if (!n) return "";
  var risk = parseInt(n.risk_score);
  var parts = ["⚠ 风控异常：该节点风控情报异常，访问部分网站可能被拦"];
  if (!isNaN(risk)) parts.push("风险分 " + risk + "/100（越高越危险）");
  if (n.is_flagged_proxy) parts.push("已被风控库标记为" + (n.flagged_type || "代理"));
  return parts.join("；");
}

// 从未查过 IP 情报的节点，健康度应显示"—"而不是 0，
// 否则"没测过"和"确实很差"在界面上长得一模一样。
function hasIpIntel(n) {
  if (!n) return false;
  return !!(n.ip_type || n.owner || n.as_name || n.location);
}

// 悬停说明：健康度(信誉) 只看节点本身质量，风控情报是另一套系统，指到风控分列。
function healthTitle(n) {
  if (!n) return "";
  var lines = [];
  var trust = parseInt(n.trust_score);
  if (!isNaN(trust)) lines.push("健康度（信誉分） " + trust + "/100，越高越好");
  else lines.push("健康度：尚未查询 IP 情报");
  lines.push("健康度只看节点本身质量（net.coffee 信誉分）");
  lines.push("风控情报（风险分 / 是否被风控拉黑）见右侧『风控分』列");
  var dev = parseInt(n.subnet_devices);
  if (!isNaN(dev)) lines.push("同网段约 " + dev + " 台设备在用" + (dev >= 100 ? "（较拥挤）" : ""));
  if (n.rdns) lines.push("反查域名 " + n.rdns);
  if (!lines.length) return "尚未查询 IP 情报";
  return lines.join("\n");
}

function healthCell(n) {
  var s = getHealthScore(n);
  if (!s && !hasIpIntel(n)) {
    return '<span class="health-badge health-unknown" title="尚未查询 IP 情报">—</span>';
  }
  var dev = parseInt(n && n.subnet_devices);
  var crowd = (!isNaN(dev) && dev >= 100)
    ? '<span title="同网段约 ' + dev + ' 台设备共用，可能较慢" style="margin-left:4px;color:var(--text-muted);font-size:11px;">' + dev + '人</span>'
    : '';
  return '<span class="health-badge ' + getHealthClass(s) + '" title="' + escAttr(healthTitle(n)) + '">'
    + s + '</span>' + crowd;
}

// 风控分（proxycheck.io 风险分）：数值越高越危险（0 最安全，100 最危险）。
// 颜色与综合健康度相反：低风险绿、中风险黄、高风险红。
function getRiskClass(v) {
  if (v <= 30) return "risk-safe";
  if (v <= 60) return "risk-warn";
  return "risk-bad";
}

// 节点列表的"风控分"列单元格：未查询显示"—"，悬停弹"风控情报"卡片。
function riskCell(n) {
  if (!n) return '<span class="risk-cell-wrap"><span class="risk-cell risk-unknown">—</span></span>';
  var risk = parseInt(n.risk_score);
  if (isNaN(risk)) {
    return '<span class="risk-cell-wrap"><span class="risk-cell risk-unknown" onmouseenter="showRiskIntel(\'' + esc(n.id) + '\', event)" onmouseleave="hideRiskIntel()">—</span></span>';
  }
  var anomalyBadge = isRiskAnomaly(n)
    ? '<span class="risk-anomaly-badge" title="' + escAttr(riskAnomalyTitle(n)) + '">⚠ 风控异常</span>'
    : '';
  return '<span class="risk-cell-wrap"><span class="risk-cell ' + getRiskClass(risk) + '" onmouseenter="showRiskIntel(\'' + esc(n.id) + '\', event)" onmouseleave="hideRiskIntel()">' + risk + '</span>' + anomalyBadge + '</span>';
}

// 风控情报卡片完整内容（悬停弹出）。
function riskIntelCardHtml(n) {
  if (!n) return "";
  var risk = parseInt(n.risk_score);
  var hasRisk = !isNaN(risk);
  var body = "";
  if (hasRisk) {
    body += '<div class="ri-row"><span class="ri-k">风险分 (risk)</span><span class="ri-v ' + getRiskClass(risk) + '">' + risk + ' / 100</span></div>';
  } else {
    body += '<div class="ri-row"><span class="ri-k">风险分 (risk)</span><span class="ri-v ri-muted">未查询</span></div>';
  }
  if (n.is_flagged_proxy) {
    body += '<div class="ri-row"><span class="ri-k">被风控标记</span><span class="ri-v ri-danger">⚠ 是</span></div>';
    body += '<div class="ri-row"><span class="ri-k">标记类型</span><span class="ri-v">' + esc(n.flagged_type || "代理") + '</span></div>';
  } else {
    body += '<div class="ri-row"><span class="ri-k">被风控标记</span><span class="ri-v ri-ok">否</span></div>';
  }
  var dev = parseInt(n.subnet_devices);
  if (!isNaN(dev)) {
    body += '<div class="ri-row"><span class="ri-k">同网段设备</span><span class="ri-v">' + dev + ' 台' + (dev >= 100 ? '（拥挤）' : '') + '</span></div>';
  }
  if (n.rdns) {
    body += '<div class="ri-row"><span class="ri-k">反查域名</span><span class="ri-v" style="font-weight:400;">' + esc(n.rdns) + '</span></div>';
  }
  body += '<div class="ri-row"><span class="ri-k">综合健康度</span><span class="ri-v">' + getHealthScore(n) + ' / 100</span></div>';
  var note = hasRisk
    ? "proxycheck.io 风险分：数值越高越危险（0 最安全，100 最危险）。仅对拨号可用的节点评分，连不通的节点不查询以节省每日额度。"
    : "该节点尚未查询 proxycheck.io 风控情报（仅对拨号可用的节点评分，以节省每日额度）。启用风控情报后，可用节点会在检测时自动补评。";
  return '<h4>🛡️ 风控情报（proxycheck.io）</h4>' + body + '<div class="ri-note">' + note + '</div>';
}

function findNodeById(id) {
  for (var i = 0; i < nodes.length; i++) {
    if (nodes[i] && nodes[i].id === id) return nodes[i];
  }
  return null;
}

function showRiskIntel(nodeId, evt) {
  var n = findNodeById(nodeId);
  if (!n) return;
  var pop = document.getElementById("risk_intel_popover");
  if (!pop) return;
  pop.innerHTML = riskIntelCardHtml(n);
  pop.style.display = "block";
  var r = evt.currentTarget.getBoundingClientRect();
  var pw = pop.offsetWidth || 286;
  var ph = pop.offsetHeight || 200;
  var left = r.right + 8;
  if (left + pw > window.innerWidth - 8) left = r.left - pw - 8;
  if (left < 8) left = 8;
  var top = r.top;
  if (top + ph > window.innerHeight - 8) top = Math.max(8, window.innerHeight - ph - 8);
  pop.style.left = left + "px";
  pop.style.top = top + "px";
}

function hideRiskIntel() {
  var pop = document.getElementById("risk_intel_popover");
  if (pop) pop.style.display = "none";
}

function getHealthClass(score) {
  if (score >= 90) return "health-excellent";
  if (score >= 70) return "health-good";
  if (score >= 50) return "health-fair";
  if (score >= 30) return "health-poor";
  return "health-critical";
}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP", "unknown": "未知", "": "未检测"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  if (countryDict[c]) return countryDict[c];
  return c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n ? translateCountry(n.country) : "").filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function getFilteredNodes() {
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  const selectedStatus = $("status_filter").value;
  const selectedHealth = $("health_filter").value;
  return nodes.filter(n => {
    if (!n) return false;
    if (selectedCountry && translateCountry(n.country) !== selectedCountry) {
      return false;
    }
    if (selectedIpType) {
      if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) {
        return false;
      }
      if (selectedIpType === "hosting" && n.ip_type !== "hosting") {
        return false;
      }
      if (selectedIpType === "unknown" && n.ip_type && n.ip_type !== "unknown") {
        return false;
      }
    }
    if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) {
      return false;
    }
    if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) {
      return false;
    }
    if (selectedHealth && selectedHealth !== "all") {
      const score = getHealthScore(n);
      const minScores = { excellent: 90, good: 70, fair: 50, poor: 30, critical: 0 };
      const maxScores = { excellent: 100, good: 89, fair: 49, poor: 29, critical: 29 };
      if (score < minScores[selectedHealth] || score > maxScores[selectedHealth]) {
        return false;
      }
    }
    const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
    if (showFavoritesOnly && !favoriteIds.includes(n.id)) {
      return false;
    }
    return true;
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    const aScore = a.score || 0;
    const bScore = b.score || 0;
    if (bScore !== aScore) {
      return bScore - aScore;
    }
    const aId = a.id || "";
    const bId = b.id || "";
    return aId.localeCompare(bId);
  });
}

// ---- 共享的活动节点卡 HTML 生成器（被主页和出站管理各调用一次） ----
function _buildActiveNodeCardHTML(slotKey, statusList) {
  // 按 slotKey 从 statusList 取数据，返回 HTML 字符串。
  // 调用方负责写入各自的 DOM 容器（home_active_node_card / egress_active_node_card）。
  const isDefault = !slotKey || slotKey === "__default__";
  const egress = (statusList || []).find(function(e) {
    return (isDefault && e.is_default) || (!isDefault && e.slot_id === slotKey);
  });
  let activeNodeId, isConnecting, lastCheckMessage, alive;
  if (isDefault) {
    activeNodeId = (state && state.active_openvpn_node_id) || "";
    isConnecting = !!(state && state.is_connecting);
    lastCheckMessage = (state && state.last_check_message) || "";
    alive = true;
  } else {
    activeNodeId = (egress && egress.active_node_id) || "";
    isConnecting = !!(egress && egress.is_connecting);
    lastCheckMessage = (egress && egress.last_check_message) || "";
    alive = !egress || egress.alive !== false;
  }
  const activeNode = activeNodeId ? (nodes || []).find(function(n) { return n && n.id === activeNodeId; }) : null;
  const titleLabel = isDefault ? "默认出口" : ((egress && (egress.name || egress.slot_id)) || slotKey);
  const isDown = !isDefault && !alive;
  const disconnectHandler = isDefault ? "disconnectNode()" : ("disconnectEgress('" + escAttr(slotKey) + "')");

  if (isDown) {
    return `
      <div class="active-card" style="border-color: var(--border-color);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(148, 163, 184, 0.12); border-color: rgba(148, 163, 184, 0.20); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #94a3b8; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge" style="background: rgba(148,163,184,0.15); color: #64748b; border-color: rgba(148,163,184,0.3);">未启动</span> ${esc(titleLabel)} 尚未启动
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              该出口的子进程未运行，请前往【出站管理】页检查或重新启动。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  if (isConnecting && !activeNode) {
    return `
      <div class="active-card" style="border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>连接中</span>
              <strong>${esc(titleLabel)}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(lastCheckMessage || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    const countryName = translateCountry(activeNode.country) || "";
    const titleText = countryName ? countryName + " 节点" : titleLabel;
    return `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(titleText)}</strong>
              <span class="port-num" style="font-family: ui-monospace, \\"SF Mono\\", Menlo, monospace; font-size: 13px; color: var(--text-muted); background: rgba(99,102,241,0.08); padding: 2px 8px; border-radius: 6px;">${esc(titleLabel)}</span>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="${disconnectHandler}">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  }

  // 未连接
  return `
    <div class="active-card" style="background: var(--surface); border-color: var(--border-color); box-shadow: none;">
      <div class="active-card-info">
        <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
        </div>
        <div class="active-card-details">
          <div class="active-card-title" style="color: var(--text-secondary);">
            <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> ${esc(titleLabel)} 当前未连接 VPN 节点
          </div>
          <div class="active-card-meta" style="margin-top: 4px;">
            ${esc(lastCheckMessage || '前往【出站管理】页选择一个可用节点并点击"切换"按钮开始连接。')}
          </div>
        </div>
      </div>
    </div>
  `;
}

// ---- 主页活动节点卡（写 home_active_node_card，用 homeEgressStatusList） ----
function renderHomeActiveNodeCard(slotKey) {
  const card = $("home_active_node_card");
  if (!card) return;
  card.innerHTML = _buildActiveNodeCardHTML(slotKey, homeEgressStatusList);
}

// ---- 出站管理活动节点卡（写 egress_active_node_card，用 egressStatusList） ----
function renderEgressActiveNodeCard(slotKey) {
  const card = $("egress_active_node_card");
  if (!card) return;
  card.innerHTML = _buildActiveNodeCardHTML(slotKey, egressStatusList);
}

// 向后兼容：旧代码中可能还有调用 renderActiveNodeCardForEgress 的地方（如 render()）
function renderActiveNodeCardForEgress(slotKey) { renderHomeActiveNodeCard(slotKey); }

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n && (n.active || n.id === activeNodeId));

  // 顶部活动节点卡：写入主页专用容器 home_active_node_card（与出站管理页独立）
  renderHomeActiveNodeCard(homeSelectedEgressSlotId || "__default__");
  // 出站管理页的活动卡由 loadEgress() 单独控制刷新（只有出站管理页显示时才渲染）。
  // 节点列表也是出站管理页专用（egress_rows），不在此处渲染。

  const shown = getFilteredNodes();
  console.log("[render] shown count:", shown.length, "currentPageNodes:", currentPageNodes.length);
  
  if ($("total")) $("total").textContent = nodes.length; 
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：${localProxy} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`; }
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  updateFavPanelUI();

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr style="display: table-row !important;"><td colspan="9" style="display: table-cell !important; text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      
      const isTesting = testingNodeIds.has(n.id);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;
      
      const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
      const isFav = favoriteIds.includes(n.id);
      const favBtn = isFav 
        ? `<button class="test-btn" style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">★ 已收藏</button>`
        : `<button class="test-btn" style="color: var(--text-secondary); border-color: var(--border-color); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">☆ 收藏</button>`;

      return `<tr ${rowClass} style="display: table-row !important;">
        <td style="display: table-cell !important; white-space: nowrap;"><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td class="mono" style="white-space: nowrap; max-width: 220px; overflow: hidden; text-overflow: ellipsis; display: table-cell !important;" title="${esc(n.ip||n.remote_host)}:${n.remote_port||""}">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td style="white-space: normal; word-break: break-word; display: table-cell !important;" title="${esc(displayLocation)}">${esc(displayLocation)}</td>
        <td style="white-space: normal; word-break: break-word; display: table-cell !important;" title="${esc(n.owner||n.as_name||"-")}">${esc(n.owner||n.as_name||"-")}</td>
        <td style="white-space: nowrap; max-width: 110px; overflow: hidden; text-overflow: ellipsis; display: table-cell !important;" title="${esc(translateIpType(n.ip_type))}">${esc(translateIpType(n.ip_type))}</td>
        <td style="white-space: nowrap; display: table-cell !important;">${latencyText}</td>
        <td style="white-space: nowrap; display: table-cell !important;">
          ${healthCell(n)}
        </td>
        <td class="risk-col" style="white-space: nowrap; display: table-cell !important; text-align: center;">
          ${riskCell(n)}
        </td>
        <td style="display: table-cell !important;">
          <div class="table-actions">
            ${favBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("node_count_total").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

function renderOverviewNodes(activeNode) {
  const container = $("overview_rows");
  const label = $("overview_filter_label");
  if (!container) return;

  const routingMode = state.routing_mode || "auto";
  const routingIpType = state.routing_ip_type || "all";
  const forceCountry = state.force_country || "";
  const favIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];

  let filtered = nodes.filter(function(n) { return n && n.id; });

  if (routingMode === "fixed_region" && forceCountry) {
    filtered = filtered.filter(function(n) {
      return n.country === forceCountry || (countryDict[n.country] || n.country) === forceCountry;
    });
  } else if (routingMode === "favorites") {
    filtered = filtered.filter(function(n) { return favIds.includes(n.id); });
  }

  if (routingIpType === "residential") {
    filtered = filtered.filter(function(n) { return n.ip_type === "residential" || n.ip_type === "mobile"; });
  } else if (routingIpType === "hosting") {
    filtered = filtered.filter(function(n) { return n.ip_type === "hosting"; });
  }

  // Sort: available first (by latency), then by status
  filtered.sort(function(a, b) {
    if (a.probe_status === "available" && b.probe_status !== "available") return -1;
    if (b.probe_status === "available" && a.probe_status !== "available") return 1;
    if (a.probe_status === "available" && b.probe_status === "available") {
      return (parseInt(a.latency_ms) || 999999) - (parseInt(b.latency_ms) || 999999);
    }
    return 0;
  });

  // Build filter label
  var parts = [];
  if (routingMode === "fixed_region" && forceCountry) parts.push(forceCountry);
  else if (routingMode === "favorites") parts.push("收藏节点");
  else parts.push("自动配置");
  if (routingIpType === "residential") parts.push("住宅IP");
  else if (routingIpType === "hosting") parts.push("机房IP");
  else parts.push("所有IP");
  label.textContent = parts.join(" + ") + " (" + filtered.length + " 个节点)";

  if (filtered.length === 0) {
    container.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-secondary);padding:30px 0;">暂无符合条件的节点</td></tr>';
    return;
  }

  container.innerHTML = filtered.map(function(n) {
    var isActive = activeNode && n.id === activeNode.id;
    var badgeClass = isActive ? "available" : (n.probe_status || "not_checked");
    var badgeText = isActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
    var latencyClass = getLatencyClass(n.latency_ms);
    var latencyText = n.latency_ms ? '<span class="latency-val ' + latencyClass + '">' + n.latency_ms + ' ms</span>' : "-";
    var displayLocation = n.location || translateCountry(n.country) || "-";
    var isUnavailable = n.probe_status === "unavailable";
    var connectBtn = isActive
      ? '<button class="connect-btn" disabled style="background:var(--success-gradient);color:white;cursor:default;opacity:1;">已连接</button>'
      : '<button class="connect-btn" ' + ((isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3;cursor:not-allowed;"' : '') + ' onclick="connectNode(\'' + esc(n.id) + '\')">切换</button>';

    return '<tr' + (isActive ? ' class="active-row"' : '') + ' style="display:table-row!important;">' +
      '<td style="display:table-cell!important;white-space:nowrap;"><span class="badge ' + badgeClass + '">' + badgeText + '</span></td>' +
      '<td class="mono" style="white-space:nowrap;max-width:220px;overflow:hidden;text-overflow:ellipsis;display:table-cell!important;" title="' + esc(n.ip||n.remote_host) + ':' + (n.remote_port||"") + '">' + esc(n.ip||n.remote_host) + ':' + (n.remote_port||"") + '</td>' +
      '<td style="white-space:normal;word-break:break-word;display:table-cell!important;" title="' + esc(displayLocation) + '">' + esc(displayLocation) + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;">' + esc(translateIpType(n.ip_type)) + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;">' + latencyText + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;">' + healthCell(n) + '</td>' +
      '<td class="risk-col" style="white-space:nowrap;display:table-cell!important;text-align:center;">' + riskCell(n) + '</td>' +
      '<td style="display:table-cell!important;">' + connectBtn + '</td>' +
      '</tr>';
  }).join("");
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetchWithCsrf("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = response;
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function batchTestFiltered() {
  const btn = $("btn_batch_test");
  const progressEl = $("batch_test_progress");
  const statusEl = $("batch_test_status");
  const countEl = $("batch_test_count");
  const barEl = $("batch_test_bar");
  
  if (btn.disabled || batchTesting) return;
  
  const filteredNodes = getFilteredNodes();
  const toTest = filteredNodes.filter(n => n && n.id);
  if (toTest.length === 0) {
    statusEl.textContent = "没有可检测的节点";
    progressEl.style.display = "block";
    barEl.style.width = "0%";
    countEl.textContent = "0/0";
    return;
  }
  
  batchTesting = true;
  btn.disabled = true;
  progressEl.style.display = "block";
  statusEl.textContent = "正在检测节点...";
  countEl.textContent = `0/${toTest.length}`;
  barEl.style.width = "0%";
  
  const startTime = Date.now();
  const nodeIds = toTest.map(n => n.id);
  let pollInterval = null;
  let timeoutHandle = null;
  
  const stopPolling = () => {
    if (pollInterval) clearInterval(pollInterval);
    if (timeoutHandle) clearTimeout(timeoutHandle);
    batchTesting = false;
    btn.disabled = false;
  };
  
  const updateProgress = async () => {
    try {
      const resp = await fetchWithCsrf("./api/nodes");
      if (resp && resp.nodes) {
        // Update local nodes
        for (const updated of resp.nodes) {
          const idx = nodes.findIndex(n => n && n.id === updated.id);
          if (idx !== -1) {
            nodes[idx] = updated;
          }
        }
        // Count tested nodes
        const testedCount = nodeIds.filter(id => {
          const n = nodes.find(x => x && x.id === id);
          return n && n.probe_status !== "not_checked";
        }).length;
        const progress = Math.min(100, Math.round((testedCount / nodeIds.length) * 100));
        barEl.style.width = progress + "%";
        countEl.textContent = `${testedCount}/${nodeIds.length}`;
        
        if (testedCount >= nodeIds.length) {
          stopPolling();
          const elapsed = Math.round((Date.now() - startTime) / 1000);
          statusEl.textContent = `检测完成！共 ${nodeIds.length} 个节点，耗时 ${elapsed} 秒`;
          render();
          setTimeout(() => {
            progressEl.style.display = "none";
          }, 3000);
          return;
        }
      }
    } catch (e) {
      // Ignore polling errors
    }
  };
  
  try {
    const response = await fetchWithCsrf("./api/test_nodes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: nodeIds })
    });
    
    if (response.ok) {
      // Start polling for results
      pollInterval = setInterval(updateProgress, 2000);
      // Timeout after 5 minutes
      timeoutHandle = setTimeout(() => {
        stopPolling();
        const elapsed = Math.round((Date.now() - startTime) / 1000);
        statusEl.textContent = `检测超时，耗时 ${elapsed} 秒`;
        render();
      }, 300000);
    } else {
      stopPolling();
      statusEl.textContent = "检测失败: " + (response.error || "未知错误");
      barEl.style.width = "0%";
    }
  } catch (e) {
    stopPolling();
    statusEl.textContent = "检测失败: 连接服务器失败";
    barEl.style.width = "0%";
  }
}

async function toggleFavorite(id, event) {
  if (event) event.stopPropagation();
  try {
    const response = await fetchWithCsrf("./api/toggle_favorite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = response;
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      render();
    }
  } catch (e) {
    console.error("切换收藏失败", e);
  }
}

let pollInterval = null;
let _pollStableOffCount = 0;

// ── 切换节点过渡遮罩：点击切换后立即显示"正在切换"，后台真正连上新 IP 才消失 ──
let switchTargetId = null;
let switchOverlayMinShow = 0;

function showSwitchOverlay(id) {
  switchTargetId = id;
  switchOverlayMinShow = Date.now() + 1000; // 至少显示 1 秒，保证"切换过程"可见
  let el = document.getElementById("switchOverlay");
  if (!el) {
    // 注入一次 spinner 动画
    if (!document.getElementById("switchSpinnerStyle")) {
      const s = document.createElement("style");
      s.id = "switchSpinnerStyle";
      s.textContent = ".switch-spinner{width:20px;height:20px;border:3px solid #cbd5e1;border-top-color:#3b82f6;border-radius:50%;display:inline-block;animation:switchspin .8s linear infinite}@keyframes switchspin{to{transform:rotate(360deg)}}";
      document.head.appendChild(s);
    }
    el = document.createElement("div");
    el.id = "switchOverlay";
    el.style.cssText = "position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45);z-index:9999;";
    el.innerHTML = '<div style="background:var(--bg,#fff);color:var(--text,#222);padding:22px 30px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.3);display:flex;align-items:center;gap:14px;font-size:15px;">'
      + '<span class="switch-spinner"></span>'
      + '<span id="switchOverlayText">正在切换节点，请稍候…</span>'
      + '</div>';
    document.body.appendChild(el);
  }
  el.style.display = "flex";
}
function hideSwitchOverlay() {
  const el = document.getElementById("switchOverlay");
  if (el) el.style.display = "none";
  switchTargetId = null;
}
function _checkSwitchDone() {
  if (!switchTargetId) return;
  if (state && state.is_connecting) return;       // 仍在连接中，保持遮罩
  if (Date.now() < switchOverlayMinShow) return;  // 最少展示 1 秒，避免一闪而过
  const active = state ? state.active_openvpn_node_id : null;
  if (active === switchTargetId) {
    hideSwitchOverlay();
    showToast("已切换至节点 " + switchTargetId, "info");
  } else if (!active) {
    hideSwitchOverlay();
    showToast("切换失败：未能建立连接，请重试", "error");
  } else {
    // 连到了其它节点（极少），结束遮罩
    hideSwitchOverlay();
  }
}

function showRefreshOverlay(text) {
  let el = document.getElementById("refreshOverlay");
  if (!el) {
    if (!document.getElementById("switchSpinnerStyle")) {
      const s = document.createElement("style");
      s.id = "switchSpinnerStyle";
      s.textContent = ".switch-spinner{width:20px;height:20px;border:3px solid #cbd5e1;border-top-color:#3b82f6;border-radius:50%;display:inline-block;animation:switchspin .8s linear infinite}@keyframes switchspin{to{transform:rotate(360deg)}}";
      document.head.appendChild(s);
    }
    el = document.createElement("div");
    el.id = "refreshOverlay";
    el.style.cssText = "position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45);z-index:9999;";
    el.innerHTML = '<div style="background:var(--bg,#fff);color:var(--text,#222);padding:22px 30px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.3);display:flex;align-items:center;gap:14px;font-size:15px;">'
      + '<span class="switch-spinner"></span>'
      + '<span id="refreshOverlayText">' + text + '</span>'
      + '</div>';
    document.body.appendChild(el);
  } else {
    const t = document.getElementById("refreshOverlayText");
    if (t) t.textContent = text;
  }
  el.style.display = "flex";
}
function setRefreshOverlayText(text) {
  const t = document.getElementById("refreshOverlayText");
  if (t) t.textContent = text;
}
function hideRefreshOverlay() {
  const el = document.getElementById("refreshOverlay");
  if (el) el.style.display = "none";
}

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  _pollStableOffCount = 0;
  pollInterval = setInterval(async () => {
    try {
      const data = await fetchWithCsrf("./api/nodes");
      nodes = Array.isArray(data.nodes) ? data.nodes : [];
      state = data.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();

      // 若正在切换节点，检查是否已连上新 IP（决定是否关闭过渡遮罩）
      if (switchTargetId) _checkSwitchDone();

      if (!state.is_connecting) {
        // 防抖：自动重连/重试过程中后端会瞬时把 is_connecting 切回 False
        // 再立刻置 True，若只在第一次 False 就停止轮询，状态卡会闪现"连接失败"。
        // 需连续 2 次确认未连接才算真正结束，避免假报错与频繁红色提示。
        _pollStableOffCount++;
        if (_pollStableOffCount >= 2) {
          clearInterval(pollInterval);
          pollInterval = null;
          try {
            await fetchWithCsrf("./api/test_proxy", { method: "POST" });
          } catch(pe){}
          load();
        }
      } else {
        _pollStableOffCount = 0;
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id, slotId){
  slotId = slotId || "__default__";
  // 防重复点击：正在连接中再次点击直接忽略，避免后端 is_connecting 守卫
  // 把第二次请求判为"已在连接"而弹报错（假报错），但第一次其实会成功。
  if (state && state.is_connecting) {
    showToast("正在连接中，请稍候…", "warning");
    return;
  }
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();

  startConnectionPolling();

  // 切换瞬间子出口进程可能正在重启/重连，转发请求会瞬时失败；
  // 但后台已受理连接，轮询会确认结果。这里重试几次吸收抖动，
  // 仅在确实无法受理时才报错，避免误弹"连接请求发送失败"。
  let lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetchWithCsrf("./api/connect",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({id, slot_id: slotId})
      });
      // 后端已改为后台异步受理（立即返回 ok），这里只要受理成功就返回，
      // 最终连接结果以轮询读到的真实状态为准，全程不弹错误。
      if (r && r.ok) {
        // 显示"正在切换节点"过渡遮罩，由轮询在真正连上新 IP 后关闭
        showSwitchOverlay(id);
        return;
      }
      // 明确的业务错误（如子出口未运行），需要告知用户
      if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
      state.is_connecting = false;
      render();
      showToast("无法发起连接：" + (r.error || "未知错误"), "error");
      return;
    } catch(e) {
      lastErr = e;
      if (attempt < 3) {
        await new Promise(res => setTimeout(res, 800));
        continue;
      }
    }
  }
  // 三次均为瞬时网络/转发抖动：请求已在后台受理的概率极高，
  // 不弹错误，保留轮询继续确认真实连接状态（状态卡会显示最终成败）。
  console.warn("connect 请求瞬时失败，已交由轮询确认:", lastErr);
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetchWithCsrf("./api/disconnect", { method: "POST" });
    const result = response;
    if (result.ok) {
      try {
        await fetchWithCsrf("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
      showToast("已断开连接", "info");
    } else {
      showToast("断开连接失败: " + (result.error || "未知错误"), "error");
    }
  } catch (e) {
    showToast("请求断开连接失败", "error");
  }
}





const THEME_KEY = 'kada_theme';
var themeLabels = { light: '明亮模式', dark: '暗黑模式', system: '跟随系统' };
var themeIcons = {
  light: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />',
  dark: '<path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" />',
  system: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />'
};
function getThemeIcon(theme) {
  var path = themeIcons[theme] || themeIcons.light;
  return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' + path + '</svg>';
}
function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme);
  var si = document.getElementById('sidebar_theme_icon');
  if (si) si.innerHTML = getThemeIcon(theme);
  var sl = document.getElementById('sidebar_theme_label');
  if (sl) sl.textContent = themeLabels[theme] || themeLabels.light;
  localStorage.setItem(THEME_KEY, theme);
}
function toggleTheme() {
  var saved = localStorage.getItem(THEME_KEY) || 'light';
  var next = saved === 'light' ? 'dark' : (saved === 'dark' ? 'system' : 'light');
  setTheme(next);
}
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar_overlay').classList.toggle('open');
}
function toggleSidebarTheme() {
  toggleTheme();
}

async function load(){
  const r=await fetchWithCsrf("./api/nodes"); 
  const d=r;
  nodes=Array.isArray(d.nodes) ? d.nodes : []; 
  console.log("[load] nodes count:", nodes.length, "first node:", nodes[0] ? nodes[0].id : "none");
  state=d.state||{}; 
  console.log("[load] state.last_fetch_status:", state.last_fetch_status);
  
  if (state.country_translations) {
    countryDict = state.country_translations;
  }
  
  // Fetch CSRF token on load
  try {
    const csrfResp = await fetchWithCsrf("./api/csrf_token");
    if (csrfResp.csrf_token) {
      csrfToken = csrfResp.csrf_token;
    }
  } catch(e) {}
  
  stableSortNodes();
  updateCountryFilter();
  populateRoutingCountries();
  render();

  if (state.is_connecting) {
    startConnectionPolling();
  }
}
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };
$("status_filter").onchange=()=>{ currentPage = 1; render(); };
$("health_filter").onchange=()=>{ currentPage = 1; render(); };

function toggleSettingsSubmenu() {
  const sub = $("settings_submenu");
  const toggle = $("settings_toggle");
  if (sub) {
    const isOpen = sub.style.display === "block";
    sub.style.display = isOpen ? "none" : "block";
    if (toggle) toggle.classList.toggle("open", !isOpen);
  }
}

// ============================================================
// 主页（page_overview）与出站管理（page_egress）—— 完全独立的两套模块
//
// 之前 v2 把两个页面共享同一组 DOM 和同一套渲染函数（共用 selectedEgressSlotId、
// 共用 loadEgress、共用 renderEgressCards、共用 active_node_card / egress_status_blocks
// / overview_node_section），导致：
//   1. 主页点切换会同时切走出站管理页的选中态
//   2. 出站管理页点删除/添加，主页的"已选中"指向已删除对象、需同步修复
//   3. 用户希望在主页快速查看/切换，但不希望影响出站管理页的"管理"操作
// 拆分为：
//   主页：homeEgressStatusList + homeSelectedEgressSlotId + home_egress_blocks +
//         home_active_node_card + renderHomeEgressCards + renderHomeActiveNodeCard +
//         selectHomeEgressCard（只读 + 切换，不显示节点列表，不提供删除/添加）
//   出站管理：egressStatusList + egressSelectedEgressSlotId + egress_status_blocks +
//             egress_active_node_card + renderEgressCards + renderEgressActiveNodeCard +
//             renderEgressNodeList + selectEgressCard（完整管理界面，含节点列表 / 删除 / 添加）
// 双方状态、DOM、函数完全分离，互不引用。switchPage 分别控制显隐。
// ============================================================

// ---- 主页模块（独立） ----
let homeEgressStatusList = [];
let homeSelectedEgressSlotId = null;  // null = 未选中（首次进入会自动选默认出口）

// ---- 出站管理模块（独立） ----
let egressRegions = [];               // 出站管理专用：从 /api/egress_regions 拉取的配置
let egressStatusList = [];            // 出站管理专用：从 /api/egress_status_all 拉取的状态
let egressSelectedEgressSlotId = null; // 出站管理页当前选中的出口（用于节点列表过滤）

// ---- 主页加载（独立） ----
async function loadHomeEgress() {
  // 主页用 homeEgressStatusList，不影响出站管理页状态
  renderHomeEgressCards();
  try {
    const statusResp = await fetchWithCsrf("./api/egress_status_all");
    homeEgressStatusList = statusResp.egress || [];

    // 合并路由配置到状态项（同 loadEgress 的修复：aggregate_egress_status 不含路由字段）
    try {
      var cfgPromises = homeEgressStatusList.map(function(e) {
        var sid = e.is_default ? "__default__" : (e.slot_id || "__default__");
        return fetchWithCsrf("./api/egress_routing_config?slot_id=" + encodeURIComponent(sid))
          .catch(function() { return null; });
      });
      var cfgResults = await Promise.all(cfgPromises);
      for (var i = 0; i < homeEgressStatusList.length && i < cfgResults.length; i++) {
        var cr = cfgResults[i];
        if (cr && cr.config) {
          var c = cr.config;
          homeEgressStatusList[i].routing_mode = c.routing_mode || "auto";
          homeEgressStatusList[i].force_country = c.force_country || "";
          homeEgressStatusList[i].routing_ip_type = c.routing_ip_type || "all";
        }
      }
    } catch(cfgErr) { /* 静默失败，卡片显示默认值 */ }

    // 主页默认自动选默认出口（首次进入 / 清空选择后）
    if (homeSelectedEgressSlotId === null) {
      const defaultEgress = homeEgressStatusList.find(function(e) { return e.is_default; });
      if (defaultEgress) homeSelectedEgressSlotId = "__default__";
    }
    renderHomeEgressCards();
    renderHomeActiveNodeCard(homeSelectedEgressSlotId || "__default__");
  } catch (e) { console.error(e); }
}
async function loadHomeEgressStatus() { return loadHomeEgress(); }

// ---- 出站管理加载（独立） ----
async function loadEgress() {
  // 出站管理用 egressStatusList/egressRegions，不影响主页
  renderEgressCards();
  try {
    const [statusResp, regionsResp] = await Promise.all([
      fetchWithCsrf("./api/egress_status_all"),
      fetchWithCsrf("./api/egress_regions")
    ]);
    egressStatusList = statusResp.egress || [];
    egressRegions = regionsResp.regions || [];

    // 关键修复：将每个出口的路由配置（routing_mode / force_country 等）
    // 合并到状态列表项中。否则 aggregate_egress_status() 只返回基础状态
    // （alive / active_node_id / proxy_port），不含路由配置，
    // 导致卡片永远显示 "自动配置 / 自动"（fallback 默认值）。
    try {
      const cfgPromises = egressStatusList.map(function(e) {
        const sid = e.is_default ? "__default__" : (e.slot_id || "__default__");
        return fetchWithCsrf("./api/egress_routing_config?slot_id=" + encodeURIComponent(sid))
          .catch(function() { return null; });
      });
      const cfgResults = await Promise.all(cfgPromises);
      for (var i = 0; i < egressStatusList.length && i < cfgResults.length; i++) {
        var cr = cfgResults[i];
        if (cr && cr.config) {
          var c = cr.config;
          egressStatusList[i].routing_mode = c.routing_mode || "auto";
          egressStatusList[i].force_country = c.force_country || "";
          egressStatusList[i].routing_ip_type = c.routing_ip_type || "all";
          egressStatusList[i].min_health_score = c.min_health_score || 0;
          egressStatusList[i].fixed_node_id = c.fixed_node_id || "";
        }
      }
    } catch(cfgErr) { console.warn("[loadEgress] 路由配置合并失败（卡片将显示默认值）:", cfgErr); }

    // 出站管理页默认选默认出口（首次进入 / 清空选择后）
    if (egressSelectedEgressSlotId === null) {
      const defaultEgress = egressStatusList.find(function(e) { return e.is_default; });
      if (defaultEgress) egressSelectedEgressSlotId = "__default__";
    }
    renderEgressCards();
    renderEgressActiveNodeCard(egressSelectedEgressSlotId || "__default__");
  } catch (e) { console.error(e); }
}
async function loadEgressStatus() { return loadEgress(); }

function escAttr(s) { return String(s || "").replace(/'/g, "&#39;").replace(/"/g, "&quot;").replace(/</g, "&lt;"); }

// ---- 轻量级 Toast 提示（非阻塞，替代 alert 弹窗） ----
// type: "info" | "success" | "error" | "warning"
function showToast(message, type) {
  type = type || "info";
  const container = document.getElementById("toast_container");
  if (!container) { console.warn("[toast]", type, message); return; }
  const colors = {
    info:    { bg: "rgba(99,102,241,0.12)",  border: "rgba(99,102,241,0.35)",  fg: "#6366f1" },
    success: { bg: "rgba(16,185,129,0.12)",  border: "rgba(16,185,129,0.35)",  fg: "#10b981" },
    error:   { bg: "rgba(220,38,38,0.10)",   border: "rgba(220,38,38,0.35)",   fg: "#dc2626" },
    warning: { bg: "rgba(245,158,11,0.12)",  border: "rgba(245,158,11,0.35)",  fg: "#f59e0b" },
  };
  const c = colors[type] || colors.info;
  const el = document.createElement("div");
  el.style.cssText = "padding:10px 14px; font-size:13px; line-height:1.5; border-radius:10px; background:" + c.bg +
    "; border:1px solid " + c.border + "; color:var(--text-primary,#0f172a); box-shadow:0 8px 24px rgba(15,23,42,0.18);" +
    " backdrop-filter:blur(6px); display:flex; align-items:flex-start; gap:8px; animation:toastIn .18s ease-out;";
  el.innerHTML = '<span style="color:' + c.fg + '; font-weight:700; flex:0 0 auto;">●</span>' +
    '<span style="flex:1;">' + esc(message) + '</span>';
  container.appendChild(el);
  // 自动消失
  setTimeout(function() {
    el.style.transition = "opacity .25s ease, transform .25s ease";
    el.style.opacity = "0";
    el.style.transform = "translateX(12px)";
    setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 260);
  }, type === "error" ? 4000 : 2600);
}

// ---- 共享的卡片 HTML 构造器 ----
// 主页（mode='home'）只提供断开按钮 + 选中切换，无删除；不可添加新实例。
// 出站管理（mode='egress'）提供断开 + 删除（仅非默认）。
function _buildEgressCardHTML(e, mode) {
  // 与主页 _buildHomeEgressSummaryHTML 统一风格：紧凑单行卡片
  const isDefault = !!e.is_default;
  const isDown = !e.alive;
  const titleLabel = isDefault ? "默认出口" : (e.name || e.slot_id);
  const port = e.proxy_port || 7928;
  const slotKey = isDefault ? "__default__" : e.slot_id;
  const isSelected = (mode === "home" ? homeSelectedEgressSlotId : egressSelectedEgressSlotId) === slotKey;

  // 国家标签（仅固定地区模式显示）
  const country = e.force_country ? translateCountry(e.force_country) : "";
  const showCountry = country && (e.routing_mode === "fixed_region");

  // 代理配置摘要：自动/固定地区/固定IP/收藏 + IP类型 + 健康度阈值
  const ROUTING_MODE_LABELS = {
    auto: "自动选最快",
    fixed_region: "固定地区",
    fixed_ip: "固定IP",
    favorites: "收藏节点"
  };
  const IP_TYPE_LABELS = {
    all: "所有IP",
    residential: "住宅IP",
    hosting: "机房IP"
  };
  const routingModeLabel = ROUTING_MODE_LABELS[e.routing_mode] || ROUTING_MODE_LABELS.auto;
  const ipTypeLabel = IP_TYPE_LABELS[e.routing_ip_type] || IP_TYPE_LABELS.all;
  let configSummary = routingModeLabel;
  if (e.routing_mode === "fixed_region" && country) {
    configSummary += "：" + country;
  } else if (e.routing_mode === "fixed_ip" && e.fixed_node_id) {
    configSummary += "：" + e.fixed_node_id;
  }
  configSummary += " | " + ipTypeLabel;
  if ((e.min_health_score || 0) > 0) {
    configSummary += " | 健康度≥" + e.min_health_score;
  }

  // proxy 端口通但管理 UI 端口不通 = 状态异常（子进程主线程卡住/崩溃，
  // 代理线程仍在跑），必须让用户一眼看出来，而不是显示"运行中"。
  const isUiAbnormal = !isDown && !e.is_default && e.ui_reachable === false;
  const isCrashed = e.crashed === true;

  // 状态徽标（与主页一致的小药丸样式）
  let statusBadge;
  if (isCrashed || isUiAbnormal) {
    statusBadge = "<span style='font-size:11px;color:#dc2626;background:rgba(220,38,38,0.10);padding:1px 8px;border-radius:10px;border:1px solid rgba(220,38,38,0.2);'>状态异常</span>";
  } else if (isDown) {
    statusBadge = "<span style='font-size:11px;color:#94a3b8;background:rgba(148,163,184,0.12);padding:1px 8px;border-radius:10px;border:1px solid rgba(148,163,184,0.2);'>未启动</span>";
  } else if (e.active_node_id) {
    statusBadge = "<span style='font-size:11px;color:#059669;background:rgba(5,150,105,0.10);padding:1px 8px;border-radius:10px;border:1px solid rgba(5,150,105,0.2);'>已连接</span>";
  } else if (e.is_connecting) {
    statusBadge = "<span style='font-size:11px;color:#d97706;background:rgba(217,119,6,0.10);padding:1px 8px;border-radius:10px;border:1px solid rgba(217,119,6,0.2);'>连接中</span>";
  } else {
    statusBadge = "<span style='font-size:11px;color:#059669;background:rgba(5,150,105,0.10);padding:1px 8px;border-radius:10px;border:1px solid rgba(5,150,105,0.2);'>运行中</span>";
  }

  // 节点信息简述 / 未连接时的诊断提示
  let nodeBrief = "";
  if (e.active_node_id) {
    nodeBrief = "<span style='color:var(--text-muted);font-size:12px;font-family:ui-monospace,\"SF Mono\",Menlo,monospace;'>" + escAttr(e.active_node_id) + "</span>";
  } else if (isCrashed) {
    nodeBrief = "<span style='color:#dc2626;font-size:12px;'>子出口进程已退出，请查看日志或重启</span>";
  } else if (isUiAbnormal) {
    nodeBrief = "<span style='color:#dc2626;font-size:12px;'>子出口管理端口无响应，代理端口可能仍存活，请点击重启恢复</span>";
  } else if (e.last_check_message) {
    nodeBrief = "<span style='color:var(--text-muted);font-size:12px;'>" + escAttr(e.last_check_message) + "</span>";
  } else if (isDown) {
    nodeBrief = "<span style='color:var(--text-muted);font-size:12px;'>子出口尚未启动，点击选中查看日志</span>";
  } else {
    nodeBrief = "<span style='color:var(--text-muted);font-size:12px;'>正在等待父进程共享可用节点...</span>";
  }

  // 操作按钮（仅出站管理页显示，主页不显示）
  // 未启动的出口也要能删除，否则子进程起不来时用户删不掉。
  let actionsHtml = "";
  if (mode !== "home") {
    const restartBtn = (isUiAbnormal || isCrashed)
      ? "<button class='btn-primary' style='height:28px;padding:0 10px;border-radius:6px;font-size:12px;display:inline-flex;align-items:center;gap:4px;flex-shrink:0;margin-right:6px;' onclick=\"event.stopPropagation();restartEgress('" + escAttr(e.slot_id) + "')\">" +
          "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' style='width:12px;height:12px;'><path d='M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15'/></svg>重启" +
        "</button>"
      : "";
    const disconnectBtn = !isDown
      ? "<button class='btn-danger' style='height:28px;padding:0 10px;border-radius:6px;font-size:12px;display:inline-flex;align-items:center;gap:4px;flex-shrink:0;' onclick=\"event.stopPropagation();disconnectEgress('" + escAttr(e.slot_id) + "')\">" +
          "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' style='width:12px;height:12px;'><path d='M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z'/></svg>断开" +
        "</button>"
      : "";
    const deleteBtn = !isDefault
      ? "<button class='btn-ghost' style='height:28px;padding:0 8px;border-radius:6px;font-size:12px;margin-left:6px;display:inline-flex;align-items:center;gap:4px;flex-shrink:0;' onclick=\"event.stopPropagation();delEgress('" + escAttr(e.slot_id) + "')\">" +
          "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' style='width:12px;height:12px;'><path d='M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6h14z'/></svg>删除" +
        "</button>"
      : "";
    actionsHtml = restartBtn + disconnectBtn + deleteBtn;
  }

  const selectedBg = isSelected ? "background: rgba(99,102,241,0.06); border-color: rgba(99,102,241,0.25);" : "";
  const selectHandler = mode === "home" ? "selectHomeEgressCard" : "selectEgressCard";

  return "<div style='display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:10px;border:1px solid var(--border-color,#e2e8f0);background:var(--surface,#ffffff);cursor:pointer;transition:all 0.15s;" + selectedBg + "' onclick=\"" + selectHandler + "('" + escAttr(slotKey) + "')\">" +
    // 左侧图标（与主页一致：32px 圆角方块）
    "<div style='width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0;" +
      (isDown ? "background:rgba(148,163,184,0.12);" : (isDefault ? "background:rgba(16,185,129,0.12);" : "background:rgba(99,102,241,0.12);")) + ">" +
      "<svg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor' stroke-width='2.5' style='width:16px;height:16px;" +
        (isDown ? "color:#94a3b8" : (isDefault ? "color:#10b981" : "color:var(--primary,#6366f1)")) + "'>" +
        (isDown
          ? "<path d='M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636'/>"
          : "<path d='M13 10V3L4 14h7v7l9-11h-7z'/>") +
      "</svg></div>" +
    // 中间信息区：名称 + 配置摘要 + 节点/诊断信息
    "<div style='flex:1;min-width:0;'>" +
      "<div style='display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>" +
        statusBadge +
        "<strong style='font-size:13px;color:var(--text-primary);'>" + escAttr(titleLabel) + "</strong>" +
        (isSelected ? "<span style='font-size:10px;color:var(--primary,#6366f1);background:rgba(99,102,241,0.10);padding:1px 6px;border-radius:6px;'>已选中</span>" : "") +
      "</div>" +
      "<div style='margin-top:3px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>" +
        "<span style='color:var(--text-muted);font-size:12px;'>" + escAttr(configSummary) + "</span>" +
        "<span style='color:var(--text-muted);font-size:11px;'>" + (isDown ? "" : ":" + port + "") + "</span>" +
      "</div>" +
      "<div style='margin-top:2px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>" +
        nodeBrief +
      "</div>" +
    "</div>" +
    // 右侧操作区（出站管理显示按钮，主页显示箭头）
    (mode !== "home"
      ? ("<div style='display:flex;align-items:center;gap:6px;flex-shrink:0;' onclick=\"event.stopPropagation();\">" + actionsHtml + "</div>")
      : "<svg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor' stroke-width='2' style='width:14px;height:14px;color:var(--text-muted);flex-shrink:0;'><path stroke-linecap='round' stroke-linejoin='round' d='M9 5l7 7-7 7'/></svg>"
    ) +
  "</div>";
}

// 默认出口固定第一；其余按 slot_id 中的数字倒序（最新创建的在前）。
function _sortEgressForDisplay(list) {
  const def = list.find(function(e) { return e && e.is_default; });
  const rest = list.filter(function(e) { return e && !e.is_default; });
  rest.sort(function(a, b) {
    const na = parseInt(String(a.slot_id || "").replace(/[^0-9]/g, ""), 10);
    const nb = parseInt(String(b.slot_id || "").replace(/[^0-9]/g, ""), 10);
    const va = Number.isFinite(na) ? na : -1;
    const vb = Number.isFinite(nb) ? nb : -1;
    return vb - va;  // 倒序：数字大的在前（最新创建）
  });
  return def ? [def].concat(rest) : rest;
}

// ---- 主页出口概览（紧凑状态条，只展示名称+状态+端口，不含路由详情和操作按钮） ----
function _buildHomeEgressSummaryHTML(e) {
  const isDefault = !!e.is_default;
  const isDown = !e.alive;
  const titleLabel = isDefault ? "默认出口" : (e.name || e.slot_id);
  const port = e.proxy_port || 7928;
  const slotKey = isDefault ? "__default__" : e.slot_id;
  const isSelected = homeSelectedEgressSlotId === slotKey;
  // 国家标签（仅当配置了固定国家时显示，避免每行都显示"自动"）
  const country = e.force_country ? translateCountry(e.force_country) : "";
  const showCountry = country && (e.routing_mode === "fixed_region");
  // 代理配置摘要（与出站管理页统一）
  const ROUTING_MODE_LABELS = {
    auto: "自动选最快",
    fixed_region: "固定地区",
    fixed_ip: "固定IP",
    favorites: "收藏节点"
  };
  const IP_TYPE_LABELS = {
    all: "所有IP",
    residential: "住宅IP",
    hosting: "机房IP"
  };
  const routingModeLabel = ROUTING_MODE_LABELS[e.routing_mode] || ROUTING_MODE_LABELS.auto;
  const ipTypeLabel = IP_TYPE_LABELS[e.routing_ip_type] || IP_TYPE_LABELS.all;
  let configSummary = routingModeLabel;
  if (e.routing_mode === "fixed_region" && country) {
    configSummary += "：" + country;
  } else if (e.routing_mode === "fixed_ip" && e.fixed_node_id) {
    configSummary += "：" + e.fixed_node_id;
  }
  configSummary += " | " + ipTypeLabel;
  if ((e.min_health_score || 0) > 0) {
    configSummary += " | 健康度≥" + e.min_health_score;
  }
  const isUiAbnormalHome = !isDown && !isDefault && e.ui_reachable === false;
  const isCrashedHome = e.crashed === true;
  // 状态徽标
  let statusBadge;
  if (isCrashedHome || isUiAbnormalHome) {
    statusBadge = "<span style='font-size:11px;color:#dc2626;background:rgba(220,38,38,0.10);padding:1px 8px;border-radius:10px;border:1px solid rgba(220,38,38,0.2);'>状态异常</span>";
  } else if (isDown) {
    statusBadge = "<span style='font-size:11px;color:#94a3b8;background:rgba(148,163,184,0.12);padding:1px 8px;border-radius:10px;border:1px solid rgba(148,163,184,0.2);'>未启动</span>";
  } else if (e.active_node_id) {
    statusBadge = "<span style='font-size:11px;color:#059669;background:rgba(5,150,105,0.10);padding:1px 8px;border-radius:10px;border:1px solid rgba(5,150,105,0.2);'>已连接</span>";
  } else if (e.is_connecting) {
    statusBadge = "<span style='font-size:11px;color:#d97706;background:rgba(217,119,6,0.10);padding:1px 8px;border-radius:10px;border:1px solid rgba(217,119,6,0.2);'>连接中</span>";
  } else {
    statusBadge = "<span style='font-size:11px;color:#059669;background:rgba(5,150,105,0.10);padding:1px 8px;border-radius:10px;border:1px solid rgba(5,150,105,0.2);'>运行中</span>";
  }
  const selectedBg = isSelected ? "background: rgba(99,102,241,0.06); border-color: rgba(99,102,241,0.25);" : "";
  return "<div style='display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:10px;border:1px solid var(--border-color,#e2e8f0);background:var(--surface,#ffffff);cursor:pointer;transition:all 0.15s;" + selectedBg + "' onclick=\"selectHomeEgressCard('" + escAttr(slotKey) + "')\">" +
    // 左侧图标
    "<div style='width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0;" +
      (isDown ? "background:rgba(148,163,184,0.12);" : (isDefault ? "background:rgba(16,185,129,0.12);" : "background:rgba(99,102,241,0.12);")) + ">" +
      "<svg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor' stroke-width='2.5' style='width:16px;height:16px;" +
        (isDown ? "color:#94a3b8" : (isDefault ? "color:#10b981" : "color:var(--primary,#6366f1)")) + "'>" +
      (isDown
        ? "<path d='M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636'/>"
        : "<path d='M13 10V3L4 14h7v7l9-11h-7z'/>") +
      "</svg></div>" +
    // 中间信息区
    "<div style='flex:1;min-width:0;'>" +
      "<div style='display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>" +
        statusBadge +
        "<strong style='font-size:13px;color:var(--text-primary);'>" + escAttr(titleLabel) + "</strong>" +
        (isSelected ? "<span style='font-size:10px;color:var(--primary,#6366f1);background:rgba(99,102,241,0.10);padding:1px 6px;border-radius:6px;'>已选中</span>" : "") +
      "</div>" +
      "<div style='margin-top:3px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>" +
        "<span style='color:var(--text-muted);font-size:12px;'>" + escAttr(configSummary) + "</span>" +
        "<span style='color:var(--text-muted);font-size:11px;'>:" + port + "</span>" +
      "</div>" +
    "</div>" +
    // 右侧箭头
    "<svg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor' stroke-width='2' style='width:14px;height:14px;color:var(--text-muted);flex-shrink:0;'><path stroke-linecap='round' stroke-linejoin='round' d='M9 5l7 7-7 7'/></svg>" +
  "</div>";
}

// ---- 主页卡片渲染（写 home_egress_blocks，紧凑概览模式） ----
function renderHomeEgressCards() {
  const box = $("home_egress_blocks");
  const countLabel = $("home_egress_count");
  if (!box) return;
  const list = _sortEgressForDisplay(homeEgressStatusList || []);
  if (countLabel) countLabel.textContent = list.length > 0 ? "共 " + list.length + " 个" : "";
  if (!list.length) { box.innerHTML = ""; return; }
  box.innerHTML = list.map(function(e) { return _buildHomeEgressSummaryHTML(e); }).join("");
}

// ---- 出站管理卡片渲染（写 egress_status_blocks，含断开 + 删除 + 节点列表） ----
function renderEgressCards() {
  const box = $("egress_status_blocks");
  const emptyHint = $("egress_empty_hint");
  const countLabel = $("egress_card_count_label");
  if (!box) return;
  const list = _sortEgressForDisplay(egressStatusList || []);
  // 更新模块卡片标题栏的计数
  if (countLabel) countLabel.textContent = list.length > 0 ? "共 " + list.length + " 个实例" : "";
  // 空状态提示
  if (!list.length) {
    box.innerHTML = "";
    if (emptyHint) emptyHint.style.display = "";
    renderEgressNodeList();
    return;
  }
  if (emptyHint) emptyHint.style.display = "none";
  box.innerHTML = list.map(function(e) { return _buildEgressCardHTML(e, "egress"); }).join("");
  renderEgressNodeList();
}

// ---- 刷新状态（带加载反馈） ----
let _egressRefreshing = false;
async function loadEgressWithFeedback() {
  if (_egressRefreshing) return;
  _egressRefreshing = true;
  const btn = $("btn_refresh_egress");
  const icon = $("refresh_egress_icon");
  const text = $("refresh_egress_text");
  if (btn) { btn.disabled = true; btn.style.opacity = "0.6"; }
  if (icon) icon.style.animation = "spin 1s linear infinite";
  if (text) text.textContent = "刷新中...";
  try {
    await loadEgress();
    if (text) text.textContent = "已刷新";
    setTimeout(function() { if (!_egressRefreshing && text) text.textContent = "刷新状态"; }, 1500);
  } catch (e) {
    if (text) text.textContent = "刷新失败";
    setTimeout(function() { if (!_egressRefreshing && text) text.textContent = "刷新状态"; }, 2000);
  } finally {
    _egressRefreshing = false;
    if (icon) icon.style.animation = "";
    if (btn) { btn.disabled = false; btn.style.opacity = ""; }
  }
}

// ---- 主页：选中卡片（只影响主页状态，不影响出站管理页） ----
function selectHomeEgressCard(slotKey) {
  homeSelectedEgressSlotId = slotKey;
  renderHomeEgressCards();
  renderHomeActiveNodeCard(slotKey);
}

// ---- 出站管理：选中卡片（只影响出站管理页状态） ----
function selectEgressCard(slotKey) {
  egressSelectedEgressSlotId = slotKey;
  renderEgressCards();
  renderEgressActiveNodeCard(slotKey);
}

// 兼容旧名（若旧代码还在引用 selectEgress / selectedEgressSlotId）
function selectEgress(slotKey) { selectEgressCard(slotKey); }

// ---- 出站管理页：节点列表（独立 DOM 容器 egress_node_section / egress_rows / egress_filter_label） ----
async function renderEgressNodeList() {
  const section = $("egress_node_section");
  const rows = $("egress_rows");
  const label = $("egress_filter_label");
  if (!section || !rows || !label) return;
  // 仅当处于出站管理页 + 选中了一个出口时显示
  const inEgressPage = (function() {
    const p = document.getElementById("page_egress");
    return p && p.style.display !== "none";
  })();
  if (!inEgressPage || !egressSelectedEgressSlotId) {
    section.style.display = "none";
    rows.innerHTML = "";
    return;
  }
  section.style.display = "";
  const slotKey = egressSelectedEgressSlotId;
  const slotIsDefault = (slotKey === "__default__");
  // 路由配置优先从已合并的 egressStatusList 读取：loadEgress() 已经把每个出口的
  // routing_mode / force_country / routing_ip_type 等合并进列表项，卡片显示的就是这份数据。
  // 不再独立 fetch /api/egress_routing_config——两份数据源若时序/取值不一致，会导致子出口
  // 节点列表不按配置过滤（显示全部/错误的国家）。统一用 egressStatusList，与卡片完全一致。
  let cfg = null;
  if (!slotIsDefault && egressStatusList && egressStatusList.length) {
    const found = egressStatusList.find(function(e) {
      return (e.slot_id || "") === slotKey;
    });
    if (found) {
      cfg = {
        routing_mode: found.routing_mode,
        force_country: found.force_country,
        routing_ip_type: found.routing_ip_type,
        min_health_score: found.min_health_score || 0,
        fixed_node_id: found.fixed_node_id || ""
      };
    }
  }
  const routingMode = (cfg && cfg.routing_mode) || (slotIsDefault ? (state.routing_mode || "auto") : "auto");
  const forceCountry = (cfg && cfg.force_country) || (slotIsDefault ? (state.force_country || "") : "");
  const routingIpType = (cfg && cfg.routing_ip_type) || (slotIsDefault ? (state.routing_ip_type || "all") : "all");
  const minHealth = (cfg && cfg.min_health_score) || (slotIsDefault ? (state.min_health_score || 0) : 0);
  const fixedId = (cfg && cfg.fixed_node_id) || (slotIsDefault ? (state.fixed_node_id || "") : "");

  let filtered = (nodes || []).filter(function(n) { return n && n.id; });
  // 统一国家字段：force_country 可能存的是代码（"KR"）也可能是中文名（"韩国"），节点 n.country 同理。
  // 这里把两边都规范化成"中文名"后再比对，避免"选了韩国却匹配到 KR/JP"或反之。
  const _normCountry = function(c) {
    if (!c) return "";
    return (countryDict[c] || c || "").toString().trim();
  };
  const _forceCountryNorm = _normCountry(forceCountry);
  if (cfg && cfg.not_found) {
    // 选中未配置出口：显示所有节点
  } else if (routingMode === "fixed_region" && _forceCountryNorm) {
    filtered = filtered.filter(function(n) {
      return _normCountry(n.country) === _forceCountryNorm;
    });
  } else if (routingMode === "fixed_ip" && fixedId) {
    filtered = filtered.filter(function(n) { return n.id === fixedId; });
  } else if (routingMode === "favorites") {
    const favIds = (slotIsDefault ? (state.favorite_node_ids || []) : []);
    filtered = filtered.filter(function(n) { return favIds.indexOf(n.id) >= 0; });
  }
  if (routingIpType === "residential") {
    filtered = filtered.filter(function(n) { return n.ip_type === "residential" || n.ip_type === "mobile"; });
  } else if (routingIpType === "hosting") {
    filtered = filtered.filter(function(n) { return n.ip_type === "hosting"; });
  }
  if (minHealth) {
    filtered = filtered.filter(function(n) { return (getHealthScore(n) || 0) >= minHealth; });
  }
  filtered.sort(function(a, b) {
    if (a.probe_status === "available" && b.probe_status !== "available") return -1;
    if (b.probe_status === "available" && a.probe_status !== "available") return 1;
    if (a.probe_status === "available" && b.probe_status === "available") {
      return (parseInt(a.latency_ms) || 999999) - (parseInt(b.latency_ms) || 999999);
    }
    return 0;
  });

  const parts = [];
  parts.push(slotIsDefault ? "默认出口" : ("出口 " + slotKey));
  if (routingMode === "fixed_region" && _forceCountryNorm) parts.push(_forceCountryNorm);
  else if (routingMode === "fixed_ip") parts.push("固定 IP");
  else if (routingMode === "favorites") parts.push("收藏节点");
  else parts.push("自动配置");
  if (routingIpType === "residential") parts.push("住宅IP");
  else if (routingIpType === "hosting") parts.push("机房IP");
  else parts.push("所有IP");
  if (cfg && cfg.not_found) parts.push("（未配置，按全部节点展示）");
  label.textContent = parts.join(" + ") + " (" + filtered.length + " 个节点)";

  if (filtered.length === 0) {
    rows.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-secondary);padding:30px 0;">' +
      '暂无符合条件的节点。<br>' +
      '<span style="font-size:12px;">可点击「更新节点」拉取更多，或到「代理设置」放宽筛选条件。</span></td></tr>';
    return;
  }
  rows.innerHTML = filtered.map(function(n) {
    var isUnavailable = n.probe_status === "unavailable";
    var latencyClass = getLatencyClass(n.latency_ms);
    var latencyText = n.latency_ms ? '<span class="latency-val ' + latencyClass + '">' + n.latency_ms + ' ms</span>' : "-";
    var displayLocation = n.location || translateCountry(n.country) || "-";
    var isActive = n.id && egressActiveNodeIdForSlot(slotKey) === n.id;
    var badgeClass = isActive ? "available" : (n.probe_status || "not_checked");
    var badgeText = isActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
    // 子出口状态异常（UI 管理端口无响应/已崩溃）时禁用切换，避免误弹 Connection refused
    const selectedEgress = !slotIsDefault && egressStatusList
      ? egressStatusList.find(function(e) { return (e.slot_id || "") === slotKey; })
      : null;
    const isEgressAbnormal = selectedEgress && (selectedEgress.crashed === true || selectedEgress.ui_reachable === false);
    var connectBtn = isActive
      ? '<button class="connect-btn" disabled style="background:var(--success-gradient);color:white;cursor:default;opacity:1;">已连接</button>'
      : '<button class="connect-btn" ' + ((isUnavailable || isEgressAbnormal) ? 'disabled style="opacity:0.3;cursor:not-allowed;"' : '') + ' onclick="connectNode(\'' + esc(n.id) + '\',\'' + escAttr(slotKey) + '\')">' + (isEgressAbnormal ? '重启出口后切换' : '切换') + '</button>';
    return '<tr' + (isActive ? ' class="active-row"' : '') + ' style="display:table-row!important;">' +
      '<td style="display:table-cell!important;white-space:nowrap;"><span class="badge ' + badgeClass + '">' + badgeText + '</span></td>' +
      '<td class="mono" style="white-space:nowrap;max-width:220px;overflow:hidden;text-overflow:ellipsis;display:table-cell!important;" title="' + esc(n.ip||n.remote_host) + ':' + (n.remote_port||"") + '">' + esc(n.ip||n.remote_host) + ':' + (n.remote_port||"") + '</td>' +
      '<td style="white-space:normal;word-break:break-word;display:table-cell!important;" title="' + esc(displayLocation) + '">' + esc(displayLocation) + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;">' + esc(translateIpType(n.ip_type)) + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;">' + latencyText + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;">' + healthCell(n) + '</td>' +
      '<td class="risk-col" style="white-space:nowrap;display:table-cell!important;text-align:center;">' + riskCell(n) + '</td>' +
      '<td style="display:table-cell!important;">' + connectBtn + '</td>' +
      '</tr>';
  }).join("");
}
function egressActiveNodeIdForSlot(slotKey) {
  if (!egressStatusList || !egressStatusList.length) return null;
  if (slotKey === "__default__") {
    for (var i = 0; i < egressStatusList.length; i++) {
      if (egressStatusList[i].is_default) return egressStatusList[i].active_node_id || null;
    }
    return null;
  }
  for (var j = 0; j < egressStatusList.length; j++) {
    if (egressStatusList[j].slot_id === slotKey) return egressStatusList[j].active_node_id || null;
  }
  return null;
}
// 添加出站管理弹窗：让用户能写实例名/端口（用户反馈"弹窗要能写字"）。
// name 留空由后端自动生成 egress_N；port 留空由后端从 7929 起自动顺延。
function openAddEgressModal() {
  const modal = $("add_egress_modal");
  const nameInput = $("add_egress_name");
  const portInput = $("add_egress_port");
  const countryInput = $("add_egress_country");
  const errBox = $("add_egress_error");
  if (!modal) return;
  if (nameInput) { nameInput.value = ""; nameInput.focus(); }
  if (portInput) portInput.value = "";
  // 用当前已加载的节点池填充国家下拉（避免再拉一次 /api/nodes）
  if (countryInput) {
    const countries = [];
    (nodes || []).forEach(function(n) { if (n && n.country && countries.indexOf(n.country) < 0) countries.push(n.country); });
    countryInput.innerHTML = '<option value="">不锁定（自动选最快）</option>' +
      countries.map(function(c) { return '<option value="' + escAttr(c) + '">' + esc(c) + '</option>'; }).join("");
  }
  if (errBox) { errBox.style.display = "none"; errBox.textContent = ""; }
  modal.style.display = "flex";
}
function closeAddEgressModal() {
  const modal = $("add_egress_modal");
  if (modal) modal.style.display = "none";
}
async function submitAddEgress() {
  const nameInput = $("add_egress_name");
  const portInput = $("add_egress_port");
  const countryInput = $("add_egress_country");
  const errBox = $("add_egress_error");
  const submitBtn = $("add_egress_submit_btn");
  if (!nameInput || !portInput) return;
  const name = (nameInput.value || "").trim();
  const country = (countryInput && countryInput.value) ? countryInput.value.trim() : "";
  let port = 0;
  const portRaw = (portInput.value || "").trim();
  if (portRaw) {
    const parsed = parseInt(portRaw, 10);
    if (!Number.isFinite(parsed) || parsed < 1024 || parsed > 65535) {
      if (errBox) { errBox.style.display = "block"; errBox.textContent = "端口必须在 1024-65535 之间"; }
      return;
    }
    port = parsed;
  }
  if (errBox) { errBox.style.display = "none"; errBox.textContent = ""; }
  if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = "添加中…"; }
  try {
    const data = await fetchWithCsrf("./api/egress_regions", {
      method: "POST",
      body: JSON.stringify({ name: name, port: port || 0, country: country }),
    });
    if (!data.ok) {
      if (errBox) { errBox.style.display = "block"; errBox.textContent = "添加失败：" + (data.error || "未知错误"); }
      return;
    }
    closeAddEgressModal();
    egressRegions = data.regions || [];
    renderEgressCards();
    try {
      const s = await fetchWithCsrf("./api/egress_status_all");
      egressStatusList = s.egress || [];
      renderEgressCards();
    } catch (e) {}
  } catch (e) {
    if (errBox) { errBox.style.display = "block"; errBox.textContent = "网络错误：" + (e && e.message ? e.message : e); }
  } finally {
    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "添加"; }
  }
}
async function delEgress(slotId) {
  if (!confirm("确定删除该出站管理？将停止其隧道并释放资源")) return;
  const data = await fetchWithCsrf("./api/egress_regions/delete", { method: "POST", body: JSON.stringify({ slot_id: slotId }) });
  if (!data.ok) { alert("删除失败：" + (data.error || "")); return; }
  egressRegions = data.regions || [];
  egressStatusList = egressStatusList.filter(function(x) { return x.slot_id !== slotId; });
  if (egressSelectedEgressSlotId === slotId) egressSelectedEgressSlotId = null;
  renderEgressCards();
  renderEgressActiveNodeCard(egressSelectedEgressSlotId || "__default__");
}
// 主页断开按钮：断开后刷新主页（不影响出站管理页）
async function homeDisconnectEgress(slotId) {
  const isDefault = !slotId || slotId === "__default__";
  if (isDefault) { disconnectNode(); return; }
  if (!confirm("确定断开该出口？该出口的隧道将停止")) return;
  try {
    const data = await fetchWithCsrf("./api/egress_disconnect", { method: "POST", body: JSON.stringify({ slot_id: slotId }) });
    if (!data.ok) { showToast("断开失败：" + (data.error || ""), "error"); return; }
    showToast("已断开该出口", "info");
    await loadHomeEgress();
  } catch (e) { showToast("请求断开连接失败", "error"); }
}
async function disconnectEgress(slotId) {
  if (!confirm("确定断开该出站管理？该出口的隧道将停止")) return;
  try {
    const data = await fetchWithCsrf("./api/egress_disconnect", { method: "POST", body: JSON.stringify({ slot_id: slotId }) });
    if (!data.ok) { showToast("断开失败：" + (data.error || ""), "error"); return; }
    showToast("已断开该出站管理", "info");
    // 只刷新出站管理页（不影响主页）
    if (window.loadEgress) loadEgress();
  } catch (e) { showToast("请求断开连接失败", "error"); }
}

function switchPage(name) {
  document.querySelectorAll(".page-content").forEach(function(p) { p.style.display = "none"; });
  document.querySelectorAll(".nav-item").forEach(function(n) { n.classList.remove("active"); });
  var page = document.getElementById("page_" + name);
  if (page) page.style.display = "";
  var nav = document.getElementById("nav_" + name);
  if (nav) nav.classList.add("active");
  localStorage.setItem("vpngate_page", name);
  // ---- 拆分后的显隐控制 ----
  var homeBlocks = document.getElementById("home_egress_blocks");
  var egressBlocks = document.getElementById("egress_status_blocks");
  var egressNodeSection = document.getElementById("egress_node_section");
  // 主页专用 DOM
  if (homeBlocks) homeBlocks.style.display = (name === "overview") ? "flex" : "none";
  // 出站管理专用 DOM
  if (egressBlocks) egressBlocks.style.display = (name === "egress") ? "flex" : "none";
  if (egressNodeSection) egressNodeSection.style.display = "none"; // 由 renderEgressNodeList 自行控制
  // 数据加载
  if (name === "egress") loadEgress();
  else if (name === "overview") loadHomeEgress();
}

async function doRefreshNodes(){ 
  const el=$("sidebar_refresh");
  if (el.dataset.refreshing === "true") return;
  el.dataset.refreshing = "true";
  el.style.pointerEvents="none"; 
  el.style.opacity="0.6"; 
  el.innerHTML = `<svg style="animation: spin 1s linear infinite;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg> 更新中...`;
  showRefreshOverlay("正在更新节点，请稍候…");
  try{
    const beforeRefresh = state.last_refresh_at || 0;
    const resp = await fetchWithCsrf("./api/refresh_nodes",{method:"POST"});
    if (resp && resp.ok) {
      const startTime = Date.now();
      while (Date.now() - startTime < 300000) {
        await new Promise(r => setTimeout(r, 2000));
        try {
          // 后端没有 /api/status，/api/nodes 会同时返回 nodes 与 state
          const status = await fetchWithCsrf("./api/nodes");
          const st = (status && status.state) ? status.state : {};
          const ra = st.last_refresh_at || 0;
          if (ra > beforeRefresh) {
            if (st.last_fetch_status === "error") {
              setRefreshOverlayText("更新失败，请稍后重试");
              await new Promise(r => setTimeout(r, 2200));
              break;
            }
            const added = st.last_fetch_added || 0;
            setRefreshOverlayText("更新完成，新增 " + added + " 个节点，正在刷新网页…");
            await new Promise(r => setTimeout(r, 1600));
            await load(); // 自动刷新网页，呈现最新节点列表
            break;
          }
        } catch(e) {}
      }
    }
  } catch(e){}
  hideRefreshOverlay();
  el.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg> 更新节点`;
  el.dataset.refreshing = "false";
  el.style.pointerEvents=""; 
  el.style.opacity="";
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetchWithCsrf("./api/test_proxy", { method: "POST" });
    const result = response;
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

let showFavoritesOnly = false;

function toggleFavoritesView() {
  showFavoritesOnly = !showFavoritesOnly;
  currentPage = 1;
  render();
}

function updateFavPanelUI() {
  const panel = $("favorites_panel");
  if (!panel) return;
  panel.style.display = showFavoritesOnly ? "block" : "none";
  
  const btn = $("btn_favorites");
  if (btn) {
    if (showFavoritesOnly) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }

  if (showFavoritesOnly && state) {
    const fallbackCheckbox = $("fav_fail_fallback_checkbox");
    if (fallbackCheckbox) {
      fallbackCheckbox.checked = !!state.fav_fail_fallback;
    }
    
    const warningDiv = $("fav_fallback_warning");
    if (warningDiv) {
      warningDiv.style.display = state.fav_fail_fallback ? "none" : "block";
    }

    const favRoutingBtn = $("btn_toggle_fav_routing");
    if (favRoutingBtn) {
      if (state.routing_mode === "favorites") {
        favRoutingBtn.textContent = "禁用仅用收藏出站";
        favRoutingBtn.style.background = "var(--danger-gradient)";
        favRoutingBtn.style.borderColor = "transparent";
        favRoutingBtn.style.color = "#ffffff";
        favRoutingBtn.style.boxShadow = "0 0 12px rgba(244, 63, 94, 0.3)";
      } else {
        favRoutingBtn.textContent = "启用仅用收藏出站";
        favRoutingBtn.style.background = "#f1f5f9";
        favRoutingBtn.style.borderColor = "var(--border-color)";
        favRoutingBtn.style.color = "var(--text-primary)";
        favRoutingBtn.style.boxShadow = "none";
      }
    }
  }
}

async function toggleFavRouting() {
  if (!state) return;
  const newMode = state.routing_mode === "favorites" ? "auto" : "favorites";
  
  state.routing_mode = newMode;
  updateFavPanelUI();
  
  try {
    const res = await fetchWithCsrf("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: newMode,
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: state.fav_fail_fallback !== false
      })
    });
    if (res.ok) {
      load();
    } else {
      alert("更新出站路由设置失败: " + (res.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败: " + (err.message || "请稍后重试"));
    load();
  }
}

async function handleFavFallbackChange(checked) {
  if (!state) return;
  
  if (!checked) {
    alert("⚠️ 警告：不勾选此项可能在所有收藏节点失效时造成网络彻底断开连接，无法自动切换到其他非收藏的可用节点！");
  }
  
  state.fav_fail_fallback = checked;
  updateFavPanelUI();
  
  try {
    const res = await fetchWithCsrf("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: state.routing_mode || "auto",
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: checked
      })
    });
    if (res.ok) {
      load();
    } else {
      alert("更新失败: " + (res.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败: " + (err.message || "请稍后重试"));
    load();
  }
}

function selectOptionCard(groupName, value) {
  if (groupName === 'routing_mode') {
    const input = $("net_routing_mode");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_mode_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
    
    handleRoutingModeChange(value);
  } else if (groupName === 'routing_ip_type') {
    const input = $("net_routing_ip_type");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_ip_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  } else if (groupName === 'upstream_type') {
    const input = $("net_upstream_type");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#upstream_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  }
}

function setRoutingMode(value) {
  selectOptionCard('routing_mode', value);
}

function setRoutingIpType(value) {
  selectOptionCard('routing_ip_type', value);
}

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");
  
  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定地区</strong>：限制仅连接选定国家的节点，且后台仅并发测速该国家的节点。如果该国的所有可用节点都失效，会造成代理中断且<strong>绝不自动切换到其他国家</strong>的节点。`;
  } else if (mode === "favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>仅用收藏</strong>：只连接和切换您收藏的节点。如果所有收藏的节点均失效，系统不会自动切换到未收藏的节点。请确保收藏列表中有足够多且可用的节点。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页 of 节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "var(--surface)";
    warningDiv.style.border = "1px solid var(--border)";
    warningDiv.innerHTML = `ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  const countMap = {};
  nodes.forEach(n => {
    const c = translateCountry(n.country);
    if (c) {
      countMap[c] = (countMap[c] || 0) + 1;
    }
  });
  
  const countries = Object.keys(countMap).sort();
  let html = '<option value="">请选择要锁定的国家...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} (${countMap[c]}个节点)</option>`;
  });
  select.innerHTML = html;
  
  if (state) {
    select.value = state.force_country ? translateCountry(state.force_country) : "";
  }
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
    $("cred_password").value = "";
    $("cred_port").value = state.port || 8790;
    $("cred_suffix").value = state.secret_path || "";
  }
  $("credentials_modal").style.display = "flex";
}

function closeCredentialsModal() {
  $("credentials_modal").style.display = "none";
}

let netEgressList = [];
async function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();

  // 性能优化：弹窗立即打开（不等数据返回），避免点击后无响应。所有数据加载放后台。
  $("network_modal").style.display = "flex";

  // 1) 加载国家列表（用全局缓存的 nodes，避免再请求 /api/nodes 拉 300+ 节点）。
  // fetchWithCsrf 内部已经 await resp.json() 并直接返回解析后的数据，不要再 .json()。
  const fc = $("net_force_country");
  if (fc) {
    const countries = [];
    (nodes || []).forEach(function(n) { if (n.country && countries.indexOf(n.country) < 0) countries.push(n.country); });
    fc.innerHTML = "<option value=''>不锁定（自动选最快）</option>" + countries.map(function(c) { return "<option value='" + c + "'>" + c + "</option>"; }).join("");
  }

  // 2) 出口列表：先展示已缓存的（若有），再后台刷新。重复打开弹窗可立即响应。
  populateEgressDropdown();
  if (netEgressList.length) {
    if ($("net_egress") && !$("net_egress").value) $("net_egress").value = "__default__";
    setNetEgress();
  }
  try {
    const data = await fetchWithCsrf("./api/egress_status_all");
    netEgressList = (data.egress || []);
    populateEgressDropdown();
    if (!$("net_egress").value) $("net_egress").value = "__default__";
    setNetEgress();
  } catch (e) { console.error(e); }
}

function populateEgressDropdown() {
  const sel = $("net_egress");
  if (!sel) return;
  if (!netEgressList.length) {
    sel.innerHTML = "<option value='__default__'>默认出口（7928）</option>";
    return;
  }
  sel.innerHTML = netEgressList.map(function(e) {
    const label = e.is_default
      ? "默认出口（" + (e.proxy_port || 7928) + "）"
      : (e.name + "（端口 " + e.proxy_port + "）") + (e.alive === false ? "（离线）" : "");
    return "<option value='" + e.slot_id + "'>" + label + "</option>";
  }).join("");
  if (!sel.value) sel.value = "__default__";
}

function setNetEgress() {
  const sel = $("net_egress");
  const slotId = sel ? sel.value : "__default__";
  const e = netEgressList.find(function(x) { return x.slot_id === slotId; }) || {};

  // 路由模式
  const rm = e.routing_mode || "auto";
  $("net_routing_mode").value = rm;
  document.querySelectorAll("#routing_mode_group .option-card").forEach(function(c) {
    c.classList.toggle("active", c.getAttribute("data-value") === rm);
  });
  handleRoutingModeChange(rm);

  // 锁定国家
  const fcEl = $("net_force_country");
  if (fcEl) fcEl.value = e.force_country || "";

  // IP 类型
  const ip = e.routing_ip_type || "all";
  $("net_routing_ip_type").value = ip;
  setRoutingIpType(ip);

  // 健康度阈值
  const mhs = e.min_health_score || 0;
  const mhEl = $("net_min_health");
  if (mhEl) mhEl.value = mhs;
  const lbl = $("health_score_label");
  if (lbl) lbl.textContent = mhs > 0 ? "≥ " + mhs + " 分" : "不限";

  // 上游代理（全局，所有出口共用节点池，故从 state 读取）
  const up = (state && state.upstream_proxy) || {};
  $("net_upstream_enabled").checked = !!up.enabled;
  toggleUpstreamFields();
  if (up.enabled) {
    $("net_upstream_type").value = up.type || "socks";
    setUpstreamType(up.type || "socks");
    $("net_upstream_host").value = up.host || "";
    $("net_upstream_port").value = up.port || 0;
    $("net_upstream_user").value = up.user || "";
    $("net_upstream_pass").value = up.pass || "";
  }

  // 端口（仅展示，不可改）
  $("net_proxy_port").value = e.proxy_port || 7928;

  // 子出口运行状态提示：在线/离线/崩溃 + 日志路径 + 重启按钮
  const st = $("net_egress_status");
  if (!st) return;
  if (e.is_default) {
    st.style.display = "none";
    st.innerHTML = "";
    return;
  }
  st.style.display = "block";
  const alive = e.alive !== false;
  const crashed = !!e.crashed;
  const logPath = e.log_path || "";
  if (alive) {
    st.style.background = "rgba(16,185,129,0.1)";
    st.style.border = "1px solid rgba(16,185,129,0.25)";
    st.style.color = "var(--success)";
    st.innerHTML = "● 该出口子进程运行中（端口 " + (e.proxy_port || "?") + "）。";
  } else if (crashed) {
    st.style.background = "rgba(244,63,94,0.1)";
    st.style.border = "1px solid rgba(244,63,94,0.25)";
    st.style.color = "var(--danger)";
    st.innerHTML = "⚠ 该出口子进程已崩溃（配置已保留）。" +
      (logPath ? "<br>日志：" + esc(logPath) : "") +
      "<br><a href=\"javascript:void(0)\" onclick=\"restartEgress('" + escAttr(e.slot_id) + "')\" style=\"color:var(--primary);font-weight:600;\">点此重启该出口</a>";
  } else {
    st.style.background = "rgba(245,158,11,0.1)";
    st.style.border = "1px solid rgba(245,158,11,0.25)";
    st.style.color = "#b45309";
    st.innerHTML = "○ 该出口子进程尚未运行（配置已保留，稍候将自动拉起）。" +
      (logPath ? "<br>日志：" + esc(logPath) : "") +
      "<br><a href=\"javascript:void(0)\" onclick=\"restartEgress('" + escAttr(e.slot_id) + "')\" style=\"color:var(--primary);font-weight:600;\">点此立即重启</a>";
  }
}

async function restartEgress(slotId) {
  if (!slotId || slotId === "__default__") {
    showToast("无法重启：出口 ID 为空", "error");
    return;
  }
  showToast("正在重启出口 " + slotId + "…", "info");
  try {
    const data = await fetchWithCsrf("./api/egress_restart", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slot_id: slotId }),
    });
    if (data && data.ok) {
      showToast("✓ 出口 " + slotId + " 已触发重启，稍候刷新状态", "success");
      // 重新拉取状态并刷新卡片、下拉框与提示
      try {
        const s = await fetchWithCsrf("./api/egress_status_all");
        netEgressList = (s.egress || []);
        populateEgressDropdown();
        setNetEgress();
      } catch (e2) { console.error(e2); }
      // 出站管理页：刷新卡片列表
      try {
        if (typeof loadEgress === "function") { await loadEgress(); }
      } catch (e3) { console.error(e3); }
    } else {
      const msg = (data && data.error) || "未知错误";
      showToast("重启出口 " + slotId + " 失败：" + msg, "error");
      // 同步失败后也把后端返回的错误写到弹窗状态区（兼容旧入口）
      const st = $("net_egress_status");
      if (st) { st.innerHTML = "<span style='color:#dc2626'>重启失败：" + esc(msg) + "</span>"; }
    }
  } catch (err) {
    const msg = (err && err.message) ? err.message : String(err);
    showToast("重启请求失败：" + msg, "error");
    const st = $("net_egress_status");
    if (st) { st.innerHTML = "<span style='color:#dc2626'>重启请求失败：" + esc(msg) + "</span>"; }
  }
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
}

function toggleUpstreamFields() {
  const enabled = $("net_upstream_enabled").checked;
  $("upstream_proxy_fields").style.display = enabled ? "block" : "none";
}

function openIntelModal() {
  const m = $("intel_modal");
  if (!m) return;
  m.style.display = "flex";
  const pc = (state && state.proxycheck) || {};
  const enabledEl = $("intel_enabled");
  if (enabledEl) {
    enabledEl.checked = !!pc.enabled;
    toggleIntelFields();
  }
  // 自部署：把已保存的密钥回显出来，方便核对是否填对
  const keyEl = $("intel_key");
  if (keyEl) keyEl.value = pc.api_key || "";
  const clearedEl = $("intel_key_cleared");
  if (clearedEl) clearedEl.value = "0";
  const hint = $("intel_key_hint");
  if (hint) {
    hint.textContent = pc.key_set
      ? "已保存的密钥显示在上方，可直接核对；清空后保存即删除。"
      : "留空则匿名调用免费额度（约 100 次/天）。";
  }
  const err = $("intel_error");
  const suc = $("intel_success");
  if (err) err.style.display = "none";
  if (suc) suc.style.display = "none";
}

function closeIntelModal() {
  $("intel_modal").style.display = "none";
}

function toggleIntelFields() {
  const el = $("intel_enabled");
  const box = $("intel_fields");
  if (el && box) box.style.display = el.checked ? "block" : "none";
}

function clearIntelKey() {
  const clearedEl = $("intel_key_cleared");
  const keyEl = $("intel_key");
  const hint = $("intel_key_hint");
  if (clearedEl) clearedEl.value = "1";
  if (keyEl) keyEl.value = "";
  if (hint) hint.textContent = "保存后将清除已存密钥，改为匿名调用。";
}

async function saveIntel(e) {
  e.preventDefault();
  const errorDivEl = $("intel_error");
  const successDiv = $("intel_success");
  const submitBtn = $("intel_submit_btn");

  errorDivEl.style.display = "none";
  successDiv.style.display = "none";

  const enabledEl = $("intel_enabled");
  const keyEl = $("intel_key");
  const clearedEl = $("intel_key_cleared");
  const proxycheck = {
    enabled: !!(enabledEl && enabledEl.checked),
    api_key: (keyEl && keyEl.value || "").trim(),
    key_cleared: !!(clearedEl && clearedEl.value === "1")
  };

  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";

  try {
    const res = await fetchWithCsrf("./api/save_proxycheck", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proxycheck: proxycheck })
    });

    if (res && res.ok) {
      successDiv.textContent = (res.message || "配置保存成功") + "，已即时生效！";
      successDiv.style.display = "block";
      // 同步本地 state，避免关闭再打开时回显滞后
      if (state) {
        state.proxycheck = {
          enabled: proxycheck.enabled,
          api_key: proxycheck.key_cleared ? "" : proxycheck.api_key,
          key_set: proxycheck.key_cleared ? false : !!proxycheck.api_key
        };
      }
      setTimeout(closeIntelModal, 1200);
    } else {
      errorDivEl.textContent = (res && res.error) || "保存失败，请重试";
      errorDivEl.style.display = "block";
    }
  } catch (err) {
    errorDivEl.textContent = "网络错误：" + (err && err.message ? err.message : err);
    errorDivEl.style.display = "block";
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "保存";
  }
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const username = $("cred_username").value.trim();
  const password = $("cred_password").value.trim();
  const port = parseInt($("cred_port").value);
  const suffix = $("cred_suffix").value.trim();
  
  if (!username || (!password && !(state && state.password_set))) {
    errorDivEl.textContent = "用户名不能为空；首次设置时密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (state && port === state.proxy_port) {
    errorDivEl.textContent = "网页管理端口不能与代理出站端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetchWithCsrf("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        password: password,
        port: port,
        secret_path: suffix
      })
    });
    
    if (res.ok) {
      if (res.restart_needed) {
        successDiv.textContent = "保存成功！网页管理端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";
        
        const inputs = $("credentials_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = window.location.hostname;
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = res.reauth_required ? "账号密码保存成功，请重新登录..." : "账号密码保存成功，已即时生效！";
        successDiv.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.textContent = "保存修改";
        setTimeout(() => {
          if (res.reauth_required) {
            window.location.reload();
          } else {
            closeCredentialsModal();
            load();
          }
        }, 1500);
      }
    } else {
      errorDivEl.textContent = res.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = err.message || "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");

  errorDivEl.style.display = "none";
  successDiv.style.display = "none";

  const slotId = ($("net_egress") && $("net_egress").value) || "__default__";
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  const routingIpType = $("net_routing_ip_type").value;
  const minHealthScore = parseInt($("net_min_health").value) || 0;

  const upstreamEnabled = $("net_upstream_enabled").checked;
  const upstreamType = $("net_upstream_type").value;
  const upstreamHost = ($("net_upstream_host").value || "").trim();
  const upstreamPort = parseInt($("net_upstream_port").value) || 0;
  const upstreamUser = ($("net_upstream_user").value || "").trim();
  const upstreamPass = ($("net_upstream_pass").value || "").trim();

  if (upstreamEnabled) {
    if (!upstreamHost) {
      errorDivEl.textContent = "请输入上游代理地址";
      errorDivEl.style.display = "block";
      return;
    }
    if (!upstreamPort || upstreamPort < 1 || upstreamPort > 65535) {
      errorDivEl.textContent = "上游代理端口范围必须在 1 至 65535 之间";
      errorDivEl.style.display = "block";
      return;
    }
  }

  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";

  try {
    const res = await fetchWithCsrf("./api/egress_save_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        slot_id: slotId,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType,
        min_health_score: minHealthScore,
        upstream_proxy: upstreamEnabled ? {
          enabled: true,
          type: upstreamType,
          host: upstreamHost,
          port: upstreamPort,
          user: upstreamUser,
          pass: upstreamPass
        } : { enabled: false }
      })
    });

    if (res && res.ok) {
      successDiv.textContent = (res.message || "配置保存成功") + "，已即时生效！";
      successDiv.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
      setTimeout(() => {
        closeNetworkModal();
        if (typeof load === "function") load();
        // 同时刷新主页和出站管理页
        if (typeof loadHomeEgressStatus === "function") loadHomeEgressStatus();
        if (typeof loadEgress === "function") loadEgress();
      }, 1200);
    } else {
      errorDivEl.textContent = (res && res.error) || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = (err && err.message) || "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}


async function logoutAdmin() {
  try {
    const res = await fetchWithCsrf("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && !state.is_connecting && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const d = await fetchWithCsrf("./api/nodes");
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
      // 主页活动节点卡 + 主页卡片（与 render 解耦）
      if (typeof renderHomeActiveNodeCard === "function") renderHomeActiveNodeCard(homeSelectedEgressSlotId || "__default__");
      if (typeof loadHomeEgress === "function") {
        try { await loadHomeEgress(); } catch (e) {}
      }
    } catch(e) {}
  }
}, 10000);

// 同样每 10 秒刷一次出口状态（含子出口健康/连接摘要），让主页/出站管理顶部的
// 活动节点卡在用户未点击卡片时也能动态反映所选出口的真实状态。
// 主页和出站管理各刷各的，互不干扰。
setInterval(async () => {
  if (typeof state !== "undefined" && document.visibilityState === "visible") {
    if (typeof loadHomeEgress === "function") {
      try { await loadHomeEgress(); } catch(e) {}
    }
    if (typeof loadEgress === "function") {
      try { await loadEgress(); } catch(e) {}
    }
  }
}, 10000);
let gatewayPollInterval = null;

function openGatewayModal() {
  $("gateway_modal").style.display = "flex";
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  $("gateway_modal").style.display = "none";
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  try {
    const res = await fetchWithCsrf("./api/gateway_status");
    if (res.ok && res.services) {
      renderGatewayServices(res.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;
  
  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';
    
    html += `
      <div style="background: var(--surface-2); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            ⚠️ 诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  container.innerHTML = html;
}

let logsPollInterval = null;
let rawLogsCache = [];

function openLogsModal() {
  $("logs_modal").style.display = "flex";
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 5000);
}

function closeLogsModal() {
  $("logs_modal").style.display = "none";
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  try {
    const res = await fetchWithCsrf("./api/logs");
    if (res.logs) {
      rawLogsCache = res.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  }
}

let lastRenderedLogKey = "";
function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;
  
  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }
  
  const renderKey = filterVal + "|" + (filtered.length > 0 ? filtered[filtered.length - 1].timestamp + filtered[filtered.length - 1].message : "");
  if (renderKey === lastRenderedLogKey) return;
  lastRenderedLogKey = renderKey;
  
  if (filtered.length === 0) {
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`;
    return;
  }
  
  const linesHtml = filtered.map(l => {
    let color = "#a5b4fc";
    if (l.module === "Proxy") color = "#38bdf8";
    if (l.module === "VPN") color = "#34d399";
    if (l.level === "WARNING") color = "#fbbf24";
    if (l.level === "ERROR") color = "#f43f5e";
    
    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");
  
  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;
  
  term.innerHTML = linesHtml;
  
  if (isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;

  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }

  function fallbackCopy() {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.top = "0";
      ta.style.left = "0";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      alert(ok ? "日志内容已复制到剪贴板！" : "复制失败，请手动选中日志后按 Ctrl+C 复制。");
    } catch (e) {
      console.error("复制失败", e);
      alert("复制失败，请手动选中日志后按 Ctrl+C 复制。");
    }
  }

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        alert("日志内容已成功复制到剪贴板！");
      }).catch(fallbackCopy);
    } else {
      fallbackCopy();
    }
  } catch (e) {
    fallbackCopy();
  }
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }
  
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
URL.revokeObjectURL(url);
}

// 页面初始化
(function(){
  // 进站强制着陆主页（overview）：不再依赖 localStorage 记录的上次位置。
  // 之前若上次停留在 egress 页，刷新/进站会直跳 egress 页，而此时
  // loadEgress() 尚未拿到数据（API 未就绪或列表为空），导致呈现空白界面。
  // 固定从主页进入，主页数据 loadHomeEgress() 在 switchPage 内被调用，进站即有内容。
  switchPage("overview");
})();

// 主题初始化
(function(){
  var saved = localStorage.getItem(THEME_KEY) || 'light';
  setTheme(saved);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(){
    if (localStorage.getItem(THEME_KEY) === 'system') {
      setTheme('system');
    }
  });
})();

</script>


</main>
</div>

<!-- 轻量级 Toast 容器：连接/断开等操作的结果提示统一在这里非阻塞展示，
     不再用 alert() 弹窗（避免"假报错"——连接实际成功却先弹了报错窗）。 -->
<div id="toast_container" style="position:fixed; top:18px; right:18px; z-index:2000; display:flex; flex-direction:column; gap:10px; max-width:340px;"></div>

</body></html>"""

def session_cleanup_loop() -> None:
    while True:
        time.sleep(SESSION_CLEANUP_INTERVAL)
        _cleanup_expired_sessions()
        _cleanup_expired_csrf_tokens()
        _cleanup_login_attempts()
