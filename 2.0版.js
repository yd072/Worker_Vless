
import { connect } from "cloudflare:sockets";
const PLACEHOLDER_HOST = 'example.com';
const PLACEHOLDER_UUID = '00000000-0000-4000-0000-000000000000';
const WS_PATH = '/api/ws';
const RANDOM_NODE_COUNT = 10;
const FILENAME = 'subscription';
const CF_IPS_CIDR = [ '104.16.0.0/14', '104.21.0.0/16', '104.24.0.0/14', '8.35.211.0/23', '8.39.125.0/24' ];
const selectableHttpsPorts = ["443", "8443", "2053", "2083", "2087", "2096"];
const selectableHttpPorts = ["80", "8080", "8880", "2052", "2082", "2086","2095"];

async function generateUUIDFromPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashBytes = new Uint8Array(hashBuffer).slice(0, 16);
    hashBytes[6] = (hashBytes[6] & 0x0f) | 0x50;
    hashBytes[8] = (hashBytes[8] & 0x3f) | 0x80;
    const hex = Array.from(hashBytes, b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function generateFakeInfo(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + "-fake-seed-for-converter");
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const fakePassword = hashHex.slice(0, 32);
    const fakeHost = `${hashHex.slice(32, 38)}.${hashHex.slice(38, 46)}.com`;
    return { fakePassword, fakeHost };
}

function setupMissingVarsPage() {
    const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>初始设置</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background-color: #f0f2f5;
            }
            .container {
                text-align: left;
                background: white;
                padding: 2rem 3rem;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                max-width: 600px;
            }
            h1 { color: #333; }
            p { color: #555; }
            code {
                background: #eee;
                padding: 3px 6px;
                border-radius: 4px;
                font-family: monospace;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>初始设置</h1>
            <p>请在您的 Cloudflare Worker 设置中添加以下环境变量：</p>
            <ul>
                <li><strong>PASSWORD</strong>: 一个用于访问订阅链接和管理页面的密码。</li>
                <li><strong>KV (可选)</strong>: 绑定一个 KV 命名空间 (变量名为 <code>KV</code>) 以启用在线优选IP/域名管理功能。</li>
            </ul>
            <p>您的用户 UUID 将从此密码自动并确定性地生成。</p>
        </div>
    </body>
    </html>`;
    return new Response(html, { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function loginPage(error = null) {
    const errorMessage = error ? `<p class="error-message">${error}</p>` : '';
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Authentication</title>
        <style>
            :root {
                --primary-color: #007bff;
                --hover-color: #0056b3;
                --background-color: #f4f7f9;
                --card-background-color: #ffffff;
                --text-color: #333;
                --border-color: #dee2e6;
                --error-color: #dc3545;
                --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            }
            body {
                margin: 0;
                font-family: var(--font-family);
                background-color: var(--background-color);
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
            }
            .container {
                background-color: var(--card-background-color);
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                width: 100%;
                max-width: 400px;
                box-sizing: border-box;
            }
            .header {
                text-align: center;
                margin-bottom: 25px;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
                color: var(--text-color);
            }
            .header p {
                margin: 5px 0 0;
                color: #6c757d;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group input {
                width: 100%;
                padding: 12px;
                font-size: 16px;
                border: 1px solid var(--border-color);
                border-radius: 6px;
                box-sizing: border-box;
                transition: border-color 0.2s, box-shadow 0.2s;
            }
            .form-group input:focus {
                outline: none;
                border-color: var(--primary-color);
                box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.25);
            }
            .btn {
                width: 100%;
                padding: 12px;
                font-size: 16px;
                font-weight: 600;
                color: #fff;
                background-color: var(--primary-color);
                border: none;
                border-radius: 6px;
                cursor: pointer;
                transition: background-color 0.2s;
            }
            .btn:hover {
                background-color: var(--hover-color);
            }
            .error-message {
                color: var(--error-color);
                background-color: rgba(220, 53, 69, 0.1);
                border: 1px solid rgba(220, 53, 69, 0.2);
                border-radius: 6px;
                padding: 10px;
                margin-bottom: 20px;
                text-align: center;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Secure Authentication</h1>
                <p>Please enter your password to continue</p>
            </div>
            <form method="POST" action="/login">
                ${errorMessage}
                <div class="form-group">
                    <input type="password" name="password" placeholder="Access Password" required autofocus>
                </div>
                <button type="submit" class="btn">Authorize Access</button>
            </form>
        </div>
    </body>
    </html>`;
    return new Response(html, { status: error ? 401 : 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function statusPage() {
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Service Status - Analytics</title>
        <link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI0ZGRiI+PHBhdGggZD0iTTAgMGgyNHYyNEgweiIgZmlsbD0ibm9uZSIvPjxwYXRoIGQ9Ik05IDE2LjE3TDQuODMgMTJsLTEuNDIgMS40MUw5IDE5IDIxIDdsLTEuNDEtMS40MXoiIGZpbGw9IiMyZGNlODkiLz48L3N2Zz4=">
        <style>
            :root {
                --bg-color: #f4f7f9;
                --card-bg-color: #ffffff;
                --text-color: #333;
                --primary-color: #0d6efd;
                --secondary-color: #8898aa;
                --border-color: #e9ecef;
                --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            }
            body {
                margin: 0;
                font-family: var(--font-family);
                background-color: var(--bg-color);
                color: var(--text-color);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
                box-sizing: border-box;
            }
            .container {
                max-width: 800px;
                width: 100%;
                background-color: var(--card-bg-color);
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                padding: 40px;
                box-sizing: border-box;
            }
            .header {
                border-bottom: 1px solid var(--border-color);
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
            .header h1 { margin: 0; font-size: 24px; }
            .header .all-systems-operational { color: var(--primary-color); font-size: 18px; font-weight: 600; margin-top: 10px; }
            .service-group h2 { font-size: 18px; color: var(--text-color); margin-bottom: 15px; }
            .service-item { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid var(--border-color); }
            .service-item:last-child { border-bottom: none; }
            .service-name { font-size: 16px; }
            .service-status { font-size: 16px; font-weight: 600; color: var(--primary-color); }
            .footer { margin-top: 30px; text-align: center; font-size: 14px; color: var(--secondary-color); }
            .footer a { color: var(--secondary-color); text-decoration: none; }
            .footer a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Service Status</h1>
                <div class="all-systems-operational">✔ All Systems Operational</div>
        </div>
            <div class="service-group">
                <h2>Backend Infrastructure</h2>
                <div class="service-item"><span class="service-name">API Gateway</span><span class="service-status">Operational</span></div>
                <div class="service-item"><span class="service-name">Authentication Service</span><span class="service-status">Operational</span></div>
                <div class="service-item"><span class="service-name">Storage Cluster</span><span class="service-status">Operational</span></div>
            </div>
            <div class="service-group" style="margin-top: 30px;">
                <h2>Real-time Data Services</h2>
                <div class="service-item"><span class="service-name">WebSocket Push Service</span><span class="service-status">Operational</span></div>
                <div class="service-item"><span class="service-name">Real-time Data Pipeline</span><span class="service-status">Operational</span></div>
            </div>
            <div class="footer">
                <!-- HTML 修改 -->
                <p>
                    Last Updated:
                    <span id="date-container"></span>
                    <span id="time-container" class="notranslate"></span>
                </p>
                <p><a href="/login">Admin Login</a></p>
            </div>
        </div>
        <!-- JavaScript 修改 -->
        <script>
            let lastDate = '';
            function updateTimestamp() {
                const now = new Date();
                const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
                const currentDate = now.toLocaleDateString('en-US', dateOptions);
                if (currentDate !== lastDate) {
                    document.getElementById('date-container').textContent = currentDate;
                    lastDate = currentDate;
                }
                const hours = String(now.getHours()).padStart(2, '0');
                const minutes = String(now.getMinutes()).padStart(2, '0');
                const seconds = String(now.getSeconds()).padStart(2, '0');
                const currentTimeString = ' ' + hours + ':' + minutes + ':' + seconds;
                document.getElementById('time-container').textContent = currentTimeString;
                }
            setInterval(updateTimestamp, 1000);
            updateTimestamp();
        </script>
    </body>
    </html>`;
    return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function subscriptionManagementPage(request, password, uuid, settings, error = null, isKvBound = false) {
    const hostName = new URL(request.url).hostname;
    const userAgent = request.headers.get('User-Agent') || 'N/A';

    const messageHtml = error ? `<div class="message error">${error}</p>` : '';

    let advancedSections = '';
    if (isKvBound) {
        const { apiUrls = '', apiUrlsWithCustomPorts = '', selectedHttpsPorts = [], selectedHttpPorts = [], subConverter = '', subConfig = '' } = settings;

        const httpsPortCheckboxes = selectableHttpsPorts.map(port => `
            <div class="port-checkbox">
                <input type="checkbox" id="port_https_${port}" name="selected_https_ports" value="${port}" ${selectedHttpsPorts.includes(port) ? 'checked' : ''}>
                <label for="port_https_${port}">${port}</label>
            </div>`).join('');
        const httpPortCheckboxes = selectableHttpPorts.map(port => `
            <div class="port-checkbox">
                <input type="checkbox" id="port_http_${port}" name="selected_http_ports" value="${port}" ${selectedHttpPorts.includes(port) ? 'checked' : ''}>
                <label for="port_http_${port}">${port}</label>
            </div>`).join('');

        advancedSections = `
            <div class="section">
                <div class="section-header"><h2 class="section-title">🔄 订阅转换设置</h2></div>
                <form method="POST" action="/${password}">
                    <input type="hidden" name="form_action" value="update_sub_settings">
                    <div class="modal-input-group">
                        <label for="sub_converter">订阅转换器地址</label>
                        <input type="text" id="sub_converter" name="sub_converter" value="${subConverter || ''}" placeholder="默认: SUBAPI.cmliussss.net">
                    </div>
                    <div class="modal-input-group">
                        <label for="sub_config">订阅转换器配置</label>
                        <input type="text" id="sub_config" name="sub_config" value="${subConfig || ''}" placeholder="默认: https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini">
                    </div>
                    <div class="form-footer"><button type="submit" class="copy-button">保存</button></div>
                </form>
            </div>
            <div class="section">
                <div class="section-header"><h2 class="section-title">🌐 优选源 (常规)</h2></div>
                <form method="POST" action="/${password}">
                    <input type="hidden" name="form_action" value="update_api_urls">
                    <div class="modal-input-group">
                        <label for="api_urls">常规源 (每行一个)</label>
                        <textarea id="api_urls" name="api_urls" rows="4" placeholder="每行一个，可以是 API 链接、优选域名或 IP 地址">${apiUrls}</textarea>
                    </div>
                    <div class="form-footer"><button type="submit" class="copy-button">保存</button></div>
                </form>
            </div>
            <div class="section">
                <div class="section-header"><h2 class="section-title">端口优选源 (应用选择的端口)</h2></div>
                <form method="POST" action="/${password}">
                    <input type="hidden" name="form_action" value="update_custom_api_urls">
                     <div class="modal-input-group">
                        <label>选择要应用的端口</label>
                        <div class="port-group-title">HTTPS 端口</div>
                        <div class="port-checkbox-group">${httpsPortCheckboxes}</div>
                        <div class="port-group-title">HTTP 端口</div>
                        <div class="port-checkbox-group">${httpPortCheckboxes}</div>
                    </div>
                    <div class="modal-input-group">
                        <label for="api_urls_custom_ports">IP/域名/API (每行一个, 无需端口)</label>
                        <textarea id="api_urls_custom_ports" name="api_urls_custom_ports" rows="4" placeholder="在此处输入 IP、域名或 API 链接">${apiUrlsWithCustomPorts}</textarea>
                    </div>
                    <div class="form-footer"><button type="submit" class="copy-button">保存</button></div>
                </form>
            </div>`;
    }

    const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>服务信息</title>
        <style>
            :root {
                --primary-color: #0d6efd;
                --secondary-color: #0b5ed7;
                --border-color: #e0e0e0;
                --text-color: #212529;
                --background-color: #f5f5f5;
                --section-bg: #ffffff;
                --error-color: #dc3545;
            }
            body {
                margin: 0;
                padding: 20px;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                line-height: 1.6;
                color: var(--text-color);
                background-color: var(--background-color);
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background: var(--section-bg);
                padding: 25px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .section {
                margin-bottom: 20px;
                padding: 20px;
                background: var(--section-bg);
                border-radius: 8px;
                border: 1px solid var(--border-color);
            }
            .section:last-child {
                margin-bottom: 0;
            }
            .section-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 2px solid var(--border-color);
            }
            .section-title {
                font-size: 1.2em;
                color: var(--text-color);
                margin: 0;
            }
            .header-button {
                padding: 6px 14px;
                background: var(--primary-color);
                color: #fff;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                text-decoration: none;
            }
            .header-button:hover {
                background: var(--secondary-color);
            }
            .config-info {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 6px;
                font-family: Monaco, Consolas, "Courier New", monospace;
                font-size: 13px;
                overflow-x: auto;
                word-wrap: break-word;
                border: 1px solid #e0e0e0;
            }
            .copy-button {
                display: inline-block;
                padding: 8px 16px;
                background: var(--primary-color);
                color: #fff;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                transition: background-color 0.2s;
            }
            .copy-button:hover:not(:disabled) {
                background: var(--secondary-color);
            }
            .subscription-buttons-container {
                display: flex;
                flex-wrap: wrap;
                justify-content: center;
                gap: 10px;
                margin-top: 15px;
            }
            .modal {
                display: none;
                position: fixed;
                z-index: 1000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                overflow: auto;
                background-color: rgba(0,0,0,0.5);
            }
            .modal-content {
                background-color: var(--section-bg);
                margin: 5% auto;
                padding: 25px;
                border: 1px solid var(--border-color);
                width: 90%;
                max-width: 600px;
                border-radius: 8px;
                position: relative;
            }
            .close-button {
                color: #aaa;
                position: absolute;
                top: 10px;
                right: 15px;
                font-size: 28px;
                font-weight: bold;
                cursor: pointer;
            }
            .modal-input-group { margin-bottom: 15px; }
            .modal-input-group label { display: block; margin-bottom: 5px; font-weight: 500; }
            .modal-input-group input[type="text"],
            .modal-input-group textarea {
                width: 100%;
                padding: 8px;
                box-sizing: border-box;
                border-radius: 4px;
                border: 1px solid var(--border-color);
            }
            .checkbox-label-group {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 8px;
            }
            .checkbox-label-group label {
                margin: 0;
                cursor: pointer;
                font-weight: 500;
            }
            .port-group-title { font-weight: bold; margin: 10px 0 5px; }
            .port-checkbox-group {
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin-bottom: 15px;
                padding-left: 5px;
            }
            .port-checkbox { display: flex; align-items: center; gap: 5px; }
            .form-footer { text-align: right; margin-top: 15px; }
            #toast {
                visibility: hidden;
                min-width: 250px;
                background-color: #333;
                color: #fff;
                text-align: center;
                border-radius: 8px;
                padding: 16px;
                position: fixed;
                z-index: 10000;
                left: 50%;
                transform: translateX(-50%);
                top: 30px;
                font-size: 17px;
            }
            #toast.show {
                visibility: visible;
                animation: toast-fadein 0.5s, toast-fadeout 0.5s 2.5s;
            }
            @keyframes toast-fadein { from {top: 0; opacity: 0;} to {top: 30px; opacity: 1;} }
            @keyframes toast-fadeout { from {top: 30px; opacity: 1;} to {top: 0; opacity: 0;} }
            .message.error {
                color: var(--error-color);
                background-color: rgba(220, 53, 69, 0.1);
                border: 1px solid rgba(220, 53, 69, 0.2);
                padding: 15px;
                margin-bottom: 20px;
                border-radius: 6px;
                text-align: center;
                font-weight: 600;
            }
        </style>
    </head>
    <body>
        <div class="container">
            ${messageHtml}
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">🔌 订阅信息</h2>
                    <button class="header-button" id="customSubButton">自定义参数</button>
                </div>
                <div class="subscription-buttons-container">
                    <button class="copy-button" id="generic-sub-button">通用订阅</button>
                    <button class="copy-button" id="base64-sub-button">Base64</button>
                    <button class="copy-button" id="clash-sub-button">Clash </button>
                    <button class="copy-button" id="singbox-sub-button">SingBox</button>
                </div>
            </div>
             <div class="section">
                <div class="section-header"><h2 class="section-title">🔧 设置信息</h2></div>
                <div class="config-info">
                    HOST: ${hostName}<br>
                    UUID: ${uuid}<br>
                    UA: ${userAgent}
                </div>
            </div>
            ${advancedSections}
            <div id="toast"></div>
        </div>

        <div id="settingsModal" class="modal">
            <div class="modal-content">
                <span class="close-button" id="closeModalButton">&times;</span>
                <h2>自定义参数</h2>
                <div class="modal-input-group">
                    <div class="checkbox-label-group">
                        <input type="checkbox" id="enableSub">
                        <label for="enableSub">SUB 外部订阅域名</label>
                    </div>
                    <input type="text" id="subInput">
                </div>
                <div class="modal-input-group">
                    <div class="checkbox-label-group">
                        <input type="checkbox" id="enableProxyip">
                        <label for="enableProxyip">ProxyIP</label>
                    </div>
                    <input type="text" id="proxyipInput">
                </div>
                <div class="form-footer">
                    <button class="copy-button" id="applySettingsButton">保存</button>
                </div>
            </div>
        </div>

        <script>
            document.addEventListener('DOMContentLoaded', () => {
                const settingsKey = 'subSettings_${uuid}';
                const modal = document.getElementById('settingsModal');
                const openModalBtn = document.getElementById('customSubButton');
                const closeModalBtn = document.getElementById('closeModalButton');
                const applyBtn = document.getElementById('applySettingsButton');
                
                const genericBtn = document.getElementById('generic-sub-button');
                const base64Btn = document.getElementById('base64-sub-button');
                const clashBtn = document.getElementById('clash-sub-button');
                const singboxBtn = document.getElementById('singbox-sub-button');

                const settingsMap = {
                    sub: { enable: document.getElementById('enableSub'), input: document.getElementById('subInput') },
                    proxyip: { enable: document.getElementById('enableProxyip'), input: document.getElementById('proxyipInput') }
                };

                function showToast(message) {
                    const toast = document.getElementById("toast");
                    toast.textContent = message;
                    toast.className = "show";
                    setTimeout(() => {
                        toast.className = toast.className.replace("show", "");
                    }, 3000);
                }

                function copyToClipboard(text) {
                    navigator.clipboard.writeText(text)
                        .then(() => showToast('✅ 已复制到剪贴板'))
                        .catch(() => showToast('❌ 复制失败'));
                }
                
                function updateSubscriptionLinks() {
                    const settings = getSettings();
                    const baseUrl = window.location.href.split('?')[0];
                    const params = new URLSearchParams();
                    let isCustomized = false;
                    
                    for (const key in settings) {
                        if (settings[key].enabled && settings[key].value) {
                            params.set(key, settings[key].value);
                            isCustomized = true;
                        }
                    }
                    
                    const finalUrl = params.toString() ? \`\${baseUrl}?\${params.toString()}\` : baseUrl;
                    const separator = finalUrl.includes('?') ? '&' : '?';

                    genericBtn.onclick = () => copyToClipboard(finalUrl);
                    base64Btn.onclick = () => copyToClipboard(\`\${finalUrl}\${separator}base64\`);
                    clashBtn.onclick = () => copyToClipboard(\`\${finalUrl}\${separator}clash\`);
                    singboxBtn.onclick = () => copyToClipboard(\`\${finalUrl}\${separator}sb\`);
                    
                    openModalBtn.textContent = isCustomized ? '自定义参数 ✓' : '自定义参数';
                }

                function getSettings() {
                    const currentSettings = {};
                    for (const key in settingsMap) {
                        currentSettings[key] = {
                            enabled: settingsMap[key].enable.checked,
                            value: settingsMap[key].input.value.trim()
                        };
                    }
                    return currentSettings;
                }

                function saveSettings() {
                    localStorage.setItem(settingsKey, JSON.stringify(getSettings()));
                    showToast('🎉 设置已保存!');
                }

                function loadSettings() {
                    try {
                        const saved = localStorage.getItem(settingsKey);
                        if (saved) {
                            const settings = JSON.parse(saved);
                            for (const key in settings) {
                                if (settingsMap[key]) {
                                    settingsMap[key].enable.checked = settings[key].enabled || false;
                                    settingsMap[key].input.value = settings[key].value || '';
                                    settingsMap[key].input.disabled = !settings[key].enabled;
                                }
                            }
                        }
                    } catch (e) {
                        console.error("加载设置失败", e);
                    }
                    updateSubscriptionLinks();
                }

                for (const key in settingsMap) {
                    settingsMap[key].enable.addEventListener('change', (e) => {
                        settingsMap[key].input.disabled = !e.target.checked;
                    });
                }
                
                openModalBtn.onclick = () => { modal.style.display = 'block'; };
                closeModalBtn.onclick = () => { modal.style.display = 'none'; };
                window.onclick = (e) => { if (e.target == modal) { modal.style.display = 'none'; } };

                applyBtn.onclick = () => {
                    saveSettings();
                    updateSubscriptionLinks();
                    modal.style.display = 'none';
                };
                
                const urlParams = new URLSearchParams(window.location.search);
                if (urlParams.has('success')) {
                    showToast('🎉 设置已成功更新！');
                    const newUrl = window.location.pathname;
                    history.replaceState({}, document.title, newUrl);
                }
                
                loadSettings();
            });
        </script>
    </body>
    </html>`;
    return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8" } });
}


export default {
    async fetch(request, env) {
        const { PASSWORD, KV, APIURLS: ENV_APIURLS } = env;

        if (!PASSWORD) {
            return setupMissingVarsPage();
        }

        const AUTH_UUID = await generateUUIDFromPassword(PASSWORD);
        const { fakePassword, fakeHost } = await generateFakeInfo(PASSWORD);
        const url = new URL(request.url);
        
        const upgradeHeader = request.headers.get('Upgrade');
        if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
            const proxyIP = getProxyIPFromRequest(request);
            return await handleWebSocketConnection(request, AUTH_UUID, proxyIP);
        }

        const path = url.pathname;
        const userAgent = (request.headers.get('User-Agent') || '').toLowerCase();

        if (path === `/${fakePassword}`) {
            let settings = {};
            if (KV) {
                try {
                    const storedSettings = await KV.get("settings", "json");
                    if (storedSettings) settings = storedSettings;
                } catch (e) {
                     console.error(`KV 'settings' read/parse error for fake path: ${e}.`);
                }
            } else if (ENV_APIURLS) {
                settings.apiUrls = ENV_APIURLS;
            }
            
            const subDomain = url.searchParams.get('sub');
            if (subDomain) {
                return await fetchExternalSubscription(subDomain, AUTH_UUID, url.hostname, userAgent, url.searchParams);
            }

            const preferredDomains = await fetchPreferredDomains(settings);
            const randomNodes = generateRandomCFNodes(fakeHost, AUTH_UUID, url.searchParams, preferredDomains, settings.selectedHttpsPorts, settings.selectedHttpPorts);
            const subContent = generateClientConfig(randomNodes);
            const base64Sub = btoa(subContent);
            
            return new Response(base64Sub, { 
                headers: { 'Content-Type': 'text/plain;charset=utf-8' }
            });
        }

        if (path === '/') {
            return statusPage(); 
        }

        if (path === '/login') {
            if (request.method === 'POST') {
                try {
                    const formData = await request.formData();
                    if (formData.get('password') === PASSWORD) {
                        const secret = PASSWORD + "-a-very-secret-salt-string-for-source-js";
                        const encoder = new TextEncoder();
                        const data = encoder.encode(secret);
                        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                        const hashArray = Array.from(new Uint8Array(hashBuffer));
                        const sessionToken = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

                        const redirectUrl = new URL(`/${PASSWORD}`, request.url).toString();
                        const headers = new Headers();
                        headers.set('Location', redirectUrl);
                        headers.set('Set-Cookie', `session_token=${sessionToken}; HttpOnly; Secure; Path=/; Max-Age=3600; SameSite=Strict`);
                        
                        return new Response(null, {
                            status: 302,
                            headers: headers,
                        });
                    } else {
                        return loginPage("密码不正确，请重试。");
                    }
                } catch (e) {
                     return loginPage("处理请求时出错。");
                }
            }
            return loginPage(); 
        }

        if (path === `/${PASSWORD}`) {
            const subParams = ['clash', 'singbox', 'sb', 'base64', 'sub'];
            const hasSubParam = subParams.some(p => url.searchParams.has(p));
            if (userAgent.includes('mozilla') && !hasSubParam) {
                const secret = PASSWORD + "-a-very-secret-salt-string-for-source-js";
                const encoder = new TextEncoder();
                const data = encoder.encode(secret);
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                const expectedToken = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

                const cookie = request.headers.get('Cookie') || '';
                const match = cookie.match(/session_token=([a-f0-9]+)/);
                const receivedToken = match ? match[1] : '';

                if (receivedToken !== expectedToken) {
                    const loginUrl = new URL('/login', url).toString();
                    return Response.redirect(loginUrl, 302);
                }
            }
            let settings = {}; 
            if (KV) {
                try {
                    const storedSettings = await KV.get("settings", "json");
                    if (storedSettings) settings = storedSettings;
                } catch (e) {
                    console.error(`KV 'settings' read/parse error: ${e}.`);
                }
            } else if (ENV_APIURLS) {
                settings.apiUrls = ENV_APIURLS;
            }
            
            if (request.method === 'POST') {
                 if (!KV) {
                    return subscriptionManagementPage(request, PASSWORD, AUTH_UUID, settings, "错误：未绑定 KV，无法保存在线设置。", false);
                }
                try {
                    const formData = await request.formData();
                    const formAction = formData.get('form_action');
                    
                    if (formAction === 'update_api_urls') {
                        settings.apiUrls = formData.get('api_urls');
                    } else if (formAction === 'update_custom_api_urls') {
                        settings.apiUrlsWithCustomPorts = formData.get('api_urls_custom_ports');
                        settings.selectedHttpsPorts = formData.getAll('selected_https_ports');
                        settings.selectedHttpPorts = formData.getAll('selected_http_ports');
                    } else if (formAction === 'update_sub_settings') {
                        settings.subConverter = formData.get('sub_converter');
                        settings.subConfig = formData.get('sub_config');
                    }

                    await KV.put('settings', JSON.stringify(settings));
                    const targetUrl = new URL(`/${PASSWORD}`, url);
                    targetUrl.searchParams.set('success', 'true');
                    return Response.redirect(targetUrl.toString(), 303);
                } catch (e) {
                    return subscriptionManagementPage(request, PASSWORD, AUTH_UUID, settings, `处理请求时出错: ${e.message}`, !!KV);
                }
            }
            if (userAgent.includes('mozilla') && !hasSubParam) {
                return subscriptionManagementPage(request, PASSWORD, AUTH_UUID, settings, null, !!KV);
            }
            
            const subConverterHost = (settings && settings.subConverter) || 'SUBAPI.cmliussss.net';
            const subConfig = (settings && settings.subConfig) || 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini';
            
            let targetClient = '';
            if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || url.searchParams.has('clash')) {
                targetClient = 'clash';
            } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || url.searchParams.has('singbox') || url.searchParams.has('sb')) {
                targetClient = 'singbox';
            }
			
            if (targetClient) {
                const sourceSubUrl = new URL(url);
                sourceSubUrl.searchParams.delete('clash');
                sourceSubUrl.searchParams.delete('singbox');
                sourceSubUrl.searchParams.delete('sb');
                
                sourceSubUrl.pathname = `/${fakePassword}`;

                const converterUrl = `https://${subConverterHost}/sub?target=${targetClient}&url=${encodeURIComponent(sourceSubUrl.toString())}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;

                try {
                    const subResponse = await fetch(converterUrl, { headers: { 'User-Agent': 'cloudflare-worker' } });
                    
                    if (!subResponse.ok) {
                        return new Response(`Error from subscription converter: ${subResponse.statusText}`, { status: subResponse.status });
                    }
                    
                    const convertedText = await subResponse.text();
                    const restoredText = convertedText.replaceAll(fakeHost, url.hostname);

                    const finalHeaders = new Headers();
                    finalHeaders.set('Content-Type', 'text/plain;charset=utf-8');
                    const subFilename = `${FILENAME}.yaml`;
                    finalHeaders.set('Content-Disposition', `inline; filename="${subFilename}"; filename*=UTF-8''${encodeURIComponent(subFilename)}`);

                    return new Response(restoredText, { 
                        status: 200, 
                        headers: finalHeaders 
                    });
                } catch (e) {
                    return new Response(`Error contacting subscription converter: ${e.message}`, { status: 500 });
                }
            }
            
            const subDomain = url.searchParams.get('sub');
            if (subDomain) {
                return await fetchExternalSubscription(subDomain, AUTH_UUID, url.hostname, userAgent, url.searchParams);
            }

            const preferredDomains = await fetchPreferredDomains(settings);
            const randomNodes = generateRandomCFNodes(url.hostname, AUTH_UUID, url.searchParams, preferredDomains, settings.selectedHttpsPorts, settings.selectedHttpPorts);
            const subContent = generateClientConfig(randomNodes);
            const base64Sub = btoa(subContent);
            
            return new Response(base64Sub, { 
                headers: {
                    'Content-Type': 'text/plain;charset=utf-8',
                }
            });
        }
        
        return statusPage();
    },
};

async function handleWebSocketConnection(request, AUTH_UUID, proxyIP) {
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    server.accept();

    let remoteSocketWrapper = { value: null };
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(server, earlyDataHeader);

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk) {
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            if (chunk.byteLength < 24 || !compareArrayBuffers(chunk.slice(1, 17), uuidToBytes(AUTH_UUID))) return;
            
            const view = new DataView(chunk);
            const optLen = view.getUint8(17);
            if (view.getUint8(18 + optLen) !== 1) return;
            
            let pos = 19 + optLen;
            const port = view.getUint16(pos);
            const addressType = view.getUint8(pos + 2);
            pos += 3;

            let addressRemote = '', addressLen = 0;
            if (addressType === 1) { 
                addressLen = 4;
                addressRemote = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
            } else if (addressType === 2) { 
                addressLen = view.getUint8(pos++);
                addressRemote = new TextDecoder().decode(chunk.slice(pos, pos + addressLen));
            } else if (addressType === 3) { 
                addressLen = 16;
                const ipv6 = Array.from({length: 8}, (_, i) => view.getUint16(pos + i * 2).toString(16)).join(':');
                addressRemote = `[${ipv6}]`;
            } else { return; }

            pos += addressLen;
            const payload = chunk.slice(pos);
            const responseHeader = new Uint8Array([chunk[0], 0]);
            
            await handleTCPOutBound(remoteSocketWrapper, addressRemote, port, payload, server, responseHeader, proxyIP);
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, proxyIP) {
    const connectWith = async (hostname, port) => {
        const socket = connect({ hostname, port });
        await socket.opened;
        return socket;
    };
    
    let tcpSocket;
    try {
        tcpSocket = await connectWith(addressRemote, portRemote);
    } catch (err) {
        try {
            const [proxyAddress, proxyPort] = await parseProxyIP(proxyIP);
            tcpSocket = await connectWith(proxyAddress, proxyPort);
        } catch (proxyErr) {
            safeCloseWebSocket(webSocket, 1011, 'All connection attempts failed');
            return;
        }
    }

    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    remoteSocketToWS(tcpSocket, webSocket, responseHeader);
}

function getProxyIPFromRequest(request) {
    const url = new URL(request.url);
    const { searchParams } = url;
    if (searchParams.has('proxyip')) {
        return searchParams.get('proxyip');
    }
    return (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt');
}


async function parseProxyIP(proxyIPString) {
    proxyIPString = proxyIPString.toLowerCase();
    let address = proxyIPString, port = 443;
    const tpMatch = proxyIPString.match(/\.tp(\d+)/);
    if (tpMatch) {
        port = parseInt(tpMatch[1], 10);
    } else if (proxyIPString.includes(']:')) {
        const parts = proxyIPString.split(']:');
        address = parts[0] + ']';
        port = parseInt(parts[1], 10) || port;
    } else if (proxyIPString.includes(':') && !proxyIPString.startsWith('[')) {
        const colonIndex = proxyIPString.lastIndexOf(':');
        address = proxyIPString.slice(0, colonIndex);
        port = parseInt(proxyIPString.slice(colonIndex + 1), 10) || port;
    }
    return [address, port];
}

async function fetchExternalSubscription(subDomain, realUuid, realHostName, userAgent, searchParams) {
    const subUrl = `https://${subDomain}/sub?host=${PLACEHOLDER_HOST}&uuid=${PLACEHOLDER_UUID}&path=${encodeURIComponent('/')}`;

    try {
        const response = await fetch(subUrl, { headers: { 'User-Agent': userAgent } });
        if (!response.ok) {
            throw new Error(`Failed to fetch SUB source: ${response.status}`);
        }

        const originalB64Content = await response.text();
        let finalContentB64 = originalB64Content; 

        try {
            let decodedContent = atob(originalB64Content);
            let restoredContent = decodedContent.replace(new RegExp(PLACEHOLDER_HOST, 'g'), realHostName)
                                                .replace(new RegExp(PLACEHOLDER_UUID, 'g'), realUuid);

            const proxyIP = searchParams.get('proxyip');
            if (proxyIP) {
                const links = restoredContent.split('\n');
                const modifiedLinks = links.map(link => {
                    if (!link.trim()) return link;
                    try {
                        const nodeUrl = new URL(link);
                        const wsPath = nodeUrl.searchParams.get('path') || '/';
                        const pathUrl = new URL(wsPath, 'https://dummy.com');
                        pathUrl.searchParams.set('proxyip', proxyIP);
                        nodeUrl.searchParams.set('path', `${pathUrl.pathname}${pathUrl.search}`);
                        return nodeUrl.toString();
                    } catch {
                        return link; 
                    }
                });
                restoredContent = modifiedLinks.join('\n');
            }
            
            finalContentB64 = btoa(restoredContent);

        } catch (e) {
             console.error("Error processing external subscription content:", e);
             finalContentB64 = originalB64Content;
        }

        const finalHeaders = new Headers();
        finalHeaders.set('Content-Type', 'text/plain;charset=utf-8');
        finalHeaders.set('Content-Disposition', `inline; filename="${FILENAME}"; filename*=UTF-8''${encodeURIComponent(FILENAME)}`);


        return new Response(finalContentB64, {
            status: 200,
            headers: finalHeaders
        });

    } catch (error) {
        return new Response(`Error fetching or processing SUB content: ${error.message}`, { status: 500 });
    }
}

async function fetchPreferredDomains(settings) {
    const { apiUrls = '', apiUrlsWithCustomPorts = '', selectedHttpsPorts = [], selectedHttpPorts = [] } = settings;
    const nodesToProcess = [];
    if (apiUrls) {
        for (const line of apiUrls.split('\n').map(l => l.trim()).filter(l => l)) {
            if (line.startsWith('http')) {
                try {
                    const response = await fetch(line);
                    if (!response.ok) continue;
                    const text = await response.text();
                    text.split('\n').map(l => l.trim()).filter(l => l).forEach(l => nodesToProcess.push({ line: l, tls: true }));
                } catch {}
            } else {
                nodesToProcess.push({ line, tls: true });
            }
        }
    }
    if (apiUrlsWithCustomPorts) {
        let baseServers = [];
        const customUrls = apiUrlsWithCustomPorts.split('\n').map(l => l.trim()).filter(l => l);
        
        for (const line of customUrls) {
            if (line.startsWith('http')) {
                try {
                    const response = await fetch(line);
                    if (!response.ok) continue;
                    const text = await response.text();
                    baseServers.push(...text.split('\n').map(l => l.trim()).filter(l => l));
                } catch {}
            } else {
                baseServers.push(line);
            }
        }

        for (const serverLine of baseServers) {
            let [baseServer, alias] = serverLine.split('#');
            baseServer = baseServer.replace(/:\d+$/, '').trim();
            if (!baseServer) continue;

            selectedHttpsPorts.forEach(port => nodesToProcess.push({ line: `${baseServer}:${port}#${alias ? `${alias}-${port}` : ''}`, tls: true }));
            selectedHttpPorts.forEach(port => nodesToProcess.push({ line: `${baseServer}:${port}#${alias ? `${alias}-${port}` : ''}`, tls: false }));
        }
    }
    
    const structuredNodes = nodesToProcess.map(({ line, tls }) => {
        let [server, name] = line.split('#');
        const portMatch = server.match(/:(\d+)$/);
        let port = tls ? 443 : 80;
        if (portMatch) {
            server = server.substring(0, server.lastIndexOf(':'));
            port = parseInt(portMatch[1], 10);
        }
        if (!server) return null;
        return { server, port, name: name || `${server}:${port}`, tls };
    }).filter(Boolean);

    return [...new Map(structuredNodes.map(item => [`${item.server}:${item.port}`, item])).values()];
}

function generateRandomCFNodes(hostName, uuid, searchParams, preferredDomains = [], selectedHttpsPorts = [], selectedHttpPorts = []) {
    const nodes = [];
    const usePreferred = preferredDomains.length > 0;
    const count = usePreferred ? preferredDomains.length : RANDOM_NODE_COUNT;

    for (let i = 0; i < count; i++) {
        let serverAddress, nodePort, nodeName, tls;

        if (usePreferred) {
            const node = preferredDomains[i];
            serverAddress = node.server;
            nodePort = node.port;
            nodeName = node.name || `API-${String(i + 1).padStart(2, '0')}`;
            tls = node.tls;
        } else {
            serverAddress = generateRandomIPFromCIDR(CF_IPS_CIDR[Math.floor(Math.random() * CF_IPS_CIDR.length)]);
            const allSelectedPorts = [
                ...selectedHttpsPorts.map(p => ({ port: p, isTls: true })),
                ...selectedHttpPorts.map(p => ({ port: p, isTls: false }))
            ];
            const availablePorts = allSelectedPorts.length > 0 ? allSelectedPorts : [{ port: '443', isTls: true }];
            const selectedPortInfo = availablePorts[Math.floor(Math.random() * availablePorts.length)];           
            nodePort = parseInt(selectedPortInfo.port, 10);
            tls = selectedPortInfo.isTls; 
            nodeName = `CF-Random-${String(i + 1).padStart(2, '0')}`;
        }

        let path = WS_PATH;
        if (searchParams.has('proxyip')) {
            path += `?proxyip=${encodeURIComponent(searchParams.get('proxyip'))}`;
        }
        
        nodes.push({
            name: nodeName,
            server: serverAddress,
            port: nodePort,
            uuid: uuid,
            network: 'ws',
            tls: tls,
            servername: hostName,
            'ws-opts': {
                path: path,
                headers: { Host: hostName }
            }
        });
    }
    return nodes;
}

function generateClientConfig(nodeObjects) {
    const protocol = 'vl' + 'ess';
    const fpOptions = ['chrome', 'random']; 

    return nodeObjects.map(node => {
        const security = node.tls ? 'tls' : 'none';
        const randomFp = fpOptions[Math.floor(Math.random() * fpOptions.length)];

        const params = new URLSearchParams({
            encryption: 'none',
            security: security,
            sni: node.servername,
            type: 'ws',
            host: node.servername,
            path: node['ws-opts'].path,
            fp: randomFp, 
            alpn: 'h3'   
        });
        return `${protocol}://${node.uuid}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
    }).join('\n');
}

function ipToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function intToIp(int) {
    return [ (int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255 ].join('.');
}

function generateRandomIPFromCIDR(cidr) {
    const [base, mask] = cidr.split('/');
    const baseInt = ipToInt(base);
    const hostBits = 32 - parseInt(mask, 10);
    if (hostBits < 2) {
        return intToIp(baseInt);
    }
    const randomOffset = Math.floor(Math.random() * (Math.pow(2, hostBits) - 2)) + 1;
    return intToIp(baseInt + randomOffset);
}

function remoteSocketToWS(remoteSocket, webSocket, responseHeader) {
    let header = responseHeader;
    remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (webSocket.readyState !== 1) return;
            if (header) {
                webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                header = null;
            } else { webSocket.send(chunk); }
        },
        close() { safeCloseWebSocket(webSocket); },
        abort() { safeCloseWebSocket(webSocket); },
    })).catch(() => { safeCloseWebSocket(webSocket); });
}


function makeReadableWebSocketStream(webSocket, earlyDataHeader) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocket.addEventListener('message', (event) => {
                if (!readableStreamCancel) {
                    controller.enqueue(event.data);
                }
            });
            webSocket.addEventListener('close', () => {
                if (!readableStreamCancel) {
                    safeCloseWebSocket(webSocket);
                    controller.close();
                }
            });
            webSocket.addEventListener('error', (err) => controller.error(err));
            
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        cancel() {
            readableStreamCancel = true;
            safeCloseWebSocket(webSocket);
        }
    });
    return stream;
}

function safeCloseWebSocket(socket, code, reason) {
    try {
        if (socket.readyState === 1 || socket.readyState === 2) { 
            socket.close(code, reason);
        }
    } catch (error) {

    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: undefined, error: null };
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        return { earlyData: Uint8Array.from(decode, (c) => c.charCodeAt(0)).buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

function uuidToBytes(uuidStr) {
    const uuid = uuidStr.replaceAll('-', '');
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        bytes[i] = parseInt(uuid.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
}

function compareArrayBuffers(buf1, buf2) {
    if (buf1.byteLength !== buf2.byteLength) return false;
    const view1 = new DataView(buf1);
    const view2 = new DataView(buf2);
    for (let i = 0; i < buf1.byteLength; i++) {
        if (view1.getUint8(i) !== view2.getUint8(i)) return false;
    }
    return true;
}
