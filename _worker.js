
import { connect } from 'cloudflare:sockets';

// --- 全局配置缓存 ---
let cachedSettings = null;     
// --------------------

let userID = '';
let proxyIP = '';
//let sub = '';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;

let fallback64Prefixes = []; 
let fallback64Enabled = false; 

let noTLS = 'false';
const expire = -1;
let proxyIPs = [];
let socks5s = [];
let go2Socks5s = [
	'*ttvnw.net',
	'*tapecontent.net',
	'*cloudatacdn.com',
	'*.loadshare.org',
];
let addresses = [];
let adds = [];
let addressesapi = [];
let addsapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;
let FileName = 'Analytics';
let proxyhosts = [];
let proxyhostsURL = '';
let RproxyIP = 'false';
let httpsPorts = ["443"];
let httpPorts = ["80"];
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
const validFingerprints = ['chrome', 'random', 'randomized'];

/**
 * 辅助工具函数
 */
const utils = {
	isValidUUID(uuid) {
		const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
		return uuidPattern.test(uuid);
	},
	base64: {
		toArrayBuffer(base64Str) {
			if (!base64Str) return { earlyData: undefined, error: null };
			try {
				base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
				const decoded = atob(base64Str);
				const arrayBuffer = Uint8Array.from(decoded, c => c.charCodeAt(0));
				return { earlyData: arrayBuffer.buffer, error: null };
			} catch (error) {
				return { earlyData: undefined, error };
			}
		}
	},
};

/**
 * @returns {string} 
 */
function generateRandomPath() {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '/';
    for (let i = 0; i < 8; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

/**
 * @returns {string} 
 */
function getRandomFingerprint() {
    return validFingerprints[Math.floor(Math.random() * validFingerprints.length)];
}

/**
 * 集中加载所有配置，严格执行 KV > 环境变量 > 默认值的优先级
 * @param {any} env
 */
async function loadConfigurations(env) {
    // 1. 检查内存缓存
    if (cachedSettings ) {
        return; // 缓存命中，直接返回
    }

    // 2. 从环境变量加载，如果存在则覆盖默认值
    if (env.UUID || env.uuid || env.PASSWORD || env.pswd) userID = env.UUID || env.uuid || env.PASSWORD || env.pswd;
    if (env.PROXYIP || env.proxyip) proxyIP = env.PROXYIP || env.proxyip;
    if (env.SOCKS5) socks5Address = env.SOCKS5;
    if (env.SUBNAME) FileName = env.SUBNAME;
    
    if (env.FALLBACK64) fallback64Prefixes = 整理(env.FALLBACK64);

    if (env.ADD) addresses = 整理(env.ADD);
    if (env.ADDS) adds = 整理(env.ADDS);
    if (env.ADDAPI) addressesapi = 整理(env.ADDAPI);
    if (env.ADDNOTLS) addressesnotls = 整理(env.ADDNOTLS);
    if (env.ADDNOTLSAPI) addressesnotlsapi = 整理(env.ADDNOTLSAPI);
    if (env.ADDCSV) addressescsv = 整理(env.ADDCSV);
    if (env.LINK) link = 整理(env.LINK);
    if (env.GO2SOCKS5) go2Socks5s = 整理(env.GO2SOCKS5);
    if (env.BAN) banHosts = 整理(env.BAN);

    if (env.DLS) DLS = Number(env.DLS);
    if (env.CSVREMARK) remarkIndex = Number(env.CSVREMARK);

    // 3. 如果存在 KV，则使用 KV 的值覆盖所有之前的值
    if (env.KV) {
        try {
            const advancedSettingsJSON = await env.KV.get('settinggs.txt');
            if (advancedSettingsJSON) {
                const settings = JSON.parse(advancedSettingsJSON);
                
                cachedSettings = settings;

                // 使用KV中的配置覆盖当前变量
                if (settings.proxyip && settings.proxyip.trim()) proxyIP = settings.proxyip;
                if (settings.socks5 && settings.socks5.trim()) socks5Address = settings.socks5.split('\n')[0].trim();
                if (settings.sub && settings.sub.trim()) env.SUB = settings.sub.trim().split('\n')[0];
                
                if (settings.fallback64 && settings.fallback64.trim()) fallback64Prefixes = 整理(settings.fallback64);
                if (settings.fallback64Enabled) {
                    fallback64Enabled = settings.fallback64Enabled === 'true';
                }

				if (settings.httpsports && settings.httpsports.trim()) {
                    httpsPorts = 整理(settings.httpsports);
                }
                if (settings.httpports && settings.httpports.trim()) {
                    httpPorts = 整理(settings.httpports);
                }
				if (settings.notls) {
                    noTLS = settings.notls;
                }

                if (settings.ADD) {
                    const 优选地址数组 = 整理(settings.ADD);
                    const 分类地址 = { 接口地址: new Set(), 链接地址: new Set(), 优选地址: new Set() };
                    for (const 元素 of 优选地址数组) {
                        if (元素.startsWith('https://')) 分类地址.接口地址.add(元素);
                        else if (元素.includes('://')) 分类地址.链接地址.add(元素);
                        else 分类地址.优选地址.add(元素);
                    }
                    addressesapi = [...分类地址.接口地址];
                    link = [...分类地址.链接地址];
                    addresses = [...分类地址.优选地址];
                }

                if (settings.ADDS) {
                    const 官方优选数组 = 整理(settings.ADDS);
                    const 官方分类地址 = { 接口地址: new Set(), 优选地址: new Set() };
                     for (const 元素 of 官方优选数组) {
                        if (元素.startsWith('https://')) {
                            官方分类地址.接口地址.add(元素);
                        } else {
                            官方分类地址.优选地址.add(元素);
                        }
                    }
                    addsapi = [...官方分类地址.接口地址];
                    adds = [...官方分类地址.优选地址];
                }
            }
        } catch (e) {
            console.error("从KV加载配置时出错: ", e);
        }
    }

    // 4. 最终处理
    proxyIPs = 整理(proxyIP);
    proxyIP = proxyIPs.length > 0 ? proxyIPs[Math.floor(Math.random() * proxyIPs.length)] : '';

    socks5s = 整理(socks5Address);
    socks5Address = socks5s.length > 0 ? socks5s[Math.floor(Math.random() * socks5s.length)] : '';
	socks5Address = socks5Address.split('//')[1] || socks5Address;

}

/**
 * @param {string} proxyString
 * @param {number} defaultPort
 * @returns {{address: string, port: number}}
 */
function parseProxyIP(proxyString, defaultPort) {
    let port = defaultPort;
    let address = proxyString;

    if (address.includes(']:')) {
        [address, port] = address.split(']:');
        address += ']';
    } else if (address.includes(':')) {
        const parts = address.split(':');
        if (parts.length > 2) {
            port = parts.pop();
            address = parts.join(':');
        } else {
            [address, port] = parts;
        }
    }


    if (address.includes('.tp')) {
        port = address.split('.tp')[1].split('.')[0] || port;
    }

    return { address: address.toLowerCase(), port: Number(port) };
}

// ReadableStream
function createWebSocketStreamWithManualBackpressure(webSocket, log) {
    let readableStreamCancel = false;
    let backpressure = false;
    let messageQueue = [];
    let isProcessing = false;

    const processMessage = async (data, controller) => {
        if (isProcessing) {
            messageQueue.push(data);
            return;
        }
        isProcessing = true;
        try {
            controller.enqueue(data);
            while (messageQueue.length > 0 && !backpressure) {
                const queuedData = messageQueue.shift();
                controller.enqueue(queuedData);
            }
        } catch (error) {
            log(`Message processing error: ${error.message}`);
        } finally {
            isProcessing = false;
        }
    };

    const handleEarlyData = async (earlyDataHeader, controller) => {
			const { earlyData, error } = utils.base64.toArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
    };
    
    const cleanup = () => {
        if (readableStreamCancel) return;
        readableStreamCancel = true;
        messageQueue = [];
        isProcessing = false;
        backpressure = false;
        safeCloseWebSocket(webSocket);
    };

    const handleStreamStart = async (controller, earlyDataHeader) => {
        try {
            webSocket.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                if (!backpressure) {
                    processMessage(event.data, controller);
                } else {
                    messageQueue.push(event.data);
                    log('Backpressure detected, message queued');
				}
			});

			webSocket.addEventListener('close', () => {
                 if (!readableStreamCancel) {
					try {
                        controller.close();
					} catch (error) {
						log(`关闭流时出错: ${error.message}`);
					}
				}
                cleanup();
			});

            webSocket.addEventListener('error', (err) => {
                log(`WebSocket error: ${err.message}`);
                if (!readableStreamCancel) {
                    try {
					controller.error(err);
                    } catch (error) {
                        log(`向流报告错误时出错: ${error.message}`);
                    }
                }
                cleanup();
            });

            await handleEarlyData(earlyDataHeader, controller);
        } catch (error) {
            log(`Stream start error: ${error.message}`);
            controller.error(error);
        }
    };

    const handleStreamPull = (controller) => {
        if (controller.desiredSize > 0) {
            backpressure = false;
            while (messageQueue.length > 0 && controller.desiredSize > 0) {
                const data = messageQueue.shift();
                processMessage(data, controller);
            }
        } else {
            backpressure = true;
        }
    };

    const handleStreamCancel = (reason) => {
        if (readableStreamCancel) return;
        log(`Readable stream canceled, reason: ${reason}`);
        cleanup();
    };

    return (earlyDataHeader) => {
        return new ReadableStream({
            start: (controller) => handleStreamStart(controller, earlyDataHeader),
            pull: (controller) => handleStreamPull(controller),
            cancel: (reason) => handleStreamCancel(reason),
        });
    }
}

// =================================================================
//  服务状态页 (Status Page)
// =================================================================
async function statusPage() {
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
            .header h1 {
                margin: 0;
                font-size: 24px;
            }
            .header .all-systems-operational {
                color: var(--primary-color);
                font-size: 18px;
                font-weight: 600;
                margin-top: 10px;
            }
            .service-group h2 {
                font-size: 18px;
                color: var(--text-color);
                margin-bottom: 15px;
            }
            .service-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 15px 0;
                border-bottom: 1px solid var(--border-color);
            }
            .service-item:last-child {
                border-bottom: none;
            }
            .service-name {
                font-size: 16px;
            }
            .service-status {
                font-size: 16px;
                font-weight: 600;
                color: var(--primary-color);
            }
            .footer {
                margin-top: 30px;
                text-align: center;
                font-size: 14px;
                color: var(--secondary-color);
            }
            .footer a {
                color: var(--secondary-color);
                text-decoration: none;
            }
            .footer a:hover {
                text-decoration: underline;
            }
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
                <div class="service-item">
                    <span class="service-name">API Gateway</span>
                    <span class="service-status">Operational</span>
                </div>
                <div class="service-item">
                    <span class="service-name">Authentication Service</span>
                    <span class="service-status">Operational</span>
                </div>
                 <div class="service-item">
                    <span class="service-name">Storage Cluster</span>
                    <span class="service-status">Operational</span>
                </div>
            </div>

            <div class="service-group" style="margin-top: 30px;">
                <h2>Real-time Data Services</h2>
                <div class="service-item">
                    <span class="service-name">WebSocket Push Service</span>
                    <span class="service-status">Operational</span>
                </div>
                <div class="service-item">
                    <span class="service-name">Real-time Data Pipeline</span>
                    <span class="service-status">Operational</span>
                </div>
            </div>

            <div class="footer">
                <p>
                    Last Updated:
                    <span id="date-container"></span>
                    <span id="time-container" class="notranslate"></span>
                </p>
                <a href="#" target="_blank" rel="noopener noreferrer">Powered by Analytics</a>
            </div>
        </div>
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
    </html>
    `;
    return new Response(html, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
}

/**
 * @param {string} domain 
 * @returns {Promise<string>}
 */
async function resolveViaFallback64(domain) {
    if (!fallback64Prefixes || fallback64Prefixes.length === 0) {
        throw new Error('未配置Fallback64');
    }

    async function fetchIPv4(domain) {
        const url = `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`;
        const response = await fetch(url, {
            headers: { 'Accept': 'application/dns-json' }
        });

        if (!response.ok) {
            throw new Error('查询失败');
        }

        const data = await response.json();
        const ipv4s = (data.Answer || [])
            .filter(record => record.type === 1) 
            .map(record => record.data);

        if (ipv4s.length === 0) {
            throw new Error('未找到');
        }

        return ipv4s[Math.floor(Math.random() * ipv4s.length)];
    }

    const ipv4 = await fetchIPv4(domain);

    const prefix = fallback64Prefixes[Math.floor(Math.random() * fallback64Prefixes.length)];

    const ipv4Parts = ipv4.split('.').map(part => parseInt(part, 10).toString(16).padStart(2, '0'));
    
    const cleanPrefix = prefix.replace(/::(?:\/\d{1,3})?$/, '::');
    const synthesizedIPv6 = `${cleanPrefix.slice(0, -1)}${ipv4Parts[0]}${ipv4Parts[1]}:${ipv4Parts[2]}${ipv4Parts[3]}`;

    return synthesizedIPv6;
}

export default {
	async fetch(request, env, ctx) {
		try {
            // 1. 统一加载所有配置 (此函数现在使用内存缓存)
            await loadConfigurations(env);
			
            // 2. 检查 UUID 是否有效，若无效则显示新的伪装页面
			if (!userID || !utils.isValidUUID(userID)) {
				return await statusPage();
			}

            // 3. 生成伪装信息
			const currentDate = new Date();
			currentDate.setHours(0, 0, 0, 0);
			const timestamp = Math.ceil(currentDate.getTime() / 1000);
			const fakeUserIDSHA256 = await 双重哈希(`${userID}${timestamp}`);
			const fakeUserID = [
                fakeUserIDSHA256.slice(0, 8),
                fakeUserIDSHA256.slice(8, 12),
                fakeUserIDSHA256.slice(12, 16),
                fakeUserIDSHA256.slice(16, 20),
                fakeUserIDSHA256.slice(20, 32)
			].join('-');

			const fakeHostName = `${fakeUserIDSHA256.slice(6, 9)}.${fakeUserIDSHA256.slice(13, 19)}`;

            // 4. 处理 SOCKS5
			if (socks5Address) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Address);
					RproxyIP = env.RPROXYIP || 'false';
					enableSocks = true;
				} catch (err) {
					console.log(err.toString());
					RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
					enableSocks = false;
				}
			} else {
				RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
			}

            // 5. 根据请求类型进行路由
			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
                let sub = env.SUB || '';
                let path = ''; // path 变量在此处作用域内定义
				if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub').toLowerCase();
				if (url.searchParams.has('notls')) noTLS = 'true';

				if (url.searchParams.has('proxyip')) {
					path = `/?proxyip=${url.searchParams.get('proxyip')}`;
					RproxyIP = 'false';
				} else if (url.searchParams.has('socks5') || url.searchParams.has('socks')) {
					path = `/?socks5=${url.searchParams.get('socks5') || url.searchParams.get('socks')}`;
					RproxyIP = 'false';
				}

				const 路径 = url.pathname.toLowerCase();
				if (路径 == '/') {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await 代理URL(env.URL, url);
					else {
						// 显示新的伪装页面
						return await statusPage();
					}
				} else if (路径 === `/${fakeUserID}`) {
					const fakeConfig = await generateIntegrationDetails(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, fakeUserID, fakeHostName, env);
					return new Response(`${fakeConfig}`, { status: 200 });
				}
				else if (路径 === `/${userID}/edit`) {
					return await KV(request, env);
				} else if (路径 === `/${userID}`) {
					const UA = request.headers.get('User-Agent') || 'null';
					const secureProtoConfig = await generateIntegrationDetails(userID, request.headers.get('Host'), sub, UA, RproxyIP, url, fakeUserID, fakeHostName, env);

                    if (secureProtoConfig instanceof Response) {
                        return secureProtoConfig;
                    }
                    
					const now = Date.now();
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776;
					const userAgent = UA.toLowerCase();
					
					if (userAgent && userAgent.includes('mozilla') && !url.searchParams.has('b64') && !url.searchParams.has('base64')) {
						return new Response(secureProtoConfig, {
							status: 200,
							headers: {
								"Content-Type": "text/html;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
								"Cache-Control": "no-store",
							}
						});
					} else {
                        // 对于 Base64 的请求，直接返回文本
						return new Response(secureProtoConfig, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					}
				} else {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await 代理URL(env.URL, url);
					else {
						// 对于所有其他未知路径，显示新的伪装页面
						return await statusPage();
					}
				}
			} else {
                // WebSocket 请求处理
				socks5Address = url.searchParams.get('socks5') || socks5Address;
				if (new RegExp('/socks5=', 'i').test(url.pathname)) {
                    socks5Address = url.pathname.split('5=')[1];
                }
				else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname)) {
					socks5Address = url.pathname.split('://')[1].split('#')[0];
					if (socks5Address.includes('@')) {
						let userPassword = socks5Address.split('@')[0];
						const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
						if (base64Regex.test(userPassword) && !userPassword.includes(':')) {
							
							try {
								userPassword = atob(userPassword);
							} catch (e) {
								console.error(`SOCKS5 auth: Failed to decode Base64 string "${userPassword}". Using it as-is. Error: ${e.message}`);
							}
						}
						socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
					}
				}

				if (socks5Address) {
					try {
						parsedSocks5Address = socks5AddressParser(socks5Address);
						enableSocks = true;
					} catch (err) {
						console.log(err.toString());
						enableSocks = false;
					}
				} else {
					enableSocks = false;
				}

				if (url.searchParams.has('proxyip')) {
					proxyIP = url.searchParams.get('proxyip');
					enableSocks = false;
				} else if (new RegExp('/proxyip=', 'i').test(url.pathname)) {
					proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
					enableSocks = false;
				} else if (new RegExp('/proxyip.', 'i').test(url.pathname)) {
					proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
					enableSocks = false;
				} else if (new RegExp('/pyip=', 'i').test(url.pathname)) {
					proxyIP = url.pathname.toLowerCase().split('/pyip=')[1];
					enableSocks = false;
				}

				return await secureProtoOverWSHandler(request);
			}
		} catch (err) {
			return new Response(err.toString());
		}
	},
};

async function secureProtoOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (info, event = '') => {
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] [${address}:${portWithRandomLog}] ${info}`, event);
    };
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const createStream = createWebSocketStreamWithManualBackpressure(webSocket, log);
    const readableWebSocketStream = createStream(earlyDataHeader);

    let remoteSocketWrapper = {
        value: null
    };
    let udpStreamProcessed = false;
    let secureProtoResponseHeader = null;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (udpStreamProcessed) {
                return;
            }
            if (remoteSocketWrapper.value) {
                try {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                } catch (error) {
                    log(`写入远程套接字时出错: ${error.message}。`);
                    controller.error(error);
                }
                return;
            }

            const {
                hasError,
                message,
                addressType,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                secureProtoVersion = new Uint8Array([0, 0]),
                isUDP,
            } = processsecureProtoHeader(chunk, userID);

            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
            if (hasError) {
                throw new Error(message);
            }

            secureProtoResponseHeader = new Uint8Array([secureProtoVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isUDP) {
                if (portRemote === 53) {
                    await handleDNSQuery(rawClientData, webSocket, secureProtoResponseHeader, log);
                    udpStreamProcessed = true;
                } else {
                    throw new Error('UDP proxying is only enabled for DNS on port 53');
                }
                return;
            }

            if (banHosts.includes(addressRemote)) {
                throw new Error('Domain is blocked');
            }
            log(`Handling TCP outbound for ${addressRemote}:${portRemote}`);
            handleTCPOutBound(remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, secureProtoResponseHeader, log);
        },
        close() {
            log(`客户端 WebSocket 的可读流已关闭 (正常关闭)。`);
            if (remoteSocketWrapper.value) {
                log('客户端已断开，正在关闭远程连接的写入端...');
                const writer = remoteSocketWrapper.value.writable.getWriter();
                writer.close();
                writer.releaseLock();
            }
        },
        abort(reason) {
            log(`客户端 WebSocket 的可读流被中止 (异常)。`, JSON.stringify(reason));
            if (remoteSocketWrapper.value) {
                 log('客户端流异常，正在中止远程连接...');
                remoteSocketWrapper.value.abort(reason);
            }
        },
    })).catch((err) => {
        log(`客户端到远程的管道发生致命错误: ${err.message}`);
        if (remoteSocketWrapper.value) {
            remoteSocketWrapper.value.abort(`Upstream error: ${err.message}`);
        }
        safeCloseWebSocket(webSocket, 1011, `Pipe error: ${err.message}`);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

function mergeData(header, chunk) {
    if (!header || !chunk) {
        throw new Error('Invalid input parameters');
    }

    const totalLength = header.length + chunk.length;

    const merged = new Uint8Array(totalLength);
    merged.set(header, 0);
    merged.set(chunk, header.length);
    return merged;
}

async function handleDNSQuery(udpChunk, webSocket, secureProtoResponseHeader, log) {
    const DNS_SERVER = { hostname: '8.8.8.8', port: 53 };

    let tcpSocket;
    const controller = new AbortController();
    const signal = controller.signal;
    let timeoutId;

    try {
        // 设置全局超时
        timeoutId = setTimeout(() => {
            controller.abort('DNS query timeout');
            if (tcpSocket) {
                try {
                    tcpSocket.close();
                } catch (e) {
                    log(`关闭TCP连接出错: ${e.message}`);
                }
            }
        }, 5000);

        try {
            // 使用Promise.race进行超时控制
            tcpSocket = await Promise.race([
                connect({
                    hostname: DNS_SERVER.hostname,
                    port: DNS_SERVER.port,
                    signal,
                }),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('DNS连接超时')), 1500)
                )
            ]);

            log(`成功连接到DNS服务器 ${DNS_SERVER.hostname}:${DNS_SERVER.port}`);

            // 发送DNS查询
            const writer = tcpSocket.writable.getWriter();
            try {
                await writer.write(udpChunk);
            } finally {
                writer.releaseLock();
            }

            // 简化的数据流处理
            let secureProtoHeader = secureProtoResponseHeader;
            const reader = tcpSocket.readable.getReader();

            try {
                // 使用更高效的循环处理数据
                while (true) {
                    const { done, value } = await reader.read();

                    if (done) {
                        log('DNS数据流处理完成');
                        break;
                    }

                    // 检查WebSocket是否仍然开放
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        break;
                    }

                    try {
                        // 处理数据包
                        if (secureProtoHeader) {
                            const data = mergeData(secureProtoHeader, value);
                            webSocket.send(data);
                            secureProtoHeader = null; // 清除header,只在第一个包使用
                } else {
                            webSocket.send(value);
                        }
                    } catch (error) {
                        log(`数据处理错误: ${error.message}`);
                        throw error;
                    }
                }
            } catch (error) {
                log(`数据读取错误: ${error.message}`);
                throw error;
            } finally {
                reader.releaseLock();
                }

        } catch (error) {
            log(`DNS查询失败: ${error.message}`);
            throw error;
        }

    } catch (error) {
        log(`DNS查询失败: ${error.message}`);
        safeCloseWebSocket(webSocket);
    } finally {
        clearTimeout(timeoutId);
        if (tcpSocket) {
            try {
                tcpSocket.close();
            } catch (e) {
                log(`关闭TCP连接出错: ${e.message}`);
        }
        }
    }
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, secureProtoResponseHeader, log) {

	const createConnection = async (address, port, proxyOptions = null) => {
		const proxyType = proxyOptions ? proxyOptions.type : 'direct';
		log(`建立连接: ${address}:${port} (方式: ${proxyType})`);

		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort('Connection timeout'), 5000);

		try {
			let tcpSocketPromise;
			if (proxyType === 'socks5') {
				tcpSocketPromise = socks5Connect(addressType, address, port, log, controller.signal);
			} else {
				tcpSocketPromise = connect({
					hostname: address,
					port: port,
					allowHalfOpen: false,
                    keepAlive: true,
                    signal: controller.signal
				});
			}

			const tcpSocket = await Promise.race([
				tcpSocketPromise,
				new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), 5000))
			]);

			clearTimeout(timeoutId);
			remoteSocket.value = tcpSocket;

			const writer = tcpSocket.writable.getWriter();
			try {
				await writer.write(rawClientData);
			} finally {
				writer.releaseLock();
			}

			return tcpSocket;
		} catch (error) {
			clearTimeout(timeoutId);
			throw error;
		}
	};

    // 所有连接策略
    async function tryConnectionStrategies(strategies) {
        if (!strategies || strategies.length === 0) {
            log('All connection strategies failed. Closing WebSocket.');            
            safeCloseWebSocket(webSocket);
            return;
        }

        const [currentStrategy, ...nextStrategies] = strategies;
        log(`Attempting connection with strategy: '${currentStrategy.name}'`);

        try {
            const tcpSocket = await currentStrategy.execute();
            log(`Strategy '${currentStrategy.name}' connected successfully. Piping data.`);

            const retryNext = () => tryConnectionStrategies(nextStrategies);
            remoteSocketToWS(tcpSocket, webSocket, secureProtoResponseHeader, retryNext, log);

        } catch (error) {
            log(`Strategy '${currentStrategy.name}' failed: ${error.message}. Trying next strategy...`);
            await tryConnectionStrategies(nextStrategies);
        }
    }

    // --- 构建不同的连接策略 ---
    const connectionStrategies = [];
    
    if (fallback64Enabled) {
        log('Fallback64 模式已强制开启。');
        connectionStrategies.push({
            name: 'Direct Connection',
            execute: () => createConnection(addressRemote, portRemote, null)
        });

        if (fallback64Prefixes.length > 0) {
            connectionStrategies.push({
                name: 'Fallback64',
                execute: async () => {
                    const fallback64Address = await resolveViaFallback64(addressRemote);
                    return createConnection(`[${fallback64Address}]`, portRemote);
                }
            });
        }

    } else {
        // --- 默认（正常）模式 ---
        const shouldUseSocks = enableSocks && go2Socks5s.some(pattern => new RegExp(`^${pattern.replace(/\*/g, '.*')}$`, 'i').test(addressRemote));

        connectionStrategies.push({
            name: 'Direct Connection',
            execute: () => createConnection(addressRemote, portRemote, null)
        });

        if (shouldUseSocks) {
            connectionStrategies.push({
                name: 'SOCKS5 Proxy (go2Socks5s)',
                execute: () => createConnection(addressRemote, portRemote, { type: 'socks5' })
            });
        }

        if (enableSocks && !shouldUseSocks) {
            connectionStrategies.push({
                name: 'SOCKS5 Proxy (Fallback)',
                execute: () => createConnection(addressRemote, portRemote, { type: 'socks5' })
            });
        }

        if (proxyIP && proxyIP.trim() !== '') {
            connectionStrategies.push({
                name: '用户配置的 PROXYIP',
                execute: () => {
                    const { address, port } = parseProxyIP(proxyIP, portRemote);
                    return createConnection(address, port);
                }
            });
        }

        if (fallback64Prefixes.length > 0) {
            connectionStrategies.push({
                name: 'Fallback64',
                execute: async () => {
                    const fallback64Address = await resolveViaFallback64(addressRemote);
                    return createConnection(`[${fallback64Address}]`, portRemote);
                }
            });
        }
    }

    // 最终的备用方案，对两种模式都适用
    connectionStrategies.push({
        name: '内置的默认 PROXYIP',
        execute: () => {
            const defaultProxyIP = atob('UFJPWFlJUC50cDEuZnh4ay5kZWR5bi5pbw==');
            const { address, port } = parseProxyIP(defaultProxyIP, portRemote);
            return createConnection(address, port);
        }
    });

    await tryConnectionStrategies(connectionStrategies);
}

function processsecureProtoHeader(secureProtoBuffer, userID) {
    if (secureProtoBuffer.byteLength < 24) {
        return { hasError: true, message: 'Invalid data' };
    }

    const version = new Uint8Array(secureProtoBuffer.slice(0, 1));
    const userIDArray = new Uint8Array(secureProtoBuffer.slice(1, 17));
    const userIDString = stringify(userIDArray);
    
    if (userIDString !== userID) {
        return { hasError: true, message: 'Invalid user' };
    }

    const optLength = new Uint8Array(secureProtoBuffer.slice(17, 18))[0];
    const command = new Uint8Array(secureProtoBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
    let isUDP = false;

    switch (command) {
        case 1: break;
        case 2: isUDP = true; break;
        default:
            return { hasError: true, message: 'Unsupported command' };
    }

    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(secureProtoBuffer).getUint16(portIndex);

    const addressIndex = portIndex + 2;
    const addressType = new Uint8Array(secureProtoBuffer.slice(addressIndex, addressIndex + 1))[0];
    let addressValue = '';
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(secureProtoBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
            break;
        case 2:
            addressLength = new Uint8Array(secureProtoBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(secureProtoBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(secureProtoBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: 'Invalid address type' };
    }

    if (!addressValue) {
        return { hasError: true, message: 'Empty address value' };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        secureProtoVersion: version,
        isUDP,
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let hasIncomingData = false;
    let header = responseHeader;
    try {
        await remoteSocket.readable.pipeTo(
            new WritableStream({
                async write(chunk) {
                    hasIncomingData = true;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        return;
                    }
                        if (header) {
                            const combinedData = new Uint8Array(header.byteLength + chunk.byteLength);
                            combinedData.set(new Uint8Array(header), 0);
                            combinedData.set(new Uint8Array(chunk), header.byteLength);
                            webSocket.send(combinedData);
                            header = null;
                        } else {
                            webSocket.send(chunk);
                        }
                },
                close() {
                    log(`远程服务器的数据流已正常关闭。`);
                },
                abort(reason) {
                    console.error(`远程服务器的数据流被中断:`, reason);
                },
            })
        );
    } catch (error) {
        console.error(`从远程到客户端的数据流传输发生错误:`, error.stack || error);
        safeCloseWebSocket(webSocket, 1011, `remoteSocketToWS pipe error: ${error.message}`);
    }
        
    if (!hasIncomingData && retry) {
        log(`连接成功但未收到任何数据，触发重试机制...`);
            retry();
    }
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

const byteToHexArray = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
    return `${byteToHexArray[arr[offset + 0]]}${byteToHexArray[arr[offset + 1]]}${byteToHexArray[arr[offset + 2]]}${byteToHexArray[arr[offset + 3]]}-` +
           `${byteToHexArray[arr[offset + 4]]}${byteToHexArray[arr[offset + 5]]}-` +
           `${byteToHexArray[arr[offset + 6]]}${byteToHexArray[arr[offset + 7]]}-` +
           `${byteToHexArray[arr[offset + 8]]}${byteToHexArray[arr[offset + 9]]}-` +
           `${byteToHexArray[arr[offset + 10]]}${byteToHexArray[arr[offset + 11]]}${byteToHexArray[arr[offset + 12]]}` +
           `${byteToHexArray[arr[offset + 13]]}${byteToHexArray[arr[offset + 14]]}${byteToHexArray[arr[offset + 15]]}`.toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!utils.isValidUUID(uuid)) {
        throw new TypeError(`Invalid UUID: ${uuid}`);
    }
    return uuid;
}

async function socks5Connect(addressType, addressRemote, portRemote, log, signal = null, customProxyAddress = null) {
    const { username, password, hostname, port } = customProxyAddress || parsedSocks5Address;
    const socket = await connect({ hostname, port, signal });

    const socksGreeting = new Uint8Array([5, 2, 0, 2]);
    const writer = socket.writable.getWriter();
    await writer.write(socksGreeting);
    log('SOCKS5 greeting sent');

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;

    if (res[0] !== 0x05) {
        log(`SOCKS5 version error: received ${res[0]}, expected 5`);
        return;
    }
    if (res[1] === 0xff) {
        log("No acceptable authentication methods");
        return;
    }

    if (res[1] === 0x02) {
        log("SOCKS5 requires authentication");
        if (!username || !password) {
            log("Username and password required");
            return;
        }
        const authRequest = new Uint8Array([
            1,
            username.length,
            ...encoder.encode(username),
            password.length,
            ...encoder.encode(password)
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log("SOCKS5 authentication failed");
            throw new Error("SOCKS5 authentication failed");
        }
    }

    let DSTADDR;
    switch (addressType) {
        case 1:
            DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
            break;
        case 2:
            DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
            break;
        case 3:
            DSTADDR = new Uint8Array([4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
            break;
        default:
            log(`Invalid address type: ${addressType}`);
            return;
    }
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    await writer.write(socksRequest);
    log('SOCKS5 request sent');

    res = (await reader.read()).value;
    if (res[1] === 0x00) {
        log("SOCKS5 connection established");
    } else {
        log("SOCKS5 connection failed");
        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

function socks5AddressParser(address) {
    let [latter, former] = address.split("@").reverse();
    let username, password, hostname, port;

    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('Invalid SOCKS address format: "username:password" required');
        }
        [username, password] = formers;
    }

    const latters = latter.split(":");
    port = Number(latters.pop());
    if (isNaN(port)) {
        throw new Error('Invalid SOCKS address format: port must be a number');
    }

    hostname = latters.join(":");

    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('Invalid SOCKS address format: IPv6 must be in brackets');
    }

    return {
        username,
        password,
        hostname,
        port,
    }
}

function decodeIntegrationData(content, userID, hostName, fakeUserID, fakeHostName, isBase64) {
    if (isBase64) {
        content = atob(content);
    }

    const escapeRegExp = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const fakeUserIDRegExp = new RegExp(escapeRegExp(fakeUserID), 'g');
    const fakeHostNameRegExp = new RegExp(escapeRegExp(fakeHostName), 'g');

    content = content.replace(fakeUserIDRegExp, userID)
                     .replace(fakeHostNameRegExp, hostName);

    return isBase64 ? btoa(content) : content;
}

async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();

    // 计算第一次哈希 (SHA-256)
    const 第一次哈希 = await crypto.subtle.digest('SHA-256', 编码器.encode(文本));
    const 第一次十六进制 = [...new Uint8Array(第一次哈希)]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

    // 截取部分哈希值，并进行二次哈希
    const 截取部分 = 第一次十六进制.substring(7, 27);
    const 第二次哈希 = await crypto.subtle.digest('SHA-256', 编码器.encode(截取部分));
    const 第二次十六进制 = [...new Uint8Array(第二次哈希)]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

    return 第二次十六进制.toLowerCase();
}

async function 代理URL(request, 代理网址, 目标网址, 调试模式 = false) {
    try {
        const 网址列表 = 整理(代理网址);
        if (!网址列表 || 网址列表.length === 0) {
            throw new Error('代理网址列表为空');
        }
        const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

        const 解析后的网址 = new URL(完整网址);
        if (调试模式) console.log(`代理 URL: ${解析后的网址}`);

        // 正确拼接目标路径和查询参数
        const 目标URL = new URL(目标网址.pathname + 目标网址.search, 解析后的网址);

        // 复制原始请求头，并可以进行一些清理
        const newHeaders = new Headers(request.headers);
        newHeaders.set('Host', 解析后的网址.hostname); 
        newHeaders.set('Referer', 解析后的网址.origin); 

        const 响应 = await fetch(目标URL.toString(), {
            method: request.method, 
            headers: newHeaders, 
            body: request.body,  
            redirect: 'manual' 
        });

        const 新响应 = new Response(响应.body, {
            status: 响应.status,
            statusText: 响应.statusText,
            headers: new Headers(响应.headers)
        });

        新响应.headers.delete('cf-ray');
        新响应.headers.delete('cf-connecting-ip');
        新响应.headers.delete('x-forwarded-proto');
        新响应.headers.delete('x-real-ip');

        return 新响应;
    } catch (error) {
        console.error(`代理请求失败: ${error.message}`);
        return new Response(`代理请求失败: ${error.message}`, { status: 500 });
    }
}

// =================================================================
// =========== START OF REFACTORED HELPER FUNCTIONS ================
// =================================================================

function getConnectionTypeInfo(enableSocks, proxyIP, proxyIPs, newSocks5s, socks5List, RproxyIP) {
    if (enableSocks) {
        return `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
    }
    if (proxyIP && proxyIP.trim() !== '') {
        return `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
    }
    if (RproxyIP === 'true') {
        return `CFCDN（访问方式）: 自动获取<br>`;
    }
    return `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`;
}

/**
 * @returns {string} 
 */
function buildAddressListsHtml() {
    const sources = [
        { label: 'ADDS', data: [...new Set([...adds, ...addsapi])] },
        { label: 'ADD', data: [...new Set([...addresses, ...addressesapi])] },
        { label: 'ADDNOTLS ', data: [...new Set([...addressesnotls, ...addressesnotlsapi])] },
        { label: `ADDCSV （IPTest csv文件 ${DLS} ）`, data: [...new Set(addressescsv)] }
    ];

    let html = '';
    for (const source of sources) {
        if (source.data.length > 0) {
            html += `${source.label}: <br>&nbsp;&nbsp;${source.data.join('<br>&nbsp;&nbsp;')}<br>`;
        }
    }
    return html;
}

// =================================================================
// ============ END OF REFACTORED HELPER FUNCTIONS =================
// =================================================================


const protocolEncodedFlag = atob('ZG14bGMzTT0=');
let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];
async function generateIntegrationDetails(uuid, hostName, sub, UA, RproxyIP, _url, fakeUserID, fakeHostName, env) {

	if (sub) {
		const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
		sub = match ? match[1] : sub;
		const subs = 整理(sub);
		sub = subs.length > 1 ? subs[0] : sub;
	}

	if ((adds.length + addsapi.length + addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
	    		let cfips = [
		            '104.16.0.0/14',
		            '104.21.0.0/16',
		            '104.24.0.0/14',

	    		];

    		function ipToInt(ip) {
        			return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
    		}

    			function intToIp(int) {
        			return [
            			(int >>> 24) & 255,
            			(int >>> 16) & 255,
            			(int >>> 8) & 255,
            			int & 255
        				].join('.');
    				}

        function generateRandomIPFromCIDR(cidr) {
            const [base, mask] = cidr.split('/');
                const baseInt = ipToInt(base);
                const maskBits = parseInt(mask, 10);
                const hostBits = 32 - maskBits;
                if (hostBits < 2) {
                return intToIp(baseInt);
                }
                const usableHosts = Math.pow(2, hostBits) - 2;
                const randomOffset = Math.floor(Math.random() * usableHosts) + 1;

                const randomIPInt = baseInt + randomOffset;
            return intToIp(randomIPInt);
        }

	    let counter = 1;
	    const totalIPsToGenerate = 10;

	    if (hostName.includes("worker") || hostName.includes("notls") || noTLS === 'true') {
		    const randomPorts = httpPorts.length > 0 ? httpPorts : ['80'];
		    for (let i = 0; i < totalIPsToGenerate; i++) {
			    const randomCIDR = cfips[Math.floor(Math.random() * cfips.length)];
			    const randomIP = generateRandomIPFromCIDR(randomCIDR);
			    const port = randomPorts[Math.floor(Math.random() * randomPorts.length)];
			    addressesnotls.push(`${randomIP}:${port}#CF随机ID${String(counter++).padStart(2, '0')}`);
		    }
	    } else {
		    const randomPorts = httpsPorts.length > 0 ? httpsPorts : ['443'];
		        for (let i = 0; i < totalIPsToGenerate; i++) {
			    const randomCIDR = cfips[Math.floor(Math.random() * cfips.length)];
			    const randomIP = generateRandomIPFromCIDR(randomCIDR);
			    const port = randomPorts[Math.floor(Math.random() * randomPorts.length)];
			    addresses.push(`${randomIP}:${port}#CF随机ID${String(counter++).padStart(2, '0')}`);
		    }
	    }
    }

	const userAgent = UA.toLowerCase();
	let proxyhost = "";
	if (hostName.includes(".workers.dev")) {
		if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
			try {
				const response = await fetch(proxyhostsURL);

				if (!response.ok) {
					console.error('获取地址时出错:', response.status, response.statusText);
					return;
				}

				const text = await response.text();
				const lines = text.split('\n');
				const nonEmptyLines = lines.filter(line => line.trim() !== '');

				proxyhosts = proxyhosts.concat(nonEmptyLines);
			} catch (error) {
				//console.error('获取地址时出错:', error);
			}
		}
		if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
	}

	const isUserAgentMozilla = userAgent.includes('mozilla');
	if (isUserAgentMozilla && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
		const newSocks5s = socks5s.map(socks5Address => {
			if (socks5Address.includes('@')) return socks5Address.split('@')[1];
			else if (socks5Address.includes('//')) return socks5Address.split('//')[1];
			else return socks5Address;
		});

		let socks5List = '';
		if (go2Socks5s.length > 0 && enableSocks) {
			socks5List = `${decodeURIComponent('SOCKS5%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
			if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) socks5List += `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}<br>`;
			else socks5List += `<br>&nbsp;&nbsp;${go2Socks5s.join('<br>&nbsp;&nbsp;')}<br>`;
		}
		
        // --- START OF OPTIMIZED LOGIC ---
        const editLink = env.KV ? ` <a href='${_url.pathname}/edit'>设置列表</a>` : '';
        const connectionInfoHtml = getConnectionTypeInfo(enableSocks, proxyIP, proxyIPs, newSocks5s, socks5List, RproxyIP);

        let settingsInfo = '<br>' + connectionInfoHtml;

        if (sub) {
            settingsInfo += `<br>SUB: ${sub}${editLink}<br>`;
        } else {
            settingsInfo += `<br>您的内容参数${editLink}<br>`;
            settingsInfo += buildAddressListsHtml();
        }
        // --- END OF OPTIMIZED LOGIC ---

		const details = `
			<!DOCTYPE html>
			<html lang="zh-CN">
			<head>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<title>${FileName} 服务信息</title>
				<style>
					:root {
						--primary-color: #0d6efd;
						--secondary-color: #0b5ed7;
						--border-color: #e0e0e0;
						--text-color: #212529;
						--background-color: #f5f5f5;
						--section-bg: #ffffff;
						--link-color: #1a0dab;
						--visited-link-color: #6c00a2;
					}

					html.dark-mode {
						--primary-color: #589bff;
						--secondary-color: #458cff;
						--border-color: #3c3c3c;
						--text-color: #e0e0e0;
						--background-color: #1c1c1e;
						--section-bg: #2a2a2a;
						--link-color: #8ab4f8;
						--visited-link-color: #c58af9;
					}

					body {
						margin: 0;
						padding: 20px;
						font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
						line-height: 1.6;
						color: var(--text-color);
						background-color: var(--background-color);
					}

					a {
						color: var(--link-color);
						text-decoration: none;
					}

					a:visited {
						color: var(--visited-link-color);
					}

					a:hover {
						text-decoration: underline;
					}

					.container {
						max-width: 1000px;
						margin: 0 auto;
						background: var(--section-bg);
						padding: 25px;
						border-radius: 10px;
						box-shadow: 0 2px 10px rgba(0,0,0,0.1);
					}

					.section {
						margin: 20px 0;
						padding: 20px;
						background: var(--section-bg);
						border-radius: 8px;
						border: 1px solid var(--border-color);
					}

					.section-title {
						font-size: 1.2em;
						color: var(--text-color);
						margin-bottom: 15px;
						padding-bottom: 10px;
						border-bottom: 2px solid var(--border-color);
					}
					
					.config-info {
						background: #f8f9fa;
						padding: 15px;
						border-radius: 6px;
						font-family: Monaco, Consolas, "Courier New", monospace;
						font-size: 13px;
						overflow-x: auto;
					}
					
					html.dark-mode .config-info {
						background: #3a3a3a;
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
						transition: background-color: 0.2s;
					}

					.copy-button:hover {
						background: var(--secondary-color);
					}
					
					.theme-switch-wrapper {
						display: flex;
						align-items: center;
						position: fixed;
						top: 15px;
						right: 15px;
					}

					.theme-switch {
						display: inline-block;
						height: 20px;
						position: relative;
						width: 36px;
					}

					.theme-switch input {
						display:none;
					}

					.slider {
						background-color: #ccc;
						bottom: 0;
						cursor: pointer;
						left: 0;
						position: absolute;
						right: 0;
						top: 0;
						transition: .4s;
					}

					.slider:before {
						background-color: #fff;
						bottom: 3px;
						content: "";
						height: 14px;
						left: 3px;
						position: absolute;
						transition: .4s;
						width: 14px;
					}

					input:checked + .slider {
						background-color: var(--primary-color);
					}

					input:checked + .slider:before {
						transform: translateX(16px);
					}

					.slider.round {
						border-radius: 20px;
					}

					.slider.round:before {
						border-radius: 50%;
					}

					.subscription-buttons-container {
						display: flex;
						flex-wrap: wrap; 
						gap: 12px; 
						justify-content: center;
						margin-top: 15px;
					}

					.subscription-button-item {
						display: flex;
						flex-direction: column;
						align-items: center;
						gap: 8px;
						padding: 12px; 
						border-radius: 8px;
						background-color: var(--section-bg);
						min-width: 135px; 
						text-align: center;
					}

					.subscription-label {
						font-weight: 500;
						font-size: 1em;
					}

					@media (max-width: 768px) {
						body {
							padding: 10px;
						}
						.container {
							padding: 15px;
						}
						.section {
							padding: 15px;
						}
						.subscription-buttons-container {
							flex-direction: column;
						}
						.subscription-button-item {
							width: 100%;
							box-sizing: border-box;
						}
					}
				</style>
                <script>
                    (function() {
                        try {
                            const theme = localStorage.getItem('theme');
                            if (theme === 'dark-mode') {
                                document.documentElement.classList.add('dark-mode');
                            }
                        } catch (e) { console.error(e); }
                    })();
                </script>
			</head>
			<body>
				<div class="theme-switch-wrapper">
					<label class="theme-switch" for="checkbox">
						<input type="checkbox" id="checkbox" />
						<div class="slider round"></div>
					</label>
				</div>
				<div class="container">
					
					<div class="section">
						<div class="section-title">🔌 服务信息</div>
						
						<div class="subscription-buttons-container">
							
							<div class="subscription-button-item">
								<button class="copy-button" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}')">通用</button>
							</div>

							<div class="subscription-button-item">
								<button class="copy-button" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?b64')">Base64</button>
							</div>

							<div class="subscription-button-item">
								<button class="copy-button" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?clash')">Clash</button>
							</div>

							<div class="subscription-button-item">
								<button class="copy-button" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sb')">Sing-box</button>
							</div>

						</div>
					</div>

					<div class="section">
						<div class="section-title">🔧 设置信息</div>
						<div class="config-info">
							HOST: ${hostName}<br>
							UUID: ${userID}<br>
							FKID: ${fakeUserID}<br>
							UA: ${UA}<br>
							${settingsInfo.replace(/\n/g, '<br>')}
						</div>
					</div>
				</div>

				<script>
					function copyToClipboard(text) {
						navigator.clipboard.writeText(text).then(() => {
							alert('已复制到剪贴板');
						}).catch(err => {
							console.error('复制失败:', err);
							alert('复制失败，请检查浏览器权限或手动复制。');
						});
					}
					
					const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
					
					(function() {
						const currentTheme = localStorage.getItem('theme');
						if (currentTheme === 'dark-mode') {
							toggleSwitch.checked = true;
						}
					})();

					function switchTheme(e) {
						if (e.target.checked) {
							document.documentElement.classList.add('dark-mode');
							localStorage.setItem('theme', 'dark-mode');
						} else {
							document.documentElement.classList.remove('dark-mode');
							localStorage.setItem('theme', 'light-mode');
						}    
					}

					toggleSwitch.addEventListener('change', switchTheme, false);

				</script>
			</body>
			</html>
		`;
		return details;
	} else {
		if (sub && sub.trim() !== '') {
			let subUrl = `https://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID}&path=${encodeURIComponent('/')}`;
			let isBase64 = true;			
			try {
				const response = await fetch(subUrl, {
					headers: {
						'User-Agent': UA + atob('IENGLVdvcmtlcnMtZWRnZXR1bm5lbC9jbWxpdQ==')
					}
				});
				const content = await response.text();
				if (_url.pathname == `/${fakeUserID}`) return content;
				return decodeIntegrationData(content, userID, hostName, fakeUserID, fakeHostName, isBase64);
			} catch (error) {
				console.error('Error fetching SUB content:', error);
				return `Error fetching SUB content: ${error.message}`;
			}

		} else {
			if (hostName.includes(".workers.dev") || noTLS === 'true') {
				noTLS = 'true';
				fakeHostName = `${fakeHostName}.workers.dev`;
			} else if (hostName.includes(".pages.dev")) {
				fakeHostName = `${fakeHostName}.pages.dev`;
			} else if (hostName.includes("worker") || hostName.includes("notls")) {
				noTLS = 'true';
				fakeHostName = `notls${fakeHostName}.net`;
			} else {
				fakeHostName = `${fakeHostName}.xyz`;
			}

			const nodeObjects = await prepareNodeList(fakeHostName, fakeUserID, noTLS);
			
			let configContent = '';
			let contentType = 'text/plain;charset=utf-8';
			let finalFileName = FileName;
			const isBrowser = userAgent.includes('mozilla');
			
			const wantsClash = (userAgent.includes('clash') && !userAgent.includes('nekobox')) || _url.searchParams.has('clash');
			const wantsSingbox = userAgent.includes('sing-box') || userAgent.includes('singbox') || _url.searchParams.has('singbox') || _url.searchParams.has('sb');

			if (wantsClash) {
				configContent = generateClashConfig(nodeObjects);
				contentType = isBrowser ? 'text/plain;charset=utf-8' : 'application/x-yaml;charset=utf-8';
				finalFileName  = `${FileName}.yaml`;
			} else if (wantsSingbox) {
				configContent = generateSingboxConfig(nodeObjects);
				contentType = isBrowser ? 'text/plain;charset=utf-8' : 'application/json;charset=utf-8';
				finalFileName = `${FileName}.json`;
			} else {
				const base64Config = generateClientConfig(nodeObjects);
				const restoredConfig = decodeIntegrationData(base64Config, userID, hostName, fakeUserID, fakeHostName, true);
				return new Response(restoredConfig);
			}
			
			const finalContent = decodeIntegrationData(configContent, userID, hostName, fakeUserID, fakeHostName, false); 

			const headers = {
				"Content-Type": contentType,
			};

			if (!isBrowser) {
				headers["Content-Disposition"] = `attachment; filename=${finalFileName}; filename*=utf-8''${encodeURIComponent(finalFileName)}`;
			}
		   
			return new Response(finalContent, { headers });
		}
	}
}

async function 整理优选列表(api) {
    if (!api || api.length === 0) return [];

    let newapi = "";
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    try {
        const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'User-Agent': atob('Q0YtV29ya2Vycy1lZGdldHVubmVsL2NtbGl1')
            },
            signal: controller.signal
        }).then(response => response.ok ? response.text() : Promise.reject())));

        for (const [index, response] of responses.entries()) {
            if (response.status === 'fulfilled') {
                const content = response.value;
                const currentApiUrl = api[index];
                const lines = content.split(/\r?\n/);

                const portMatchInUrl = currentApiUrl.match(/port=([^&]*)/);
                const 链接指定端口 = portMatchInUrl ? portMatchInUrl[1] : null;

                const idMatchInUrl = currentApiUrl.match(/id=([^&]*)/);
                const 链接指定备注 = idMatchInUrl ? idMatchInUrl[1] : '';

                if (lines.length > 0 && lines[0].split(',').length > 3) {
                    // CSV 格式处理
                    const 测速端口 = 链接指定端口 || '443';
                    const 备注 = 链接指定备注;
                    for (let i = 1; i < lines.length; i++) {
                        const columns = lines[i].split(',');
                        if (columns[0]) {
                            const addressWithPort = `${columns[0]}:${测速端口}`;
                            newapi += `${addressWithPort}${备注 ? `#${备注}` : ''}\n`;
                            if (currentApiUrl.includes('proxyip=true') && !httpsPorts.includes(测速端口)) {
                                proxyIPPool.push(addressWithPort);
                            }
                        }
                    }
                } else {
                    // 纯文本格式处理
                    const linesFromApi = content.split(/\r?\n/).filter(Boolean);
                    linesFromApi.forEach(line => {
                        const baseItem = line.trim().split('#')[0];
                        const originalRemark = line.trim().includes('#') ? line.trim().split('#')[1] : '';
                        
                        const finalRemark = 链接指定备注 || originalRemark;
                        
                        let finalBaseItem = baseItem;
                        if (baseItem && !baseItem.includes(':') && 链接指定端口) {
                            finalBaseItem = `${baseItem}:${链接指定端口}`;
                        }
                        
                        if (finalBaseItem) {
                            const processedLine = `${finalBaseItem}${finalRemark ? `#${finalRemark}` : ''}`;
                            newapi += processedLine + '\n';
                            
                            if (currentApiUrl.includes('proxyip=true')) {
                                if (finalBaseItem.includes(':')) {
                                    const port = finalBaseItem.split(':')[1];
                                    if (!httpsPorts.includes(port)) {
                                        proxyIPPool.push(finalBaseItem);
                                    }
                                } else {
                                    proxyIPPool.push(`${finalBaseItem}:443`);
                                }
                            }
                        }
                    });
                }
            }
        }
    } catch (error) {
        console.error(error);
    } finally {
        clearTimeout(timeout);
    }

    return 整理(newapi);
}


async function 整理测速结果(tls) {
	if (!addressescsv || addressescsv.length === 0) {
		return [];
	}

	let newAddressescsv = [];

	for (const csvUrl of addressescsv) {
		try {
			const response = await fetch(csvUrl);

			if (!response.ok) {
				console.error('获取CSV地址时出错:', response.status, response.statusText);
				continue;
			}

			const text = await response.text();
			let lines;
			if (text.includes('\r\n')) {
				lines = text.split('\r\n');
			} else {
				lines = text.split('\n');
			}

			const header = lines[0].split(',');
			const tlsIndex = header.indexOf('TLS');

			const ipAddressIndex = 0;
			const portIndex = 1;
			const dataCenterIndex = tlsIndex + remarkIndex;

			if (tlsIndex === -1) {
				console.error('CSV文件缺少必需的字段');
				continue;
			}

			for (let i = 1; i < lines.length; i++) {
				const columns = lines[i].split(',');
				const speedIndex = columns.length - 1;
				if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
					const ipAddress = columns[ipAddressIndex];
					const port = columns[portIndex];
					const dataCenter = columns[dataCenterIndex];

					const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
					newAddressescsv.push(formattedAddress);
					if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'true' && !httpsPorts.includes(port)) {
						proxyIPPool.push(`${ipAddress}:${port}`);
					}
				}
			}
		} catch (error) {
			console.error('获取CSV地址时出错:', error);
			continue;
		}
	}

	return newAddressescsv;
}

async function prepareNodeList(host, UUID, noTLS) {
    let nodeCounter = 1;
    const allSources = [];

    // 1. 统一收集所有地址源，并标记来源
    // 官方(直连地址)
    [...new Set(adds)].forEach(addr => allSources.push({ address: addr, source: 'adds' }));
    
    // 官方 (API地址)
    const newAddsApi = await 整理优选列表(addsapi);
    [...new Set(newAddsApi)].forEach(addr => allSources.push({ address: addr, source: 'adds' }));

    // 用户 (TLS)
    const newAddressesapi = await 整理优选列表(addressesapi);
    const newAddressescsv = await 整理测速结果('TRUE');
    [...new Set(addresses.concat(newAddressesapi).concat(newAddressescsv))]
        .forEach(addr => allSources.push({ address: addr, source: 'add', tls: true }));

    // 用户 (noTLS)
    if (noTLS === 'true') {
        const newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
        const newAddressesnotlscsv = await 整理测速结果('FALSE');
        [...new Set(addressesnotls.concat(newAddressesnotlsapi).concat(newAddressesnotlscsv))]
            .forEach(addr => allSources.push({ address: addr, source: 'add', tls: false }));
    }

    // 2. 统一处理
    const finalNodeObjects = allSources.flatMap(sourceItem => {
        const { address: addressString, source } = sourceItem;
        const tls = source === 'adds' ? noTLS !== 'true' : sourceItem.tls;
        
        let server, initialPort = "-1", name = addressString;

        const match = addressString.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (match) {
            server = match[1] || addressString;
            initialPort = match[2] || "-1";
            name = match[3] || server;
        }

        let portsToUse = [];

        if (source === 'adds') {
            // 官方列表逻辑
            if (initialPort !== "-1") {
                portsToUse.push(initialPort);
            } else {
                const selectedPorts = tls 
                    ? (httpsPorts.length > 0 ? httpsPorts : ["443"]) 
                    : (httpPorts.length > 0 ? httpPorts : ["80"]);
                portsToUse.push(...selectedPorts);
            }
        } else { // source === 'add'
            // 用户列表逻辑
            if (initialPort !== "-1") {
                portsToUse.push(initialPort);
            } else {
                let port = tls ? "443" : "80"; // 默认值
                const portList = tls 
                    ? ["443", "2053", "2083", "2087", "2096", "8443"] 
                    : ["80", "8080", "8880", "2052", "2082", "2086", "2095"];
                if (!isValidIPv4(server)) {
                    for (let p of portList) {
                        if (server.includes(p)) {
                            port = p;
                            break;
                        }
                    }
                }
                portsToUse.push(port);
            }
        }

        // 为每个确定的端口创建对象
        return portsToUse.map(port => {
            let finalName = name;
            let servername = host;
            let finalPath = generateRandomPath();
            
            if (proxyhosts.length > 0 && servername.includes('.workers.dev')) {
                finalPath = `/${servername}${finalPath}`;
                servername = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
                finalName += ` (via ${servername.substring(0,10)}...)`;
            }

            // 附加全局唯一的编号
            finalName = `${finalName} #${nodeCounter++}`;

            return {
                name: finalName,
                type: atob(protocolEncodedFlag),
                server: server,
                port: parseInt(port, 10),
                uuid: UUID,
                network: 'ws',
                tls: tls,
                servername: servername,
                'client-fingerprint': tls ? getRandomFingerprint() : '',
                'ws-opts': {
                    path: finalPath,
                    headers: {
                        Host: servername
                    }
                }
            };
        });
    });

    return finalNodeObjects.filter(Boolean);
}


//生成 Base64 编码内容
function generateClientConfig(nodeObjects) {
    	const protocolType = atob(protocolEncodedFlag);
	const secureProtoLinks = nodeObjects.map(node => {
		const cxw = `${protocolType}://${node.uuid}@${node.server}:${node.port}?` +
			`${atob('ZW5jcnlwdGlvbj1ub25l')}&` +
			`${atob('c2VjdXJpdHk=')}=${node.tls ? atob('dGxz') : atob('bm9uZQ==')}&` +
			`${node.tls ? `${atob('c25p')}=${node.servername}&` : ''}` +
			`${node.tls ? `${atob('ZnA=')}=${node['client-fingerprint']}&` : ''}` +
			`${atob('dHlwZQ==')}=${node.network}&` +
			`${atob('aG9zdA==')}=${node.servername}&` +
			`${atob('cGF0aA==')}=${encodeURIComponent(node['ws-opts'].path)}` +
			`${atob('Iw==')}${encodeURIComponent(node.name)}`;
		return cxw;
	}).join('\n');
    
    let finalLinks = secureProtoLinks;
    if (link.length > 0) {
        finalLinks += '\n' + link.join('\n');
    }
	return btoa(finalLinks);
}

function generateClashConfig(nodeObjects) {
    const header = `
# =================================================================
#      System Performance & Network Routing Configuration
# =================================================================
#
# File Version: 2.7.3
# Last Modified: ${new Date().toISOString()}
#
# !! DO NOT EDIT THIS FILE MANUALLY !!
# Changes should be deployed via the central configuration management system.
#
# monitoring settings for internal services.
#
`;

    const proxiesYaml = nodeObjects.map(p => {
        let entryConfig = `  - name: ${JSON.stringify(p.name)}\n`;
        entryConfig += `    ${atob('dHlwZQ==')}: ${p.type}\n`;
        entryConfig += `    ${atob('c2VydmVy')}: ${p.server}\n`;
        entryConfig += `    ${atob('cG9ydA==')}: ${p.port}\n`;
        entryConfig += `    ${atob('dXVpZA==')}: ${p.uuid}\n`;
        entryConfig += `    ${atob('bmV0d29yaw==')}: ${p.network}\n`;
        entryConfig += `    ${atob('dGxz')}: ${p.tls}\n`;
        entryConfig += `    ${atob('dWRw')}: true\n`;
        if (p.tls) {
            entryConfig += `    ${atob('c2VydmVybmFtZQ==')}: ${p.servername}\n`;
            if (p['client-fingerprint']) {
                entryConfig += `    ${atob('Y2xpZW50LWZpbmdlcnByaW50')}: ${p['client-fingerprint']}\n`;
            }
        }
        if (p['ws-opts']) {
            entryConfig += `    ${atob('d3Mtb3B0cw==')}:\n`;
            entryConfig += `      ${atob('cGF0aA==')}: ${JSON.stringify(p['ws-opts'].path)}\n`;
            if (p['ws-opts'].headers && p['ws-opts'].headers.Host) {
                entryConfig += `      ${atob('aGVhZGVycw==')}:\n`;
                entryConfig += `        ${atob('SG9zdA==')}: ${p['ws-opts'].headers.Host}\n`;
            }
        }
        return entryConfig;
    }).join('');

    const proxyNames = nodeObjects.map(p => p.name);
    
    const healthCheckGroupName = "自动";
    const primaryRouteGroupName = "手动";
    const bypassGroupName = "直连";
    const rejectGroupName = "广告拦截";


    const customRulesArray = [
        '# Rule set for internal traffic management',
        `GEOSITE,category-ads-all,${rejectGroupName}`, 
        `GEOSITE,private,${bypassGroupName}`,          
        `GEOIP,private,${bypassGroupName},no-resolve`, 
        `GEOSITE,cn,${bypassGroupName}`,               
        `GEOIP,CN,${bypassGroupName}`,                 
        '# Default traffic is routed through the primary data path',
        `MATCH,${primaryRouteGroupName}`   
    ];

    const rulesYaml = customRulesArray.map(rule => `  - ${rule}`).join('\n');

    const footer = `
# --- END OF CONFIGURATION ---
# checksum: ${Math.random().toString(36).substring(2)}
`;
    
    const config = `
${header}
# Core service ports
mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

# DNS settings for service discovery
dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: true
  enhanced-mode: redir-host
  nameserver:
    - 223.5.5.5
    - https://dns.google/dns-query
  nameserver-policy:
    'geosite:cn': '223.5.5.5'

# Network interface card (NIC) layer settings
tun:
  enable: true
  stack: mixed
  auto-route: true
  strict-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53

# Data entry points (DEPs)
proxies:
${proxiesYaml}

# Traffic routing policies
proxy-groups:
  - name: ${JSON.stringify(healthCheckGroupName)}
    # Type: Latency-based health check
    type: url-test
    proxies:
${proxyNames.map(name => `      - ${JSON.stringify(name)}`).join('\n')}
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
    
  - name: ${JSON.stringify(primaryRouteGroupName)}
    # Type: Manual selection with failover
    type: select
    proxies:
      - ${JSON.stringify(healthCheckGroupName)}
      - ${JSON.stringify(bypassGroupName)}
      - ${JSON.stringify(rejectGroupName)}
${proxyNames.map(name => `      - ${JSON.stringify(name)}`).join('\n')}

  - name: ${JSON.stringify(bypassGroupName)}
    type: select
    proxies:
      - DIRECT
      
  - name: ${JSON.stringify(rejectGroupName)}
    type: select
    proxies:
      - REJECT

# Access Control List (ACL)
rules:
${rulesYaml}

${footer}
`;
    return config.trim();
}

function generateSingboxConfig(nodeObjects) {
    const outbounds = nodeObjects.map(p => {
        let outbound = {
            type: p.type,
            tag: p.name,
            server: p.server,
            server_port: p.port,
            uuid: p.uuid,
            transport: {
                type: p.network,
                path: p['ws-opts'].path,
                headers: {
                    Host: p.servername 
                }
            }
        };

        if (p.tls) {
            outbound.tls = {
                enabled: true,
                server_name: p.servername,
                utls: {
                    enabled: true,
                    fingerprint: p['client-fingerprint']
                }
            };
        }
        return outbound;
    });

    const proxyNames = outbounds.map(o => o.tag);

    const config = {
        "log": {
            "level": "error",
            "timestamp": true
        },
        "dns": {
            "servers": [{
                "tag": "proxy-dns",
                "server": "8.8.8.8",
                "detour": "proxy",
                "type": "https"
            }, {
                "tag": "local-dns",
                "type": "local",
                "detour": "direct"
            }, {
                "tag": "direct-dns",
                "server": "223.5.5.5",
                "type": "https"
            }],
            "rules": [{
                "rule_set": "geosite-cn", 
                "server": "direct-dns"
            }, {
                "server": "proxy-dns",
                "source_ip_cidr": [
                    "172.19.0.1/30",
                    "fdfe:dcba:9876::1/126"
                ]
            }, {
                "clash_mode": "直连",
                "server": "direct-dns"
            }, {
                "clash_mode": "全局",
                "server": "proxy-dns"
            }],
            "strategy": "prefer_ipv4",
            "final": "proxy-dns",
            "independent_cache": true
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "stack": "mixed",
            "mtu": 9000,
            "auto_route": true,
            "address": [
                "172.19.0.1/30",
                "fdfe:dcba:9876::1/126"
            ],
            "platform": {
                "http_proxy": {
                    "enabled": true,
                    "server": "127.0.0.1",
                    "server_port": 7890
                }
            }
        }, {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 7890
        }],
        "outbounds": [{
                "type": "selector",
                "tag": "proxy",
                "outbounds": [
                    "auto",
                    ...proxyNames
                ],
                "default": "auto"
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": proxyNames,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m0s",
                "tolerance": 50,
                "interrupt_exist_connections": false
            },
            ...outbounds, 
            {
                "type": "direct",
                "tag": "direct",
                "domain_resolver": {
                    "server": "local-dns",
                    "strategy": "prefer_ipv4"
                }
            },
            {
                "type": "block",
                "tag": "block"
            }
        ],
        "route": {
            "auto_detect_interface": true,
            "default_domain_resolver": "direct-dns",
            "final": "proxy",
            "override_android_vpn": true,
            "rule_set": [{
                    "tag": "geosite-ads",
                    "type": "remote",
                    "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geoip-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs",
                    "download_detour": "direct"
                }
            ],
            "rules": [{
                "action": "sniff",
                "timeout": "1s"
            }, {
                "action": "hijack-dns",
                "protocol": "dns"
            }, {
                "ip_is_private": true, 
                "outbound": "direct"
            }, {
                "clash_mode": "直连",
                "outbound": "direct"
            }, {
                "outbound": "direct",
                "rule_set": [
                    "geosite-cn",
                    "geoip-cn"
                ]
            }, {
                "outbound": "block",
                "rule_set": "geosite-ads"
            }, {
                "clash_mode": "全局",
                "outbound": "proxy"
            }]
        },
        "experimental": {
            "cache_file": {
                "enabled": true
            }
        }
    };

    return JSON.stringify(config, null, 2);
}

function 整理(内容) {
    return (内容 || '')
        .split(/[\s,|"'\r\n]+/)
        .filter(Boolean);
}

function isValidIPv4(address) {
	const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
	return ipv4Regex.test(address);
}

async function KV(request, env) {
	try {
		if (request.method === "POST") {
			return await handlePostRequest(request, env);
		}
		return await handleGetRequest(env);
	} catch (error) {
		console.error('处理请求时发生错误:', error);
		return new Response("服务器错误: " + error.message, {
			status: 500,
			headers: { "Content-Type": "text/plain;charset=utf-8" }
		});
	}
}

async function handlePostRequest(request, env) {
    const url = new URL(request.url);
    const action = url.searchParams.get('action');

    // 根据 'action' 参数进行路由
    if (action === 'test') {
        return handleTestConnection(request);
    }

    // 默认行为是保存配置
    if (!env.KV) {
        return new Response("未绑定KV空间", { status: 400 });
    }
    try {
        const settingsJSON = await env.KV.get('settinggs.txt');
        let settings = settingsJSON ? JSON.parse(settingsJSON) : {};

        const updates = await request.json();
        
        // 合并更新
        settings = { ...settings, ...updates };

        await env.KV.put('settinggs.txt', JSON.stringify(settings, null, 2));

        // --- 清除内存缓存以实现即时生效 ---
		cachedSettings = null;
		console.log("配置已更新，内存缓存已清除。");
		
        return new Response("保存成功");
    } catch (error) {
        console.error('保存KV时发生错误:', error);
        return new Response("保存失败: " + error.message, { status: 500 });
    }
}

// #################################################################
// ############## START OF TABBED UI REPLACEMENT ###################
// #################################################################

async function handleGetRequest(env) {
    let content = '';
    let addsContent = '';
    let hasKV = !!env.KV;
    let proxyIPContent = '';
    let socks5Content = '';
    let subContent = '';
	let httpsPortsContent = '';
    let httpPortsContent = '';
    let noTLSContent = 'false';
    
    let fallback64Content = ''; 
    let fallback64Enabled = false;

    if (hasKV) {
        try {
            const advancedSettingsJSON = await env.KV.get('settinggs.txt');
            if (advancedSettingsJSON) {
                const settings = JSON.parse(advancedSettingsJSON);
                content = settings.ADD || ''; 
                addsContent = settings.ADDS || '';
                proxyIPContent = settings.proxyip || '';
                socks5Content = settings.socks5 || '';
                subContent = settings.sub || '';
				httpsPortsContent = settings.httpsports || httpsPorts.join(',');
                httpPortsContent = settings.httpports || httpPorts.join(',');
                noTLSContent = settings.notls || 'false';
                fallback64Content = settings.fallback64 || ''; 
                fallback64Enabled = settings.fallback64Enabled === 'true';
            } else {
				httpsPortsContent = httpsPorts.join(',');
				httpPortsContent = httpPorts.join(',');
			}
        } catch (error) {
            console.error('读取KV时发生错误:', error);
            content = '读取数据时发生错误: ' + error.message;
        }
    }
	
	// 为端口选择框生成HTML
    const defaultHttpsPorts = ["443", "2053", "2083", "2087", "2096", "8443"];
    const defaultHttpPorts = ["80", "8080", "8880", "2052", "2082", "2086", "2095"];

    const savedHttpsPorts = httpsPortsContent.split(',');
    const allHttpsPorts = [...new Set([...defaultHttpsPorts, ...savedHttpsPorts])].filter(p => p.trim() !== "");
    const httpsCheckboxesHTML = allHttpsPorts.map(port => {
        const isChecked = savedHttpsPorts.includes(port.trim());
        return `<div class="checkbox-item">
                    <input type="checkbox" id="https-port-${port.trim()}" name="httpsports" value="${port.trim()}" ${isChecked ? 'checked' : ''}>
                    <label for="https-port-${port.trim()}">${port.trim()}</label>
                </div>`;
    }).join('\n');

    const savedHttpPorts = httpPortsContent.split(',');
    const allHttpPorts = [...new Set([...defaultHttpPorts, ...savedHttpPorts])].filter(p => p.trim() !== "");
    const httpCheckboxesHTML = allHttpPorts.map(port => {
        const isChecked = savedHttpPorts.includes(port.trim());
        return `<div class="checkbox-item">
                    <input type="checkbox" id="http-port-${port.trim()}" name="httpports" value="${port.trim()}" ${isChecked ? 'checked' : ''}>
                    <label for="http-port-${port.trim()}">${port.trim()}</label>
                </div>`;
    }).join('\n');

    const html = `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <title>服务设置</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                :root {
                    --primary-color: #0d6efd;
                    --secondary-color: #0b5ed7;
                    --border-color: #e0e0e0;
                    --text-color: #212529;
                    --background-color: #f5f5f5;
					--section-bg: white;
					--link-color: #1a0dab;
					--visited-link-color: #6c00a2;
                    --tab-inactive-bg: #f1f1f1;
                }

                html.dark-mode {
                    --primary-color: #589bff;
                    --secondary-color: #458cff;
                    --border-color: #3c3c3c;
                    --text-color: #e0e0e0;
                    --background-color: #1c1c1e;
					--section-bg: #2a2a2a;
					--link-color: #8ab4f8;
					--visited-link-color: #c58af9;
                    --tab-inactive-bg: #3a3a3a;
                }

                body {
                    margin: 0;
                    padding: 20px;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    line-height: 1.6;
                    color: var(--text-color);
                    background-color: var(--background-color);
				}

                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                    background: var(--section-bg);
                    padding: 25px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }

                .title {
                    font-size: 1.5em;
                    color: var(--text-color);
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid var(--border-color);
                }

                /* --- Tabbed Interface Styles --- */
                .tab-container {
                    overflow: hidden;
                    border: 1px solid var(--border-color);
                    border-bottom: none;
                    border-radius: 8px 8px 0 0;
                    background-color: var(--tab-inactive-bg);
                }

                .tab-container button {
                    background-color: inherit;
                    float: left;
                    border: none;
                    outline: none;
                    cursor: pointer;
                    padding: 14px 16px;
                    font-size: 16px;
                    color: var(--text-color);
                }
                
                .tab-container button:hover {
                    background-color: #ddd;
                }
                html.dark-mode .tab-container button:hover {
                     background-color: #444;
                }

                .tab-container button.active {
                    background-color: var(--section-bg);
                    font-weight: bold;
                    border-bottom: 2px solid var(--primary-color);
                    padding-bottom: 12px;
                }
				
                .tab-content {
                    display: none;
                    padding: 20px;
                    border: 1px solid var(--border-color);
                    border-top: none;
                    border-radius: 0 0 8px 8px;
                    animation: fadeEffect 0.5s;
				}
                
                @keyframes fadeEffect {
                    from {opacity: 0;}
                    to {opacity: 1;}
                }
                /* --- End Tabbed Styles --- */

                .editor {
                    width: 100%;
                    height: 520px;
                    padding: 15px; box-sizing: border-box; border: 1px solid var(--border-color);
                    border-radius: 8px; font-family: Monaco, Consolas, "Courier New", monospace;
                    font-size: 14px; line-height: 1.5; resize: vertical;
                    background-color: var(--section-bg); color: var(--text-color);
                }
				
                .editor:focus, .setting-editor:focus {
                    outline: none;
                    border-color: var(--primary-color);
                    box-shadow: 0 0 0 2px color-mix(in srgb, var(--primary-color) 25%, transparent);
                }

                .setting-item { margin-bottom: 20px; }
                .setting-item p { margin: 0 0 8px 0; color: #666; }
                html.dark-mode .setting-item p { color: #bbb; }

                .setting-editor {
                    width: 100%; min-height: 100px; padding: 10px; box-sizing: border-box;
                    border: 1px solid var(--border-color); border-radius: 4px;
                    font-family: Monaco, Consolas, "Courier New", monospace; font-size: 14px;
                    resize: vertical; background-color: var(--section-bg); color: var(--text-color);
                }

                .button-group { display: flex; align-items: center; gap: 12px; margin-top: 15px; }
                .btn { padding: 8px 20px; border: none; border-radius: 6px; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s ease; }
                .btn-primary { background: var(--primary-color); color: #fff; }
                .btn-primary:hover:not(:disabled) { background: var(--secondary-color); }
                .btn-secondary { background: #6c757d; color: #fff; }
                .btn-secondary:hover:not(:disabled) { background: #5c636a; }
                .save-status { font-size: 14px; color: var(--text-color); }

                .test-group { display: flex; align-items: center; gap: 10px; margin-top: 8px; }
                .btn-sm { padding: 5px 10px; font-size: 12px; }
                .test-status { font-size: 14px; font-weight: 500; }
                .test-status.success { color: #28a745; }
                .test-status.error { color: #dc3545; }
                .test-note { 
                    font-size: 14px;
                    color: #6c757d;
                    align-self: center;
                    padding-left: 5px;
                }
                html.dark-mode .test-note { color: #aaa; }
                
                .test-results-container {
                    margin-top: 10px;
                    padding: 10px;
                    border: 1px solid var(--border-color);
                    border-radius: 6px;
                    max-height: 200px;
                    overflow-y: auto;
                    font-family: Monaco, Consolas, "Courier New", monospace;
                    font-size: 13px;
                    display: none; 
                }
                .test-result-item {
                    padding: 4px 0;
                    border-bottom: 1px dashed var(--border-color);
                }
                .test-result-item:last-child {
                    border-bottom: none;
                }
                .test-result-item .success { color: #28a745; font-weight: bold; }
                .test-result-item .error { color: #dc3545; font-weight: bold; }
				
                .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(80px, 1fr)); gap: 10px; margin-top: 10px; }
                .checkbox-item { display: flex; align-items: center; gap: 5px; }

                a { color: var(--link-color); text-decoration: none; }
                a:visited { color: var(--visited-link-color); }
                a:hover { text-decoration: underline; }

                /* --- Switch Styles --- */
                .switch-container { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }
                .theme-switch-wrapper { display: flex; align-items: center; position: fixed; top: 15px; right: 15px; }
                .theme-switch { display: inline-block; height: 20px; position: relative; width: 36px; }
                .theme-switch input { display:none; }
                .slider { background-color: #ccc; bottom: 0; cursor: pointer; left: 0; position: absolute; right: 0; top: 0; transition: .4s; }
                .slider:before { background-color: #fff; bottom: 3px; content: ""; height: 14px; left: 3px; position: absolute; transition: .4s; width: 14px; }
                input:checked + .slider { background-color: var(--primary-color); }
                input:checked + .slider:before { transform: translateX(16px); }
                .slider.round { border-radius: 20px; }
                .slider.round:before { border-radius: 50%; }

            </style>
            <script>
                (function() {
                    try {
                        const theme = localStorage.getItem('theme');
                        if (theme === 'dark-mode') {
                            document.documentElement.classList.add('dark-mode');
                        }
                    } catch (e) { console.error(e); }
                })();
            </script>
        </head>
        <body>
            <div class="theme-switch-wrapper">
                <label class="theme-switch" for="theme-checkbox">
                    <input type="checkbox" id="theme-checkbox" />
                    <div class="slider round"></div>
                </label>
            </div>
            <div class="container">
                <div class="title">📝 ${FileName} 服务设置</div>

                <div class="tab-container">
                    <button class="tab-link active" onclick="openTab(event, 'tab-main')">自定义端点</button>
                    <button class="tab-link" onclick="openTab(event, 'tab-adds')">官方端点</button>
                    <button class="tab-link" onclick="openTab(event, 'tab-proxy')">ID设置</button>
                    <button class="tab-link" onclick="openTab(event, 'tab-sub')">订阅设置</button>
                </div>

                <div id="tab-main" class="tab-content" style="display: block;">
                    ${hasKV ? `
                        <textarea class="editor" id="content" placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=='))}">${content}</textarea>

                        <div class="button-group">
                            <button class="btn btn-secondary" onclick="goBack()">返回服务页</button>
                            <button class="btn btn-primary" onclick="saveAddTab(this)">保存</button>
                            <span class="save-status" id="saveStatus"></span>
                        </div>
                    ` : '<p>未绑定KV空间</p>'}
                </div>

                <div id="tab-adds" class="tab-content">
                    ${hasKV ? `
                        <div class="setting-item" style="border-bottom: 1px solid var(--border-color); padding-bottom: 20px; margin-bottom: 20px;">
                            <h4>端口设置</h4>
                            <p>启用 noTLS (将不使用 TLS 加密)</p>
                            <div class="switch-container">
                                <label class="theme-switch" for="notls-checkbox">
                                    <input type="checkbox" id="notls-checkbox" ${noTLSContent === 'true' ? 'checked' : ''}>
                                    <div class="slider round"></div>
                                </label>
                                <span>启用 noTLS</span>
                            </div>

                            <h5 style="margin-top: 15px; margin-bottom: 5px;">TLS 端口</h5>
                            <div class="checkbox-grid" id="httpsports-grid">${httpsCheckboxesHTML}</div>
                            
                            <h5 style="margin-top: 15px; margin-bottom: 5px;">noTLS 端口</h5>
                            <div class="checkbox-grid" id="httpports-grid">${httpCheckboxesHTML}</div>
                        </div>

                        <textarea class="editor" id="adds_content" placeholder="${decodeURIComponent(atob('JTBBQUREUyVFNyVBNCVCQSVFNCVCRSU4QiVFRiVCQyU5QSUwQXZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQlMEExMjcuMC4wLjElMjNDRm5hdCUwQSU1QjI2ODYlM0E0NzY2JTNBJTNBJTVEJTIzSVB2NiUwQSUwQSUwQUFERFNBUEklRTclQTQlQkElRTQlQkUlOEIlRUYlQkMlOUElMEFodHRwcyUzQSUyRiUyRnJhdy5naXRodWJ1c2VyY29udGVudC5jb20lMkZjbWxpdSUyRldvcmtlclZsZXNzMnN1YiUyRnJlZnMlMkZoZWFkcyUyRm1haW4lMkZhZGRyZXNzZXNhcGkudHh0'))}">${addsContent}</textarea>
                        
                        <div class="button-group">
                            <button class="btn btn-secondary" onclick="goBack()">返回服务页</button>
                            <button class="btn btn-primary" onclick="saveAddsTab(this)">保存</button>
                            <span class="save-status" id="adds-save-status"></span>
                        </div>
                    ` : '<p>未绑定KV空间</p>'}
                </div>

                <div id="tab-proxy" class="tab-content">
                        <div class="setting-item">
                        <h4>PROXYIP</h4>
                                <p>每行一个IP，格式：IP:端口(可不添加端口)</p>
                                <textarea id="proxyip" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCjEuMi4zLjQlM0E4MApwcml2YXRlLmV4YW1wbGUuY29tJTNBMjA1Mg=='))}">${proxyIPContent}</textarea>
                        <div class="test-group">
                                <button type="button" class="btn btn-secondary btn-sm" onclick="testSetting(event, 'proxyip')">测试连接</button>
                                <span id="proxyip-status" class="test-status"></span>
                            <span class="test-note">（批量测试并自动移除失败地址）</span>
                            </div>
                        <div id="proxyip-results" class="test-results-container"></div>
                        </div>
                        <div class="setting-item">
                        <h4>SOCKS5</h4>
                                <p>每行一个地址，格式：[用户名:密码@]主机:端口</p>
                                <textarea id="socks5" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCnVzZXIlM0FwYXNzJTQwMTI3LjAuMC4xJTNBMTA4MAoxMjcuMC4wLjElM0ExMDgw'))}">${socks5Content}</textarea>
                         <div class="test-group">
                                <button type="button" class="btn btn-secondary btn-sm" onclick="testSetting(event, 'socks5')">测试连接</button>
                                <span id="socks5-status" class="test-status"></span>
                            <span class="test-note">（批量测试并自动移除失败地址）</span>
                            </div>
                        <div id="socks5-results" class="test-results-container"></div>
                        </div>                        
                        <div class="setting-item" style="border-top: 1px solid var(--border-color); padding-top: 20px;">
                            <h4>Fallback64 </h4>
                            <p>
                               <a id="Fallback64-link" target="_blank">自行查询</a>
                            </p>
                            <script>
                                (function() {
                                    const encodedURL = 'aHR0cHM6Ly9uYXQ2NC54eXo=';
                                    const decodedURL = atob(encodedURL);
                                    const link = document.getElementById('Fallback64-link');
                                    if (link) {
                                        link.setAttribute('href', decodedURL);
                                    }
                                })();
                            </script>
                             <div class="switch-container">
                                <label class="theme-switch" for="fallback64-switch-checkbox">
                                    <input type="checkbox" id="fallback64-switch-checkbox" ${fallback64Enabled ? 'checked' : ''}>
                                    <div class="slider round"></div>
                                </label>
                                <span>启用 Fallback64</span>
                            </div>
                            <p style="margin-top: 15px;">每行或每个逗号/空格分隔一个</p>
                            <textarea id="fallback64" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJUVGJUJDJTlBJTBBMjYwMiUzQWZjNTklM0ExMSUzQTY0JTNBJTNBJTBBMjYwMiUzQWZjNTklM0ExMSUzQTY0JTNBJTNBJTJGOTY='))}">${fallback64Content}</textarea>
							<div class="test-group">
								<button type="button" class="btn btn-secondary btn-sm" onclick="testSetting(event, 'fallback64')">测试连接</button>
								<span id="fallback64-status" class="test-status"></span>
								<span class="test-note">（将尝试连接）</span>
							</div>
							<div id="fallback64-results" class="test-results-container"></div>
                        </div>
                    <div class="button-group">
                        <button class="btn btn-secondary" onclick="goBack()">返回服务页</button>
                        <button class="btn btn-primary" onclick="saveProxyTab(this)">保存</button>
                        <span class="save-status" id="proxy-save-status"></span>
                            </div>
                        </div>

                <div id="tab-sub" class="tab-content">
                        <div class="setting-item">
                        <h4>SUB </h4>
                                <p>只支持单个地址</p>
                                <textarea id="sub" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCnN1Yi5nb29nbGUuY29tCnN1Yi5leGFtcGxlLmNvbQ=='))}">${subContent}</textarea>
                            </div>
                    <div class="button-group">
                        <button class="btn btn-secondary" onclick="goBack()">返回服务页</button>
                        <button class="btn btn-primary" onclick="saveSubTab(this)">保存</button>
                        <span class="save-status" id="sub-save-status"></span>
                    </div>
                        </div>

            </div>

            <script>
                function openTab(evt, tabName) {
                    let i, tabcontent, tablinks;
                    tabcontent = document.getElementsByClassName("tab-content");
                    for (i = 0; i < tabcontent.length; i++) {
                        tabcontent[i].style.display = "none";
                    }
                    tablinks = document.getElementsByClassName("tab-link");
                    for (i = 0; i < tablinks.length; i++) {
                        tablinks[i].className = tablinks[i].className.replace(" active", "");
                    }
                    document.getElementById(tabName).style.display = "block";
                    evt.currentTarget.className += " active";
                }

                function goBack() {
                    const pathParts = window.location.pathname.split('/');
                    pathParts.pop(); // Remove "edit"
                    const newPath = pathParts.join('/');
                    window.location.href = newPath || '/';
                }
                
                async function saveAddTab(button) {
                    const statusEl = button.parentElement.querySelector('.save-status');
                    const payload = {
                        ADD: document.getElementById('content').value
                    };
                    await saveData(button, statusEl, JSON.stringify(payload));
                }

                async function saveAddsTab(button) {
                    const statusEl = button.parentElement.querySelector('.save-status');
                    const selectedHttpsPorts = Array.from(document.querySelectorAll('input[name="httpsports"]:checked')).map(cb => cb.value).join(',');
                    const selectedHttpPorts = Array.from(document.querySelectorAll('input[name="httpports"]:checked')).map(cb => cb.value).join(',');
                    const payload = {
                        ADDS: document.getElementById('adds_content').value,
                        notls: document.getElementById('notls-checkbox').checked.toString(),
                        httpsports: selectedHttpsPorts,
                        httpports: selectedHttpPorts
                    };
                    await saveData(button, statusEl, JSON.stringify(payload));
                }

                async function saveProxyTab(button) {
                    const statusEl = button.parentElement.querySelector('.save-status');
                    const payload = {
                        proxyip: document.getElementById('proxyip').value,
                        socks5: document.getElementById('socks5').value,
                        fallback64: document.getElementById('fallback64').value,
                        fallback64Enabled: document.getElementById('fallback64-switch-checkbox').checked.toString()
                    };
                    await saveData(button, statusEl, JSON.stringify(payload));
                }

                async function saveSubTab(button) {
                    const statusEl = button.parentElement.querySelector('.save-status');
                    const payload = {
                        sub: document.getElementById('sub').value
                    };
                    await saveData(button, statusEl, JSON.stringify(payload));
                }

                async function saveData(button, statusEl, body) {
                    if (!button || !statusEl) return;
                    button.disabled = true;
                    statusEl.textContent = '保存中...';
                    try {
                        const response = await fetch(window.location.href + '?type=advanced', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: body
                        });
                        if (!response.ok) throw new Error('保存失败: ' + await response.text());
                        
                        statusEl.textContent = '保存成功';
                        setTimeout(() => { statusEl.textContent = ''; }, 3000);
                    } catch (error) {
                        statusEl.textContent = '❌ ' + error.message;
                        console.error('保存时发生错误:', error);
                    } finally {
                        button.disabled = false;
                    }
                }
                
                async function testSetting(event, type) {
                    const elementId = type;
                    const textarea = document.getElementById(elementId);
                    const statusEl = document.getElementById(type + '-status');
                    const resultsContainer = document.getElementById(type + '-results');
                    const testButton = event.target;

                    statusEl.textContent = '';
                    resultsContainer.innerHTML = '';
                    resultsContainer.style.display = 'none';

                    const originalAddresses = textarea.value.trim().split(/[\\s,]+/).map(addr => addr.trim()).filter(Boolean);
                    const total = originalAddresses.length;

                    if (total === 0) {
                        statusEl.textContent = '❌ 地址不能为空';
                        statusEl.className = 'test-status error';
                        return;
                    }

                    testButton.disabled = true;
                    statusEl.className = 'test-status';
                    resultsContainer.style.display = 'block';
                    
                    let completedCount = 0;
                    let successCount = 0;
                    const successfulAddresses = [];

                    statusEl.textContent = \`测试中 (\${completedCount}/\${total})...\`;

                    const testPromises = originalAddresses.map(async (address) => {
                        let result;
                    try {
                        const response = await fetch(window.location.href.split('?')[0] + '?action=test', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ type: type, address: address })
                        });
                            result = await response.json();
                            
                            if (!response.ok) {
                                throw new Error(result.message || \`服务器错误 \${response.status}\`);
                        }

                    } catch (error) {
                            result = { success: false, message: \`请求失败: \${error.message}\` };
                    } finally {
                            completedCount++;
                            statusEl.textContent = \`测试中 (\${completedCount}/\${total})...\`;
                            
                            const resultItem = document.createElement('div');
                            resultItem.className = 'test-result-item';
                            let statusSpan;

                            if (result.success) {
                                successCount++;
                                successfulAddresses.push(address);
                                statusSpan = \`<span class="success">✅ 成功:</span>\`;
                            } else {
                                statusSpan = \`<span class="error">❌ 失败:</span>\`;
                            }
                            
                            resultItem.innerHTML = \`\${statusSpan} \${address} - \${result.message}\`;
                            resultsContainer.appendChild(resultItem);
                        }
                    });

                    await Promise.allSettled(testPromises);

                    textarea.value = successfulAddresses.sort().join('\\n');
                    
                    const failedCount = total - successCount;
                    let finalStatusMessage = \`测试完成: \${successCount} / \${total} 成功。\`;
                    if (failedCount > 0) {
                        finalStatusMessage += \` 已自动移除 \${failedCount} 个失败地址。\`;
                    }

                    statusEl.textContent = finalStatusMessage;
                    statusEl.className = successCount > 0 ? 'test-status success' : 'test-status error';
                    testButton.disabled = false;

                    setTimeout(() => { 
                        statusEl.textContent = ''; 
                    }, 15000);
                }

                const themeToggleSwitch = document.querySelector('#theme-checkbox');
                (function() {
                    const currentTheme = localStorage.getItem('theme');
                    if (currentTheme === 'dark-mode') {
                        themeToggleSwitch.checked = true;
                    }
                })();
                function switchTheme(e) {
                    if (e.target.checked) {
                        document.documentElement.classList.add('dark-mode');
                        localStorage.setItem('theme', 'dark-mode');
                    } else {
                        document.documentElement.classList.remove('dark-mode');
                        localStorage.setItem('theme', 'light-mode');
                    }    
                }
                themeToggleSwitch.addEventListener('change', switchTheme, false);
            </script>
        </body>
        </html>
    `;

    return new Response(html, {
        headers: { "Content-Type": "text/html;charset=utf-8" }
    });
}

// #################################################################
// ############### END OF TABBED UI REPLACEMENT ####################
// #################################################################

/**
 * @param {Request} request
 * @returns {Promise<Response>}
 */
async function handleTestConnection(request) {
    if (request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
    }

    const log = (info) => { console.log(`[TestConnection] ${info}`); };
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort('连接超时 (5秒)'), 5000);

    try {
        const { type, address } = await request.json();
        if (!type || !address || address.trim() === '') {
            throw new Error('请求参数不完整或地址为空');
        }

        let successMessage = '连接成功！';

        switch (type) {
            case 'socks5': {
                const parsed = socks5AddressParser(address);
                const testSocket = await socks5Connect(2, 'www.cloudflare.com', 443, log, controller.signal, parsed);
                await testSocket.close();
                break;
            }
            case 'proxyip': {
                const { address: ip, port } = parseProxyIP(address, 443);
                const testSocket = await connect({ hostname: ip, port: port, signal: controller.signal });

                try {
                    const writer = testSocket.writable.getWriter();
                    const workerHostname = new URL(request.url).hostname;
                    
                    const httpProbeRequest = [
                        `GET / HTTP/1.1`,
                        `Host: ${workerHostname}`,
                        'User-Agent: Cloudflare-Connectivity-Test',
                        'Connection: close',
                        '\r\n'
                    ].join('\r\n');

                    await writer.write(new TextEncoder().encode(httpProbeRequest));
                    writer.releaseLock();

                    const reader = testSocket.readable.getReader();
                    const { value, done } = await reader.read();
                    
                    if (done || !value) {
                        throw new Error("连接已关闭，未收到任何响应。");
                    }

                    const responseText = new TextDecoder().decode(value);
                    if (responseText.toLowerCase().includes('server: cloudflare')) {
                        successMessage = '连接成功';
                    } else {
                        throw new Error("该IP可能无效。");
                    }
                    
                    await testSocket.close();
                    reader.releaseLock();

                } catch(err) {
                    if (testSocket) await testSocket.close();
                    throw err;
                }
                break;
            }
			case 'fallback64': {
                const prefix = address;
                if (!prefix || !/::(?:\/\d{1,3})?$/.test(prefix)) {
                     throw new Error("无效的 Fallback64 ");
                }

                const testDomain = 'www.cloudflare.com';
                const testPath = '/cdn-cgi/trace';
                const dnsUrl = `https://cloudflare-dns.com/dns-query?name=${testDomain}&type=A`;
                const dnsResponse = await fetch(dnsUrl, { headers: { 'Accept': 'application/dns-json' }, signal: controller.signal });
                if (!dnsResponse.ok) throw new Error('DNS查询失败');
                const dnsData = await dnsResponse.json();
                const ipv4 = (dnsData.Answer || []).find(record => record.type === 1)?.data;
                if (!ipv4) throw new Error(`未能找到 ${testDomain} 的 IPv4 地址`);

                const ipv4Parts = ipv4.split('.').map(part => parseInt(part, 10).toString(16).padStart(2, '0'));
                
                const prefixPart = prefix.split('/96')[0];
                const synthesizedIPv6 = prefixPart + ipv4Parts[0] + ipv4Parts[1] + ":" + ipv4Parts[2] + ipv4Parts[3];
                
                let testSocket;
                try {
                    testSocket = await connect({ hostname: `[${synthesizedIPv6}]`, port: 80, signal: controller.signal });
                    log(`Fallback64 Test: TCP 连接成功。`);
                    
                    const writer = testSocket.writable.getWriter();
                    const httpProbeRequest = [
                        `GET ${testPath} HTTP/1.1`,
                        `Host: ${testDomain}`,
                        'User-Agent: Cloudflare-Fallback64-Test',
                        'Connection: close',
                        '\r\n'
                    ].join('\r\n');

                    await writer.write(new TextEncoder().encode(httpProbeRequest));
                    writer.releaseLock();
                    
                    const reader = testSocket.readable.getReader();
                    const { value, done } = await reader.read();

                    if (done || !value) {
                        throw new Error("连接已关闭，未收到任何响应。");
                    }
                    
                    const responseText = new TextDecoder().decode(value);
                    if (responseText.includes(`h=${testDomain}`) && responseText.includes('colo=')) {
                        successMessage = `可用！成功通过 ${testDomain} 验证`;
                    } else {
                        throw new Error("响应无效，或非 Cloudflare trace 信息。");
                    }
                    reader.releaseLock();
                } finally {
                     if (testSocket) {
                        await testSocket.close();
                    }
                }
                break;
            }
            default:
                throw new Error('不支持的测试类型');
        }
        
        log(`Test successful for ${type}: ${address}`);
        return new Response(JSON.stringify({ success: true, message: successMessage }), { 
            status: 200,
            headers: { 'Content-Type': 'application/json;charset=utf-8' } 
        });

    } catch (err) {
        console.error(`[TestConnection] Error: ${err.stack || err}`);
        return new Response(JSON.stringify({ success: false, message: `测试失败: ${err.message}` }), { 
            status: 200, 
            headers: { 'Content-Type': 'application/json;charset=utf-8' } 
        });
    } finally {
        clearTimeout(timeoutId);
    }
}
