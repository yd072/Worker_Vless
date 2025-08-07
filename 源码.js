
import { connect } from 'cloudflare:sockets';

// --- 全局配置缓存 ---
let cachedSettings = null;       // 用于存储从KV读取的配置对象
// --------------------

let userID = '';
let proxyIP = '';
//let sub = '';
let subConverter = atob('U1VCQVBJLkNNTGl1c3Nzcy5uZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;
// --- HTTP 代理相关变量 ---
let httpProxyAddress = '';
let parsedHttpProxyAddress = {};
let enableHttpProxy = false;

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
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;
let FileName = atob('ZWRnZXR1bm5lbA==');
let BotToken = '';
let ChatID = '';
let proxyhosts = [];
let proxyhostsURL = '';
let RproxyIP = 'false';
let httpsPorts = ["443", "2053", "2083", "2087", "2096", "8443"];
let httpPorts = ["80", "8080", "8880", "2052", "2082", "2086", "2095"];
let 有效时间 = 7;
let 更新时间 = 3;
let userIDLow;
let userIDTime = "";
let proxyIPPool = [];
// let path = '/?ed=2560'; // 已被随机路径取代
let 动态UUID = null;
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
let DNS64Server = '';
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
 * 生成一个8位的随机路径
 * @returns {string} 例如 /aK7b2CDE
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
 * 随机获取一个 TLS 指纹
 * @returns {string} 例如 'chrome', 'random', 'randomized'
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
    if (env.HTTP) httpProxyAddress = env.HTTP;
    if (env.SUBAPI) subConverter = atob(env.SUBAPI);
    if (env.SUBCONFIG) subConfig = atob(env.SUBCONFIG);
    if (env.SUBNAME) FileName = atob(env.SUBNAME);
    if (env.DNS64 || env.NAT64) DNS64Server = env.DNS64 || env.NAT64;

    if (env.ADD) addresses = await 整理(env.ADD);
    if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
    if (env.ADDNOTLS) addressesnotls = await 整理(env.ADDNOTLS);
    if (env.ADDNOTLSAPI) addressesnotlsapi = await 整理(env.ADDNOTLSAPI);
    if (env.ADDCSV) addressescsv = await 整理(env.ADDCSV);
    if (env.LINK) link = await 整理(env.LINK);
    if (env.GO2SOCKS5) go2Socks5s = await 整理(env.GO2SOCKS5);
    if (env.BAN) banHosts = (await 整理(env.BAN)).map(h => atob(h));

    if (env.DLS) DLS = Number(env.DLS);
    if (env.CSVREMARK) remarkIndex = Number(env.CSVREMARK);
    if (env.TGTOKEN) BotToken = env.TGTOKEN;
    if (env.TGID) ChatID = env.TGID;
    if (env.SUBEMOJI || env.EMOJI) subEmoji = env.SUBEMOJI || env.EMOJI;

    // 3. 如果存在 KV，则使用 KV 的值覆盖所有之前的值
    if (env.KV) {
        try {
            const advancedSettingsJSON = await env.KV.get('settinggs.txt');
            if (advancedSettingsJSON) {
                const settings = JSON.parse(advancedSettingsJSON);
                
                // 将新配置存入内存缓存
                cachedSettings = settings;

                // 使用KV中的配置覆盖当前变量
                if (settings.proxyip && settings.proxyip.trim()) proxyIP = settings.proxyip;
                if (settings.socks5 && settings.socks5.trim()) socks5Address = settings.socks5.split('\n')[0].trim();
                if (settings.httpproxy && settings.httpproxy.trim()) httpProxyAddress = settings.httpproxy.split('\n')[0].trim();
                if (settings.sub && settings.sub.trim()) env.SUB = settings.sub.trim().split('\n')[0];
                if (settings.subapi && settings.subapi.trim()) subConverter = settings.subapi.trim().split('\n')[0];
                if (settings.subconfig && settings.subconfig.trim()) subConfig = settings.subconfig.trim().split('\n')[0];
                if (settings.nat64 && settings.nat64.trim()) DNS64Server = settings.nat64.trim().split('\n')[0];
				if (settings.httpsports && settings.httpsports.trim()) {
                    httpsPorts = await 整理(settings.httpsports);
                }
                if (settings.httpports && settings.httpports.trim()) {
                    httpPorts = await 整理(settings.httpports);
                }
				if (settings.notls) {
                    noTLS = settings.notls;
                }
                if (settings.ADD) {
                    const 优选地址数组 = await 整理(settings.ADD);
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
            }
        } catch (e) {
            console.error("从KV加载配置时出错: ", e);
        }
    }

    // 4. 最终处理
    if (subConverter.includes("http://")) {
        subConverter = subConverter.split("//")[1];
        subProtocol = 'http';
    } else {
        subConverter = subConverter.split("//")[1] || subConverter;
    }

    proxyIPs = await 整理(proxyIP);
    proxyIP = proxyIPs.length > 0 ? proxyIPs[Math.floor(Math.random() * proxyIPs.length)] : '';

    socks5s = await 整理(socks5Address);
    socks5Address = socks5s.length > 0 ? socks5s[Math.floor(Math.random() * socks5s.length)] : '';
	socks5Address = socks5Address.split('//')[1] || socks5Address;

    if (httpProxyAddress) {
        try {
            parsedHttpProxyAddress = httpProxyAddressParser(httpProxyAddress);
            enableHttpProxy = true;
        } catch (err) {
            console.log(`解析HTTP代理地址时出错: ${err.toString()}`);
            enableHttpProxy = false;
        }
    }
}


/**
 * 解析 PROXYIP 字符串，提取地址和端口
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
        [address, port] = address.split(':');
    }

    if (address.includes('.tp')) {
        port = address.split('.tp')[1].split('.')[0] || port;
    }

    return { address: address.toLowerCase(), port: Number(port) };
}


// TransformStream
function createWebSocketStream(webSocket, earlyDataHeader, log) {
	let streamCancelled = false;
	const stream = new TransformStream({
		start(controller) {
			// 处理早期数据
			const { earlyData, error } = utils.base64.toArrayBuffer(earlyDataHeader);
			if (error) {
				log(`处理早期数据时出错: ${error.message}`);
				controller.error(error);
			} else if (earlyData) {
				log('成功注入早期数据到流中。');
				controller.enqueue(earlyData);
			}

			// 监听 WebSocket 事件
			webSocket.addEventListener('message', event => {
				// TransformStream 自动处理背压，我们只需将数据写入即可
				if (streamCancelled) return;
				try {
					controller.enqueue(event.data);
				} catch (error) {
					log(`向流控制器添加数据时出错: ${error.message}`);
				}
			});

			webSocket.addEventListener('close', () => {
				log('WebSocket 已关闭，终止流。');
				if (!streamCancelled) {
					streamCancelled = true;
					try {
						controller.terminate();
					} catch (error) {
						log(`关闭流时出错: ${error.message}`);
					}
				}
			});

			webSocket.addEventListener('error', err => {
				log(`WebSocket 遇到错误: ${err.message}`);
				if (!streamCancelled) {
					streamCancelled = true;
					controller.error(err);
				}
			});
		},

		cancel(reason) {
			// 当流的消费者取消时（例如，pipeTo的另一端出错）
			if (streamCancelled) return;
			streamCancelled = true;
			log(`流被消费者取消，原因: ${reason}`);
			safeCloseWebSocket(webSocket);
		}
	});

	return stream.readable;
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
        <title>Service Status</title>
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
                <a href="#" target="_blank" rel="noopener noreferrer">Powered by EdgeTunnel</a>
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

async function resolveToIPv6(target) {
    // 检查是否为IPv4
    function isIPv4(str) {
        const parts = str.split('.');
        return parts.length === 4 && parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && part === num.toString();
        });
    }

    // 检查是否为IPv6
    function isIPv6(str) {
        return str.includes(':') && /^[0-9a-fA-F:]+$/.test(str);
    }

    // 获取域名的IPv4地址
    async function fetchIPv4(domain) {
        const url = `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`;
        const response = await fetch(url, {
            headers: { 'Accept': 'application/dns-json' }
        });

        if (!response.ok) throw new Error('DNS查询失败');

        const data = await response.json();
        const ipv4s = (data.Answer || [])
            .filter(record => record.type === 1)
            .map(record => record.data);

        if (ipv4s.length === 0) throw new Error('未找到IPv4地址');
        return ipv4s[Math.floor(Math.random() * ipv4s.length)];
    }

    // 查询NAT64 IPv6地址
    async function queryNAT64(domain) {
        const socket = connect({
            hostname: isIPv6(DNS64Server) ? `[${DNS64Server}]` : DNS64Server,
            port: 53
        });

        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        try {
            // 发送DNS查询
            const query = buildDNSQuery(domain);
            const queryWithLength = new Uint8Array(query.length + 2);
            queryWithLength[0] = query.length >> 8;
            queryWithLength[1] = query.length & 0xFF;
            queryWithLength.set(query, 2);
            await writer.write(queryWithLength);

            // 读取响应
            const response = await readDNSResponse(reader);
            const ipv6s = parseIPv6(response);

            if (ipv6s.length > 0) {
                return ipv6s[0];
            } else {
                throw new Error('No IPv6 address found in DNS response from NAT64 server');
            }
        } finally {
            await writer.close();
            await reader.cancel();
        }
    }

    // 构建DNS查询包
    function buildDNSQuery(domain) {
        const buffer = new ArrayBuffer(512);
        const view = new DataView(buffer);
        let offset = 0;
        view.setUint16(offset, Math.floor(Math.random() * 65536)); offset += 2;
        view.setUint16(offset, 0x0100); offset += 2;
        view.setUint16(offset, 1); offset += 2;
        view.setUint16(offset, 0); offset += 6;
		 // 域名编码
        for (const label of domain.split('.')) {
            view.setUint8(offset++, label.length);
            for (let i = 0; i < label.length; i++) {
                view.setUint8(offset++, label.charCodeAt(i));
            }
        }
        view.setUint8(offset++, 0);
		// 查询类型和类
        view.setUint16(offset, 28); offset += 2; // AAAA记录
        view.setUint16(offset, 1); offset += 2; // IN类

        return new Uint8Array(buffer, 0, offset);
    }

    // 读取DNS响应
    async function readDNSResponse(reader) {
        const chunks = [];
        let totalLength = 0;
        let expectedLength = null;
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            chunks.push(value);
            totalLength += value.length;
            if (expectedLength === null && totalLength >= 2) {
                expectedLength = (chunks[0][0] << 8) | chunks[0][1];
            }
            if (expectedLength !== null && totalLength >= expectedLength + 2) {
                break;
            }
        }
        const fullResponse = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            fullResponse.set(chunk, offset);
            offset += chunk.length;
        }
        return fullResponse.slice(2);
    }

    // 解析IPv6地址
    function parseIPv6(response) {
        const view = new DataView(response.buffer);
        let offset = 12;
        while (view.getUint8(offset) !== 0) {
            offset += view.getUint8(offset) + 1;
        }
        offset += 5;
        const answers = [];
        const answerCount = view.getUint16(6);
        for (let i = 0; i < answerCount; i++) {
            if ((view.getUint8(offset) & 0xC0) === 0xC0) {
                offset += 2;
            } else {
                while (view.getUint8(offset) !== 0) {
                    offset += view.getUint8(offset) + 1;
                }
                offset++;
            }
            const type = view.getUint16(offset); offset += 2;
            offset += 6;
            const dataLength = view.getUint16(offset); offset += 2;
            if (type === 28 && dataLength === 16) {
                const parts = [];
                for (let j = 0; j < 8; j++) {
                    parts.push(view.getUint16(offset + j * 2).toString(16));
                }
                answers.push(parts.join(':'));
            }
            offset += dataLength;
        }
        return answers;
    }

    function convertToNAT64IPv6(ipv4Address) {
        const parts = ipv4Address.split('.');
        if (parts.length !== 4) throw new Error('Invalid IPv4 address for NAT64 conversion');
        const hex = parts.map(part => parseInt(part, 10).toString(16).padStart(2, '0'));
        return DNS64Server.split('/96')[0] + hex[0] + hex[1] + ":" + hex[2] + hex[3];
    }

    try {
        if (isIPv6(target)) return target;
        const ipv4 = isIPv4(target) ? target : await fetchIPv4(target);
        const nat64 = DNS64Server.endsWith('/96') ? convertToNAT64IPv6(ipv4) : await queryNAT64(ipv4 + atob('LmlwLjA5MDIyNy54eXo='));

        if (isIPv6(nat64)) {
            return nat64;
        } else {
            throw new Error('Resolved NAT64 address is not a valid IPv6 address.');
        }
    } catch (error) {
        throw new Error(`NAT64 resolution failed: ${error.message}`);
	}
}

export default {
	async fetch(request, env, ctx) {
		try {
            // 1. 统一加载所有配置 (此函数现在使用内存缓存)
            await loadConfigurations(env);

            // 2. 处理动态 UUID
			const UA = request.headers.get('User-Agent') || 'null';
			const userAgent = UA.toLowerCase();
			if (env.KEY || env.TOKEN || (userID && !utils.isValidUUID(userID))) {
				动态UUID = env.KEY || env.TOKEN || userID;
				有效时间 = Number(env.TIME) || 有效时间;
				更新时间 = Number(env.UPTIME) || 更新时间;
				const userIDs = await 生成动态UUID(动态UUID);
				userID = userIDs[0];
				userIDLow = userIDs[1];
				userIDTime = userIDs[2];
			}

            // 3. 检查 UUID 是否有效，若无效则显示新的伪装页面
			if (!userID) {
				return await statusPage();
			}

            // 4. 生成伪装信息
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

            // 5. 处理 SOCKS5
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

            // 6. 根据请求类型（WebSocket 或 HTTP）进行路由
			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				// HTTP 请求处理
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
					const fakeConfig = await 生成配置信息(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, fakeUserID, fakeHostName, env);
					return new Response(`${fakeConfig}`, { status: 200 });
				}
				else if ((动态UUID && url.pathname === `/${动态UUID}/edit`) || 路径 === `/${userID}/edit`) {
					return await KV(request, env);
				} else if ((动态UUID && url.pathname === `/${动态UUID}`) || 路径 === `/${userID}`) {
					await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);

					const uuid_to_use = (动态UUID && url.pathname === `/${动态UUID}`) ? 动态UUID : userID;
					const secureProtoConfig = await 生成配置信息(uuid_to_use, request.headers.get('Host'), sub, UA, RproxyIP, url, fakeUserID, fakeHostName, env);

					const now = Date.now();
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776;

					if (userAgent && userAgent.includes('mozilla')) {
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
						return new Response(`${secureProtoConfig}`, {
							status: 200,
							headers: {
								"Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
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
				if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
				else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname)) {
					socks5Address = url.pathname.split('://')[1].split('#')[0];
					if (socks5Address.includes('@')) {
						let userPassword = socks5Address.split('@')[0];
						const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
						if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
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
    const readableWebSocketStream = createWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = {
        value: null
    };
    let udpStreamProcessed = false;
    const banHostsSet = new Set(banHosts);
    let secureProtoResponseHeader = null;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (udpStreamProcessed) {
                return;
            }
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
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
                // UDP-specific handling
                if (portRemote === 53) {
                    const udpHandler = await handleUDPOutBound(webSocket, secureProtoResponseHeader, log);
                    udpHandler.write(rawClientData);
                    udpStreamProcessed = true;
                } else {
                    // All other UDP traffic is blocked
                    throw new Error('UDP proxying is only enabled for DNS on port 53');
                }
                return;
            }

            // TCP-specific handling
            if (banHosts.includes(addressRemote)) {
                throw new Error('Domain is blocked');
            }
            log(`Handling TCP outbound for ${addressRemote}:${portRemote}`);
            await handleTCPOutBound(remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, secureProtoResponseHeader, log);
        },
        close() {
            log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
            log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream pipe error', err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

/**
 * 处理出站 UDP (DNS over HTTPS) 
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 
 * @param {ArrayBuffer} secureProtoResponseHeader 
 * @param {(string)=> void} log 
 */
async function handleUDPOutBound(webSocket, secureProtoResponseHeader, log) {

    const DOH_URL = 'https://dns.google/dns-query'; //https://cloudflare-dns.com/dns-query

    let issecureProtoHeaderSent = false;
    let buffer = new Uint8Array(0);
    const transformStream = new TransformStream({
        transform(chunk, controller) {
            const newBuffer = new Uint8Array(buffer.length + chunk.length);
            newBuffer.set(buffer);
            newBuffer.set(chunk, buffer.length);
            buffer = newBuffer;
            while (buffer.length >= 2) {
                const udpPacketLength = new DataView(buffer.buffer, buffer.byteOffset, 2).getUint16(0);
                if (buffer.length >= 2 + udpPacketLength) {
                    const udpData = buffer.slice(2, 2 + udpPacketLength);
                    controller.enqueue(udpData);
                    buffer = buffer.slice(2 + udpPacketLength);
                } else {
                    break;
                }
            }
        },
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            // 将DNS查询发送到指定的DoH服务器
            const resp = await fetch(DOH_URL, {
                method: 'POST',
                headers: {
                    'content-type': 'application/dns-message',
                },
                body: chunk,
            });

            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                log(`DoH查询成功，DNS消息长度为: ${udpSize}`);
                if (issecureProtoHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([secureProtoResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    issecureProtoHeaderSent = true;
                }
            }
        }
    })).catch((error) => {
        log('处理DNS UDP时出错: ' + error);
    });

    const writer = transformStream.writable.getWriter();

    return {
        write(chunk) {
            writer.write(chunk);
        }
    };
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, secureProtoResponseHeader, log) {

	const createConnection = async (address, port, proxyOptions = null) => {
		const proxyType = proxyOptions ? proxyOptions.type : 'direct';
		log(`建立连接: ${address}:${port} (方式: ${proxyType})`);

		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort('Connection timeout'), 5000);

		try {
			let tcpSocketPromise;
			if (proxyType === 'http') {
				tcpSocketPromise = httpConnect(address, port, log);
			} else if (proxyType === 'socks5') {
				tcpSocketPromise = socks5Connect(addressType, address, port, log);
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

    // 新的递归函数，用于按顺序尝试所有连接策略
    async function tryConnectionStrategies(strategies) {
        if (!strategies || strategies.length === 0) {
            log('All connection strategies failed. Closing WebSocket.');
            
            // 自愈机制：当所有策略都失败后，清空缓存，强制下一次请求从KV重新加载。
            log('Invalidating configuration cache due to connection failures.');
            cachedSettings = null;
            
            safeCloseWebSocket(webSocket);
            return;
        }

        const [currentStrategy, ...nextStrategies] = strategies;
        log(`Attempting connection with strategy: '${currentStrategy.name}'`);

        try {
            const tcpSocket = await currentStrategy.execute();
            log(`Strategy '${currentStrategy.name}' connected successfully. Piping data.`);

            // 关键点：如果本次连接失败，重试函数将用剩余的策略继续尝试
            const retryNext = () => tryConnectionStrategies(nextStrategies);
            remoteSocketToWS(tcpSocket, webSocket, secureProtoResponseHeader, retryNext, log);

        } catch (error) {
            log(`Strategy '${currentStrategy.name}' failed: ${error.message}. Trying next strategy...`);
            await tryConnectionStrategies(nextStrategies); // 立即尝试下一个策略
        }
    }

    // --- 组装策略列表 ---
    const connectionStrategies = [];
    const shouldUseSocks = enableSocks && go2Socks5s.some(pattern => new RegExp(`^${pattern.replace(/\*/g, '.*')}$`, 'i').test(addressRemote));

    // 1. 主要连接策略
    if (enableHttpProxy) {
        connectionStrategies.push({
            name: 'HTTP Proxy',
            execute: () => createConnection(addressRemote, portRemote, { type: 'http' })
        });
    } else if (shouldUseSocks) {
        connectionStrategies.push({
            name: 'SOCKS5 Proxy (go2Socks5s)',
            execute: () => createConnection(addressRemote, portRemote, { type: 'socks5' })
        });
    } else {
        connectionStrategies.push({
            name: 'Direct Connection',
            execute: () => createConnection(addressRemote, portRemote, null)
        });
    }

    // 2. 备用 (Fallback) 策略
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

    const userNat64Server = DNS64Server && DNS64Server.trim() !== '' && DNS64Server !== atob("ZG5zNjQuY21saXVzc3NzLm5ldA==");
    if (userNat64Server) {
        connectionStrategies.push({
            name: '用户配置的 NAT64',
            execute: async () => {
                const nat64Address = await resolveToIPv6(addressRemote);
                return createConnection(`[${nat64Address}]`, 443);
            }
        });
    }

    connectionStrategies.push({
        name: '内置的默认 PROXYIP',
        execute: () => {
            const defaultProxyIP = atob('UFJPWFlJUC50cDEuZnh4ay5kZWR5bi5pbw==');
            const { address, port } = parseProxyIP(defaultProxyIP, portRemote);
            return createConnection(address, port);
        }
    });

    connectionStrategies.push({
        name: '内置的默认 NAT64',
        execute: async () => {
            if (!DNS64Server || DNS64Server.trim() === '') {
                DNS64Server = atob("ZG5zNjQuY21pLnp0dmkub3Jn");
            }
            const nat64Address = await resolveToIPv6(addressRemote);
            return createConnection(`[${nat64Address}]`, 443);
        }
    });

    // --- 启动策略链 ---
    await tryConnectionStrategies(connectionStrategies);
}

function processsecureProtoHeader(secureProtoBuffer, userID) {
    if (secureProtoBuffer.byteLength < 24) {
        return { hasError: true, message: 'Invalid data' };
    }

    const version = new Uint8Array(secureProtoBuffer.slice(0, 1));
    const userIDArray = new Uint8Array(secureProtoBuffer.slice(1, 17));
    const userIDString = stringify(userIDArray);
    const isValidUser = userIDString === userID || userIDString === userIDLow;

    if (!isValidUser) {
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
    let header = responseHeader; // 用于发送初始响应头。
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
                    log(`远程连接的数据流已正常关闭, 是否接收到数据: ${hasIncomingData}`);
                },
                // abort 方法在数据流被异常中止时调用。
                abort(reason) {
                    console.error(`远程连接的数据流被中断:`, reason);
                },
            })
        );
    } catch (error) {
        // 捕获在 pipeTo 过程中可能发生的任何错误。
        console.error(`数据流传输时发生异常:`, error.stack || error);
        // 发生错误时，安全地关闭WebSocket连接。
        safeCloseWebSocket(webSocket);
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

async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port });

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
            return;
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

//  HTTP 代理地址解析函数
function httpProxyAddressParser(address) {
    let [latter, former] = address.split("@").reverse();
    let username, password, hostname, port;

    if (former) {
        const formers = former.split(":");
        if (formers.length > 2) { // 密码中可能包含冒号，但用户名不能
             const userSeparatorIndex = former.indexOf(":");
             username = former.substring(0, userSeparatorIndex);
             password = former.substring(userSeparatorIndex + 1);
        } else if (formers.length === 2){
            [username, password] = formers;
        } else {
             throw new Error('Invalid HTTP proxy address format: "username:password" required');
        }
    }

    const latters = latter.split(":");
    port = Number(latters.pop());
    if (isNaN(port)) {
        throw new Error('Invalid HTTP proxy address format: port must be a number');
    }

    hostname = latters.join(":");

    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('Invalid HTTP proxy address format: IPv6 must be in brackets');
    }

    return {
        username,
        password,
        hostname,
        port,
    }
}

async function httpConnect(addressRemote, portRemote, log) {
	const { username, password, hostname, port } = parsedHttpProxyAddress;
	const sock = await connect({
		hostname: hostname,
		port: port
	});

	// 构建HTTP CONNECT请求
	let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
	connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

	// 添加代理认证（如果需要）
	if (username && password) {
		const authString = `${username}:${password}`;
		const base64Auth = btoa(authString);
		connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
	}

	connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
	connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
	connectRequest += `Connection: Keep-Alive\r\n`; // 添加标准 Connection 头
	connectRequest += `\r\n`;

	log(`正在连接到 ${addressRemote}:${portRemote} 通过代理 ${hostname}:${port}`);

	try {
		// 发送连接请求
		const writer = sock.writable.getWriter();
		await writer.write(new TextEncoder().encode(connectRequest));
		writer.releaseLock();
	} catch (err) {
		console.error('发送HTTP CONNECT请求失败:', err);
		throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
	}

	// 读取HTTP响应
	const reader = sock.readable.getReader();
	let respText = '';
	let connected = false;
	let responseBuffer = new Uint8Array(0);

	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) {
				console.error('HTTP代理连接中断');
				throw new Error('HTTP代理连接中断');
			}

			// 合并接收到的数据
			const newBuffer = new Uint8Array(responseBuffer.length + value.length);
			newBuffer.set(responseBuffer);
			newBuffer.set(value, responseBuffer.length);
			responseBuffer = newBuffer;

			// 将收到的数据转换为文本
			respText = new TextDecoder().decode(responseBuffer);

			// 检查是否收到完整的HTTP响应头
			if (respText.includes('\r\n\r\n')) {
				// 分离HTTP头和可能的数据部分
				const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
				const headers = respText.substring(0, headersEndPos);

				log(`收到HTTP代理响应: ${headers.split('\r\n')[0]}`);

				// 检查响应状态
				if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
					connected = true;

					// 如果响应头之后还有数据，我们需要保存这些数据以便后续处理
					if (headersEndPos < responseBuffer.length) {
						const remainingData = responseBuffer.slice(headersEndPos);
						// 创建一个缓冲区来存储这些数据，以便稍后使用
						const dataStream = new ReadableStream({
							start(controller) {
								controller.enqueue(remainingData);
							}
						});

						// 创建一个新的TransformStream来处理额外数据
						const { readable, writable } = new TransformStream();
						dataStream.pipeTo(writable).catch(err => console.error('处理剩余数据错误:', err));

						// 替换原始readable流
						// @ts-ignore
						sock.readable = readable;
					}
				} else {
					const errorMsg = `HTTP代理连接失败: ${headers.split('\r\n')[0]}`;
					console.error(errorMsg);
					throw new Error(errorMsg);
				}
				break;
			}
		}
	} catch (err) {
		reader.releaseLock();
		throw new Error(`处理HTTP代理响应失败: ${err.message}`);
	}

	reader.releaseLock();

	if (!connected) {
		throw new Error('HTTP代理连接失败: 未收到成功响应');
	}

	log(`HTTP代理连接成功: ${addressRemote}:${portRemote}`);
	return sock;
}


function 恢复伪装信息(content, userID, hostName, fakeUserID, fakeHostName, isBase64) {
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
        const 网址列表 = await 整理(代理网址);
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
        newHeaders.set('Host', 解析后的网址.hostname); // 将Host头修改为代理目标的域名
        newHeaders.set('Referer', 解析后的网址.origin); // 可选：伪造或设置正确的Referer

        const 响应 = await fetch(目标URL.toString(), {
            method: request.method, // 传递原始请求方法
            headers: newHeaders,    // 传递处理过的请求头，增强伪装
            body: request.body,     // 传递请求体，支持POST等方法
            redirect: 'manual'      // 手动处理重定向
        });

        const 新响应 = new Response(响应.body, {
            status: 响应.status,
            statusText: 响应.statusText,
            headers: new Headers(响应.headers)
        });

        // 移除可能暴露信息的特有请求头
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

const protocolEncodedFlag = atob('ZG14bGMzTT0=');
function 配置信息(UUID, 域名地址) {
	const 协议类型 = atob(protocolEncodedFlag);

	const 别名 = FileName;
	let 地址 = 域名地址;
	let 端口 = 443;

	const 用户ID = UUID;
	const 加密方式 = 'none';

	const 传输层协议 = 'ws';
	const 伪装域名 = 域名地址;
	const 路径 = generateRandomPath(); // 使用随机路径
	const 指纹 = getRandomFingerprint(); // 使用随机指纹

	let 传输层安全 = ['tls', true];
	const SNI = 域名地址;


	if (域名地址.includes('.workers.dev') || noTLS === 'true') {
		地址 = atob('dmlzYS5jbg==');
		端口 = 80;
		传输层安全 = ['', false];
	}

	const 威图瑞 = `${协议类型}://${用户ID}@${地址}:${端口}\u003f\u0065\u006e\u0063\u0072\u0079` + 'p' + `${atob('dGlvbj0=') + 加密方式}\u0026\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079\u003d${传输层安全[0]}&sni=${SNI}&fp=${指纹}&type=${传输层协议}&host=${伪装域名}&path=${encodeURIComponent(路径)}#${encodeURIComponent(别名)}`;
	const 猫猫猫 = `- {name: ${FileName}, server: ${地址}, port: ${端口}, type: ${协议类型}, uuid: ${用户ID}, tls: ${传输层安全[1]}, alpn: [h3], udp: false, sni: ${SNI}, tfo: false, skip-cert-verify: true, servername: ${伪装域名}, client-fingerprint: ${指纹}, network: ${传输层协议}, ws-opts: {path: "${路径}", headers: {${伪装域名}}}}`;
	return [威图瑞, 猫猫猫];
}

let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQo='));

async function 生成配置信息(uuid, hostName, sub, UA, RproxyIP, _url, fakeUserID, fakeHostName, env) {

	if (sub) {
		const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
		sub = match ? match[1] : sub;
		const subs = await 整理(sub);
		sub = subs.length > 1 ? subs[0] : sub;
	}

	if ((addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
	    		let cfips = [
		            '104.16.0.0/14',
		            '104.21.0.0/16',
		            '188.114.96.0/20',

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
			    addressesnotls.push(`${randomIP}:${port}#CF随机节点${String(counter++).padStart(2, '0')}`);
		    }
	    } else {
		    const randomPorts = httpsPorts.length > 0 ? httpsPorts : ['443'];
		        for (let i = 0; i < totalIPsToGenerate; i++) {
			    const randomCIDR = cfips[Math.floor(Math.random() * cfips.length)];
			    const randomIP = generateRandomIPFromCIDR(randomCIDR);
			    const port = randomPorts[Math.floor(Math.random() * randomPorts.length)];
			    addresses.push(`${randomIP}:${port}#CF随机节点${String(counter++).padStart(2, '0')}`);
		    }
	    }
    }

	const userAgent = UA.toLowerCase();
	const Config = 配置信息(uuid, hostName);
	const proxyConfig = Config[0];
	const clash = Config[1];
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

		let 订阅器 = '<br>';
		let 判断是否绑定KV空间 = env.KV ? ` <a href='${_url.pathname}/edit'>编辑优选列表</a>` : '';

		if (sub) {
			if (enableSocks) 订阅器 += `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
			else if (proxyIP && proxyIP != '') 订阅器 += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
			else if (RproxyIP == 'true') 订阅器 += `CFCDN（访问方式）: 自动获取ProxyIP<br>`;
			else 订阅器 += `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`
			订阅器 += `<br>SUB（优选订阅生成器）: ${sub}${判断是否绑定KV空间}<br>`;
		} else {
			if (enableSocks) 订阅器 += `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
			else if (proxyIP && proxyIP != '') 订阅器 += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
			else 订阅器 += `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`;
			订阅器 += `<br>您的订阅内容由 内置 addresses/ADD* 参数变量提供${判断是否绑定KV空间}<br>`;
			if (addresses.length > 0) 订阅器 += `ADD（TLS优选域名&IP）: <br>&nbsp;&nbsp;${addresses.join('<br>&nbsp;&nbsp;')}<br>`;
			if (addressesnotls.length > 0) 订阅器 += `ADDNOTLS（noTLS优选域名&IP）: <br>&nbsp;&nbsp;${addressesnotls.join('<br>&nbsp;&nbsp;')}<br>`;
			if (addressesapi.length > 0) 订阅器 += `ADDAPI（TLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesapi.join('<br>&nbsp;&nbsp;')}<br>`;
			if (addressesnotlsapi.length > 0) 订阅器 += `ADDNOTLSAPI（noTLS优选域名&IP 的 API）: <br>&nbsp;&nbsp;${addressesnotlsapi.join('<br>&nbsp;&nbsp;')}<br>`;
			if (addressescsv.length > 0) 订阅器 += `ADDCSV（IPTest测速csv文件 限速 ${DLS} ）: <br>&nbsp;&nbsp;${addressescsv.join('<br>&nbsp;&nbsp;')}<br>`;
		}

		if (动态UUID && _url.pathname !== `/${动态UUID}`) 订阅器 = '';
		else 订阅器 += `<br>SUBAPI（订阅转换后端）: ${subProtocol}://${subConverter}<br>SUBCONFIG（订阅转换配置文件）: ${subConfig}`;
		const 动态UUID信息 = (uuid != userID) ? `TOKEN: ${uuid}<br>UUIDNow: ${userID}<br>UUIDLow: ${userIDLow}<br>${userIDTime}TIME（动态UUID有效时间）: ${有效时间} 天<br>UPTIME（动态UUID更新时间）: ${更新时间} 时（北京时间）<br><br>` : `${userIDTime}`;
		const 节点配置页 = `
			<!DOCTYPE html>
			<html lang="zh-CN">
			<head>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<title>${FileName} 配置信息</title>
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

					.divider {
						height: 1px;
						background: var(--border-color);
						margin: 15px 0;
					}

					.subscription-link {
						display: block;
						margin: 10px 0;
						padding: 12px;
						background: #f8f9fa;
						border-radius: 6px;
						border: 1px solid var(--border-color);
						word-break: break-all;
					}

					html.dark-mode .subscription-link {
						background: #3a3a3a;
					}

					.qrcode-container {
						margin: 10px 0;
						text-align: center;
					}

					.notice-toggle {
						color: var(--primary-color);
						cursor: pointer;
						display: inline-block;
						margin: 10px 0;
						font-weight: 500;
					}

					.notice-content {
						background: #f8f9fa;
						border-left: 4px solid var(--primary-color);
						padding: 15px;
						margin: 10px 0;
						border-radius: 0 8px 8px 0;
						word-break: break-all;
						overflow-wrap: break-word;
					}
					
					html.dark-mode .notice-content {
						background: #3a3a3a;
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
						padding: 6px 12px;
						background: var(--primary-color);
						color: #fff;
						border: none;
						border-radius: 4px;
						cursor: pointer;
						font-size: 14px;
						margin: 5px 0;
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
						<div class="section-title">📋 订阅信息</div>
						<div class="subscription-link">
							自适应订阅地址:<br>
							<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sub','qrcode_0')">
								https://${proxyhost}${hostName}/${uuid}
							</a>
							<div id="qrcode_0" class="qrcode-container"></div>
						</div>

						<div class="subscription-link">
							Base64订阅地址:<br>
							<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?b64','qrcode_1')">
								https://${proxyhost}${hostName}/${uuid}?b64
							</a>
							<div id="qrcode_1" class="qrcode-container"></div>
						</div>

						<div class="subscription-link">
							clash订阅地址:<br>
							<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?clash','qrcode_2')">
								https://${proxyhost}${hostName}/${uuid}?clash
							</a>
							<div id="qrcode_2" class="qrcode-container"></div>
						</div>

						<div class="subscription-link">
							singbox订阅地址:<br>
							<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sb','qrcode_3')">
								https://${proxyhost}${hostName}/${uuid}?sb
							</a>
							<div id="qrcode_3" class="qrcode-container"></div>
						</div>

						<div class="subscription-link">
							Loon订阅地址:<br>
							<a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?loon','qrcode_4')">
								https://${proxyhost}${hostName}/${uuid}?loon
							</a>
							<div id="qrcode_4" class="qrcode-container"></div>
						</div>
					</div>

					<div class="section">
						<div class="section-title">ℹ️ 使用说明</div>
						<a href="javascript:void(0);" id="noticeToggle" class="notice-toggle" onclick="toggleNotice()">
							实用订阅技巧 ∨
						</a>
						<div id="noticeContent" class="notice-content" style="display: none">
							<strong>1.</strong> 如您使用的是 PassWall、PassWall2 路由插件，订阅编辑的 <strong>用户代理(User-Agent)</strong> 设置为 <strong>PassWall</strong> 即可；<br><br>
							<strong>2.</strong> 如您使用的是 SSR+ 等路由插件，推荐使用 <strong>Base64订阅地址</strong> 进行订阅；<br><br>
							<strong>3.</strong> 快速切换 <a href='${atob('aHR0cHM6Ly9naXRodWIuY29tL2NtbGl1L1dvcmtlclZsZXNzMnN1Yg==')}'>优选订阅生成器</a> 至：sub.google.com，您可将"?sub=sub.google.com"参数添加到链接末尾，例如：<br>
							&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?sub=sub.google.com</strong><br><br>
							<strong>4.</strong> 快速更换 PROXYIP 至：proxyip.fxxk.dedyn.io:443，您可将"?proxyip=proxyip.fxxk.dedyn.io:443"参数添加到链接末尾，例如：<br>
							&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?proxyip=proxyip.fxxk.dedyn.io:443</strong><br><br>
							<strong>5.</strong> 快速更换 SOCKS5 至：user:password@127.0.0.1:1080，您可将"?socks5=user:password@127.0.0.1:1080"参数添加到链接末尾，例如：<br>
							&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?socks5=user:password@127.0.0.1:1080</strong><br><br>
							<strong>6.</strong> 如需指定多个参数则需要使用'&'做间隔，例如：<br>
							&nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}?sub=sub.google.com<strong>&</strong>proxyip=proxyip.fxxk.dedyn.io
						</div>
					</div>

					<div class="section">
						<div class="section-title">🔧 配置信息</div>
						<div class="config-info">
							${动态UUID信息.replace(/\n/g, '<br>')}
							HOST: ${hostName}<br>
							UUID: ${userID}<br>
							FKID: ${fakeUserID}<br>
							UA: ${UA}<br>
							${订阅器.replace(/\n/g, '<br>')}
						</div>
					</div>

					<div class="section">
						<div class="section-title">📝 proxyConfig</div>
						<div class="config-info" style="overflow-x: auto; max-width: 100%;">
							<button class="copy-button" onclick="copyToClipboard('${proxyConfig}','qrcode_proxyConfig')">复制配置</button>
							<div style="word-break: break-all; overflow-wrap: anywhere;">${proxyConfig}</div>
							<div id="qrcode_proxyConfig" class="qrcode-container"></div>
						</div>
					</div>

					<div class="section">
						<div class="section-title">⚙️ Clash Meta 配置</div>
						<div class="config-info" style="overflow-x: auto; max-width: 100%;">
							<div style="word-break: break-all; overflow-wrap: anywhere;">${clash}</div>
						</div>
					</div>

					<div class="divider"></div>
					${cmad}
				</div>

				<script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
				<script>
					function copyToClipboard(text, qrcode) {
						navigator.clipboard.writeText(text).then(() => {
							alert('已复制到剪贴板');
						}).catch(err => {
							console.error('复制失败:', err);
						});
						const qrcodeDiv = document.getElementById(qrcode);
						qrcodeDiv.innerHTML = '';
						new QRCode(qrcodeDiv, {
							text: text,
							width: 220,
							height: 220,
							colorDark: "#000000",
							colorLight: "#ffffff",
							correctLevel: QRCode.CorrectLevel.Q,
							scale: 1
						});
					}

					function toggleNotice() {
						const noticeContent = document.getElementById('noticeContent');
						const noticeToggle = document.getElementById('noticeToggle');
						if (noticeContent.style.display === 'none') {
							noticeContent.style.display = 'block';
							noticeToggle.textContent = '实用订阅技巧 ∧';
						} else {
							noticeContent.style.display = 'none';
							noticeToggle.textContent = '实用订阅技巧 ∨';
						}
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
		return 节点配置页;
	} else {
		if (typeof fetch != 'function') {
			return 'Error: fetch is not available in this environment.';
		}

		let newAddressesapi = [];
		let newAddressescsv = [];
		let newAddressesnotlsapi = [];
		let newAddressesnotlscsv = [];

		if (hostName.includes(".workers.dev") || noTLS === 'true') {
			noTLS = 'true';
			fakeHostName = `${fakeHostName}.workers.dev`;
			newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
			newAddressesnotlscsv = await 整理测速结果('FALSE');
		} else if (hostName.includes(".pages.dev")) {
			fakeHostName = `${fakeHostName}.pages.dev`;
		} else if (hostName.includes("worker") || hostName.includes("notls")) {
			noTLS = 'true';
			fakeHostName = `notls${fakeHostName}.net`;
			newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
			newAddressesnotlscsv = await 整理测速结果('FALSE');
		} else {
			fakeHostName = `${fakeHostName}.xyz`
		}
		console.log(`虚假HOST: ${fakeHostName}`);
        
        // 这里的 path 参数不再是固定的，但为了兼容订阅转换器，我们仍然需要传递一个路径。
        // 使用 generateRandomPath() 或者一个简单的 '/' 都可以。
        // 为了让订阅器那边能处理，我们仍然用一个固定的查询参数格式，但路径本身是隐藏的。
		let url = `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID + atob('JmVkZ2V0dW5uZWw9Y21saXUmcHJveHlpcD0=') + RproxyIP}&path=${encodeURIComponent('/')}`; // Path is now dynamic inside the node
		let isBase64 = true;

		if (!sub || sub == "") {
			if (hostName.includes('workers.dev')) {
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
						console.error('获取地址时出错:', error);
					}
				}
				proxyhosts = [...new Set(proxyhosts)];
			}

			newAddressesapi = await 整理优选列表(addressesapi);
			newAddressescsv = await 整理测速结果('TRUE');
			url = `https://${hostName}/${fakeUserID + _url.search}`;
			if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
				if (_url.search) url += '&notls';
				else url += '?notls';
			}
			console.log(`虚假订阅: ${url}`);
		}

		if (!userAgent.includes(('CF-Workers-SUB').toLowerCase()) && !_url.searchParams.has('b64')  && !_url.searchParams.has('base64')) {
			if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
				url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			} else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || ((_url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
				url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			} else if (userAgent.includes('loon') || (_url.searchParams.has('loon') && !userAgent.includes('subconverter'))) {
				// 添加Loon支持
				url = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			}
		}

		try {
			let content;
			if ((!sub || sub == "") && isBase64 == true) {
				content = await 生成本地订阅(fakeHostName, fakeUserID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv);
			} else {
				const response = await fetch(url, {
					headers: {
						'User-Agent': (isBase64 ? 'v2rayN' : UA) + atob('IENGLVdvcmtlcnMtZWRnZXR1bm5lbC9jbWxpdQ==')
					}
				});
				content = await response.text();
			}

			if (_url.pathname == `/${fakeUserID}`) return content;

			return 恢复伪装信息(content, userID, hostName, fakeUserID, fakeHostName, isBase64);

		} catch (error) {
			console.error('Error fetching content:', error);
			return `Error fetching content: ${error.message}`;
		}
	}
}

async function 整理优选列表(api) {
	if (!api || api.length === 0) return [];

	let newapi = "";

	const controller = new AbortController();

	const timeout = setTimeout(() => {
		controller.abort();
	}, 2000);

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
				const content = await response.value;

				const lines = content.split(/\r?\n/);
				let 节点备注 = '';
				let 测速端口 = '443';

				if (lines[0].split(',').length > 3) {
					const idMatch = api[index].match(/id=([^&]*)/);
					if (idMatch) 节点备注 = idMatch[1];

					const portMatch = api[index].match(/port=([^&]*)/);
					if (portMatch) 测速端口 = portMatch[1];

					for (let i = 1; i < lines.length; i++) {
						const columns = lines[i].split(',')[0];
						if (columns) {
							newapi += `${columns}:${测速端口}${节点备注 ? `#${节点备注}` : ''}\n`;
							if (api[index].includes('proxyip=true')) proxyIPPool.push(`${columns}:${测速端口}`);
						}
					}
				} else {
					if (api[index].includes('proxyip=true')) {
						// 如果URL带有'proxyip=true'，则将内容添加到proxyIPPool
						proxyIPPool = proxyIPPool.concat((await 整理(content)).map(item => {
							const baseItem = item.split('#')[0] || item;
							if (baseItem.includes(':')) {
								const port = baseItem.split(':')[1];
								if (!httpsPorts.includes(port)) {
									return baseItem;
								}
							} else {
								return `${baseItem}:443`;
							}
							return null;
						}).filter(Boolean));
					}
					newapi += content + '\n';
				}
			}
		}
	} catch (error) {
		console.error(error);
	} finally {
		clearTimeout(timeout);
	}

	const newAddressesapi = await 整理(newapi);

	return newAddressesapi;
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
				// 检查TLS是否为"TRUE"且速度大于DLS
				if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
					const ipAddress = columns[ipAddressIndex];
					const port = columns[portIndex];
					const dataCenter = columns[dataCenterIndex];

					const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
					newAddressescsv.push(formattedAddress);
					if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'true' && !httpsPorts.includes(port)) {
						// 如果URL带有'proxyip=true'，则将内容添加到proxyIPPool
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

function 生成本地订阅(host, UUID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
	const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
	addresses = addresses.concat(newAddressesapi);
	addresses = addresses.concat(newAddressescsv);
	let notlsresponseBody;
	if (noTLS == 'true') {
		addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
		addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
		const uniqueAddressesnotls = [...new Set(addressesnotls)];

		notlsresponseBody = uniqueAddressesnotls.map(address => {
			let port = "-1";
			let addressid = address;

			const match = addressid.match(regex);
			if (!match) {
				if (address.includes(':') && address.includes('#')) {
					const parts = address.split(':');
					address = parts[0];
					const subParts = parts[1].split('#');
					port = subParts[0];
					addressid = subParts[1];
				} else if (address.includes(':')) {
					const parts = address.split(':');
					address = parts[0];
					port = parts[1];
				} else if (address.includes('#')) {
					const parts = address.split('#');
					address = parts[0];
					addressid = parts[1];
				}

				if (addressid.includes(':')) {
					addressid = addressid.split(':')[0];
				}
			} else {
				address = match[1];
				port = match[2] || port;
				addressid = match[3] || address;
			}

			const localHttpPorts = httpPorts.length > 0 ? httpPorts : ["80", "8080", "8880", "2052", "2082", "2086", "2095"];
			if (!isValidIPv4(address) && port == "-1") {
				for (let httpPort of localHttpPorts) {
					if (address.includes(httpPort)) {
						port = httpPort;
						break;
					}
				}
			}
			if (port == "-1") port = "80";

			let 伪装域名 = host;
			let 最终路径 = generateRandomPath();
			let 节点备注 = '';
			const 协议类型 = atob(protocolEncodedFlag);

            const secureProtoLink = `${协议类型}://${UUID}@${address}:${port}?` +
                `encryption=none&` +
                `security=none&` +
                `type=ws&` +
                `host=${伪装域名}&` +
                `path=${encodeURIComponent(最终路径)}` +
                `#${encodeURIComponent(addressid + 节点备注)}`;

			return secureProtoLink;

		}).join('\n');

	}

	const uniqueAddresses = [...new Set(addresses)];

	const responseBody = uniqueAddresses.map(address => {
		let port = "-1";
		let addressid = address;

		const match = addressid.match(regex);
		if (!match) {
			if (address.includes(':') && address.includes('#')) {
				const parts = address.split(':');
				address = parts[0];
				const subParts = parts[1].split('#');
				port = subParts[0];
				addressid = subParts[1];
			} else if (address.includes(':')) {
				const parts = address.split(':');
				address = parts[0];
				port = parts[1];
			} else if (address.includes('#')) {
				const parts = address.split('#');
				address = parts[0];
				addressid = parts[1];
			}

			if (addressid.includes(':')) {
				addressid = addressid.split(':')[0];
			}
		} else {
			address = match[1];
			port = match[2] || port;
			addressid = match[3] || address;
		}
		
		const localHttpsPorts = httpsPorts.length > 0 ? httpsPorts : ["443", "2053", "2083", "2087", "2096", "8443"];
		if (!isValidIPv4(address) && port == "-1") {
			for (let httpsPort of localHttpsPorts) {
				if (address.includes(httpsPort)) {
					port = httpsPort;
					break;
				}
			}
		}
		if (port == "-1") port = "443";

		let 伪装域名 = host;
		let 最终路径 = generateRandomPath(); // <-- 每个节点都有自己的随机路径
		let 节点备注 = '';
		const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(address));
		if (matchingProxyIP) 最终路径 = `/?proxyip=${matchingProxyIP}`;

		if (proxyhosts.length > 0 && (伪装域名.includes('.workers.dev'))) {
			最终路径 = `/${伪装域名}${最终路径}`;
			伪装域名 = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
			节点备注 = ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
		}

		const 协议类型 = atob(protocolEncodedFlag);

		const secureProtoLink = `${协议类型}://${UUID}@${address}:${port}?` +
			`encryption=none&` +
			`security=tls&` +
			`sni=${伪装域名}&` +
			`fp=${getRandomFingerprint()}&` + // <-- 使用随机指纹
			`alpn=h3&` +
			`type=ws&` +
			`host=${伪装域名}&` +
            `path=${encodeURIComponent(最终路径)}` +
			`#${encodeURIComponent(addressid + 节点备注)}`;

		return secureProtoLink;
	}).join('\n');

	let base64Response = responseBody;
	if (noTLS == 'true') base64Response += `\n${notlsresponseBody}`;
	if (link.length > 0) base64Response += '\n' + link.join('\n');
	return btoa(base64Response);
}

async function 整理(内容) {
    if (!内容) return [];
    const 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',')
        .replace(/^,|,$/g, '');

    return 替换后的内容.split(',');
}

async function sendMessage(type, ip, add_data = "") {
	if (!BotToken || !ChatID) return;

	try {
		let msg = "";
		const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
		if (response.ok) {
			const ipInfo = await response.json();
			msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
		} else {
			msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
		}

		const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
		return fetch(url, {
			method: 'GET',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
			}
		});
	} catch (error) {
		console.error('Error sending message:', error);
	}
}

function isValidIPv4(address) {
	const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
	return ipv4Regex.test(address);
}

function 生成动态UUID(密钥) {
	const 时区偏移 = 8;
	const 起始日期 = new Date(2007, 6, 7, 更新时间, 0, 0);
	const 一周的毫秒数 = 1000 * 60 * 60 * 24 * 有效时间;

	function 获取当前周数() {
		const 现在 = new Date();
		const 调整后的现在 = new Date(现在.getTime() + 时区偏移 * 60 * 60 * 1000);
		const 时间差 = Number(调整后的现在) - Number(起始日期);
		return Math.ceil(时间差 / 一周的毫秒数);
	}

	function 生成UUID(基础字符串) {
		const 哈希缓冲区 = new TextEncoder().encode(基础字符串);
		return crypto.subtle.digest('SHA-256', 哈希缓冲区).then((哈希) => {
			const 哈希数组 = Array.from(new Uint8Array(哈希));
			const 十六进制哈希 = 哈希数组.map(b => b.toString(16).padStart(2, '0')).join('');
			return `${十六进制哈希.substr(0, 8)}-${十六进制哈希.substr(8, 4)}-4${十六进制哈希.substr(13, 3)}-${(parseInt(十六进制哈希.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${十六进制哈希.substr(18, 2)}-${十六进制哈希.substr(20, 12)}`;
		});
	}

	const 当前周数 = 获取当前周数();
	const 结束时间 = new Date(起始日期.getTime() + 当前周数 * 一周的毫秒数);

	const 当前UUIDPromise = 生成UUID(密钥 + 当前周数);
	const 上一个UUIDPromise = 生成UUID(密钥 + (当前周数 - 1));

	const 到期时间UTC = new Date(结束时间.getTime() - 时区偏移 * 60 * 60 * 1000); // UTC时间
	const 到期时间字符串 = `到期时间(UTC): ${到期时间UTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${结束时间.toISOString().slice(0, 19).replace('T', ' ')}\n`;

	return Promise.all([当前UUIDPromise, 上一个UUIDPromise, 到期时间字符串]);
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
    if (!env.KV) {
        return new Response("未绑定KV空间", { status: 400 });
    }
    try {
        const url = new URL(request.url);
        const type = url.searchParams.get('type');

        // 获取当前的 settings 对象
        const settingsJSON = await env.KV.get('settinggs.txt');
        let settings = settingsJSON ? JSON.parse(settingsJSON) : {};

        if (type === 'advanced') {
            // 更新高级设置
            const advancedSettingsUpdate = JSON.parse(await request.text());
            settings = { ...settings, ...advancedSettingsUpdate };
        } else {
            // 更新主列表内容 (ADD)
            settings.ADD = await request.text();
        }

        // 将合并后的 settings 对象写回 KV
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

async function handleGetRequest(env) {
    let content = '';
    let hasKV = !!env.KV;
    let proxyIPContent = '';
    let socks5Content = '';
    let httpProxyContent = '';
    let subContent = '';
    let subAPIContent = '';
    let subConfigContent = '';
    let nat64Content = '';
	let httpsPortsContent = '';
    let httpPortsContent = '';
    let noTLSContent = 'false';

    if (hasKV) {
        try {
            const advancedSettingsJSON = await env.KV.get('settinggs.txt');
            if (advancedSettingsJSON) {
                const settings = JSON.parse(advancedSettingsJSON);
                content = settings.ADD || ''; // 从 'ADD' 字段加载主内容
                proxyIPContent = settings.proxyip || '';
                socks5Content = settings.socks5 || '';
                httpProxyContent = settings.httpproxy || '';
                subContent = settings.sub || '';
                subAPIContent = settings.subapi || '';
                subConfigContent = settings.subconfig || '';
                nat64Content = settings.nat64 || '';
				httpsPortsContent = settings.httpsports || httpsPorts.join(',');
                httpPortsContent = settings.httpports || httpPorts.join(',');
                noTLSContent = settings.notls || 'false';
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
        <html>
        <head>
            <title>优选订阅列表</title>
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
                    background: var(--section-bg, white);
                    padding: 25px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                
                html.dark-mode .container {
                    background: #242526;
                }

                .title {
                    font-size: 1.5em;
                    color: var(--text-color);
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid var(--border-color);
                }

                .editor-container {
                    width: 100%;
                    margin: 20px 0;
                }

                .editor, .setting-editor {
                    background-color: var(--section-bg, white);
                    color: var(--text-color);
                }
                
                html.dark-mode .editor, html.dark-mode .setting-editor {
                    background-color: #2a2a2a;
                }

                .editor:focus, .setting-editor:focus {
                    outline: none;
                    border-color: var(--primary-color);
                    box-shadow: 0 0 0 2px rgba(13, 110, 253, 0.25);
                }
				
				html.dark-mode .editor:focus,
				html.dark-mode .setting-editor:focus {
					outline: none;
					border-color: var(--primary-color);
					box-shadow: 0 0 0 2px rgba(88, 155, 255, 0.25);
				}

                .editor {
                    width: 100%;
                    height: 520px;
                    padding: 15px;
                    box-sizing: border-box;
                    border: 1px solid var(--border-color);
                    border-radius: 8px;
                    font-family: Monaco, Consolas, "Courier New", monospace;
                    font-size: 14px;
                    line-height: 1.5;
                    resize: vertical;
                }
				
                .button-group {
                    display: flex;
					align-items: center;
                    gap: 12px;
                    margin-top: 15px;
                }

                .btn {
                    padding: 8px 20px;
                    border: none;
                    border-radius: 6px;
                    font-size: 14px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.2s ease;
                }

                .btn:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }

                .btn-primary {
                    background: var(--primary-color);
                    color: #fff;
                }

                .btn-primary:hover:not(:disabled) {
                    background: var(--secondary-color);
                }

                .btn-secondary {
                    background: #6c757d;
                    color: #fff;
                }

                .btn-secondary:hover:not(:disabled) {
                    background: #5c636a;
                }

                .save-status {
                    font-size: 14px;
                    color: #666;
                }
				
				html.dark-mode .save-status {
                    color: var(--text-color);
                }

                .notice-toggle {
                    color: var(--primary-color);
                    cursor: pointer;
                    display: inline-block;
                    margin: 10px 0;
                    font-weight: 500;
                }

                .notice-content {
                    background: #f8f9fa;
                    border-left: 4px solid var(--primary-color);
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 0 8px 8px 0;
                    word-break: break-all;
                }
                
                html.dark-mode .notice-content {
						background: #3a3a3a;
				}

                .divider {
                    height: 1px;
                    background: var(--border-color);
                    margin: 20px 0;
                }

                .advanced-settings {
                    margin: 20px 0;
                    padding: 20px;
                    background: #f8f9fa;
                    border-radius: 8px;
                    border: 1px solid var(--border-color);
                }
                
                 html.dark-mode .advanced-settings {
						background: #3a3a3a;
				}

                .advanced-settings-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                    cursor: pointer;
                }

                #advanced-settings-content {
                    display: none;
                }

                .setting-item {
                    margin-bottom: 10px;
                    border: 1px solid var(--border-color);
                    border-radius: 6px;
                    overflow: hidden;
                }

                .setting-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 10px 15px;
                    background-color: #f0f0f0;
                    cursor: pointer;
                    font-weight: 500;
                }
                
                 html.dark-mode .setting-header {
						background: #424242;
				}

                .setting-content {
                    display: none; /* Initially hidden */
                    padding: 15px;
                    background-color: #fafafa;
                }
                
                 html.dark-mode .setting-content {
						background: #3a3a3a;
				}
				 
				 .setting-content p {
					 margin: 5px 0 10px 0;
					 color: #666;
				 }

				 html.dark-mode .setting-content p {
					 color: #bbb;
				 }
				 
                .setting-editor {
                    width: 100%;
                    min-height: 80px;
                    margin-top: 10px;
                    padding: 10px;
                    box-sizing: border-box;
                    border: 1px solid var(--border-color);
                    border-radius: 4px;
                    font-family: Monaco, Consolas, "Courier New", monospace;
                    font-size: 14px;
                    resize: vertical;
                }
				
				.setting-editor::placeholder {
					color: #aaa;
				}
				
				html.dark-mode .setting-editor::placeholder {
					color: #666;
				}
				
				.switch-container {
					display: flex;
					align-items: center;
					gap: 10px;
                    margin-bottom: 15px;
				}
                
                .checkbox-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));
                    gap: 10px;
                    margin-top: 10px;
                }

                .checkbox-item {
                    display: flex;
                    align-items: center;
                    gap: 5px;
                }

                .checkbox-item input[type="checkbox"] {
                    cursor: pointer;
                }
                
                .checkbox-item label {
                    cursor: pointer;
                    user-select: none;
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

                @media (max-width: 768px) {
                    body {
                        padding: 10px;
                    }

                    .container {
                        padding: 15px;
                    }

                    .editor {
                        height: 400px;
                    }

                    .checkbox-grid {
                        grid-template-columns: repeat(auto-fill, minmax(70px, 1fr));
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
                <div class="title">📝 ${FileName} 优选订阅列表</div>

                <div class="advanced-settings">
                    <div class="advanced-settings-header" onclick="toggleAdvancedSettings()">
                        <h3 style="margin: 0;">⚙️ 高级设置</h3>
                    </div>
                    <div id="advanced-settings-content">
                        <!-- PROXYIP设置 -->
                        <div class="setting-item">
                            <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>PROXYIP </strong></span>
                            </div>
                            <div class="setting-content">
                                <p>每行一个IP，格式：IP:端口(可不添加端口)</p>
                                <textarea id="proxyip" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCjEuMi4zLjQlM0E0NDMKcHJveHkuZXhhbXBsZS5jb20lM0E4NDQz'))}">${proxyIPContent}</textarea>
                            </div>
                        </div>

                        <!-- SOCKS5设置 -->
                        <div class="setting-item">
                             <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>SOCKS5 </strong></span>
                            </div>
                            <div class="setting-content">
                                <p>每行一个地址，格式：[用户名:密码@]主机:端口</p>
                                <textarea id="socks5" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCnVzZXIlM0FwYXNzJTQwMTI3LjAuMC4xJTNBMTA4MAoxMjcuMC4wLjElM0ExMDgw'))}">${socks5Content}</textarea>
                            </div>
                        </div>

                        <!-- HTTP Proxy 设置 -->
                        <div class="setting-item">
                            <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>HTTP </strong></span>
                            </div>
                            <div class="setting-content">
                                <p>每行一个地址，格式：[用户名:密码@]主机:端口</p>
                                <textarea id="httpproxy" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCnVzZXI6cGFzc0AxLjIuMy40OjgwODAKMS4yLjMuNDo4MDgw'))}">${httpProxyContent}</textarea>
                            </div>
                        </div>

                        <!-- SUB设置 -->
                        <div class="setting-item">
                            <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>SUB </strong> (优选订阅生成器)</span>
                            </div>
                            <div class="setting-content">
                                <p>只支持单个优选订阅生成器地址</p>
                                <textarea id="sub" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCnN1Yi5nb29nbGUuY29tCnN1Yi5leGFtcGxlLmNvbQ=='))}">${subContent}</textarea>
                            </div>
                        </div>

                        <!-- SUBAPI设置 -->
                        <div class="setting-item">
                            <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>SUBAPI </strong> (订阅转换后端)</span>
                            </div>
                            <div class="setting-content">
                                <p>订阅转换后端地址</p>
                                <textarea id="subapi" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCmFwaS52MS5tawpzdWIueGV0b24uZGV2'))}">${subAPIContent}</textarea>
                            </div>
                        </div>

                        <!-- SUBCONFIG设置 -->
                        <div class="setting-item">
                            <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>SUBCONFIG </strong> (订阅转换配置)</span>
                            </div>
                            <div class="setting-content">
                                <p>订阅转换配置文件地址</p>
                                <textarea id="subconfig" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRkFDTDRTU1IlMkZBQ0w0U1NSJTI1MkZtYXN0ZXIlMkZDbGFzaCUyRmNvbmZpZyUyRkFDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ=='))}">${subConfigContent}</textarea>
                            </div>
                        </div>

                        <!-- NAT64/DNS64 设置 -->
                        <div class="setting-item">
                           <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>NAT64/DNS64 </strong></span>
                            </div>
                             <div class="setting-content">
                                <p>
                                    <a id="nat64-link" target="_blank">自行查询</a>
                                </p>
                                <textarea id="nat64" class="setting-editor" placeholder="${decodeURIComponent(atob('JUU0JUJFJThCJUU1JUE2JTgyJTNBJTBBZG5zNjQuZXhhbXBsZS5jb20lMEEyYTAxJTNBNGY4JTNBYzJjJTNBMTIzZiUzQSUzQSUyRjk2'))}">${nat64Content}</textarea>
                            </div>
                        </div>
						<script>
  							const encodedURL = 'aHR0cHM6Ly9uYXQ2NC54eXo=';
  							const decodedURL = atob(encodedURL);
  							document.getElementById('nat64-link').setAttribute('href', decodedURL);
						</script>
						
						<!-- HTTPS Ports Setting -->
                        <div class="setting-item">
                            <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>随机节点 TLS 端口</strong></span>
                            </div>
                            <div class="setting-content">
                                <p>请选择用于随机生成 TLS 节点时使用的端口。</p>
                                <div class="checkbox-grid" id="httpsports-grid">
                                    ${httpsCheckboxesHTML}
                                </div>
                            </div>
                        </div>

                        <!-- HTTP Ports Setting -->
                        <div class="setting-item">
                            <div class="setting-header" onclick="toggleSetting(this)">
                                <span><strong>随机节点 noTLS 端口</strong></span>
                            </div>
                            <div class="setting-content">
                                <div class="switch-container">
                                    <label class="theme-switch" for="notls-checkbox">
                                        <input type="checkbox" id="notls-checkbox" ${noTLSContent === 'true' ? 'checked' : ''}>
                                        <div class="slider round"></div>
                                    </label>
                                    <span>启用 noTLS (将不使用 TLS 加密)</span>
                                </div>
                                <p>请选择用于随机生成 noTLS 节点时使用的端口。</p>
                                <div class="checkbox-grid" id="httpports-grid">
                                    ${httpCheckboxesHTML}
                                </div>
                            </div>
                        </div>

                        <!-- 统一的保存按钮 -->
                        <div style="margin-top: 20px;">
                            <button class="btn btn-primary" onclick="saveSettings()">保存</button>
                            <span id="settings-save-status" class="save-status"></span>
                        </div>
                    </div>
                </div>

                <!-- 保持现有内容 -->
                <a href="javascript:void(0);" id="noticeToggle" class="notice-toggle" onclick="toggleNotice()">
                    ℹ️ 注意事项 ∨
                </a>

                <div id="noticeContent" class="notice-content" style="display: none">
				    ${decodeURIComponent(atob('JTNDc3Ryb25nJTNFMS4lM0MlMkZzdHJvbmclM0UlMjBBREQlRTYlQTAlQkMlRTUlQkMlOEYlRTglQUYlQjclRTYlQUMlQTElRTclQUMlQUMlRTQlQjglODAlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTglRUYlQkMlOENJUHY2JUU1JTlDJUIwJUU1JTlEJTgwJUU5JTgwJTlBJUU1JUI4JUI4JUU4JUE2JTgxJUU3JTk0JUE4JUU0JUI4JUFEJUU2JThCJUFDJUU1JThGJUI3JUU2JThCJUFDJUU4JUI1JUI3JUU1JUI5JUI2JUU1JThBJUEwJUU3JUFCJUFGJUU1JThGJUEzJUVGJUJDJThDJUU0JUI4JThEJUU1JThBJUEwJUU3JUFCJUFGJUU1JThGJUEzJUU5JUJCJTk4JUU4JUFFJUE0JUU0JUI4JUJBJTIyNDQzJTIyJUUzJTgwJTgyJUU0JUJFJThCJUU1JUE2JTgyJUVGJUJDJTlBJTNDYnIlM0UlMEExMjcuMC4wLjElM0EyMDUzJTIzJUU0JUJDJTk4JUU5JTgwJTg5SVAlM0NiciUzRSUwQXZpc2EuY24lM0EyMDUzJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThEJTNDYnIlM0UlMEElNUIyNjA2JTNBNDcwMCUzQSUzQSU1RCUzQTIwNTMlMjMlRTQlQkMlOTglRTklODAlODlJUHY2JTNDYnIlM0UlM0NiciUzRSUwQSUwQSUzQ3N0cm9uZyUzRTIuJTNDJTJGc3Ryb25nJTNFJTIwQUREQVBJJTIwJUU1JUE2JTgyJUU2JTlFJTlDJUU2JTk4JUFGJUU0JUJCJUEzJUU3JTkwJTg2SVAlRUYlQkMlOEMlRTUlOEYlQUYlRTQlQkQlOUMlRTQlQjglQkFQUk9YWUlQJUU3JTlBJTg0JUU4JUFGJTlEJUVGJUJDJThDJUU1JThGJUFGJUU1JUIwJTg2JTIyJTNGcHJveHlpcCUzRHRydWUlMjIlRTUlOEYlODIlRTYlOTUlQjAlRTYlQjclQkIlRTUlOEElQTAlRTUlODglQjAlRTklOTMlQkUlRTYlOEUlQTUlRTYlOUMlQUIlRTUlQjAlQkUlRUYlQkMlOEMlRTQlQkUlOEIlRTUlQTYlODIlRUYlQkMlOUElM0NiciUzRSUwQWh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQlM0Zwcm94eWlwJTNEdHJ1ZSUzQ2JyJTNFJTNDYnIlM0UlMEElMEElM0NzdHJvbmclM0UzLiUzQyUyRnN0cm9uZyUzRSUyMEFEREFQSSUyMCVFNSVBNiU4MiVFNiU5RSU5QyVFNiU5OCVBRiUyMCUzQ2ElMjBocmVmJTNEJ2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRlhJVTIlMkZDbG91ZGZsYXJlU3BlZWRUZXN0JyUzRUNsb3VkZmxhcmVTcGVlZFRlc3QlM0MlMkZhJTNFJTIwJUU3JTlBJTg0JTIwY3N2JTIwJUU3JUJCJTkzJUU2JTlFJTlDJUU2JTk2JTg3JUU0JUJCJUI2JUUzJTgwJTgyJUU0JUJFJThCJUU1JUE2JTgyJUVGJUJDJTlBJTNDYnIlM0UlMEFodHRwcyUzQSUyRiUyRnJhdy5naXRodWJ1c2VyY29udGVudC5jb20lMkZjbWxpdSUyRldvcmtlclZsZXNzMnN1YiUyRm1haW4lMkZDbG91ZGZsYXJlU3BlZWRUZXN0LmNzdiUzQ2JyJTNF'))}
                </div>

                <div class="editor-container">
                    ${hasKV ? `
                        <textarea class="editor"
                            placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=='))}"
                            id="content">${content}</textarea>
                        <div class="button-group">
                            <button class="btn btn-secondary" onclick="goBack()">返回配置页</button>
                            <button class="btn btn-primary" onclick="saveContent(this)">保存</button>
                            <span class="save-status" id="saveStatus"></span>
                        </div>
                        <div class="divider"></div>
                        ${cmad}
                    ` : '<p>未绑定KV空间</p>'}
                </div>
            </div>

            <script>
                function goBack() {
                    const pathParts = window.location.pathname.split('/');
                    pathParts.pop(); // 移除 "edit"
                    const newPath = pathParts.join('/');
                    window.location.href = newPath;
                }

                async function saveContent(button) {
                    try {
                        button.disabled = true;
                        const content = document.getElementById('content').value;
                        const saveStatus = document.getElementById('saveStatus');

                        saveStatus.textContent = '保存中...';

                        const response = await fetch(window.location.href, {
                            method: 'POST',
                            body: content
                        });

                        if (response.ok) {
                            saveStatus.textContent = '保存成功';
                            setTimeout(() => {
                                saveStatus.textContent = '';
                            }, 3000);
                        } else {
                            throw new Error('保存失败: ' + await response.text());
                        }
                    } catch (error) {
                        const saveStatus = document.getElementById('saveStatus');
                        saveStatus.textContent = '❌ ' + error.message;
                        console.error('保存时发生错误:', error);
                    } finally {
                        button.disabled = false;
                    }
                }

                function toggleNotice() {
                    const noticeContent = document.getElementById('noticeContent');
                    const noticeToggle = document.getElementById('noticeToggle');
                    if (noticeContent.style.display === 'none') {
                        noticeContent.style.display = 'block';
                        noticeToggle.textContent = 'ℹ️ 注意事项 ∧';
                    } else {
                        noticeContent.style.display = 'none';
                        noticeToggle.textContent = 'ℹ️ 注意事项 ∨';
                    }
                }

                function toggleAdvancedSettings() {
                    const content = document.getElementById('advanced-settings-content');
                    const isOpening = content.style.display === 'none' || !content.style.display;

                    if (isOpening) {
                        content.style.display = 'block';
                    } else {
                        content.style.display = 'none';
                        
                        const allSettings = document.querySelectorAll('.setting-content');
                        allSettings.forEach(setting => {
                            setting.style.display = 'none';
                        });
                        const allHeaders = document.querySelectorAll('.setting-header');
                        allHeaders.forEach(header => {
                            header.classList.remove('open');
                        });
                    }
                }

                function toggleSetting(headerElement) {
                    const content = headerElement.nextElementSibling;
                    headerElement.classList.toggle('open');
                    if (content.style.display === 'none' || content.style.display === '') {
                        content.style.display = 'block';
                    } else {
                        content.style.display = 'none';
                    }
                }

                async function saveSettings() {
                    const saveStatus = document.getElementById('settings-save-status');
                    saveStatus.textContent = '保存中...';

                    try {
						const selectedHttpsPorts = Array.from(document.querySelectorAll('input[name="httpsports"]:checked')).map(cb => cb.value).join(',');
						const selectedHttpPorts = Array.from(document.querySelectorAll('input[name="httpports"]:checked')).map(cb => cb.value).join(',');

                        const advancedSettings = {
                            proxyip: document.getElementById('proxyip').value,
                            socks5: document.getElementById('socks5').value,
                            httpproxy: document.getElementById('httpproxy').value,
                            sub: document.getElementById('sub').value,
                            subapi: document.getElementById('subapi').value,
                            subconfig: document.getElementById('subconfig').value,
                            nat64: document.getElementById('nat64').value,
							notls: document.getElementById('notls-checkbox').checked.toString(),
							httpsports: selectedHttpsPorts,
                            httpports: selectedHttpPorts
                        };

                        const response = await fetch(window.location.href + '?type=advanced', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify(advancedSettings)
                        });

                        if (response.ok) {
                            saveStatus.textContent = '保存成功';
                            setTimeout(() => {
                                saveStatus.textContent = '';
                            }, 3000);
                        } else {
                            throw new Error('保存失败: ' + await response.text());
                        }
                    } catch (error) {
                        saveStatus.textContent = '❌ ' + error.message;
                        console.error('保存设置时发生错误:', error);
                    }
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

    return new Response(html, {
        headers: { "Content-Type": "text/html;charset=utf-8" }
    });
}
