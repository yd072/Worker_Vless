import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIP = '';
let subConverter = 'SUBAPI.fxxk.dedyn.io';
let subConfig = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini";
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;

let noTLS = 'false';
const expire = 4102329600; // 2099-12-31
let proxyIPs;
let socks5s;
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
let remarkIndex = 1; // CSV备注所在列偏移量
let FileName = atob('ZWRnZXR1bm5lbA==');
let BotToken;
let ChatID;
let proxyhosts = [];
let proxyhostsURL = '';
let RproxyIP = 'false';
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let 有效时间 = 7;
let 更新时间 = 3;
let userIDLow;
let userIDTime = "";
let proxyIPPool = [];
let path = '/?ed=2560';
let 动态UUID;
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];

export default {
    async fetch(request, env, ctx) {
        try {
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;
            if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
                动态UUID = env.KEY || env.TOKEN || userID;
                有效时间 = Number(env.TIME) || 有效时间;
                更新时间 = Number(env.UPTIME) || 更新时间;
                const userIDs = await 生成动态UUID(动态UUID);
                userID = userIDs[0];
                userIDLow = userIDs[1];
            }

            if (!userID) {
                return new Response('请设置你的UUID变量，或尝试重试部署，检查变量是否生效？', {
                    status: 404,
                    headers: {
                        "Content-Type": "text/plain;charset=utf-8",
                    }
                });
            }

            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);
            const fakeUserIDMD5 = await 双重哈希(`${userID}${timestamp}`);
            const fakeUserID = [
                fakeUserIDMD5.slice(0, 8),
                fakeUserIDMD5.slice(8, 12),
                fakeUserIDMD5.slice(12, 16),
                fakeUserIDMD5.slice(16, 20),
                fakeUserIDMD5.slice(20)
            ].join('-');

            const fakeHostName = `${fakeUserIDMD5.slice(6, 9)}.${fakeUserIDMD5.slice(13, 19)}`;

            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = await 整理(proxyIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

            socks5Address = env.SOCKS5 || socks5Address;
            socks5s = await 整理(socks5Address);
            socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
            socks5Address = socks5Address.split('//')[1] || socks5Address;
            if (env.GO2SOCKS5) go2Socks5s = await 整理(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await 整理(env.CFPORTS);
            if (env.BAN) banHosts = await 整理(env.BAN);
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

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                if (env.ADD) addresses = await 整理(env.ADD);
                if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
                if (env.ADDNOTLS) addressesnotls = await 整理(env.ADDNOTLS);
                if (env.ADDNOTLSAPI) addressesnotlsapi = await 整理(env.ADDNOTLSAPI);
                if (env.ADDCSV) addressescsv = await 整理(env.ADDCSV);
                DLS = Number(env.DLS) || DLS;
                remarkIndex = Number(env.CSVREMARK) || remarkIndex;
                BotToken = env.TGTOKEN || BotToken;
                ChatID = env.TGID || ChatID;
                FileName = env.SUBNAME || FileName;
                subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
                if (subEmoji == '0') subEmoji = 'false';
                if (env.LINK) link = await 整理(env.LINK);
                let sub = env.SUB || '';
                subConverter = env.SUBAPI || subConverter;
                if (subConverter.includes("http://")) {
                    subConverter = subConverter.split("//")[1];
                    subProtocol = 'http';
                } else {
                    subConverter = subConverter.split("//")[1] || subConverter;
                }
                subConfig = env.SUBCONFIG || subConfig;
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub');
                if (url.searchParams.has('notls')) noTLS = 'true';

                if (url.searchParams.has('proxyip')) {
                    path = `/?ed=2560&proxyip=${url.searchParams.get('proxyip')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks5')) {
                    path = `/?ed=2560&socks5=${url.searchParams.get('socks5')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks')) {
                    path = `/?ed=2560&socks5=${url.searchParams.get('socks')}`;
                    RproxyIP = 'false';
                }

                const 路径 = url.pathname.toLowerCase();
                if (路径 == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response(JSON.stringify(request.cf, null, 4), {
                        status: 200,
                        headers: {
                            'content-type': 'application/json',
                        },
                    });
                } else if (路径 == `/${fakeUserID}`) {
                    const fakeConfig = await 生成配置信息(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, fakeUserID, fakeHostName, env);
                    return new Response(`${fakeConfig}`, { status: 200 });
                } else if (url.pathname == `/${动态UUID}/edit` || 路径 == `/${userID}/edit`) {
                    const html = await KV(request, env);
                    return html;
                } else if (url.pathname == `/${动态UUID}` || 路径 == `/${userID}`) {
                    await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
                    const 维列斯Config = await 生成配置信息(userID, request.headers.get('Host'), sub, UA, RproxyIP, url, fakeUserID, fakeHostName, env);
                    const now = Date.now();
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;

                    if (userAgent && userAgent.includes('mozilla')) {
                        return new Response(`<div style="font-size:13px;">${维列斯Config}</div>`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                                "Cache-Control": "no-store",
                            }
                        });
                    } else {
                        return new Response(`${维列斯Config}`, {
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
                    else return new Response('不用怀疑！你UUID就是错的！！！', { status: 404 });
                }
            } else {
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

                return await 维列斯OverWSHandler(request);
            }
        } catch (err) {
            return new Response(err.toString());
        }
    },
};

async function 维列斯OverWSHandler(request) {
    // @ts-ignore
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    // 接受 WebSocket 连接
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    // 日志函数，用于记录连接信息
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };
    // 获取早期数据头部，可能包含了一些初始化数据
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    // 创建一个可读的 WebSocket 流，用于接收客户端数据
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    // 用于存储远程 Socket 的包装器
    let remoteSocketWrapper = {
        value: null,
    };
    // 标记是否为 DNS 查询
    let isDns = false;

    // 将 banHosts 转换为 Set 以提高查找速度
    const banHostsSet = new Set(banHosts);

    // WebSocket 数据流向远程服务器的管道
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            try {
                if (isDns) {
                    // 如果是 DNS 查询，调用 DNS 处理函数
                    return await handleDNSQuery(chunk, webSocket, null, log);
                }
                if (remoteSocketWrapper.value) {
                    // 如果已有远程 Socket，直接写入数据
                    const writer = remoteSocketWrapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }

                // 处理 维列斯 协议头部
                const {
                    hasError,
                    message,
                    addressType,
                    portRemote = 443,
                    addressRemote = '',
                    rawDataIndex,
                    维列斯Version = new Uint8Array([0, 0]),
                    isUDP,
                } = process维列斯Header(chunk, userID);
                // 设置地址和端口信息，用于日志
                address = addressRemote;
                portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
                if (hasError) {
                    // 如果有错误，抛出异常
                    throw new Error(message);
                }
                // 如果是 UDP 且端口不是 DNS 端口（53），则关闭连接
                if (isUDP) {
                    if (portRemote === 53) {
                        isDns = true;
                    } else {
                        throw new Error('UDP 代理仅对 DNS（53 端口）启用');
                    }
                }
                // 构建 维列斯 响应头部
                const 维列斯ResponseHeader = new Uint8Array([维列斯Version[0], 0]);
                // 获取实际的客户端数据
                const rawClientData = chunk.slice(rawDataIndex);

                if (isDns) {
                    // 如果是 DNS 查询，调用 DNS 处理函数
                    return handleDNSQuery(rawClientData, webSocket, 维列斯ResponseHeader, log);
                }
                // 处理 TCP 出站连接
                if (!banHostsSet.has(addressRemote)) {
                    log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
                    handleTCPOutBound(remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log);
                } else {
                    throw new Error(`黑名单关闭 TCP 出站连接 ${addressRemote}:${portRemote}`);
                }
            } catch (error) {
                log('处理数据时发生错误', error.message);
            }
        },
        close() {
            log(`readableWebSocketStream 已关闭`);
        },
        abort(reason) {
            log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream 管道错误', err);
    });

    // 返回一个 WebSocket 升级的响应
    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log,) {
	async function useSocks5Pattern(address) {
		if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) return true;
		return go2Socks5s.some(pattern => {
			let regexPattern = pattern.replace(/\*/g, '.*');
			let regex = new RegExp(`^${regexPattern}$`, 'i');
			return regex.test(address);
		});
	}

	async function connectAndWrite(address, port, socks = false) {
		log(`connected to ${address}:${port}`);
		//if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
		// 如果指定使用 SOCKS5 代理，则通过 SOCKS5 协议连接；否则直接连接
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
			: connect({
				hostname: address,
				port: port,
			});
		remoteSocket.value = tcpSocket;
		//log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		// 首次写入，通常是 TLS 客户端 Hello 消息
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

/**
 * 重试函数：当 Cloudflare 的 TCP Socket 没有传入数据时，我们尝试重定向 IP
 * 这可能是因为某些网络问题导致的连接失败
 */
async function retry() {
    if (enableSocks) {
        // 如果启用了 SOCKS5，通过 SOCKS5 代理重试连接
        tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
    } else {
        // 否则，尝试使用预设的代理 IP（如果有）或原始地址重试连接
        if (!proxyIP || proxyIP === '') {
            proxyIP = atob(`UFJPWFlJUC50cDEuZnh4ay5kZWR5bi5pbw==`);
        } else {
            const proxyParts = proxyIP.split(':');
            if (proxyIP.includes(']:')) {
                [proxyIP, portRemote] = proxyIP.split(']:');
            } else if (proxyParts.length === 2) {
                [proxyIP, portRemote] = proxyParts;
            }
            if (proxyIP.includes('.tp')) {
                portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
            }
        }
        tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
    }
    // 无论重试是否成功，都要关闭 WebSocket（可能是为了重新建立连接）
    tcpSocket.closed.catch(error => {
        console.log('retry tcpSocket closed error', error);
    }).finally(() => {
        safeCloseWebSocket(webSocket);
    });
    // 建立从远程 Socket 到 WebSocket 的数据流
    remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, null, log);
}

// 确保以下代码在函数或模块的正确位置
let shouldUseSocks = false;
if (go2Socks5s.length > 0 && enableSocks) {
    shouldUseSocks = await useSocks5Pattern(addressRemote);
}
// 首次尝试连接远程服务器
let tcpSocket = await connectAndWrite(addressRemote, portRemote, shouldUseSocks);

// 当远程 Socket 就绪时，将其传递给 WebSocket
// 建立从远程服务器到 WebSocket 的数据流，用于将远程服务器的响应发送回客户端
// 如果连接失败或无数据，retry 函数将被调用进行重试
remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, retry, log);
}
	
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let isReadableStreamCancelled = false;

    const stream = new ReadableStream({
        start(controller) {
            const onMessage = (event) => {
                if (isReadableStreamCancelled) return;
                const message = event.data;
                controller.enqueue(message);
            };

            const onClose = () => {
                safeCloseWebSocket(webSocketServer);
                if (!isReadableStreamCancelled) {
                    controller.close();
                }
                removeEventListeners();
            };

            const onError = (err) => {
                log('WebSocket 服务器发生错误', err.message);
                controller.error(err);
                removeEventListeners();
            };

            const removeEventListeners = () => {
                webSocketServer.removeEventListener('message', onMessage);
                webSocketServer.removeEventListener('close', onClose);
                webSocketServer.removeEventListener('error', onError);
            };

            webSocketServer.addEventListener('message', onMessage);
            webSocketServer.addEventListener('close', onClose);
            webSocketServer.addEventListener('error', onError);

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
            // 实现反压机制
        },

        cancel(reason) {
            if (isReadableStreamCancelled) return;
            log(`可读流被取消，原因是 ${reason}`);
            isReadableStreamCancelled = true;
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

// https://xtls.github.io/development/protocols/维列斯.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * 解析 维列斯 协议的头部数据
 * @param {ArrayBuffer} 维列斯Buffer 维列斯 协议的原始头部数据
 * @param {string} userID 用于验证的用户 ID
 * @returns {Object} 解析结果，包括是否有错误、错误信息、远程地址信息等
 */
function process维列斯Header(维列斯Buffer, userID) {
    if (维列斯Buffer.byteLength < 24) {
        return {
            hasError: true,
            message: '数据长度不足，无法解析维列斯协议头部',
        };
    }

    const 维列斯Version = new Uint8Array(维列斯Buffer.slice(0, 1));
    const userIDArray = new Uint8Array(维列斯Buffer.slice(1, 17));
    const userIDString = stringify(userIDArray);
    const isValidUser = userIDString === userID || userIDString === userIDLow;

    if (!isValidUser) {
        return {
            hasError: true,
            message: `无效的用户 ID: ${userIDString}`,
        };
    }

    const optLength = new Uint8Array(维列斯Buffer.slice(17, 18))[0];
    const command = new Uint8Array(维列斯Buffer.slice(18 + optLength, 18 + optLength + 1))[0];
    let isUDP = false;

    switch (command) {
        case 1:
            break;
        case 2:
            isUDP = true;
            break;
        default:
            return {
                hasError: true,
                message: `不支持的命令 ${command}，支持的命令有 01-tcp, 02-udp, 03-mux`,
            };
    }

    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(维列斯Buffer, portIndex, 2).getUint16(0);

    const addressIndex = portIndex + 2;
    const addressType = new Uint8Array(维列斯Buffer.slice(addressIndex, addressIndex + 1))[0];
    let addressValue = '';
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
            break;
        case 2:
            addressLength = new Uint8Array(维列斯Buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            break;
        default:
            return {
                hasError: true,
                message: `无效的地址类型: ${addressType}`,
            };
    }

    if (!addressValue) {
        return {
            hasError: true,
            message: `地址值为空，地址类型为 ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        维列斯Version,
        isUDP,
    };
}
	
async function remoteSocketToWS(remoteSocket, webSocket, 维列斯ResponseHeader, retry, log) {
    const WS_READY_STATE_OPEN = 1; // WebSocket open state

    let chunkCount = 0;
    let hasIncomingData = false;
    let 维列斯Header = 维列斯ResponseHeader;

    try {
        await remoteSocket.readable.pipeTo(
            new WritableStream({
                start() {
                    // 初始化时不需要任何操作
                },
                async write(chunk, controller) {
                    hasIncomingData = true;

                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error('WebSocket 连接未打开，可能已关闭');
                        return;
                    }

                    try {
                        if (维列斯Header) {
                            const combinedData = await new Blob([维列斯Header, chunk]).arrayBuffer();
                            webSocket.send(combinedData);
                            维列斯Header = null;
                        } else {
                            webSocket.send(chunk);
                        }
                    } catch (error) {
                        controller.error(`发送数据时发生错误: ${error.message}`);
                        safeCloseWebSocket(webSocket);
                    }
                },
                close() {
                    log(`远程连接的可读流已关闭，hasIncomingData: ${hasIncomingData}`);
                },
                abort(reason) {
                    console.error(`远程连接的可读流中断`, reason);
                },
            })
        );
    } catch (error) {
        console.error(`remoteSocketToWS 发生异常`, error.stack || error);
        safeCloseWebSocket(webSocket);
    }

    if (!hasIncomingData && retry) {
        log(`重试连接`);
        retry();
    }
}

/**
 * 将 Base64 编码的字符串转换为 ArrayBuffer
 * 
 * @param {string} base64Str Base64 编码的输入字符串
 * @returns {{ earlyData: ArrayBuffer | undefined, error: Error | null }} 返回解码后的 ArrayBuffer 或错误
 */
function base64ToArrayBuffer(base64Str) {
    if (typeof base64Str !== 'string' || !base64Str) {
        return { earlyData: undefined, error: new Error('输入必须是非空字符串') };
    }

    try {
        // 将 URL 安全的 Base64 变体转换为标准 Base64
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');

        // 使用 atob 函数解码 Base64 字符串
        const decodedString = atob(base64Str);

        // 将二进制字符串转换为 Uint8Array
        const arrayBuffer = Uint8Array.from(decodedString, (c) => c.charCodeAt(0));

        return { earlyData: arrayBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error: new Error(`Base64 解码失败: ${error.message}`) };
    }
}

/**
 * 这不是真正的 UUID 验证，而是一个简化的版本
 * @param {string} uuid 要验证的 UUID 字符串
 * @returns {boolean} 如果字符串匹配 UUID 格式则返回 true，否则返回 false
 */
function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

// WebSocket 的两个重要状态常量
const WS_READY_STATE_OPEN = 1;    // WebSocket 处于开放状态，可以发送和接收消息
const WS_READY_STATE_CLOSING = 2; // WebSocket 正在关闭过程中

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

// 预计算 0-255 每个字节的十六进制表示
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

/**
 * 快速地将字节数组转换为 UUID 字符串，不进行有效性检查
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} UUID 字符串
 */
function unsafeStringify(arr, offset = 0) {
    return `${byteToHex[arr[offset + 0]]}${byteToHex[arr[offset + 1]]}${byteToHex[arr[offset + 2]]}${byteToHex[arr[offset + 3]]}-${byteToHex[arr[offset + 4]]}${byteToHex[arr[offset + 5]]}-${byteToHex[arr[offset + 6]]}${byteToHex[arr[offset + 7]]}-${byteToHex[arr[offset + 8]]}${byteToHex[arr[offset + 9]]}-${byteToHex[arr[offset + 10]]}${byteToHex[arr[offset + 11]]}${byteToHex[arr[offset + 12]]}${byteToHex[arr[offset + 13]]}${byteToHex[arr[offset + 14]]}${byteToHex[arr[offset + 15]]}`.toLowerCase();
}

/**
 * 将字节数组转换为 UUID 字符串，并验证其有效性
 * 这是一个安全的函数，它确保返回的 UUID 格式正确
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} 有效的 UUID 字符串
 * @throws {TypeError} 如果生成的 UUID 字符串无效
 */
function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw new TypeError(`生成的 UUID 不符合规范: ${uuid}`);
    }
    return uuid;
}

/**
 * 处理 DNS 查询的函数
 * @param {ArrayBuffer} udpChunk - 客户端发送的 DNS 查询数据
 * @param {WebSocket} webSocket - 用于发送响应的 WebSocket
 * @param {ArrayBuffer} 维列斯ResponseHeader - 维列斯 协议的响应头部数据
 * @param {(string) => void} log - 日志记录函数
 */
async function handleDNSQuery(udpChunk, webSocket, 维列斯ResponseHeader, log) {
    const WS_READY_STATE_OPEN = 1; // WebSocket open state

    try {
        const dnsServer = '8.8.4.4'; // Google DNS server
        const dnsPort = 53; // Standard DNS port

        let 维列斯Header = 维列斯ResponseHeader;

        const tcpSocket = connect({
            hostname: dnsServer,
            port: dnsPort,
        });

        log(`连接到 ${dnsServer}:${dnsPort}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();

        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    try {
                        if (维列斯Header) {
                            const combinedData = await new Blob([维列斯Header, chunk]).arrayBuffer();
                            webSocket.send(combinedData);
                            维列斯Header = null;
                        } else {
                            webSocket.send(chunk);
                        }
                    } catch (error) {
                        console.error(`发送数据时发生错误: ${error.message}`);
                        safeCloseWebSocket(webSocket);
                    }
                }
            },
            close() {
                log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`);
            },
            abort(reason) {
                console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason);
            },
        }));
    } catch (error) {
        console.error(`handleDNSQuery 函数发生异常，错误信息: ${error.message}`, error.stack);
        safeCloseWebSocket(webSocket);
    }
}

/**
 * 建立 SOCKS5 代理连接
 * @param {number} addressType 目标地址类型（1: IPv4, 2: 域名, 3: IPv6）
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 * @param {function} log 日志记录函数
 * @returns {Promise<Socket>} 返回与 SOCKS5 服务器的连接
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;

    try {
        const socket = connect({
            hostname,
            port,
        });

        const socksGreeting = new Uint8Array([5, 2, 0, 2]);
        const writer = socket.writable.getWriter();
        await writer.write(socksGreeting);
        log('已发送 SOCKS5 问候消息');

        const reader = socket.readable.getReader();
        const encoder = new TextEncoder();
        let res = (await reader.read()).value;

        if (res[0] !== 0x05) {
            log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
            return;
        }
        if (res[1] === 0xff) {
            log("服务器不接受任何认证方法");
            return;
        }

        if (res[1] === 0x02) {
            log("SOCKS5 服务器需要认证");
            if (!username || !password) {
                log("请提供用户名和密码");
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
                log("SOCKS5 服务器认证失败");
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
                DSTADDR = new Uint8Array([4, ...addressRemote.split(':').flatMap(x => {
                    const part = parseInt(x, 16);
                    return [(part >> 8) & 0xff, part & 0xff];
                })]);
                break;
            default:
                log(`无效的地址类型: ${addressType}`);
                return;
        }
        const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
        await writer.write(socksRequest);
        log('已发送 SOCKS5 请求');

        res = (await reader.read()).value;
        if (res[1] === 0x00) {
            log("SOCKS5 连接已建立");
        } else {
            log(`SOCKS5 连接建立失败，错误码: ${res[1]}`);
            return;
        }

        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        log(`socks5Connect 函数发生异常，错误信息: ${error.message}`);
        throw error;
    }
}

/**
 * SOCKS5 代理地址解析器
 * @param {string} address SOCKS5 代理地址
 * @returns {Object} 包含解析后的用户名、密码、主机名和端口号
 */
function socks5AddressParser(address) {
    let [latter, former] = address.split("@").reverse();
    let username, password, hostname, port;

    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
        }
        [username, password] = formers;
    }

    const latters = latter.split(":");
    port = Number(latters.pop());
    if (isNaN(port)) {
        throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    }

    hostname = latters.join(":");

    const ipv6Regex = /^\[.*\]$/;
    if (hostname.includes(":") && !ipv6Regex.test(hostname)) {
        throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
    }

    return {
        username,
        password,
        hostname,
        port,
    };
}

/**
 * 恢复被伪装的信息
 * 这个函数用于将内容中的假用户ID和假主机名替换回真实的值
 * 
 * @param {string} content 需要处理的内容
 * @param {string} userID 真实的用户ID
 * @param {string} hostName 真实的主机名
 * @param {string} fakeUserID 伪装的用户ID
 * @param {string} fakeHostName 伪装的主机名
 * @param {boolean} isBase64 内容是否是Base64编码的
 * @returns {string} 恢复真实信息后的内容
 */
function 恢复伪装信息(content, userID, hostName, fakeUserID, fakeHostName, isBase64) {
    try {
        if (isBase64) {
            content = atob(content);  // 如果内容是Base64编码的，先解码
        }

        const escapeRegExp = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const fakeUserIDRegex = new RegExp(escapeRegExp(fakeUserID), 'g');
        const fakeHostNameRegex = new RegExp(escapeRegExp(fakeHostName), 'g');

        content = content.replace(fakeUserIDRegex, userID)
                         .replace(fakeHostNameRegex, hostName);

        if (isBase64) {
            content = btoa(content);  // 如果原内容是Base64编码的，处理完后再次编码
        }

        return content;
    } catch (error) {
        console.error('处理内容时发生错误:', error);
        return content;  // 返回原始内容以防止数据丢失
    }
}

/**
 * 双重MD5哈希函数
 * 这个函数对输入文本进行两次MD5哈希，增强安全性
 * 第二次哈希使用第一次哈希结果的一部分作为输入
 * 
 * @param {string} 文本 要哈希的文本
 * @returns {Promise<string>} 双重哈希后的小写十六进制字符串
 */
async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();

    const 计算哈希 = async (输入) => {
        const 哈希 = await crypto.subtle.digest('MD5', 编码器.encode(输入));
        const 哈希数组 = Array.from(new Uint8Array(哈希));
        return 哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');
    };

    try {
        // 第一次哈希
        const 第一次十六进制 = await 计算哈希(文本);

        // 第二次哈希，使用第一次哈希结果的一部分
        const 第二次十六进制 = await 计算哈希(第一次十六进制.slice(7, 27));

        return 第二次十六进制.toLowerCase();
    } catch (error) {
        console.error('哈希计算时发生错误:', error);
        throw error;  // 重新抛出错误以便调用者处理
    }
}

/**
 * 代理URL函数
 * 通过从代理网址列表中随机选择一个网址来构建新的请求
 * 
 * @param {string} 代理网址 - 用于代理的基础网址
 * @param {URL} 目标网址 - 目标网址对象
 * @returns {Promise<Response>} 返回新的响应对象
 */
async function 代理URL(代理网址, 目标网址) {
    try {
        const 网址列表 = await 整理(代理网址);
        if (网址列表.length === 0) {
            throw new Error('代理网址列表为空');
        }

        const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];
        const 解析后的网址 = new URL(完整网址);

        const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
        const 主机名 = 解析后的网址.hostname;
        let 路径名 = 解析后的网址.pathname;
        const 查询参数 = 解析后的网址.search;

        // 确保路径名正确拼接
        if (!路径名.endsWith('/')) {
            路径名 += '/';
        }
        路径名 += 目标网址.pathname.replace(/^\//, '');

        // 构建新的 URL
        const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

        // 反向代理请求
        const 响应 = await fetch(新网址);

        // 创建新的响应
        const 新响应 = new Response(响应.body, {
            status: 响应.status,
            statusText: 响应.statusText,
            headers: 响应.headers
        });

        // 添加自定义头部，包含 URL 信息
        新响应.headers.set('X-New-URL', 新网址);

        return 新响应;
    } catch (error) {
        console.error('代理URL函数发生异常:', error);
        throw error;
    }
}

const 啥啥啥_写的这是啥啊 = atob('ZG14bGMzTT0=');
function 配置信息(UUID, 域名地址) {
	const 协议类型 = atob(啥啥啥_写的这是啥啊);

	const 别名 = FileName;
	let 地址 = 域名地址;
	let 端口 = 443;

	const 用户ID = UUID;
	const 加密方式 = 'none';

	const 传输层协议 = 'ws';
	const 伪装域名 = 域名地址;
	const 路径 = path;

	let 传输层安全 = ['tls', true];
	const SNI = 域名地址;
	const 指纹 = 'randomized';

	if (域名地址.includes('.workers.dev')) {
		地址 = atob('dmlzYS5jbg==');
		端口 = 80;
		传输层安全 = ['', false];
	}

	const 威图瑞 = `${协议类型}://${用户ID}@${地址}:${端口}\u003f\u0065\u006e\u0063\u0072\u0079` + 'p' + `${atob('dGlvbj0=') + 加密方式}\u0026\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079\u003d${传输层安全[0]}&sni=${SNI}&fp=${指纹}&type=${传输层协议}&host=${伪装域名}&path=${encodeURIComponent(路径)}#${encodeURIComponent(别名)}`;
	const 猫猫猫 = `- {name: ${FileName}, server: ${地址}, port: ${端口}, type: ${协议类型}, uuid: ${用户ID}, tls: ${传输层安全[1]}, alpn: [h3], udp: false, sni: ${SNI}, tfo: false, skip-cert-verify: true, servername: ${伪装域名}, client-fingerprint: ${指纹}, network: ${传输层协议}, ws-opts: {path: "${路径}", headers: {${伪装域名}}}}`;
	return [威图瑞, 猫猫猫];
}

let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjM='));
/**
 * @param {string} userID
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
async function 生成配置信息(userID, hostName, sub, UA, RproxyIP, _url, fakeUserID, fakeHostName, env) {
    if (sub) {
        const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) {
            sub = match[1];
        }
        const subs = await 整理(sub);
        if (subs.length > 1) sub = subs[0];
    } else {
        if (env.KV) {
            await 迁移地址列表(env);
            const 优选地址列表 = await env.KV.get('ADD.txt');
            if (优选地址列表) {
                const 优选地址数组 = await 整理(优选地址列表);
                const 分类地址 = {
                    接口地址: new Set(),
                    链接地址: new Set(),
                    优选地址: new Set()
                };

                for (const 元素 of 优选地址数组) {
                    if (元素.startsWith('https://')) {
                        分类地址.接口地址.add(元素);
                    } else if (元素.includes('://')) {
                        分类地址.链接地址.add(元素);
                    } else {
                        分类地址.优选地址.add(元素);
                    }
                }

                addressesapi = [...分类地址.接口地址];
                link = [...分类地址.链接地址];
                addresses = [...分类地址.优选地址];
            }
        }

        if ((addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
            const cfips = [
                '103.21.244.0/23',
                '104.16.0.0/13',
                '104.24.0.0/14',
                '172.64.0.0/14',
                '103.21.244.0/23',
                '104.16.0.0/14',
                '104.24.0.0/15',
                '141.101.64.0/19',
                '172.64.0.0/14',
                '188.114.96.0/21',
                '190.93.240.0/21',
            ];

            function generateRandomIPFromCIDR(cidr) {
                const [base, mask] = cidr.split('/');
                const baseIP = base.split('.').map(Number);
                const subnetMask = 32 - parseInt(mask, 10);
                const maxHosts = Math.pow(2, subnetMask) - 1;
                const randomHost = Math.floor(Math.random() * maxHosts);

                const randomIP = baseIP.map((octet, index) => {
                    if (index < 3) {
                        if (index === 2) {
                            return (octet & (255 << (8 - (subnetMask % 8)))) + ((randomHost >> 8) & 255);
                        }
                        return octet;
                    }
                    return (octet & (255 << subnetMask)) + (randomHost & 255);
                });

                return randomIP.join('.');
            }

            addresses = addresses.concat('127.0.0.1:1234#CFnat');
            if (hostName.includes(".workers.dev")) {
                addressesnotls = addressesnotls.concat(cfips.map(cidr => generateRandomIPFromCIDR(cidr) + '#CF随机节点'));
            } else {
                addresses = addresses.concat(cfips.map(cidr => generateRandomIPFromCIDR(cidr) + '#CF随机节点'));
            }
        }
    }

    const uuid = (_url.pathname == `/${动态UUID}`) ? 动态UUID : userID;
    const userAgent = UA.toLowerCase();
    const Config = 配置信息(userID, hostName);
    const v2ray = Config[0];
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
                console.error('获取地址时出错:', error);
            }
        }
        if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
    }

    if (userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
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
        if (sub) {
            if (enableSocks) 订阅器 += `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
            else if (proxyIP && proxyIP != '') 订阅器 += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
            else if (RproxyIP == 'true') 订阅器 += `CFCDN（访问方式）: 自动获取ProxyIP<br>`;
            else 订阅器 += `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`
            订阅器 += `<br>SUB（优选订阅生成器）: ${sub}`;
        } else {
            if (enableSocks) 订阅器 += `CFCDN（访问方式）: Socks5<br>&nbsp;&nbsp;${newSocks5s.join('<br>&nbsp;&nbsp;')}<br>${socks5List}`;
            else if (proxyIP && proxyIP != '') 订阅器 += `CFCDN（访问方式）: ProxyIP<br>&nbsp;&nbsp;${proxyIPs.join('<br>&nbsp;&nbsp;')}<br>`;
            else 订阅器 += `CFCDN（访问方式）: 无法访问, 需要您设置 proxyIP/PROXYIP ！！！<br>`;
            let 判断是否绑定KV空间 = '';
            if (env.KV) 判断是否绑定KV空间 = ` <a href='${_url.pathname}/edit'>编辑优选列表</a>`;
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
            ################################################################<br>
            Subscribe / sub 订阅地址, 点击链接自动 <strong>复制订阅链接</strong> 并 <strong>生成订阅二维码</strong> <br>
            ---------------------------------------------------------------<br>
            自适应订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sub','qrcode_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}</a><br>
            <div id="qrcode_0" style="margin: 10px 10px 10px 10px;"></div>
            Base64订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?b64','qrcode_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?b64</a><br>
            <div id="qrcode_1" style="margin: 10px 10px 10px 10px;"></div>
            clash订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?clash','qrcode_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?clash</a><br>
            <div id="qrcode_2" style="margin: 10px 10px 10px 10px;"></div>
            singbox订阅地址:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyhost}${hostName}/${uuid}?sb','qrcode_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyhost}${hostName}/${uuid}?sb</a><br>
            <div id="qrcode_3" style="margin: 10px 10px 10px 10px;"></div>
            <strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">实用订阅技巧∨</a></strong><br>
                <div id="noticeContent" class="notice-content" style="display: none;">
                    <strong>1.</strong> 如您使用的是 PassWall、SSR+ 等路由插件，推荐使用 <strong>Base64订阅地址</strong> 进行订阅；<br>
                    <br>
                    <strong>2.</strong> 快速切换 <a href='${atob('aHR0cHM6Ly9naXRodWIuY29tL2NtbGl1L1dvcmtlclZsZXNzMnN1Yg==')}'>优选订阅生成器</a> 至：sub.google.com，您可将"?sub=sub.google.com"参数添加到链接末尾，例如：<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?sub=sub.google.com</strong><br>
                    <br>
                    <strong>3.</strong> 快速更换 PROXYIP 至：proxyip.fxxk.dedyn.io:443，您可将"?proxyip=proxyip.fxxk.dedyn.io:443"参数添加到链接末尾，例如：<br>
                    &nbsp;&nbsp; https://${proxyhost}${hostName}/${uuid}<strong>?proxyip=proxyip.fxxk.dedyn.io:443</strong><br>
                    <br>
                    <strong>4.</strong> 快速更换 SOCKS5 至：user:password@127.0.0.1:1080，您可将"?socks5=user:password@127.0.0.1:1080"参数添加到链接末尾，例如：<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}<strong>?socks5=user:password@127.0.0.1:1080</strong><br>
                    <br>
                    <strong>5.</strong> 如需指定多个参数则需要使用'&'做间隔，例如：<br>
                    &nbsp;&nbsp;https://${proxyhost}${hostName}/${uuid}?sub=sub.google.com<strong>&</strong>proxyip=proxyip.fxxk.dedyn.io<br>
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
                    noticeToggle.textContent = '实用订阅技巧∧';
                } else {
                    noticeContent.style.display = 'none'; 
                    noticeToggle.textContent = '实用订阅技巧∨';
                }
            }
            </script>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            ${FileName} 配置信息<br>
            ---------------------------------------------------------------<br>
            ${动态UUID信息}HOST: ${hostName}<br>
            UUID: ${userID}<br>
            FKID: ${fakeUserID}<br>
            UA: ${UA}<br>
            ${订阅器}<br>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            v2ray<br>
            ---------------------------------------------------------------<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('${v2ray}','qrcode_v2ray')" style="color:blue;text-decoration:underline;cursor:pointer;">${v2ray}</a><br>
            <div id="qrcode_v2ray" style="margin: 10px 10px 10px 10px;"></div>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            clash-meta<br>
            ---------------------------------------------------------------<br>
            ${clash}<br>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            ${cmad}
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

        if (hostName.includes(".workers.dev")) {
            noTLS = 'true';
            fakeHostName = `${fakeHostName}.workers.dev`;
            newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
            newAddressesnotlscsv = await 整理测速结果('FALSE');
        } else if (hostName.includes(".pages.dev")) {
            fakeHostName = `${fakeHostName}.pages.dev`;
        } else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
            noTLS = 'true';
            fakeHostName = `notls${fakeHostName}.net`;
            newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
            newAddressesnotlscsv = await 整理测速结果('FALSE');
        } else {
            fakeHostName = `${fakeHostName}.xyz`
        }
        console.log(`虚假HOST: ${fakeHostName}`);
        let url = `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID + atob('JmVkZ2V0dW5uZWw9Y21saXUmcHJveHlpcD0=') + RproxyIP}&path=${encodeURIComponent(path)}`;
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

        if (!userAgent.includes(('CF-Workers-SUB').toLowerCase())) {
            if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
                url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || ((_url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
                url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
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
                        'User-Agent': UA + atob('IENGLVdvcmtlcnMtZWRnZXR1bm5lbC9jbWxpdQ==')
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
                const content = await response.value;
                newapi += processContent(content, api[index]);
            }
        }
    } catch (error) {
        console.error('请求处理出错:', error);
    } finally {
        clearTimeout(timeout);
    }

    return await 整理(newapi);
}

function processContent(content, apiUrl) {
    const lines = content.split(/\r?\n/);
    let 节点备注 = '';
    let 测速端口 = '443';
    let result = '';

    if (lines[0].split(',').length > 3) {
        节点备注 = extractParam(apiUrl, 'id');
        测速端口 = extractParam(apiUrl, 'port') || 测速端口;

        for (let i = 1; i < lines.length; i++) {
            const columns = lines[i].split(',')[0];
            if (columns) {
                result += `${columns}:${测速端口}${节点备注 ? `#${节点备注}` : ''}\n`;
                if (apiUrl.includes('proxyip=true')) proxyIPPool.push(`${columns}:${测速端口}`);
            }
        }
    } else {
        if (apiUrl.includes('proxyip=true')) {
            proxyIPPool = proxyIPPool.concat((整理(content)).map(item => {
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
        result += content + '\n';
    }

    return result;
}

function extractParam(url, param) {
    const match = url.match(new RegExp(`${param}=([^&]*)`));
    return match ? match[1] : '';
}

async function 整理测速结果(tls) {
    if (!addressescsv || addressescsv.length === 0) {
        return [];
    }

    const fetchCsvData = async (csvUrl) => {
        try {
            const response = await fetch(csvUrl);
            if (!response.ok) {
                console.error('获取CSV地址时出错:', response.status, response.statusText);
                return [];
            }

            const text = await response.text();
            const lines = text.includes('\r\n') ? text.split('\r\n') : text.split('\n');
            return lines;
        } catch (error) {
            console.error('获取CSV地址时出错:', error);
            return [];
        }
    };

    const processCsvLines = (lines, tls) => {
        const newAddressescsv = [];
        if (lines.length === 0) return newAddressescsv;

        const header = lines[0].split(',');
        const tlsIndex = header.indexOf('TLS');
        if (tlsIndex === -1) {
            console.error('CSV文件缺少必需的字段');
            return newAddressescsv;
        }

        const ipAddressIndex = 0;
        const portIndex = 1;
        const dataCenterIndex = tlsIndex + remarkIndex;

        for (let i = 1; i < lines.length; i++) {
            const columns = lines[i].split(',');
            const speedIndex = columns.length - 1;

            if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
                const ipAddress = columns[ipAddressIndex];
                const port = columns[portIndex];
                const dataCenter = columns[dataCenterIndex];

                const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
                newAddressescsv.push(formattedAddress);

                if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() === 'TRUE' && !httpsPorts.includes(port)) {
                    proxyIPPool.push(`${ipAddress}:${port}`);
                }
            }
        }
        return newAddressescsv;
    };

    const csvDataPromises = addressescsv.map(csvUrl => fetchCsvData(csvUrl));
    const csvDataArray = await Promise.all(csvDataPromises);

    return csvDataArray.flatMap(lines => processCsvLines(lines, tls));
}

function 生成本地订阅(host, UUID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
    const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
    const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
    const httpsPorts = ["443", "8443", "2053", "2083", "2087", "2096"];
    const 协议类型 = atob(啥啥啥_写的这是啥啊);

    const processAddresses = (addresses, isNoTLS) => {
        const uniqueAddresses = [...new Set(addresses)];
        return uniqueAddresses.map(address => {
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

            if (!isValidIPv4(address) && port == "-1") {
                const ports = isNoTLS ? httpPorts : httpsPorts;
                for (let p of ports) {
                    if (address.includes(p)) {
                        port = p;
                        break;
                    }
                }
            }
            if (port == "-1") port = isNoTLS ? "80" : "443";

            let 伪装域名 = host;
            let 最终路径 = path;
            let 节点备注 = '';
            if (!isNoTLS) {
                const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(address));
                if (matchingProxyIP) 最终路径 += `&proxyip=${matchingProxyIP}`;

                if (proxyhosts.length > 0 && (伪装域名.includes('.workers.dev'))) {
                    最终路径 = `/${伪装域名}${最终路径}`;
                    伪装域名 = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
                    节点备注 = ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
                }
            }

            const 维列斯Link = `${协议类型}://${UUID}@${address}:${port + atob(isNoTLS ? 'P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT0mdHlwZT13cyZob3N0PQ==' : 'P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT10bHMmc25pPQ==') + 伪装域名}&fp=random&type=ws&host=${伪装域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;

            return 维列斯Link;
        }).join('\n');
    };

    const addresses = newAddressesapi.concat(newAddressescsv);
    const responseBody = processAddresses(addresses, false);

    let base64Response = responseBody;
    if (noTLS == 'true') {
        const addressesnotls = newAddressesnotlsapi.concat(newAddressesnotlscsv);
        const notlsresponseBody = processAddresses(addressesnotls, true);
        base64Response += `\n${notlsresponseBody}`;
    }
    if (link.length > 0) base64Response += '\n' + link.join('\n');
    return btoa(base64Response);
}

async function 整理(内容) {
    // 将制表符、双引号、单引号和换行符都替换为逗号
    // 然后将连续的多个逗号替换为单个逗号
    let 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');

    // 删除开头和结尾的逗号（如果有的话）
    替换后的内容 = 替换后的内容.replace(/^,|,$/g, '');

    // 使用逗号分割字符串，得到地址数组
    const 地址数组 = 替换后的内容.split(',');

    return 地址数组;
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
        const telegramResponse = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
            }
        });

        if (!telegramResponse.ok) {
            console.error('Error sending message to Telegram:', telegramResponse.statusText);
        }
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

function isValidIPv4(address) {
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(address);
}

async function 生成动态UUID(密钥) {
    const 时区偏移 = 8; // 北京时间相对于UTC的时区偏移+8小时
    const 起始日期 = new Date(2007, 6, 7, 更新时间, 0, 0); // 固定起始日期为2007年7月7日的凌晨3点
    const 一周的毫秒数 = 1000 * 60 * 60 * 24 * 有效时间;

    function 获取当前周数() {
        const 现在 = new Date();
        const 调整后的现在 = new Date(现在.getTime() + 时区偏移 * 60 * 60 * 1000);
        const 时间差 = Number(调整后的现在) - Number(起始日期);
        return Math.ceil(时间差 / 一周的毫秒数);
    }

    async function 生成UUID(基础字符串) {
        const 哈希缓冲区 = new TextEncoder().encode(基础字符串);
        const 哈希 = await crypto.subtle.digest('SHA-256', 哈希缓冲区);
        const 哈希数组 = Array.from(new Uint8Array(哈希));
        const 十六进制哈希 = 哈希数组.map(b => b.toString(16).padStart(2, '0')).join('');
        return `${十六进制哈希.substr(0, 8)}-${十六进制哈希.substr(8, 4)}-4${十六进制哈希.substr(13, 3)}-${(parseInt(十六进制哈希.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${十六进制哈希.substr(18, 2)}-${十六进制哈希.substr(20, 12)}`;
    }

    const 当前周数 = 获取当前周数(); // 获取当前周数
    const 结束时间 = new Date(起始日期.getTime() + 当前周数 * 一周的毫秒数);

    // 生成两个 UUID
    const 当前UUID = await 生成UUID(密钥 + 当前周数);
    const 上一个UUID = await 生成UUID(密钥 + (当前周数 - 1));

    // 格式化到期时间
    const 到期时间UTC = new Date(结束时间.getTime() - 时区偏移 * 60 * 60 * 1000); // UTC时间
    const 到期时间字符串 = `到期时间(UTC): ${到期时间UTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${结束时间.toISOString().slice(0, 19).replace('T', ' ')}\n`;

    return [当前UUID, 上一个UUID, 到期时间字符串];
}

async function 迁移地址列表(env, txt = 'ADD.txt') {
    try {
        const 旧数据 = await env.KV.get(`/${txt}`);
        const 新数据 = await env.KV.get(txt);

        if (旧数据 && !新数据) {
            // 写入新位置
            await env.KV.put(txt, 旧数据);
            // 删除旧数据
            await env.KV.delete(`/${txt}`);
            return true;
        }
        return false;
    } catch (error) {
        console.error('迁移地址列表时发生错误:', error);
        return false;
    }
}

async function KV(request, env, txt = 'ADD.txt') {
    try {
        if (request.method === "POST") {
            if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
            try {
                const content = await request.text();
                await env.KV.put(txt, content);
                return new Response("保存成功");
            } catch (error) {
                console.error('保存KV时发生错误:', error);
                return new Response("保存失败: " + error.message, { status: 500 });
            }
        }

        let content = '';
        const hasKV = !!env.KV;

        if (hasKV) {
            try {
                content = await env.KV.get(txt) || '';
            } catch (error) {
                console.error('读取KV时发生错误:', error);
                content = '读取数据时发生错误: ' + error.message;
            }
        }

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>优选订阅列表</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body { margin: 0; padding: 15px; box-sizing: border-box; font-size: 13px; }
                    .editor-container { width: 100%; max-width: 100%; margin: 0 auto; }
                    .editor { width: 100%; height: 520px; margin: 15px 0; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; font-size: 13px; line-height: 1.5; overflow-y: auto; resize: none; }
                    .save-container { margin-top: 8px; display: flex; align-items: center; gap: 10px; }
                    .save-btn, .back-btn { padding: 6px 15px; color: white; border: none; border-radius: 4px; cursor: pointer; }
                    .save-btn { background: #4CAF50; }
                    .save-btn:hover { background: #45a049; }
                    .back-btn { background: #666; }
                    .back-btn:hover { background: #555; }
                    .save-status { color: #666; }
                    .notice-content { display: none; margin-top: 10px; font-size: 13px; color: #333; }
                </style>
            </head>
            <body>
                ################################################################<br>
                ${FileName} 优选订阅列表:<br>
                ---------------------------------------------------------------<br>
                &nbsp;&nbsp;<strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">注意事项∨</a></strong><br>
                <div id="noticeContent" class="notice-content">
                    ${decodeURIComponent(atob('JTA5JTA5JTA5JTA5JTA5JTNDc3Ryb25nJTNFMS4lM0MlMkZzdHJvbmclM0UlMjBBRERBUEklMjAlRTUlQTYlODIlRTYlOUUlOUMlRTYlOTglQUYlRTUlOEYlOEQlRTQlQkIlQTNJUCVFRiVCQyU4QyVFNSU4RiVBRiVFNCVCRCU5QyVFNCVCOCVCQVBST1hZSVAlRTclOUElODQlRTglQUYlOUQlRUYlQkMlOEMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwcm94eWlwJTNEdHJ1ZSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGYWRkcmVzc2VzYXBpLnR4dCUzQ3N0cm9uZyUzRSUzRnByb3h5aXAlM0R0cnVlJTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklM0NzdHJvbmclM0UyLiUzQyUyRnN0cm9uZyUzRSUyMEFEREFQSSUyMCVFNSVBNiU4MiVFNiU5RSU5QyVFNiU5OCVBRiUyMCUzQ2ElMjBocmVmJTNEJTI3aHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGWElVMiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QlMjclM0VDbG91ZGZsYXJlU3BlZWRUZXN0JTNDJTJGYSUzRSUyMCVFNyU5QSU4NCUyMGNzdiUyMCVFNyVCQiU5MyVFNiU5RSU5QyVFNiU5NiU4NyVFNCVCQiVCNiVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NiciUzRSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCLSUyMCVFNSVBNiU4MiVFOSU5QyU4MCVFNiU4QyU4NyVFNSVBRSU5QTIwNTMlRTclQUIlQUYlRTUlOEYlQTMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwb3J0JTNEMjA1MyUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0Zwb3J0JTNEMjA1MyUzQyUyRnN0cm9uZyUzRSUzQ2JyJTNFJTNDYnIlM0UKJTA5JTA5JTA5JTA5JTA5JTI2bmJzcCUzQiUyNm5ic3AlM0ItJTIwJUU1JUE2JTgyJUU5JTlDJTgwJUU2JThDJTg3JUU1JUFFJTlBJUU4JThBJTgyJUU3JTgyJUI5JUU1JUE0JTg3JUU2JUIzJUE4JUU1JThGJUFGJUU1JUIwJTg2JTIyJTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0ZpZCUzRENGJUU0JUJDJTk4JUU5JTgwJTg5JTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQi0lMjAlRTUlQTYlODIlRTklOUMlODAlRTYlOEMlODclRTUlQUUlOUElRTUlQTQlOUElRTQlQjglQUElRTUlOEYlODIlRTYlOTUlQjAlRTUlODglOTklRTklOUMlODAlRTglQTYlODElRTQlQkQlQkYlRTclOTQlQTglMjclMjYlMjclRTUlODElOUElRTklOTclQjQlRTklOUElOTQlRUYlQkMlOEMlRTQlQkUlOEIlRTUlQTYlODIlRUYlQkMlOUElM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGbWFpbiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QuY3N2JTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUzQ3N0cm9uZyUzRSUyNiUzQyUyRnN0cm9uZyUzRXBvcnQlM0QyMDUzJTNDYnIlM0U='))}
                </div>
                <div class="editor-container">
                    ${hasKV ? `
                    <textarea class="editor" 
                        placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=='))}"
                        id="content">${content}</textarea>
                    <div class="save-container">
                        <button class="back-btn" onclick="goBack()">返回配置页</button>
                        <button class="save-btn" onclick="saveContent(this)">保存</button>
                        <span class="save-status" id="saveStatus"></span>
                    </div>
                    <br>
                    ################################################################<br>
                    ${cmad}
                    ` : '<p>未绑定KV空间</p>'}
                </div>
        
                <script>
                if (document.querySelector('.editor')) {
                    let timer;
                    const textarea = document.getElementById('content');
                    const originalContent = textarea.value;
        
                    function goBack() {
                        const currentUrl = window.location.href;
                        const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
                        window.location.href = parentUrl;
                    }
        
                    function replaceFullwidthColon() {
                        const text = textarea.value;
                        textarea.value = text.replace(/：/g, ':');
                    }
                    
                    function saveContent(button) {
                        try {
                            const updateButtonText = (step) => {
                                button.textContent = \`保存中: \${step}\`;
                            };
                            const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
                            
                            if (!isIOS) {
                                replaceFullwidthColon();
                            }
                            updateButtonText('开始保存');
                            button.disabled = true;
                            const textarea = document.getElementById('content');
                            if (!textarea) {
                                throw new Error('找不到文本编辑区域');
                            }
                            updateButtonText('获取内容');
                            let newContent;
                            let originalContent;
                            try {
                                newContent = textarea.value || '';
                                originalContent = textarea.defaultValue || '';
                            } catch (e) {
                                console.error('获取内容错误:', e);
                                throw new Error('无法获取编辑内容');
                            }
                            updateButtonText('准备状态更新函数');
                            const updateStatus = (message, isError = false) => {
                                const statusElem = document.getElementById('saveStatus');
                                if (statusElem) {
                                    statusElem.textContent = message;
                                    statusElem.style.color = isError ? 'red' : '#666';
                                }
                            };
                            updateButtonText('准备按钮重置函数');
                            const resetButton = () => {
                                button.textContent = '保存';
                                button.disabled = false;
                            };
                            if (newContent !== originalContent) {
                                updateButtonText('发送保存请求');
                                fetch(window.location.href, {
                                    method: 'POST',
                                    body: newContent,
                                    headers: {
                                        'Content-Type': 'text/plain;charset=UTF-8'
                                    },
                                    cache: 'no-cache'
                                })
                                .then(response => {
                                    updateButtonText('检查响应状态');
                                    if (!response.ok) {
                                        throw new Error(\`HTTP error! status: \${response.status}\`);
                                    }
                                    updateButtonText('更新保存状态');
                                    const now = new Date().toLocaleString();
                                    document.title = \`编辑已保存 \${now}\`;
                                    updateStatus(\`已保存 \${now}\`);
                                })
                                .catch(error => {
                                    updateButtonText('处理错误');
                                    console.error('Save error:', error);
                                    updateStatus(\`保存失败: \${error.message}\`, true);
                                })
                                .finally(() => {
                                    resetButton();
                                });
                            } else {
                                updateButtonText('检查内容变化');
                                updateStatus('内容未变化');
                                resetButton();
                            }
                        } catch (error) {
                            console.error('保存过程出错:', error);
                            button.textContent = '保存';
                            button.disabled = false;
                            const statusElem = document.getElementById('saveStatus');
                            if (statusElem) {
                                statusElem.textContent = \`错误: \${error.message}\`;
                                statusElem.style.color = 'red';
                            }
                        }
                    }
        
                    textarea.addEventListener('blur', saveContent);
                    textarea.addEventListener('input', () => {
                        clearTimeout(timer);
                        timer = setTimeout(saveContent, 5000);
                    });
                }
        
                function toggleNotice() {
                    const noticeContent = document.getElementById('noticeContent');
                    const noticeToggle = document.getElementById('noticeToggle');
                    if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
                        noticeContent.style.display = 'block';
                        noticeToggle.textContent = '注意事项∧';
                    } else {
                        noticeContent.style.display = 'none';
                        noticeToggle.textContent = '注意事项∨';
                    }
                }
        
                document.addEventListener('DOMContentLoaded', () => {
                    document.getElementById('noticeContent').style.display = 'none';
                });
                </script>
            </body>
            </html>
        `;

        return new Response(html, {
            headers: { "Content-Type": "text/html;charset=utf-8" }
        });
    } catch (error) {
        console.error('处理请求时发生错误:', error);
        return new Response("服务器错误: " + error.message, {
            status: 500,
            headers: { "Content-Type": "text/plain;charset=utf-8" }
        });
    }
}
