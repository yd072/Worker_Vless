import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIP = '';
//let sub = '';
let subConverter = 'SUBAPI.fxxk.dedyn.io';
let subConfig = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini";
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;

let noTLS = 'false';
const expire = 4102329600;//2099-12-31
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
let remarkIndex = 1;
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

// 增加详细的日志记录
function logInfo(message) {
    console.log(`[INFO] ${message}`);
}

function logError(message, error) {
    console.error(`[ERROR] ${message}`, error);
}

// 在关键位置添加日志
async function fetchData(url) {
    try {
        logInfo(`Fetching data from ${url}`);
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch data: ${response.statusText}`);
        }
        return await response.text();
    } catch (error) {
        logError(`Error fetching data from ${url}`, error);
        throw error;
    }
}

// 优化错误处理
async function handleRequest(request) {
    try {
        // existing logic...
    } catch (error) {
        logError('Error handling request', error);
        return new Response('Internal Server Error', { status: 500 });
    }
}

function handleError(err) {
    console.log(err.toString());
    return new Response(err.toString(), {
        status: 500,
        headers: {
            "Content-Type": "text/plain;charset=utf-8",
        }
    });
}

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
					let e = err;
					console.log(e.toString());
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
					//const timestamp = Math.floor(now / 1000);
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
						let e = err;
						console.log(e.toString());
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
			let e = err;
			return new Response(e.toString());
		}
	},
};

async function 维列斯OverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (info, event = '') => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event);
    };

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = { value: null };
    let isDns = false;
    const banHostsSet = new Set(banHosts);

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            try {
                if (isDns) {
                    return handleDNSQuery(chunk, webSocket, null, log);
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
                    维列斯Version = new Uint8Array([0, 0]),
                    isUDP,
                } = process维列斯Header(chunk, userID);

                address = addressRemote;
                portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
                if (hasError) {
                    throw new Error(message);
                }
                if (isUDP) {
                    if (portRemote === 53) {
                        isDns = true;
                    } else {
                        throw new Error('UDP 代理仅对 DNS（53 端口）启用');
                    }
                }
                const 维列斯ResponseHeader = new Uint8Array([维列斯Version[0], 0]);
                const rawClientData = chunk.slice(rawDataIndex);

                if (isDns) {
                    return handleDNSQuery(rawClientData, webSocket, 维列斯ResponseHeader, log);
                }
                if (!banHostsSet.has(addressRemote)) {
                    log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
                    handleTCPOutBound(remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log);
                } else {
                    throw new Error(`黑名单关闭 TCP 出站连接 ${addressRemote}:${portRemote}`);
                }
            } catch (error) {
                log('处理数据时发生错误', error.message);
                webSocket.close(1011, '内部错误');
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
        webSocket.close(1011, '管道错误');
    });

    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

async function handleDNSQuery(udpChunk, webSocket, 维列斯ResponseHeader, log) {
    const WS_READY_STATE_OPEN = 1;

    try {
        const dnsServer = '8.8.4.4';
        const dnsPort = 53;

        let 维列斯Header = 维列斯ResponseHeader;
        const tcpSocket = await getOrCreateConnection(dnsServer, dnsPort);

        log(`连接到 ${dnsServer}:${dnsPort}`);

        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();

        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    try {
                        const combinedData = 维列斯Header ? mergeData(维列斯Header, chunk) : chunk;
                        webSocket.send(combinedData);
                        if (维列斯Header) 维列斯Header = null;
                    } catch (error) {
                        console.error(`发送数据时发生错误: ${error.message}`);
                        safeCloseWebSocket(webSocket);
                    }
                } else {
                    console.warn('WebSocket 连接已关闭，无法发送数据');
                }
            },
            close() {
                log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`);
            },
            abort(reason) {
                console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason);
            }
        }));
    } catch (error) {
        console.error(`handleDNSQuery 函数发生异常，错误信息: ${error.message}`, error.stack);
        safeCloseWebSocket(webSocket);
    }
}

async function getOrCreateConnection(hostname, port) {

}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log) {
    async function useSocks5Pattern(address) {
        if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) return true;
        return go2Socks5s.some(pattern => {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, socks = false) {
        log(`Connecting to ${address}:${port}`);
        const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
            : connect({ hostname: address, port: port });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        try {
            if (enableSocks) {
                tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
            } else {
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
            tcpSocket.closed.catch(error => {
                console.log('Retry tcpSocket closed error', error);
            }).finally(() => {
                safeCloseWebSocket(webSocket);
            });
            remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, null, log);
        } catch (error) {
            log('Retry error:', error);
        }
    }

    let shouldUseSocks = false;
    if (go2Socks5s.length > 0 && enableSocks) {
        shouldUseSocks = await useSocks5Pattern(addressRemote);
    }
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, shouldUseSocks);
    remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    let backpressure = false;

    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                const message = event.data;
                if (!backpressure) {
                    controller.enqueue(message);
                } else {
                    log('Backpressure, message discarded');
                }
            });

            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (!readableStreamCancel) {
                    controller.close();
                }
            });

            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket server error');
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
            if (controller.desiredSize > 0) {
                backpressure = false;
            }
        },

        cancel(reason) {
            if (readableStreamCancel) return;
            log(`Readable stream canceled, reason: ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

function process维列斯Header(维列斯Buffer, userID) {
    if (维列斯Buffer.byteLength < 24) {
        return { hasError: true, message: 'Invalid data' };
    }

    const version = new Uint8Array(维列斯Buffer.slice(0, 1));
    const userIDArray = new Uint8Array(维列斯Buffer.slice(1, 17));
    const userIDString = stringify(userIDArray);
    const isValidUser = userIDString === userID || userIDString === userIDLow;

    if (!isValidUser) {
        return { hasError: true, message: 'Invalid user' };
    }

    const optLength = new Uint8Array(维列斯Buffer.slice(17, 18))[0];
    const command = new Uint8Array(维列斯Buffer.slice(18 + optLength, 18 + optLength + 1))[0];
    let isUDP = false;

    switch (command) {
        case 1: break;
        case 2: isUDP = true; break;
        default:
            return { hasError: true, message: 'Unsupported command' };
    }

    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(维列斯Buffer).getUint16(portIndex);

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
        维列斯Version: version,
        isUDP,
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let hasIncomingData = false;
    let header = responseHeader;

    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    hasIncomingData = true;

                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error('WebSocket not open');
                    }

                    if (header) {
                        webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                        header = null;
                    } else {
                        webSocket.send(chunk);
                    }
                },
                close() {
                    log(`Remote connection closed, data received: ${hasIncomingData}`);
                },
                abort(reason) {
                    console.error(`Remote connection aborted`);
                },
            })
        )
        .catch((error) => {
            console.error(`remoteSocketToWS exception`);
            safeCloseWebSocket(webSocket);
        });

    if (!hasIncomingData && retry) {
        log(`Retrying connection`);
        retry();
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decoded = atob(base64Str);
        const arrayBuffer = Uint8Array.from(decoded, c => c.charCodeAt(0));
        return { earlyData: arrayBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

function isValidUUID(uuid) {
    const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidPattern.test(uuid);
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
    if (!isValidUUID(uuid)) {
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

    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次十六进制 = Array.from(new Uint8Array(第一次哈希))
        .map(字节 => 字节.toString(16).padStart(2, '0'))
        .join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次十六进制 = Array.from(new Uint8Array(第二次哈希))
        .map(字节 => 字节.toString(16).padStart(2, '0'))
        .join('');

    return 第二次十六进制.toLowerCase();
}

async function 代理URL(代理网址, 目标网址) {
    const 网址列表 = await 整理(代理网址);
    const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

    const 解析后的网址 = new URL(完整网址);
    console.log(解析后的网址);

    const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
    const 主机名 = 解析后的网址.hostname;
    let 路径名 = 解析后的网址.pathname;
    const 查询参数 = 解析后的网址.search;

    if (路径名.endsWith('/')) {
        路径名 = 路径名.slice(0, -1);
    }
    路径名 += 目标网址.pathname;

    const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

    const 响应 = await fetch(新网址);

    const 新响应 = new Response(响应.body, {
        status: 响应.status,
        statusText: 响应.statusText,
        headers: 响应.headers
    });

    新响应.headers.set('X-New-URL', 新网址);

    return 新响应;
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
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGYWRkcmVzc2VzYXBpLnR4dCUzQ3N0cm9uZyUzRSUzRnByb3h5aXAlM0R0cnVlJTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklM0NzdHJvbmclM0UyLiUzQyUyRnN0cm9uZyUzRSUyMEFEREFQSSUyMCVFNSVBNiU4MiVFNiU5RSU5QyVFNiU5OCVBRiUyMCUzQ2ElMjBocmVmJTNEJTI3aHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGWElVMiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QlMjclM0VDbG91ZGZsYXJlU3BlZWRUZXN0JTNDJTJGYSUzRSUyMCVFNyU5QSU4NCUyMGNzdiUyMCVFNyVCQiU5MyVFNiU5RSU5QyVFNiU5NiU4NyVFNCVCQiVCNiVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NiciUzRSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCLSUyMCVFNSVBNiU4MiVFOSU5QyU4MCVFNiU4QyU4NyVFNSVBRSU5QTIwNTMlRTclQUIlQUYlRTUlOEYlQTMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwb3J0JTNEMjA1MyUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0Zwb3J0JTNEMjA1MyUzQyUyRnN0cm9uZyUzRSUzQ2JyJTNFJTNDYnIlM0UKJTA5JTA5JTA5JTA5JTA5JTI2bmJzcCUzQiUyNm5ic3AlM0ItJTIwJUU1JUE2JTgyJUU5JTlDJTgwJUU2JThDJTg3JUU1JUFFJTlBJUU4JThBJTgyJUU3JTgyJUI5JUU1JUE0JTg3JUU2JUIzJUE4JUU1JThGJUFGJUU1JUIwJTg2JTIyJTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0ZpZCUzRENGJUU0JUJDJTk4JUU5JTgwJTg5JTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQi0lMjAlRTUlQTYlODIlRTklOUMlODAlRTYlOEMlODclRTUlQUUlOUElRTUlQTQlOUElRTQlQjglQUElRTUlOEYlODIlRTYlOTUlQjAlRTUlODglOTklRTklOUMlODAlRTglQTYlODElRTQlQkQlQkYlRTclOTQlQTglMjclMjYlMjclRTUlODElOUElRTklOTclQjQlRTklOUElOTQlRUYlQkMlOEMlRTQlQkUlOEIlRTUlQTYlODIlRUYlQkMlOUElM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGbWFpbiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QuY3N2JTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUzQ3N0cm9uZyUzRSUyNiUzQyUyRnN0cm9uZyUzRXBvcnQlM0QyMDUzJTNDYnIlM0U='))}
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
							// 检测是否为iOS设备
							const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
							
							// 仅在非iOS设备上执行replaceFullwidthColon
							if (!isIOS) {
								replaceFullwidthColon();
							}
							updateButtonText('开始保存');
							button.disabled = true;
							// 获取textarea内容和原始内容
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
		
				// 初始化 noticeContent 的 display 属性
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
