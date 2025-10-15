
import { connect } from 'cloudflare:sockets';

let userID = '';
let proxyIP = '';
//let sub = '';
let subConverter = atob('U3ViQXBpLkNtbGlVc3NzUy5OZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;
let enableHttp = false;
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
let adds = [];
let addressesapi = [];
let addsapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;//CSV备注所在列偏移量
let FileName = atob('ZWRnZXR1bm5lbA==');
let BotToken;
let ChatID;
let proxyhosts = [];
let 请求CF反代IP = 'false';
let httpsPorts = ["443"];
let httpPorts = ["80"];
let proxyIPPool = [];
let path = '/?ed=2560';
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
let SCV = 'true';
let allowInsecure = '&allowInsecure=1';

export default {
    async fetch(request, env, ctx) {
        try {
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            userID = env.UUID || env.uuid || env.PASSWORD || env.pswd || userID;

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
            socks5Address = env.HTTP || env.SOCKS5 || socks5Address;
            socks5s = await 整理(socks5Address);
            socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
            enableHttp = env.HTTP ? true : socks5Address.toLowerCase().includes('http://');
            socks5Address = socks5Address.split('//')[1] || socks5Address;
            if (env.GO2SOCKS5) go2Socks5s = await 整理(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await 整理(env.CFPORTS);
            if (env.BAN) banHosts = await 整理(env.BAN);
            if (socks5Address) {
                try {
                    parsedSocks5Address = socks5AddressParser(socks5Address);
                    请求CF反代IP = env.RPROXYIP || 'false';
                    enableSocks = true;
                } catch (err) {
                    let e = err;
                    console.log(e.toString());
                    请求CF反代IP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
                    enableSocks = false;
                }
            } else {
                请求CF反代IP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
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
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub').toLowerCase();
                if (url.searchParams.has('notls')) noTLS = 'true';

                if (url.searchParams.has('proxyip')) {
                    path = `/proxyip=${url.searchParams.get('proxyip')}`;
                    请求CF反代IP = 'false';
                } else if (url.searchParams.has('socks5')) {
                    path = url.searchParams.has('globalproxy') ? `/?socks5=${url.searchParams.get('socks5')}&globalproxy` : `/?socks5=${url.searchParams.get('socks5')}`;
                    请求CF反代IP = 'false';
                } else if (url.searchParams.has('socks')) {
                    path = url.searchParams.has('globalproxy') ? `/?socks5=${url.searchParams.get('socks')}&globalproxy` : `/?socks5=${url.searchParams.get('socks')}`;
                    请求CF反代IP = 'false';
                } else if (url.searchParams.has('http')) {
                    path = url.searchParams.has('globalproxy') ? `/?http=${url.searchParams.get('http')}&globalproxy` : `/?http=${url.searchParams.get('http')}`;
                    请求CF反代IP = 'false';
                }

                SCV = env.SCV || SCV;
                if (!SCV || SCV == '0' || SCV == 'false') allowInsecure = '';
                else SCV = 'true';
                const 路径 = url.pathname.toLowerCase();
                if (路径 == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response(await nginx(), {
                        status: 200,
                        headers: {
                            'Content-Type': 'text/html; charset=UTF-8',
                        },
                    });
                } else if (路径 == `/${fakeUserID}`) {
                    const fakeConfig = await 生成配置信息(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', 请求CF反代IP, url, fakeUserID, fakeHostName, env);
                    return new Response(`${fakeConfig}`, { status: 200 });
                } else if (路径 == `/${userID}/config.json` && url.searchParams.get('token') === await 双重哈希(fakeUserID + UA)) {
                    return await config_Json(userID, request.headers.get('Host'), sub, UA, 请求CF反代IP, url, fakeUserID, fakeHostName, env);
                } else if (路径 == `/${userID}/edit`) {
                    return await KV(request, env);
                } else if (路径 == `/${userID}`) {
                    await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
                    const 维列斯Config = await 生成配置信息(userID, request.headers.get('Host'), sub, UA, 请求CF反代IP, url, fakeUserID, fakeHostName, env);
                    const now = Date.now();
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;
                    if (userAgent && userAgent.includes('mozilla')) {
                        return new Response(维列斯Config, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                                "Cache-Control": "no-store",
                            }
                        });
                    } else {
                        return new Response(维列斯Config, {
                            status: 200,
                            headers: {
                                "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
                                //"Content-Type": "text/plain;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Profile-web-page-url": request.url.includes('?') ? request.url.split('?')[0] : request.url,
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
                socks5Address = url.searchParams.get('socks5') || url.searchParams.get('http') || socks5Address;
                enableHttp = url.searchParams.get('http') ? true : enableHttp;
                go2Socks5s = url.searchParams.has('globalproxy') ? ['all in'] : go2Socks5s;

                if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
                else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname) || new RegExp('/http://', 'i').test(url.pathname)) {
                    enableHttp = url.pathname.includes('http://');
                    socks5Address = url.pathname.split('://')[1].split('#')[0];
                    if (socks5Address.includes('@')) {
                        const lastAtIndex = socks5Address.lastIndexOf('@');
                        let userPassword = socks5Address.substring(0, lastAtIndex).replaceAll('%3D', '=');
                        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                        socks5Address = `${userPassword}@${socks5Address.substring(lastAtIndex + 1)}`;
                    }
                    go2Socks5s = ['all in'];//开启全局SOCKS5
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
	const log = (info, event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	let remoteSocketWapper = {
		value: null
	};
	let udpWriter = null;
	let isDns = false;

	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) return udpWriter?.write(chunk);
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter();
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			if (chunk.byteLength < 24) {
				return;
			}

			const uuidBytes = new Uint8Array(chunk.slice(1, 17));
			const expectedUUID = userID.replace(/-/g, '');
			for (let i = 0; i < 16; i++) {
				if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16)) return;
			}

			const view = new DataView(chunk);
			const optLen = view.getUint8(17);
			const cmd = view.getUint8(18 + optLen);
			if (cmd !== 1 && cmd !== 2) {
				return;
			}

			let pos = 19 + optLen;
			const port = view.getUint16(pos);
			const type = view.getUint8(pos + 2);
			pos += 3;

			let addr = '';
			if (type === 1) {
				addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
				pos += 4;
			} else if (type === 2) {
				const len = view.getUint8(pos++);
				addr = new TextDecoder().decode(chunk.slice(pos, pos + len));
				pos += len;
			} else if (type === 3) {
				const ipv6 = [];
				for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos).toString(16));
				addr = ipv6.join(':');
			} else {
				return;
			}

			address = addr;
			portWithRandomLog = `${port}--${Math.random()} ${cmd === 2 ? 'udp ' : 'tcp '} `;

			const header = new Uint8Array([chunk[0], 0]);
			const payload = chunk.slice(pos);

			if (cmd === 2) {
				if (port !== 53) {
					throw new Error('UDP 代理仅对 DNS（53 端口）启用');
				}
				isDns = true;
				let sent = false;
				const {
					readable,
					writable
				} = new TransformStream({
					transform(chunk, ctrl) {
						for (let i = 0; i < chunk.byteLength;) {
							const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
							ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
							i += 2 + len;
						}
					}
				});

				readable.pipeTo(new WritableStream({
					async write(query) {
						try {
							const resp = await fetch('https://1.1.1.1/dns-query', {
								method: 'POST',
								headers: {
									'content-type': 'application/dns-message'
								},
								body: query
							});
							if (webSocket.readyState === 1) {
								const result = new Uint8Array(await resp.arrayBuffer());
								webSocket.send(new Uint8Array([...(sent ? [] : header), result.length >> 8, result.length & 0xff, ...result]));
								sent = true;
							}
						} catch (e) {
							log('dns fetch error' + e.toString());
						}
					}
				}));
				udpWriter = writable.getWriter();
				return udpWriter.write(payload);
			}

			if (cmd === 1) {
				if (!banHosts.includes(addr)) {
					log(`处理 TCP 出站连接 ${addr}:${port}`);
					handleTCPOutBound(remoteSocketWapper, type, addr, port, payload, webSocket, header, log);
				} else {
					throw new Error(`黑名单关闭 TCP 出站连接 ${addr}:${port}`);
				}
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

	return new Response(null, {
		status: 101,
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

    async function connectAndWrite(address, port, socks = false, http = false) {
        log(`connected to ${address}:${port}`);
        //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
        // 先确定连接方式，再创建连接
        const tcpSocket = socks
            ? (http ? await httpConnect(address, port, log) : await socks5Connect(addressType, address, port, log))
            : connect({ hostname: address, port: port });

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
        let tcpSocket;
        if (enableSocks) {
            // 如果启用了 SOCKS5，通过 SOCKS5 代理重试连接
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
        } else {
            // 否则，尝试使用预设的代理 IP（如果有）或原始地址重试连接
            if (!proxyIP || proxyIP == '') {
                proxyIP = atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg==');
            } else if (proxyIP.includes(']:')) {
                portRemote = proxyIP.split(']:')[1] || portRemote;
                proxyIP = proxyIP.split(']:')[0] + "]" || proxyIP;
            } else if (proxyIP.split(':').length === 2) {
                portRemote = proxyIP.split(':')[1] || portRemote;
                proxyIP = proxyIP.split(':')[0] || proxyIP;
            }
            if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
            tcpSocket = await connectAndWrite(proxyIP.toLowerCase() || addressRemote, portRemote);
        }
        /* 无论重试是否成功，都要关闭 WebSocket（可能是为了重新建立连接）
        tcpSocket.closed.catch(error => {
            console.log('retry tcpSocket closed error', error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        */
        // 建立从远程 Socket 到 WebSocket 的数据流
        remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, null, log);
    }

    let useSocks = false;
    if (go2Socks5s.length > 0 && enableSocks) useSocks = await useSocks5Pattern(addressRemote);
    // 首次尝试连接远程服务器
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks, enableHttp);

    // 当远程 Socket 就绪时，将其传递给 WebSocket
    // 建立从远程服务器到 WebSocket 的数据流，用于将远程服务器的响应发送回客户端
    // 如果连接失败或无数据，retry 函数将被调用进行重试
    remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    // 标记可读流是否已被取消
    let readableStreamCancel = false;

    // 创建一个新的可读流
    const stream = new ReadableStream({
        // 当流开始时的初始化函数
        start(controller) {
            // 监听 WebSocket 的消息事件
            webSocketServer.addEventListener('message', (event) => {
                // 如果流已被取消，不再处理新消息
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                // 将消息加入流的队列中
                controller.enqueue(message);
            });

            // 监听 WebSocket 的关闭事件
            // 注意：这个事件意味着客户端关闭了客户端 -> 服务器的流
            // 但是，服务器 -> 客户端的流仍然打开，直到在服务器端调用 close()
            // WebSocket 协议要求在每个方向上都要发送单独的关闭消息，以完全关闭 Socket
            webSocketServer.addEventListener('close', () => {
                // 客户端发送了关闭信号，需要关闭服务器端
                safeCloseWebSocket(webSocketServer);
                // 如果流未被取消，则关闭控制器
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });

            // 监听 WebSocket 的错误事件
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket 服务器发生错误');
                // 将错误传递给控制器
                controller.error(err);
            });

            // 处理 WebSocket 0-RTT（零往返时间）的早期数据
            // 0-RTT 允许在完全建立连接之前发送数据，提高了效率
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                // 如果解码早期数据时出错，将错误传递给控制器
                controller.error(error);
            } else if (earlyData) {
                // 如果有早期数据，将其加入流的队列中
                controller.enqueue(earlyData);
            }
        },

        // 当使用者从流中拉取数据时调用
        pull(controller) {
            // 这里可以实现反压机制
            // 如果 WebSocket 可以在流满时停止读取，我们就可以实现反压
            // 参考：https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },

        // 当流被取消时调用
        cancel(reason) {
            // 流被取消的几种情况：
            // 1. 当管道的 WritableStream 有错误时，这个取消函数会被调用，所以在这里处理 WebSocket 服务器的关闭
            // 2. 如果 ReadableStream 被取消，所有 controller.close/enqueue 都需要跳过
            // 3. 但是经过测试，即使 ReadableStream 被取消，controller.error 仍然有效
            if (readableStreamCancel) {
                return;
            }
            log(`可读流被取消，原因是 ${reason}`);
            readableStreamCancel = true;
            // 安全地关闭 WebSocket
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, 维列斯ResponseHeader, retry, log) {
    // 将数据从远程服务器转发到 WebSocket
    let remoteChunkCount = 0;
    let chunks = []; // @type {ArrayBuffer | null} 
    let 维列斯Header = 维列斯ResponseHeader;
    let hasIncomingData = false; // 检查远程 Socket 是否有传入数据

    // 使用管道将远程 Socket 的可读流连接到一个可写流
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {
                    // 初始化时不需要任何操作
                },
                // @param {Uint8Array} chunk 数据块
                // @param {*} controller 控制器
                async write(chunk, controller) {
                    hasIncomingData = true; // 标记已收到数据
                    // remoteChunkCount++; // 用于流量控制，现在似乎不需要了

                    // 检查 WebSocket 是否处于开放状态
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error(
                            'webSocket.readyState is not open, maybe close'
                        );
                    }

                    if (维列斯Header) {
                        // 如果有 维列斯 响应头部，将其与第一个数据块一起发送
                        webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
                        维列斯Header = null; // 清空头部，之后不再发送
                    } else {
                        // 直接发送数据块
                        // 以前这里有流量控制代码，限制大量数据的发送速率
                        // 但现在 Cloudflare 似乎已经修复了这个问题
                        // if (remoteChunkCount > 20000) {
                        // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
                        // 	await delay(1);
                        // }
                        webSocket.send(chunk);
                    }
                },
                close() {
                    // 当远程连接的可读流关闭时
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                    // 不需要主动关闭 WebSocket，因为这可能导致 HTTP ERR_CONTENT_LENGTH_MISMATCH 问题
                    // 客户端无论如何都会发送关闭事件
                    // safeCloseWebSocket(webSocket);
                },
                abort(reason) {
                    // 当远程连接的可读流中断时
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            // 捕获并记录任何异常
            console.error(
                `remoteSocketToWS has exception `,
                error.stack || error
            );
            // 发生错误时安全地关闭 WebSocket
            safeCloseWebSocket(webSocket);
        });

    // 处理 Cloudflare 连接 Socket 的特殊错误情况
    // 1. Socket.closed 将有错误
    // 2. Socket.readable 将关闭，但没有任何数据
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry(); // 调用重试函数，尝试重新建立连接
    }
}

/**
 * 将 Base64 编码的字符串转换为 ArrayBuffer
 * 
 * @param {string} base64Str Base64 编码的输入字符串
 * @returns {{ earlyData: ArrayBuffer | undefined, error: Error | null }} 返回解码后的 ArrayBuffer 或错误
 */
function base64ToArrayBuffer(base64Str) {
    // 如果输入为空，直接返回空结果
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        // Go 语言使用了 URL 安全的 Base64 变体（RFC 4648）
        // 这种变体使用 '-' 和 '_' 来代替标准 Base64 中的 '+' 和 '/'
        // JavaScript 的 atob 函数不直接支持这种变体，所以我们需要先转换
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');

        // 使用 atob 函数解码 Base64 字符串
        // atob 将 Base64 编码的 ASCII 字符串转换为原始的二进制字符串
        const decode = atob(base64Str);

        // 将二进制字符串转换为 Uint8Array
        // 这是通过遍历字符串中的每个字符并获取其 Unicode 编码值（0-255）来完成的
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));

        // 返回 Uint8Array 的底层 ArrayBuffer
        // 这是实际的二进制数据，可以用于网络传输或其他二进制操作
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        // 如果在任何步骤中出现错误（如非法 Base64 字符），则返回错误
        return { earlyData: undefined, error };
    }
}

// WebSocket 的两个重要状态常量
const WS_READY_STATE_OPEN = 1;	 // WebSocket 处于开放状态，可以发送和接收消息
const WS_READY_STATE_CLOSING = 2;  // WebSocket 正在关闭过程中

function safeCloseWebSocket(socket) {
    try {
        // 只有在 WebSocket 处于开放或正在关闭状态时才调用 close()
        // 这避免了在已关闭或连接中的 WebSocket 上调用 close()
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        // 记录任何可能发生的错误，虽然按照规范不应该有错误
        console.error('safeCloseWebSocket error', error);
    }
}

/**
 * 建立 SOCKS5 代理连接
 * @param {number} addressType 目标地址类型（1: IPv4, 2: 域名, 3: IPv6）
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 * @param {function} log 日志记录函数
 */
async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    // 连接到 SOCKS5 代理服务器
    const socket = connect({
        hostname, // SOCKS5 服务器的主机名
        port,	// SOCKS5 服务器的端口
    });

    // 请求头格式（Worker -> SOCKS5 服务器）:
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |	1	 | 1 to 255 |
    // +----+----------+----------+

    // https://en.wikipedia.org/wiki/SOCKS#SOCKS5
    // METHODS 字段的含义:
    // 0x00 不需要认证
    // 0x02 用户名/密码认证 https://datatracker.ietf.org/doc/html/rfc1929
    const socksGreeting = new Uint8Array([5, 2, 0, 2]);
    // 5: SOCKS5 版本号, 2: 支持的认证方法数, 0和2: 两种认证方法（无认证和用户名/密码）

    const writer = socket.writable.getWriter();

    await writer.write(socksGreeting);
    log('已发送 SOCKS5 问候消息');

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;
    // 响应格式（SOCKS5 服务器 -> Worker）:
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1	|
    // +----+--------+
    if (res[0] !== 0x05) {
        log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
        return;
    }
    if (res[1] === 0xff) {
        log("服务器不接受任何认证方法");
        return;
    }

    // 如果返回 0x0502，表示需要用户名/密码认证
    if (res[1] === 0x02) {
        log("SOCKS5 服务器需要认证");
        if (!username || !password) {
            log("请提供用户名和密码");
            return;
        }
        // 认证请求格式:
        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        // +----+------+----------+------+----------+
        const authRequest = new Uint8Array([
            1,				   // 认证子协议版本
            username.length,	// 用户名长度
            ...encoder.encode(username), // 用户名
            password.length,	// 密码长度
            ...encoder.encode(password)  // 密码
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        // 期望返回 0x0100 表示认证成功
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log("SOCKS5 服务器认证失败");
            return;
        }
    }

    // 请求数据格式（Worker -> SOCKS5 服务器）:
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |	2	 |
    // +----+-----+-------+------+----------+----------+
    // ATYP: 地址类型
    // 0x01: IPv4 地址
    // 0x03: 域名
    // 0x04: IPv6 地址
    // DST.ADDR: 目标地址
    // DST.PORT: 目标端口（网络字节序）

    // addressType
    // 1 --> IPv4  地址长度 = 4
    // 2 --> 域名
    // 3 --> IPv6  地址长度 = 16
    let DSTADDR;	// DSTADDR = ATYP + DST.ADDR
    switch (addressType) {
        case 1: // IPv4
            DSTADDR = new Uint8Array(
                [1, ...addressRemote.split('.').map(Number)]
            );
            break;
        case 2: // 域名
            DSTADDR = new Uint8Array(
                [3, addressRemote.length, ...encoder.encode(addressRemote)]
            );
            break;
        case 3: // IPv6
            DSTADDR = new Uint8Array(
                [4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
            );
            break;
        default:
            log(`无效的地址类型: ${addressType}`);
            return;
    }
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    // 5: SOCKS5版本, 1: 表示CONNECT请求, 0: 保留字段
    // ...DSTADDR: 目标地址, portRemote >> 8 和 & 0xff: 将端口转为网络字节序
    await writer.write(socksRequest);
    log('已发送 SOCKS5 请求');

    res = (await reader.read()).value;
    // 响应格式（SOCKS5 服务器 -> Worker）:
    //  +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |	2	 |
    // +----+-----+-------+------+----------+----------+
    if (res[1] === 0x00) {
        log("SOCKS5 连接已建立");
    } else {
        log("SOCKS5 连接建立失败");
        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

/**
 * 建立 HTTP 代理连接
 * @param {string} addressRemote 目标地址（可以是 IP 或域名）
 * @param {number} portRemote 目标端口
 * @param {function} log 日志记录函数
 */
async function httpConnect(addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
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

/**
 * SOCKS5 代理地址解析器
 * 此函数用于解析 SOCKS5 代理地址字符串，提取出用户名、密码、主机名和端口号
 * 
 * @param {string} address SOCKS5 代理地址，格式可以是：
 *   - "username:password@hostname:port" （带认证）
 *   - "hostname:port" （不需认证）
 *   - "username:password@[ipv6]:port" （IPv6 地址需要用方括号括起来）
 */
function socks5AddressParser(address) {
    // 使用 "@" 分割地址，分为认证部分和服务器地址部分
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port;

    // 如果存在 former 部分，说明提供了认证信息
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
        }
        [username, password] = formers;
    }

    // 解析服务器地址部分
    const latters = latter.split(":");
    // 检查是否是IPv6地址带端口格式 [xxx]:port
    if (latters.length > 2 && latter.includes("]:")) {
        // IPv6地址带端口格式：[2001:db8::1]:8080
        port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
        hostname = latter.split("]:")[0] + "]"; // 正确提取hostname部分
    } else if (latters.length === 2) {
        // IPv4地址带端口或域名带端口
        port = Number(latters.pop().replace(/[^\d]/g, ''));
        hostname = latters.join(":");
    } else {
        port = 80;
        hostname = latter;
    }

    if (isNaN(port)) {
        throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    }

    // 处理 IPv6 地址的特殊情况
    // IPv6 地址包含多个冒号，所以必须用方括号括起来，如 [2001:db8::1]
    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
    }

    //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
    // 返回解析后的结果
    return {
        username,  // 用户名，如果没有则为 undefined
        password,  // 密码，如果没有则为 undefined
        hostname,  // 主机名，可以是域名、IPv4 或 IPv6 地址
        port,	 // 端口号，已转换为数字类型
    }
}

/**
 * 恢复被伪装的信息
 * 这个函数用于将内容中的假用户ID和假主机名替换回真实的值
 * 
 * @param {string} content 需要处理的内容
 * @param {string} userID 真实的用户ID
 * @param {string} hostName 真实的主机名
 * @param {boolean} isBase64 内容是否是Base64编码的
 * @returns {string} 恢复真实信息后的内容
 */
function 恢复伪装信息(content, userID, hostName, fakeUserID, fakeHostName, isBase64) {
    if (isBase64) content = atob(content);  // 如果内容是Base64编码的，先解码

    // 使用正则表达式全局替换（'g'标志）
    // 将所有出现的假用户ID和假主机名替换为真实的值
    content = content.replace(new RegExp(fakeUserID, 'g'), userID)
        .replace(new RegExp(fakeHostName, 'g'), hostName);

    if (isBase64) content = btoa(content);  // 如果原内容是Base64编码的，处理完后再次编码

    return content;
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

    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    return 第二次十六进制.toLowerCase();
}

async function 代理URL(代理网址, 目标网址) {
    const 网址列表 = await 整理(代理网址);
    const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

    // 解析目标 URL
    let 解析后的网址 = new URL(完整网址);
    console.log(解析后的网址);
    // 提取并可能修改 URL 组件
    let 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
    let 主机名 = 解析后的网址.hostname;
    let 路径名 = 解析后的网址.pathname;
    let 查询参数 = 解析后的网址.search;

    // 处理路径名
    if (路径名.charAt(路径名.length - 1) == '/') {
        路径名 = 路径名.slice(0, -1);
    }
    路径名 += 目标网址.pathname;

    // 构建新的 URL
    let 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

    // 反向代理请求
    let 响应 = await fetch(新网址);

    // 创建新的响应
    let 新响应 = new Response(响应.body, {
        status: 响应.status,
        statusText: 响应.statusText,
        headers: 响应.headers
    });

    // 添加自定义头部，包含 URL 信息
    //新响应.headers.set('X-Proxied-By', 'Cloudflare Worker');
    //新响应.headers.set('X-Original-URL', 完整网址);
    新响应.headers.set('X-New-URL', 新网址);

    return 新响应;
}


let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];

async function 整理优选列表(api) {
    if (!api || api.length === 0) return [];

    let newapi = "";

    // 创建一个AbortController对象，用于控制fetch请求的取消
    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort(); // 取消所有请求
    }, 2000); // 2秒后触发

    try {
        // 使用Promise.allSettled等待所有API请求完成，无论成功或失败
        // 对api数组进行遍历，对每个API地址发起fetch请求
        const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'User-Agent': atob('Q0YtV29ya2Vycy1lZGdldHVubmVsL2NtbGl1')
            },
            signal: controller.signal // 将AbortController的信号量添加到fetch请求中，以便于需要时可以取消请求
        }).then(response => response.ok ? response.text() : Promise.reject())));

        // 遍历所有响应
        for (const [index, response] of responses.entries()) {
            // 检查响应状态是否为'fulfilled'，即请求成功完成
            if (response.status === 'fulfilled') {
                // 获取响应的内容
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
                    // 验证当前apiUrl是否带有'proxyip=true'
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
                            return null; // 不符合条件时返回 null
                        }).filter(Boolean)); // 过滤掉 null 值
                    }
                    // 将内容添加到newapi中
                    newapi += content + '\n';
                }
            }
        }
    } catch (error) {
        console.error(error);
    } finally {
        // 无论成功或失败，最后都清除设置的超时定时器
        clearTimeout(timeout);
    }

    const newAddressesapi = await 整理(newapi);

    // 返回处理后的结果
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

            const text = await response.text();// 使用正确的字符编码解析文本内容
            let lines;
            if (text.includes('\r\n')) {
                lines = text.split('\r\n');
            } else {
                lines = text.split('\n');
            }

            // 检查CSV头部是否包含必需字段
            const header = lines[0].split(',');
            const tlsIndex = header.indexOf('TLS');

            const ipAddressIndex = 0;// IP地址在 CSV 头部的位置
            const portIndex = 1;// 端口在 CSV 头部的位置
            const dataCenterIndex = tlsIndex + remarkIndex; // 数据中心是 TLS 的后一个字段

            if (tlsIndex === -1) {
                console.error('CSV文件缺少必需的字段');
                continue;
            }

            // 从第二行开始遍历CSV行
            for (let i = 1; i < lines.length; i++) {
                const columns = lines[i].split(',');
                const speedIndex = columns.length - 1; // 最后一个字段
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

function createNodeLink(address, port, remark, UUID, host, isTLS) {
    let finalPath = path;
    const matchingProxyIP = proxyIPPool.find(pIP => pIP.includes(address));
    if (matchingProxyIP) {
        finalPath = `/proxyip=${matchingProxyIP}`;
    }

    const protocolType = atob(啥啥啥_写的这是啥啊);
    const baseUri = `${protocolType}://${UUID}@${address}:${port}`;
    
    if (isTLS) {
        const tlsParams = `?encryption=none&security=tls&sni=${host}&fp=random&type=ws&host=${host}&path=${encodeURIComponent(finalPath) + allowInsecure}&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`;
        return `${baseUri}${tlsParams}#${encodeURIComponent(remark)}`;
    } else {
        const noTlsParams = `?encryption=none&security=&type=ws&host=${host}&path=${encodeURIComponent(finalPath)}`;
        return `${baseUri}${noTlsParams}#${encodeURIComponent(remark)}`;
    }
}

async function 生成本地订阅(host, UUID, noTLSValue, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
    
    let nodeCounter = 1;
    const allSources = [];

    const combinedAddsApi = await 整理优选列表(addsapi);
    [...new Set(adds.concat(combinedAddsApi))].forEach(addr => allSources.push({ address: addr, source: 'adds' }));

    const combinedAddressesApi = newAddressesapi;
    const combinedAddressesCsv = newAddressescsv;
    [...new Set(addresses.concat(combinedAddressesApi, combinedAddressesCsv))].forEach(addr => allSources.push({ address: addr, source: 'add', tls: true }));

    if (noTLSValue === 'true') {
        const combinedAddressesNotlsApi = newAddressesnotlsapi;
        const combinedAddressesNotlsCsv = newAddressesnotlscsv;
        [...new Set(addressesnotls.concat(combinedAddressesNotlsApi, combinedAddressesNotlsCsv))].forEach(addr => allSources.push({ address: addr, source: 'add', tls: false }));
    }

    // 2. Process sources and generate links
    const finalLinks = allSources.flatMap(sourceItem => {
        const { address: rawAddress, source } = sourceItem;
        const isTls = source === 'adds' ? noTLSValue !== 'true' : sourceItem.tls;

        const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]|[^#:]+):?(\d+)?#?(.*)?$/;
        let address, port = "-1", remark;
        const match = rawAddress.match(regex);
        if (match) {
            address = match[1];
            port = match[2] || "-1";
            remark = match[3] || address;
        } else {
            address = rawAddress.split('#')[0].split(':')[0];
            remark = rawAddress;
        }

        let portsToUse = [];
        if (port !== "-1") {
            portsToUse.push(port);
        } else {
            if (source === 'adds') {
                const selectedPorts = isTls
                    ? (httpsPorts.length > 0 ? httpsPorts : ["443"])
                    : (httpPorts.length > 0 ? httpPorts : ["80"]);
                portsToUse.push(...selectedPorts);
            } else { 
                 const defaultPort = isTls ? "443" : "80";
                 portsToUse.push(defaultPort);
            }
        }

        return portsToUse.map(p => {
            const finalRemark = `${remark}#${nodeCounter++}`;
            return createNodeLink(address, p, finalRemark, UUID, host, isTls);
        });
    });

    let combinedLinks = finalLinks.join('\n');
    if (link.length > 0) {
        combinedLinks += '\n' + link.join('\n');
    }

    return btoa(combinedLinks);
}


async function 整理(内容) {
    // 将制表符、双引号、单引号和换行符都替换为逗号
    // 然后将连续的多个逗号替换为单个逗号
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');

    // 删除开头和结尾的逗号（如果有的话）
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

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
    // 默认行为是保存配置
    if (!env.KV) {
        return new Response("未绑定KV空间", { status: 400 });
    }
    try {
        const settingsJSON = await env.KV.get('settinggs.txt');
        let settings = settingsJSON ? JSON.parse(settingsJSON) : {};

        const updates = await request.json();

        // 只允许更新指定的键，防止保存已移除的设置
        const allowedKeys = ['ADD', 'ADDS', 'notls', 'httpsports', 'httpports'];
		for (const key of allowedKeys) {
			if (updates.hasOwnProperty(key)) {
				settings[key] = updates[key];
			}
		}

        await env.KV.put('settinggs.txt', JSON.stringify(settings, null, 2));

        return new Response("保存成功");
    } catch (error) {
        console.error('保存KV时发生错误:', error);
        return new Response("保存失败: " + error.message, { status: 500 });
    }
}

async function handleGetRequest(env) {
    let content = '';
    let addsContent = '';
    let hasKV = !!env.KV;
	let httpsPortsContent = '';
    let httpPortsContent = '';
    let noTLSContent = 'false';

    if (hasKV) {
        try {
            const advancedSettingsJSON = await env.KV.get('settinggs.txt');
            if (advancedSettingsJSON) {
                const settings = JSON.parse(advancedSettingsJSON);
                content = settings.ADD || '';
                addsContent = settings.ADDS || '';
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

                .editor:focus {
                    outline: none;
                    border-color: var(--primary-color);
                    box-shadow: 0 0 0 2px color-mix(in srgb, var(--primary-color) 25%, transparent);
                }

                .setting-item { margin-bottom: 20px; }

                .button-group { display: flex; align-items: center; gap: 12px; margin-top: 15px; }
                .btn { padding: 8px 20px; border: none; border-radius: 6px; font-size: 14px; font-weight: 500; cursor: pointer; }
                .btn-primary { background: var(--primary-color); color: #fff; }
                .btn-primary:hover:not(:disabled) { background: var(--secondary-color); }
                .btn-secondary { background: #6c757d; color: #fff; }
                .btn-secondary:hover:not(:disabled) { background: #5c636a; }
                .save-status { font-size: 14px; color: var(--text-color); }

                .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(80px, 1fr)); gap: 10px; margin-top: 10px; }
                .checkbox-item { display: flex; align-items: center; gap: 5px; }

                /* --- Switch Styles --- */
                .switch-container { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; }
                .theme-switch-wrapper { display: flex; align-items: center; position: fixed; top: 15px; right: 15px; }
                .theme-switch { display: inline-block; height: 20px; position: relative; width: 36px; }
                .theme-switch input { display:none; }
                .slider { background-color: #ccc; bottom: 0; cursor: pointer; left: 0; position: absolute; right: 0; top: 0; }
                .slider:before { background-color: #fff; bottom: 3px; content: ""; height: 14px; left: 3px; position: absolute; width: 14px; }
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
                <div class="title">📝 ${FileName} 设置</div>

                <div class="tab-container">
                    <button class="tab-link active" onclick="openTab(event, 'tab-main')">优选列表</button>
                    <button class="tab-link" onclick="openTab(event, 'tab-adds')">官方列表</button>
                </div>

                <div id="tab-main" class="tab-content" style="display: block;">
                    ${hasKV ? `
                        <textarea class="editor" id="content" placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU5RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU4RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU4RCVCMyVFNSU4RiVBRg=='))}">${content}</textarea>

                        <div class="button-group">
                            <button class="btn btn-secondary" onclick="goBack()">返回首页</button>
                            <button class="btn btn-primary" onclick="saveAddTab(this)">保存</button>
                            <span class="save-status" id="saveStatus-main"></span>
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
                            <button class="btn btn-secondary" onclick="goBack()">返回首页</button>
                            <button class="btn btn-primary" onclick="saveAddsTab(this)">保存</button>
                            <span class="save-status" id="saveStatus-adds"></span>
                        </div>
                    ` : '<p>未绑定KV空间</p>'}
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
                    const statusEl = document.getElementById('saveStatus-main');
                    const payload = {
                        ADD: document.getElementById('content').value
                    };
                    await saveData(button, statusEl, JSON.stringify(payload));
                }

                async function saveAddsTab(button) {
                    const statusEl = document.getElementById('saveStatus-adds');
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

                async function saveData(button, statusEl, body) {
                    if (!button || !statusEl) return;
                    button.disabled = true;
                    statusEl.textContent = '保存中...';
                    try {
                        const response = await fetch(window.location.href, {
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

async function nginx() {
    const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
    return text;
}

const 啥啥啥_写的这是啥啊 = atob('ZG14bGMzTT0=');
async function config_Json(userID, hostName, sub, UA, 请求CF反代IP, _url, fakeUserID, fakeHostName, env) {
    const newSocks5s = socks5s.map(socks5Address => {
        if (socks5Address.includes('@')) return socks5Address.split('@')[1];
        else if (socks5Address.includes('//')) return socks5Address.split('//')[1];
        else return socks5Address;
    }).filter(address => address !== '');

    let CF访问方法 = "auto";
    if (enableSocks) CF访问方法 = enableHttp ? "http" : "socks5";
    else if (proxyIP && proxyIP != '') CF访问方法 = "proxyip";
    else if (请求CF反代IP == 'true') CF访问方法 = "auto";
    
    const config = {
        timestamp: new Date().toISOString(),
        config: {
            HOST: hostName,
            KEY: {
                DynamicUUID: false,
                UUID: userID.toLowerCase() || null,
                fakeUserID: fakeUserID || null,
            },
            SCV: SCV
        },
        proxyip: {
            RequestProxyIP: 请求CF反代IP,
            GO2CF: CF访问方法,
            List: {
                PROXY_IP: proxyIPs.filter(ip => ip !== ''),
                SOCKS5: enableHttp ? [] : newSocks5s,
                HTTP: enableHttp ? newSocks5s : []
            },
            GO2SOCKS5: (go2Socks5s.includes('all in') || go2Socks5s.includes('*')) ? ["all in"] : go2Socks5s
        },
        sub: {
            SUBNAME: FileName,
            SUB: (sub && sub != "local") ? sub : "local",
            ADD: addresses,
            ADDNOTLS: addressesnotls,
            ADDAPI: addressesapi,
            ADDNOTLSAPI: addressesnotlsapi,
            ADDCSV: addressescsv,
            DLS: DLS,
            CSVREMARK: remarkIndex,
            SUBAPI: `${subProtocol}://${subConverter}`,
            SUBCONFIG: subConfig
        },
        KV: env.KV ? true : false,
        UA: UA || null
    };
    return new Response(JSON.stringify(config, null, 2), {
        headers: {
            'access-control-allow-origin': '*',
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache'
        },
    });
}

// Sample JavaScript code for a simple, safe functionality
// This code creates a basic counter application with user interaction
async function 生成配置信息(userID, hostName, sub, UA, 请求CF反代IP, _url, fakeUserID, fakeHostName, env) {
    if (sub) {
        const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) {
            sub = match[1];
        }
        const subs = await 整理(sub);
        if (subs.length > 1) sub = subs[0];
    } else {
        if (env.KV) {
            try {
                const advancedSettingsJSON = await env.KV.get('settinggs.txt');
                if (advancedSettingsJSON) {
                    const settings = JSON.parse(advancedSettingsJSON);
                    if (settings.httpsports && settings.httpsports.trim()) httpsPorts = await 整理(settings.httpsports);
                    if (settings.httpports && settings.httpports.trim()) httpPorts = await 整理(settings.httpports);
                    if (settings.notls) noTLS = settings.notls;
                    
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

                    if (settings.ADDS) {
                        const 官方优选数组 = await 整理(settings.ADDS);
                        const 官方分类地址 = { 接口地址: new Set(), 优选地址: new Set() };
                         for (const 元素 of 官方优选数组) {
                            if (元素.startsWith('https://')) 官方分类地址.接口地址.add(元素);
                            else 官方分类地址.优选地址.add(元素);
                        }
                        addsapi = [...官方分类地址.接口地址];
                        adds = [...官方分类地址.优选地址];
                    }
                }
            } catch (e) {
                console.error("从KV加载配置时出错: ", e);
            }
        }

        // CORRECTED LOGIC: Check for nodes *after* all sources have been potentially populated.
        if ((addresses.length + addressesapi.length + adds.length + addsapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
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
            const generatedNodes = [];

            if (hostName.includes("worker") || hostName.includes("notls") || noTLS === 'true') {
                const randomPorts = httpPorts.length > 0 ? httpPorts : ['80'];
                for (let i = 0; i < totalIPsToGenerate; i++) {
                    const randomCIDR = cfips[Math.floor(Math.random() * cfips.length)];
                    const randomIP = generateRandomIPFromCIDR(randomCIDR);
                    const port = randomPorts[Math.floor(Math.random() * randomPorts.length)];
                    generatedNodes.push(`${randomIP}:${port}#CF随机节点${String(counter++).padStart(2, '0')}`);
                }
                addressesnotls = addressesnotls.concat(generatedNodes);
            } else {
                const randomPorts = httpsPorts.length > 0 ? httpsPorts : ['443'];
                for (let i = 0; i < totalIPsToGenerate; i++) {
                    const randomCIDR = cfips[Math.floor(Math.random() * cfips.length)];
                    const randomIP = generateRandomIPFromCIDR(randomCIDR);
                    const port = randomPorts[Math.floor(Math.random() * randomPorts.length)];
                    generatedNodes.push(`${randomIP}:${port}#CF随机节点${String(counter++).padStart(2, '0')}`);
                }
                addresses = addresses.concat(generatedNodes);
            }
        }
    }

    const userAgent = UA.toLowerCase();
    let proxyhost = "";
    if (hostName.includes(".workers.dev")) {
        if (proxyhosts.length > 0) {
			proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
		}
    }

    if (userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
        const token = await 双重哈希(fakeUserID + UA);
        return config_Html(token, proxyhost);
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
        let url = `${subProtocol}://${sub}/sub?host=${fakeHostName}&uuid=${fakeUserID}&proxyip=${请求CF反代IP}&path=${encodeURIComponent(path)}&${atob('ZWRnZXR1bm5lbD1jbWxpdQ==')}`;
        let isBase64 = true;

        if (!sub || sub == "") {
            newAddressesapi = await 整理优选列表(addressesapi);
            newAddressescsv = await 整理测速结果('TRUE');
            url = `https://${hostName}/${fakeUserID + _url.search}`;
            if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
                if (_url.search) url += '&notls';
                else url += '?notls';
            }
            console.log(`虚假订阅: ${url}`);
        }

        if (userAgent.includes(('CF-Workers-SUB').toLowerCase()) || _url.searchParams.has('b64') || _url.searchParams.has('base64') || userAgent.includes('subconverter')) {
            isBase64 = true;
        } else if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash'))) {
            url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || _url.searchParams.has('singbox') || _url.searchParams.has('sb')) {
            url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else if (userAgent.includes('loon') || _url.searchParams.has('loon')) {
            url = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        }

        try {
            let content;
            if ((!sub || sub == "") && isBase64 == true) {
                content = await 生成本地订阅(fakeHostName, fakeUserID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv);
            } else {
                const response = await fetch(url, {
                    headers: {
                        'User-Agent': atob('djJyYXlOL2VkZ2V0dW5uZWwgKGh0dHBzOi8vZ2l0aHViLmNvbS9jbWxpdS9lZGdldHVubmVsKQ==')
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

function config_Html(token = "test", proxyhost = "") {
    const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title id="pageTitle">配置页面</title>
    <style>
        :root {
            --primary-color: #0d6efd;
            --secondary-color: #0b5ed7;
            --border-color: #e0e0e0;
            --text-color: #212529;
            --background-color: #f5f5f5;
            --section-bg: #ffffff;
            --btn-secondary-bg: #6c757d;
            --btn-secondary-hover-bg: #5a6268;
        }

        html.dark-mode {
            --primary-color: #589bff;
            --secondary-color: #458cff;
            --border-color: #3c3c3c;
            --text-color: #e0e0e0;
            --background-color: #1c1c1e;
            --section-bg: #2a2a2a;
            --btn-secondary-bg: #5a6268;
            --btn-secondary-hover-bg: #494e53;
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
        }
        
        .main-title {
            font-size: 2em;
            text-align: center;
            margin-bottom: 25px;
            color: #000000;
        }

        .loading {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 60vh;
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(128, 128, 128, 0.2);
            border-top-color: var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 16px;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        .content { display: none; }
        
        .section {
            margin-bottom: 25px;
            padding: 25px;
            background: var(--section-bg);
            border-radius: 10px;
            border: 1px solid var(--border-color);
        }

        .section-header {
             display: flex;
             justify-content: space-between;
             align-items: center;
             margin-bottom: 20px;
             padding-bottom: 15px;
             border-bottom: 1px solid var(--border-color);
        }

        .section-title {
            font-size: 1.3em;
            font-weight: 600;
            margin: 0;
        }

        .header-button {
            padding: 8px 16px;
            background: var(--primary-color);
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            text-decoration: none;
        }
        .header-button:hover { background: var(--secondary-color); }

        .subscription-buttons-container {
            display: flex;
            flex-wrap: wrap; 
            gap: 12px; 
            justify-content: center;
        }
        
        .copy-button {
            min-width: 135px;
            flex-grow: 1;
            padding: 10px 16px;
            background: var(--primary-color);
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }
        .copy-button:hover {
            background: var(--secondary-color);
        }

        #config-text-display {
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.9em;
            background: var(--background-color);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        /* Modal Styles */
        .modal {
            display: none; position: fixed; z-index: 1000;
            left: 0; top: 0; width: 100%; height: 100%;
            overflow: auto; background-color: rgba(0,0,0,0.5);
            animation: fadeIn 0.3s;
        }
        .modal-content {
            background-color: var(--section-bg);
            margin: 10% auto; padding: 25px; border: 1px solid var(--border-color);
            width: 90%; max-width: 600px; border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            animation: slideIn 0.3s;
        }
        @keyframes fadeIn { from {opacity: 0;} to {opacity: 1;} }
        @keyframes slideIn { from {transform: translateY(-50px);} to {transform: translateY(0);} }
        .modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; margin-bottom: 20px; }
        .modal-title { margin: 0; font-size: 1.4em; }
        .modal-close { color: #aaa; font-size: 28px; font-weight: bold; cursor: pointer; }
        .modal-close:hover, .modal-close:focus { color: var(--text-color); }
        .modal-body .setting-item { margin-bottom: 18px; }
        .setting-label { display: block; margin-bottom: 8px; font-weight: 500; cursor: pointer; display: flex; align-items: center; }
        .setting-input { width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 1em; background-color: var(--background-color); color: var(--text-color); box-sizing: border-box; }
        .setting-input:focus { border-color: var(--primary-color); outline: none; }
        .setting-input:disabled { background-color: #eee; cursor: not-allowed; }
        html.dark-mode .setting-input:disabled { background-color: #333; }
        .setting-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
        .setting-row .setting-label { margin-bottom: 0; }
        .global-proxy-label { font-size: 0.9em; }

        .modal-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 25px; padding-top: 15px; border-top: 1px solid var(--border-color); }
        .btn-secondary {
             background-color: var(--btn-secondary-bg);
        }
        .btn-secondary:hover {
             background-color: var(--btn-secondary-hover-bg);
        }
        
        /* Checkbox Styles for Modal */
        .setting-label input[type="checkbox"] { margin-right: 10px; width: 16px; height: 16px; }

        /* Switch Styles */
        .theme-switch-wrapper { display: flex; align-items: center; position: fixed; top: 15px; right: 15px; z-index: 1001; }
        .theme-switch { display: inline-block; height: 20px; position: relative; width: 36px; }
        .theme-switch input { display:none; }
        .slider { background-color: #ccc; bottom: 0; cursor: pointer; left: 0; position: absolute; right: 0; top: 0; }
        .slider:before { background-color: #fff; bottom: 3px; content: ""; height: 14px; left: 3px; position: absolute; width: 14px; }
        input:checked + .slider { background-color: var(--primary-color); }
        input:checked + .slider:before { transform: translateX(16px); }
        .slider.round { border-radius: 20px; }
        .slider.round:before { border-radius: 50%; }

        /* Toast Notification */
        #toast {
            visibility: hidden; min-width: 250px; background-color: #333; color: #fff;
            text-align: center; border-radius: 8px; padding: 16px; position: fixed;
            z-index: 10000; left: 50%; transform: translateX(-50%); bottom: 30px;
            font-size: 17px;
        }
        #toast.show { visibility: visible; animation: toast-fadein 0.5s, toast-fadeout 0.5s 2.5s; }
        @keyframes toast-fadein { from {bottom: 0; opacity: 0;} to {bottom: 30px; opacity: 1;} }
        @keyframes toast-fadeout { from {bottom: 30px; opacity: 1;} to {bottom: 0; opacity: 0;} }

        @media (max-width: 768px) {
            .subscription-buttons-container {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="theme-switch-wrapper">
        <label class="theme-switch" for="theme-checkbox">
            <input type="checkbox" id="theme-checkbox" />
            <div class="slider round"></div>
        </label>
    </div>
    
    <div class="container">
        <h1 id="pageHeader" class="main-title">🚀 edgetunnel 配置中心</h1>

        <div id="loading" class="loading">
            <div class="spinner"></div>
            <p>正在加载配置...</p>
        </div>

        <div id="content" class="content">
            <div class="section">
                <div class="section-header">
                    <h2 class="section-title">订阅信息</h2>
                    <button class="header-button" onclick="openAdvancedSettings()">⚙️ 自定义订阅</button>
                </div>
                <div class="subscription-buttons-container" id="subscriptionLinks"></div>
            </div>
            
            <div class="section">
                <div class="section-header" id="config-details-header">
                    <h2 class="section-title">详细配置信息</h2>
                </div>
                <pre id="config-text-display"></pre>
            </div>
        </div>
    </div>
    
    <div id="toast"></div>

    <!-- Advanced Settings Modal -->
    <div id="advancedModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">⚙️ 自定义订阅设置</h3>
                <span class="modal-close" onclick="closeAdvancedSettings()">&times;</span>
            </div>
            <div class="modal-body">
                <div class="setting-item">
                    <label class="setting-label">
                        <input type="checkbox" id="subEnabled" onchange="updateSettings()">
                        🚀 优选订阅生成器
                    </label>
                    <input type="text" id="subInput" placeholder="sub.google.com" class="setting-input">
                </div>
                
                <div class="setting-item">
                    <label class="setting-label">
                        <input type="checkbox" id="proxyipEnabled" onchange="updateProxySettings('proxyip')">
                        🌐 PROXYIP
                    </label>
                    <input type="text" id="proxyipInput" placeholder="proxyip.cmliussss.net:443" class="setting-input">
                </div>
                
                <div class="setting-item">
                    <div class="setting-row">
                        <label class="setting-label">
                            <input type="checkbox" id="socks5Enabled" onchange="updateProxySettings('socks5')">
                            🔒 SOCKS5
                        </label>
                        <label class="setting-label global-proxy-label">
                            <input type="checkbox" id="socks5GlobalEnabled">
                            全局代理
                        </label>
                    </div>
                    <input type="text" id="socks5Input" placeholder="user:password@127.0.0.1:1080" class="setting-input">
                </div>
                
                <div class="setting-item">
                     <div class="setting-row">
                        <label class="setting-label">
                            <input type="checkbox" id="httpEnabled" onchange="updateProxySettings('http')">
                            🌍 HTTP
                        </label>
                        <label class="setting-label global-proxy-label">
                            <input type="checkbox" id="httpGlobalEnabled">
                            全局代理
                        </label>
                    </div>
                    <input type="text" id="httpInput" placeholder="34.87.109.175:9443" class="setting-input">
                </div>
            </div>
            <div class="modal-footer">
                <button class="header-button btn-secondary" onclick="closeAdvancedSettings()">返回</button>
                <button class="header-button" onclick="saveAdvancedSettings()">保存</button>
            </div>
        </div>
    </div>

    <script>
        let configData = null;

        document.addEventListener('DOMContentLoaded', () => {
            loadConfig();
            setupTheme();
        });

        function setupTheme() {
            const themeToggle = document.querySelector('#theme-checkbox');
            if (localStorage.getItem('theme') === 'dark-mode') {
                document.documentElement.classList.add('dark-mode');
                themeToggle.checked = true;
            }
            themeToggle.addEventListener('change', (e) => {
                if (e.target.checked) {
                    document.documentElement.classList.add('dark-mode');
                    localStorage.setItem('theme', 'dark-mode');
                } else {
                    document.documentElement.classList.remove('dark-mode');
                    localStorage.setItem('theme', 'light-mode');
                }    
            });
        }
        
        async function loadConfig() {
            try {
                const response = await fetch(window.location.pathname + '/config.json?token=${token}&t=' + Date.now());
                if (!response.ok) throw new Error('HTTP error! status: ' + response.status);
                configData = await response.json();
                document.getElementById('loading').style.display = 'none';
                document.getElementById('content').style.display = 'block';
                renderPage();
            } catch (error) {
                console.error('加载配置失败:', error);
                document.getElementById('loading').innerHTML = '<p style="color: red;">❌ 加载配置失败，请刷新页面重试</p>';
            }
        }
        
        function renderPage() {
            updatePageTitles();
            renderSubscriptionLinks();
            renderConfigAsText();
        }
        
        function updatePageTitles() {
            const subName = configData.sub.SUBNAME;
            if (subName && subName !== 'edgetunnel') {
                document.getElementById('pageTitle').textContent = subName + ' 配置页面';
                document.getElementById('pageHeader').textContent = '🚀 ' + subName + ' 配置中心';
            }
        }

        function renderSubscriptionLinks() {
            const container = document.getElementById('subscriptionLinks');
            const host = configData.config.HOST;
            const uuid = configData.config.KEY.UUID;
            const subscriptions = [
                { name: '通用', suffix: '' },
                { name: 'Base64', suffix: '?b64' },
                { name: 'Clash', suffix: '?clash' },
                { name: 'Sing-Box', suffix: '?sb' },
                { name: 'Loon', suffix: '?loon' }
            ];
            container.innerHTML = subscriptions.map(sub => {
                const url = buildSubscriptionUrl(host, uuid, sub.suffix);
                return \`<button class="copy-button" onclick="copyToClipboard('\${url}')">\${sub.name}</button>\`;
            }).join('');
        }
        
        function renderConfigAsText() {
            const displayEl = document.getElementById('config-text-display');
            let textContent = '';

            const addSection = (title, data) => {
                textContent += \`--- \${title} ---\\n\`;
                for (const [key, value] of Object.entries(data)) {
                    if (value && (!Array.isArray(value) || value.length > 0)) {
                        const displayValue = Array.isArray(value) ? '\\n  ' + value.join('\\n  ') : value;
                        textContent += \`\${key}: \${displayValue}\\n\`;
                    }
                }
                textContent += '\\n';
            };
            
            addSection('详细配置信息', {
                'HOST': configData.config.HOST,
                'UUID': configData.config.KEY.UUID,
                'FKID': configData.config.KEY.fakeUserID,
                '跳过TLS验证': configData.config.SCV === 'true' ? '启用' : '禁用'
            });

            const sub = configData.sub;
            const subInfo = {
                '订阅名称': sub.SUBNAME,
                '优选订阅生成器': sub.SUB,
                'ADDCSV速度下限': sub.DLS,
                'KV 状态': configData.KV ? '🟢已绑定' : '🔴未绑定'
            };
            if (sub.SUB === 'local') {
                Object.assign(subInfo, {
                    'ADD (TLS)': sub.ADD,
                    'ADDNOTLS (非TLS)': sub.ADDNOTLS,
                    'ADDAPI (TLS)': sub.ADDAPI,
                    'ADDNOTLSAPI (非TLS)': sub.ADDNOTLSAPI,
                    'ADDCSV': sub.ADDCSV
                });
            }
            addSection('优选订阅配置', subInfo);

            addSection('订阅转换配置', {
                '订阅转换后端': sub.SUBAPI,
                '订阅转换配置': sub.SUBCONFIG
            });
            
            const proxy = configData.proxyip;
            addSection('ProxyIP配置', {
                'CDN访问模式': proxy.GO2CF,
                'SOCKS5/HTTP白名单': proxy.GO2SOCKS5,
                'ProxyIP列表': proxy.List.PROXY_IP,
                'SOCKS5列表': proxy.List.SOCKS5,
                'HTTP列表': proxy.List.HTTP
            });
            
            displayEl.textContent = textContent.trim();
            
            const configHeader = document.getElementById('config-details-header');
            if (configData.KV && configData.sub.SUB === 'local') {
                const editButton = document.createElement('a');
                editButton.href = window.location.pathname + '/edit';
                editButton.className = 'header-button';
                editButton.textContent = '📝 编辑优选列表';
                configHeader.appendChild(editButton);
            }
        }


        function buildSubscriptionUrl(host, uuid, suffix) {
            let baseUrl = 'https://' + '${proxyhost}' + host + '/' + uuid + suffix;
            const settings = getAdvancedSettings();
            const params = new URLSearchParams();

            if (settings.subEnabled && settings.subValue) {
                params.append('sub', settings.subValue);
            }
            if (settings.proxyipEnabled && settings.proxyipValue) {
                params.append('proxyip', settings.proxyipValue);
            } else if (settings.socks5Enabled && settings.socks5Value) {
                params.append('socks5', settings.socks5Value);
                if (settings.socks5GlobalEnabled) params.append('globalproxy', '');
            } else if (settings.httpEnabled && settings.httpValue) {
                params.append('http', settings.httpValue);
                if (settings.httpGlobalEnabled) params.append('globalproxy', '');
            }
            
            const paramString = params.toString().replace(/=&/g, '&').replace(/=$/, '');
            return paramString ? baseUrl + (baseUrl.includes('?') ? '&' : '?') + paramString : baseUrl;
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('✅ 已复制到剪贴板');
            }, () => {
                showToast('❌ 复制失败');
            });
        }
        
        function showToast(message) {
            const toast = document.getElementById("toast");
            toast.textContent = message;
            toast.className = "show";
            setTimeout(() => { toast.className = toast.className.replace("show", ""); }, 3000);
        }

        // Modal Logic
        const modal = document.getElementById('advancedModal');
        
        function openAdvancedSettings() {
            loadAdvancedSettings();
            modal.style.display = "block";
        }

        function closeAdvancedSettings() {
            modal.style.display = "none";
        }
        
        window.onclick = (event) => { if (event.target == modal) closeAdvancedSettings(); }

        function getAdvancedSettings() {
            try {
                const settings = localStorage.getItem('advancedSubSettingsV3');
                return settings ? JSON.parse(settings) : {};
            } catch { return {}; }
        }
        
        function loadAdvancedSettings() {
            const settings = getAdvancedSettings();
            ['sub', 'proxyip', 'socks5', 'http'].forEach(type => {
                document.getElementById(type + 'Enabled').checked = settings[type + 'Enabled'] || false;
                document.getElementById(type + 'Input').value = settings[type + 'Value'] || '';
            });
            document.getElementById('socks5GlobalEnabled').checked = settings.socks5GlobalEnabled || false;
            document.getElementById('httpGlobalEnabled').checked = settings.httpGlobalEnabled || false;
            // Trigger update to set initial disabled states correctly
            updateSettings();
            updateProxySettings('proxyip');
            updateProxySettings('socks5');
            updateProxySettings('http');
        }

        function saveAdvancedSettings() {
            const settings = {
                subEnabled: document.getElementById('subEnabled').checked,
                subValue: document.getElementById('subInput').value,
                proxyipEnabled: document.getElementById('proxyipEnabled').checked,
                proxyipValue: document.getElementById('proxyipInput').value,
                socks5Enabled: document.getElementById('socks5Enabled').checked,
                socks5Value: document.getElementById('socks5Input').value,
                socks5GlobalEnabled: document.getElementById('socks5GlobalEnabled').checked,
                httpEnabled: document.getElementById('httpEnabled').checked,
                httpValue: document.getElementById('httpInput').value,
                httpGlobalEnabled: document.getElementById('httpGlobalEnabled').checked,
            };
            localStorage.setItem('advancedSubSettingsV3', JSON.stringify(settings));
            closeAdvancedSettings();
            renderSubscriptionLinks();
            showToast('🎉 设置已保存, 链接已更新!');
        }
        
        function updateSettings() {
            document.getElementById('subInput').disabled = !document.getElementById('subEnabled').checked;
        }

        function updateProxySettings(type) {
            const enabled = document.getElementById(type + 'Enabled').checked;
            document.getElementById(type + 'Input').disabled = !enabled;

            if (type === 'socks5' || type === 'http') {
                const globalCheckbox = document.getElementById(type + 'GlobalEnabled');
                globalCheckbox.disabled = !enabled;
                if (!enabled) {
                    globalCheckbox.checked = false;
                }
            }
            
            if (enabled) {
                ['proxyip', 'socks5', 'http'].forEach(proxyType => {
                    if (proxyType !== type) {
                        document.getElementById(proxyType + 'Enabled').checked = false;
                        document.getElementById(proxyType + 'Input').disabled = true;
                        if (proxyType === 'socks5' || proxyType === 'http') {
                           const globalCheckbox = document.getElementById(proxyType + 'GlobalEnabled');
                           globalCheckbox.disabled = true;
                           globalCheckbox.checked = false;
                        }
                    }
                });
            }
        }
    </script>
</body>
</html>`;
    return html;
}
