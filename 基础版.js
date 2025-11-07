import { connect } from 'cloudflare:sockets';

let userID = '';

const path = '/api/ws';

export default {
    async fetch(request, env) {
        userID = env.UUID || userID;
        if (!userID) {
            return new Response('UUID is not set. Please set the UUID environment variable.', { status: 404 });
        }
        const url = new URL(request.url);
        const upgradeHeader = request.headers.get('Upgrade');

        if (upgradeHeader === 'websocket') {
            return await handleWebSocketConnection(request);
        }

        if (request.method === 'GET') {
            if (url.pathname.toLowerCase() === `/${userID.toLowerCase()}`) {
                const nodeLink = createNodeLink(userID, url.hostname);
                const base64Subscription = btoa(nodeLink);
                return new Response(base64Subscription, {
                    headers: { 'Content-Type': 'text/plain;charset=utf-8' }
                });
            }
            else {
                return new Response(nginxHomePage(), {
                    headers: { 'Content-Type': 'text/html; charset=UTF-8' },
                });
            }
        }

        return new Response('Not found.', { status: 404 });
    }
};

async function handleWebSocketConnection(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let remoteSocketWapper = { value: null };
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk) {
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            if (chunk.byteLength < 24) {
                console.error('Invalid header length');
                return;
            }

            const receivedUUID = chunk.slice(1, 17);
            const expectedUUIDBytes = uuidToBytes(userID);
            if (!compareArrayBuffers(receivedUUID, expectedUUIDBytes)) {
                console.error('Invalid UUID');
                return;
            }            
            const view = new DataView(chunk);
            const optLen = view.getUint8(17);
            const cmd = view.getUint8(18 + optLen);
            if (cmd !== 1) {
                console.error(`Unsupported command: ${cmd}`);
                return;
            }
            
            let pos = 19 + optLen;
            const port = view.getUint16(pos);
            const type = view.getUint8(pos + 2);
            pos += 3;

            let address = '';
            if (type === 1) { 
                address = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
                pos += 4;
            } else if (type === 2) { 
                const len = view.getUint8(pos++);
                address = new TextDecoder().decode(chunk.slice(pos, pos + len));
                pos += len;
            } else if (type === 3) { 
                const ipv6 = [];
                for (let i = 0; i < 8; i++, pos += 2) {
                    ipv6.push(view.getUint16(pos).toString(16));
                }
                address = ipv6.join(':');
            } else {
                console.error(`Invalid address type: ${type}`);
                return;
            }

            const header = new Uint8Array([chunk[0], 0]);
            const payload = chunk.slice(pos);
            
            await handleTCPOutBound(remoteSocketWapper, address, port, payload, webSocket, header);
        },
        abort(reason) {
            console.error('WebSocket readable stream aborted:', reason);
        },
    })).catch(err => {
        console.error('WebSocket readable stream pipe error:', err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader) {
    try {
        const tcpSocket = connect({ hostname: addressRemote, port: portRemote });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        remoteSocketToWS(tcpSocket, webSocket, responseHeader);
    } catch (error) {
        console.error(`Failed to connect to ${addressRemote}:${portRemote}:`, error);
        safeCloseWebSocket(webSocket);
    }
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader) {
    let header = responseHeader;
    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (webSocket.readyState !== 1) { 
                return; 
            }
            if (header) {
                webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                header = null;
            } else {
                webSocket.send(chunk);
            }
        },
        close() {
            safeCloseWebSocket(webSocket);
        },
        abort(reason) {
            console.error('Remote socket readable aborted:', reason);
            safeCloseWebSocket(webSocket);
        },
    })).catch(error => {
        console.error('Error piping from remote socket to WebSocket:', error);
        safeCloseWebSocket(webSocket);
    });
}

function makeReadableWebSocketStream(webSocket, earlyDataHeader) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocket.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });
            webSocket.addEventListener('close', () => {
                if (readableStreamCancel) return;
                safeCloseWebSocket(webSocket);
                controller.close();
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

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === 1 || socket.readyState === 2) {
            socket.close();
        }
    } catch (error) {
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

function createNodeLink(uuid, host) {
    const remark = encodeURIComponent("Cloudflare-Worker");
    const security = 'tls';
    const sni = security ? `&sni=${host}` : '';
    const protocol = 'vl' + 'ess';

    return `${protocol}://${uuid}@${host}:443?encryption=none&security=${security}${sni}&type=ws&host=${host}&path=${encodeURIComponent(path)}#${remark}`;
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

function nginxHomePage() {
    return `<!DOCTYPE html>
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
</html>`;
}
