import http from "http";
import crypto from "crypto";

const PORT = process.env.PORT || 3000;
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const clients = new Set(); // Set<net.Socket>

function makeAcceptValue(secWebSocketKey) {
  return crypto
    .createHash("sha1")
    .update(secWebSocketKey + GUID, "utf8")
    .digest("base64");
}

// --- WebSocket framing (минимум для text frames) ---

function unmaskPayload(payload, maskKey) {
  for (let i = 0; i < payload.length; i++) {
    payload[i] ^= maskKey[i % 4];
  }
  return payload;
}

function encodeTextFrame(str) {
  const payload = Buffer.from(str, "utf8");
  const len = payload.length;

  // FIN=1, opcode=1 (text)
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81;
    header[1] = len; // no mask
    return Buffer.concat([header, payload]);
  }

  if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
    return Buffer.concat([header, payload]);
  }

  // 64-bit length (редко нужно для чата, но добавим корректно)
  header = Buffer.alloc(10);
  header[0] = 0x81;
  header[1] = 127;
  // пишем BigInt длины
  header.writeBigUInt64BE(BigInt(len), 2);
  return Buffer.concat([header, payload]);
}

/**
 * Пытается вытащить 1 фрейм из буфера.
 * Возвращает { frame, rest } или null если данных мало.
 */
function tryDecodeFrame(buffer) {
  if (buffer.length < 2) return null;

  const b0 = buffer[0];
  const b1 = buffer[1];

  const fin = (b0 & 0x80) !== 0;
  const opcode = b0 & 0x0f;

  const masked = (b1 & 0x80) !== 0;
  let payloadLen = b1 & 0x7f;

  let offset = 2;

  if (payloadLen === 126) {
    if (buffer.length < offset + 2) return null;
    payloadLen = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (payloadLen === 127) {
    if (buffer.length < offset + 8) return null;
    const bigLen = buffer.readBigUInt64BE(offset);
    if (bigLen > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("Frame too large");
    }
    payloadLen = Number(bigLen);
    offset += 8;
  }

  let maskKey = null;
  if (masked) {
    if (buffer.length < offset + 4) return null;
    maskKey = buffer.subarray(offset, offset + 4);
    offset += 4;
  }

  if (buffer.length < offset + payloadLen) return null;

  let payload = buffer.subarray(offset, offset + payloadLen);
  const rest = buffer.subarray(offset + payloadLen);

  // Браузер -> сервер: masked (обычно всегда true)
  if (masked && maskKey) {
    payload = Buffer.from(payload); // копия, чтобы XOR не портил оригинал
    unmaskPayload(payload, maskKey);
  }

  return {
    frame: { fin, opcode, masked, payload },
    rest
  };
}

// Управляющие кадры
function encodeCloseFrame(code = 1000) {
  const payload = Buffer.alloc(2);
  payload.writeUInt16BE(code, 0);

  const header = Buffer.alloc(2);
  header[0] = 0x88; // FIN=1 opcode=8 close
  header[1] = payload.length;
  return Buffer.concat([header, payload]);
}

function encodePongFrame(payload = Buffer.alloc(0)) {
  const len = payload.length;
  const header = Buffer.alloc(2);
  header[0] = 0x8a; // FIN=1 opcode=10 pong
  header[1] = len;
  return Buffer.concat([header, payload]);
}

function encodePingFrame(payload = Buffer.alloc(0)) {
  const len = payload.length;
  const header = Buffer.alloc(2);
  header[0] = 0x89; // FIN=1 opcode=9 ping
  header[1] = len;
  return Buffer.concat([header, payload]);
}

function broadcastText(str) {
  const frame = encodeTextFrame(str);
  for (const sock of clients) {
    sock.write(frame);
  }
}

// --- HTTP server + upgrade ---
const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }
  res.writeHead(404);
  res.end();
});

server.on("upgrade", (req, socket) => {
  // 1) принимаем только нужный путь
  if (req.url !== "/ws") {
    socket.destroy();
    return;
  }

  // 2) проверяем нужные заголовки
  const upgrade = (req.headers.upgrade || "").toLowerCase();
  const key = req.headers["sec-websocket-key"];
  const version = req.headers["sec-websocket-version"];

  if (upgrade !== "websocket" || !key || version !== "13") {
    socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
    socket.destroy();
    return;
  }

  // (опционально) origin-check: важно если не хочешь, чтобы любой сайт мог подключаться
  // const origin = req.headers.origin;
  // if (origin !== "https://<username>.github.io") { socket.destroy(); return; }

  // 3) считаем accept и отвечаем 101
  const accept = makeAcceptValue(key);

  const responseHeaders =
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${accept}\r\n` +
    "\r\n";

  socket.write(responseHeaders);

  // 4) теперь сокет = WebSocket соединение
  clients.add(socket);

  // буфер для “склейки” TCP кусков
  let buf = Buffer.alloc(0);

  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);

    while (true) {
      const decoded = tryDecodeFrame(buf);
      if (!decoded) break;

      const { frame, rest } = decoded;
      buf = rest;

      // opcode: 1=text, 8=close, 9=ping, 10=pong
      if (frame.opcode === 0x8) {
        socket.write(encodeCloseFrame(1000));
        socket.end();
        return;
      }

      if (frame.opcode === 0x9) {
        // ping -> pong с тем же payload
        socket.write(encodePongFrame(frame.payload));
        continue;
      }

      if (frame.opcode === 0x1) {
        // text
        const text = frame.payload.toString("utf8");
        // примитивный broadcast
        broadcastText(text);
        continue;
      }

      // игнор других opcodes в этом минимальном чате
    }
  });

  socket.on("close", () => clients.delete(socket));
  socket.on("end", () => clients.delete(socket));
  socket.on("error", () => clients.delete(socket));

  // keepalive: раз в 30 сек ping (не обязательно, но полезно)
  const t = setInterval(() => {
    if (socket.destroyed) {
      clearInterval(t);
      return;
    }
    socket.write(encodePingFrame());
  }, 30000);

  socket.on("close", () => clearInterval(t));
});

server.listen(PORT, () => {
  console.log(`Listening on ${PORT} (ws path: /ws)`);
});
