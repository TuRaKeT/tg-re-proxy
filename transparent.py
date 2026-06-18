import os
import sys
import struct
import socket
import logging
import asyncio
import ssl
import base64
from typing import Optional, Tuple, List

# --- AES CTR SHIM (from proxy._aes) ---
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    import ctypes
    import ctypes.util

    def _load_libcrypto():
        name = ctypes.util.find_library("crypto")
        candidates = []
        if name:
            candidates.append(name)
        candidates += [
            "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so.1.0.0",
            "libcrypto.so", "/opt/lib/libcrypto.so",
            "/opt/lib/libcrypto.so.1.1", "/opt/lib/libcrypto.so.3",
        ]
        last_err = None
        for c in candidates:
            try:
                return ctypes.CDLL(c)
            except OSError as e:
                last_err = e
        raise RuntimeError(
            "libcrypto not found; last error: %r" % last_err
        )

    _libcrypto = _load_libcrypto()

    _libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    _libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    _libcrypto.EVP_aes_128_ctr.restype = ctypes.c_void_p
    _libcrypto.EVP_aes_192_ctr.restype = ctypes.c_void_p
    _libcrypto.EVP_aes_256_ctr.restype = ctypes.c_void_p
    _libcrypto.EVP_EncryptInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_char_p,
    ]
    _libcrypto.EVP_EncryptInit_ex.restype = ctypes.c_int
    _libcrypto.EVP_EncryptUpdate.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p, ctypes.c_int,
    ]
    _libcrypto.EVP_EncryptUpdate.restype = ctypes.c_int

    _EVP_BY_KEY = {
        16: _libcrypto.EVP_aes_128_ctr,
        24: _libcrypto.EVP_aes_192_ctr,
        32: _libcrypto.EVP_aes_256_ctr,
    }

    class algorithms:
        class AES:
            __slots__ = ("key",)
            def __init__(self, key: bytes):
                if len(key) not in _EVP_BY_KEY:
                    raise ValueError("AES key must be 16/24/32 bytes")
                self.key = bytes(key)

    class modes:
        class CTR:
            __slots__ = ("iv",)
            def __init__(self, iv: bytes):
                if len(iv) != 16:
                    raise ValueError("CTR IV must be 16 bytes")
                self.iv = bytes(iv)

    class _CtrStream:
        __slots__ = ("_ctx",)
        def __init__(self, key: bytes, iv: bytes):
            ctx = _libcrypto.EVP_CIPHER_CTX_new()
            if not ctx:
                raise RuntimeError("EVP_CIPHER_CTX_new failed")
            self._ctx = ctx
            evp = _EVP_BY_KEY[len(key)]()
            if _libcrypto.EVP_EncryptInit_ex(ctx, evp, None, key, iv) != 1:
                _libcrypto.EVP_CIPHER_CTX_free(ctx)
                self._ctx = None
                raise RuntimeError("EVP_EncryptInit_ex failed")

        def update(self, data: bytes) -> bytes:
            if not data:
                return b""
            outlen = ctypes.c_int(0)
            buf = ctypes.create_string_buffer(len(data) + 16)
            if _libcrypto.EVP_EncryptUpdate(
                self._ctx, buf, ctypes.byref(outlen), bytes(data), len(data)
            ) != 1:
                raise RuntimeError("EVP_EncryptUpdate failed")
            return buf.raw[:outlen.value]

        def __del__(self):
            ctx = getattr(self, "_ctx", None)
            if ctx:
                _libcrypto.EVP_CIPHER_CTX_free(ctx)
                self._ctx = None

    class Cipher:
        __slots__ = ("_key", "_iv")
        def __init__(self, algorithm, mode):
            if not isinstance(algorithm, algorithms.AES):
                raise TypeError("only AES is supported")
            if not isinstance(mode, modes.CTR):
                raise TypeError("only CTR mode is supported")
            self._key = algorithm.key
            self._iv = mode.iv

        def encryptor(self) -> _CtrStream:
            return _CtrStream(self._key, self._iv)
        decryptor = encryptor

# --- CONSTANTS ---
ZERO_64 = b'\x00' * 64
PROTO_TAG_ABRIDGED = b'\xef\xef\xef\xef'
PROTO_TAG_INTERMEDIATE = b'\xee\xee\xee\xee'
PROTO_TAG_SECURE = b'\xdd\xdd\xdd\xdd'

PROTO_ABRIDGED_INT = 0xEFEFEFEF
PROTO_INTERMEDIATE_INT = 0xEEEEEEEE
PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD

SOL_IP = 0
SO_ORIGINAL_DST = 80
WS_FALLBACK_IP = '149.154.167.220'
CF_WORKER_DOMAIN = os.environ.get('TG_RE_PROXY_CF_WORKER', '')

# --- MSGSPLITTER ---
_st_I_le = struct.Struct('<I')

class MsgSplitter:
    """
    Splits TCP stream data into individual MTProto transport packets
    so each can be sent as a separate WS frame.
    """
    __slots__ = ('_dec', '_proto', '_cipher_buf', '_plain_buf', '_disabled')

    def __init__(self, relay_init: bytes, proto_int: int):
        cipher = Cipher(algorithms.AES(relay_init[8:40]),
                        modes.CTR(relay_init[40:56]))
        self._dec = cipher.encryptor()
        self._dec.update(ZERO_64)
        self._proto = proto_int
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes) -> List[bytes]:
        if not chunk:
            return []
        if self._disabled:
            return [chunk]

        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(self._dec.update(chunk))

        parts = []
        offset = 0
        buf_len = len(self._cipher_buf)
        while offset < buf_len:
            packet_len = self._next_packet_len(offset, buf_len - offset)
            if packet_len is None:
                break
            if packet_len <= 0:
                parts.append(bytes(self._cipher_buf[offset:]))
                offset = buf_len
                self._disabled = True
                break
            parts.append(bytes(self._cipher_buf[offset:offset + packet_len]))
            offset += packet_len

        if offset:
            del self._cipher_buf[:offset]
            del self._plain_buf[:offset]
        return parts

    def flush(self) -> List[bytes]:
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _next_packet_len(self, offset: int, avail: int) -> Optional[int]:
        if avail <= 0:
            return None
        if self._proto == PROTO_ABRIDGED_INT:
            return self._next_abridged_len(offset, avail)
        if self._proto in (PROTO_INTERMEDIATE_INT,
                           PROTO_PADDED_INTERMEDIATE_INT):
            return self._next_intermediate_len(offset, avail)
        return 0

    def _next_abridged_len(self, offset: int, avail: int) -> Optional[int]:
        first = self._plain_buf[offset]
        if first in (0x7F, 0xFF):
            if avail < 4:
                return None
            payload_len = int.from_bytes(
                self._plain_buf[offset + 1:offset + 4], 'little') * 4
            header_len = 4
        else:
            payload_len = (first & 0x7F) * 4
            header_len = 1
        if payload_len <= 0:
            return 0
        packet_len = header_len + payload_len
        if avail < packet_len:
            return None
        return packet_len

    def _next_intermediate_len(self, offset: int, avail: int) -> Optional[int]:
        if avail < 4:
            return None
        payload_len = _st_I_le.unpack_from(self._plain_buf, offset)[0] & 0x7FFFFFFF
        if payload_len <= 0:
            return 0
        packet_len = 4 + payload_len
        if avail < packet_len:
            return None
        return packet_len

# --- RAW WEBSOCKET ---
_st_BB = struct.Struct('>BB')
_st_BBH = struct.Struct('>BBH')
_st_BBQ = struct.Struct('>BBQ')
_st_BB4s = struct.Struct('>BB4s')
_st_BBH4s = struct.Struct('>BBH4s')
_st_BBQ4s = struct.Struct('>BBQ4s')
_st_H = struct.Struct('>H')
_st_Q = struct.Struct('>Q')

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str,
                 headers: Optional[dict] = None, location: Optional[str] = None):
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)

def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    mask_rep = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, 'big') ^
            int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')

def set_sock_opts(transport, buffer_size: int = 131072):
    sock = transport.get_extra_info('socket')
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
    except OSError:
        pass

class RawWebSocket:
    __slots__ = ('reader', 'writer', '_closed')

    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False

    @staticmethod
    async def connect(host: str, domain: str, timeout: float = 10.0,
                      path: str = '/apiws') -> 'RawWebSocket':
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=_ssl_ctx,
                                    server_hostname=domain),
            timeout=min(timeout, 10))
        
        set_sock_opts(writer.transport)

        ws_key = base64.b64encode(os.urandom(16)).decode()

        req = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {domain}\r\n'
            f'Upgrade: websocket\r\n'
            f'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {ws_key}\r\n'
            f'Sec-WebSocket-Version: 13\r\n'
            f'Sec-WebSocket-Protocol: binary\r\n'
            f'\r\n'
        )
        writer.write(req.encode())
        await writer.drain()

        response_lines: list[str] = []
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(),
                                              timeout=timeout)
                if line in (b'\r\n', b'\n', b''):
                    break
                response_lines.append(
                    line.decode('utf-8', errors='replace').strip())
        except asyncio.TimeoutError:
            writer.close()
            raise

        if not response_lines:
            writer.close()
            raise WsHandshakeError(0, 'empty response')

        first_line = response_lines[0]
        parts = first_line.split(' ', 2)
        try:
            status_code = int(parts[1]) if len(parts) >= 2 else 0
        except ValueError:
            status_code = 0

        if status_code == 101:
            return RawWebSocket(reader, writer)

        headers: dict[str, str] = {}
        for hl in response_lines[1:]:
            if ':' in hl:
                k, v = hl.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        writer.close()
        raise WsHandshakeError(status_code, first_line, headers,
                                location=headers.get('location'))

    async def send(self, data: bytes):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        frame = self._build_frame(self.OP_BINARY, data, mask=True)
        self.writer.write(frame)
        await self.writer.drain()

    async def send_batch(self, parts: List[bytes]):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        for part in parts:
            self.writer.write(
                self._build_frame(self.OP_BINARY, part, mask=True))
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            opcode, payload = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                try:
                    self.writer.write(self._build_frame(
                        self.OP_CLOSE,
                        payload[:2] if payload else b'', mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    self.writer.write(
                        self._build_frame(self.OP_PONG, payload, mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (0x1, 0x2):
                return payload
            continue
        return None

    async def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.write(
                self._build_frame(self.OP_CLOSE, b'', mask=True))
            await self.writer.drain()
        except Exception:
            pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    @staticmethod
    def _build_frame(opcode: int, data: bytes,
                     mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode
        if not mask:
            if length < 126:
                return _st_BB.pack(fb, length) + data
            if length < 65536:
                return _st_BBH.pack(fb, 126, length) + data
            return _st_BBQ.pack(fb, 127, length) + data
        mask_key = os.urandom(4)
        masked = _xor_mask(data, mask_key)
        if length < 126:
            return _st_BB4s.pack(fb, 0x80 | length, mask_key) + masked
        if length < 65536:
            return _st_BBH4s.pack(fb, 0x80 | 126, length, mask_key) + masked
        return _st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> Tuple[int, bytes]:
        hdr = await self.reader.readexactly(2)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = _st_H.unpack(await self.reader.readexactly(2))[0]
        elif length == 127:
            length = _st_Q.unpack(await self.reader.readexactly(8))[0]
        if hdr[1] & 0x80:
            mask_key = await self.reader.readexactly(4)
            payload = await self.reader.readexactly(length)
            return opcode, _xor_mask(payload, mask_key)
        payload = await self.reader.readexactly(length)
        return opcode, payload

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s  %(levelname)-5s  %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('tg-re-proxy')

# --- DETECTOR & SERVER LOGIC ---
def get_original_dst(writer) -> Optional[Tuple[str, int]]:
    sock = writer.get_extra_info('socket')
    if sock is None:
        return None
    try:
        dst = sock.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        port, ip = struct.unpack('!H4s', dst[2:8])
        return socket.inet_ntoa(ip), port
    except Exception as e:
        log.error("Failed to get original destination IP: %r", e)
        return None

def get_dc_by_ip(ip: str) -> int:
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return 2
        o1, o2, o3 = int(parts[0]), int(parts[1]), int(parts[2])
        if o1 == 149 and o2 == 154:
            if 164 <= o3 <= 167:
                if ip == '149.154.167.91':
                    return 4
                return 2
            elif 168 <= o3 <= 171:
                return 5
            elif 172 <= o3 <= 175:
                if ip == '149.154.175.100':
                    return 3
                return 1
        elif o1 == 91 and o2 == 108:
            if 4 <= o3 <= 7:
                return 1
            elif 8 <= o3 <= 11:
                return 2
            elif 12 <= o3 <= 15:
                return 4
            elif 16 <= o3 <= 19:
                return 5
            elif 56 <= o3 <= 59:
                return 5
        elif o1 == 194 and o2 == 221 and o3 == 250:
            return 2
        elif ip == '91.105.192.100':
            return 2
    except Exception as e:
        log.error("Error parsing IP %s: %r", ip, e)
    return 2

def try_direct_handshake(handshake: bytes) -> Optional[Tuple[int, bool, int]]:
    if len(handshake) < 64:
        return None
        
    dec_prekey_and_iv = handshake[8:56]
    dec_prekey = dec_prekey_and_iv[:32]
    dec_iv = dec_prekey_and_iv[32:]
    
    # Initialize decryptor using client's keys (no secret hash in direct connection)
    dec_iv_int = int.from_bytes(dec_iv, 'big')
    decryptor = Cipher(
        algorithms.AES(dec_prekey), modes.CTR(dec_iv_int.to_bytes(16, 'big'))
    ).encryptor()
    
    decrypted = decryptor.update(handshake)
    
    proto_tag = decrypted[56:60]
    if proto_tag == PROTO_TAG_ABRIDGED:
        proto_int = PROTO_ABRIDGED_INT
    elif proto_tag == PROTO_TAG_INTERMEDIATE:
        proto_int = PROTO_INTERMEDIATE_INT
    elif proto_tag == PROTO_TAG_SECURE:
        proto_int = PROTO_PADDED_INTERMEDIATE_INT
    else:
        return None
        
    dc_idx = int.from_bytes(decrypted[60:62], 'little', signed=True)
    dc_id = abs(dc_idx)
    is_media = dc_idx < 0
    
    return dc_id, is_media, proto_int

async def bridge_ws_plain(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ws: RawWebSocket, label: str, handshake: bytes, proto_int: int):
    log.info("[%s] Starting data bridge with MsgSplitter", label)
    
    splitter = MsgSplitter(handshake, proto_int)
    
    async def tcp_to_ws():
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    log.info("[%s] TCP closed (EOF)", label)
                    tail = splitter.flush()
                    if tail:
                        await ws.send(tail[0])
                    break
                
                parts = splitter.split(chunk)
                if not parts:
                    continue
                
                if len(parts) > 1:
                    await ws.send_batch(parts)
                else:
                    await ws.send(parts[0])
        except (asyncio.CancelledError, ConnectionError, OSError) as e:
            log.info("[%s] TCP -> WS ended: %r", label, e)
            return
        except Exception as e:
            log.error("[%s] TCP -> WS error: %r", label, e)

    async def ws_to_tcp():
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    log.info("[%s] WS closed (EOF)", label)
                    break
                writer.write(data)
                await writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError) as e:
            log.info("[%s] WS -> TCP ended: %r", label, e)
            return
        except Exception as e:
            log.error("[%s] WS -> TCP error: %r", label, e)

    tasks = [
        asyncio.create_task(tcp_to_ws()),
        asyncio.create_task(ws_to_tcp())
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        log.info("[%s] Ending data bridge", label)
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        try:
            await ws.close()
        except BaseException:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except BaseException:
            pass

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"
    
    # Read the 64-byte handshake from the client
    try:
        handshake = await asyncio.wait_for(reader.readexactly(64), timeout=10.0)
    except Exception as e:
        log.error("[%s] Failed to read handshake: %r", label, e)
        writer.close()
        return

    orig_dst = get_original_dst(writer)
    if orig_dst:
        dest_ip, dest_port = orig_dst
    else:
        dest_ip, dest_port = "unknown", 0

    parsed = try_direct_handshake(handshake)
    if parsed:
        dc, is_media, proto_int = parsed
        log.info("[%s] Intercepted direct connection: DC%d%s proto=0x%08X (Original Target: %s:%d)", 
                 label, dc, "m" if is_media else "", proto_int, dest_ip, dest_port)
    else:
        log.warning("[%s] Failed to parse client handshake. Slicing with IP fallbacks.", label)
        dc = get_dc_by_ip(dest_ip)
        is_media = False
        proto_int = PROTO_ABRIDGED_INT
    
    if dc in (2, 4):
        domain = f"kws{dc}.web.telegram.org"
        log.info("[%s] Connection to DC %d -> proxying directly via wss://%s/apiws",
                 label, dc, domain)
        try:
            ws = await RawWebSocket.connect(WS_FALLBACK_IP, domain, timeout=10.0)
        except Exception as e:
            log.error("[%s] Failed to connect to WebSocket %s via %s: %r", label, domain, WS_FALLBACK_IP, e)
            writer.close()
            return
    else:
        if not CF_WORKER_DOMAIN:
            log.error("[%s] Connection to DC %d requires a Cloudflare Worker proxy, but TG_RE_PROXY_CF_WORKER is not configured. Connection closed.", label, dc)
            writer.close()
            return
        path = f"/apiws?dst={dest_ip}&dc={dc}"
        log.info("[%s] Connection to DC %d -> proxying via CF Worker wss://%s%s",
                 label, dc, CF_WORKER_DOMAIN, path)
        try:
            ws = await RawWebSocket.connect(CF_WORKER_DOMAIN, CF_WORKER_DOMAIN, path=path, timeout=10.0)
        except Exception as e:
            log.error("[%s] Failed to connect to CF Worker %s: %r", label, CF_WORKER_DOMAIN, e)
            writer.close()
            return

    # Forward the handshake first
    try:
        await ws.send(handshake)
    except Exception as e:
        log.error("[%s] Failed to send handshake to WS: %r", label, e)
        await ws.close()
        writer.close()
        return

    await bridge_ws_plain(reader, writer, ws, label, handshake, proto_int)

async def main():
    port = int(os.environ.get('TG_RE_PROXY_PORT', '1444'))
    host = os.environ.get('TG_RE_PROXY_HOST', '0.0.0.0')
    
    server = await asyncio.start_server(handle_client, host, port, reuse_port=True)
    
    for sock in server.sockets:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass
            
    log.info("Telegram Transparent WS Proxy listening on %s:%d", host, port)
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
