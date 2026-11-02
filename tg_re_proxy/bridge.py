import asyncio
import os
import struct
import time

from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode

from .utils import *
from ._aes import Cipher, algorithms, modes
from .balancer import balancer
from .config import proxy_config
from .raw_websocket import RawWebSocket
from .pool import cf_worker_pool
from .cf_h2 import bridge_h2


_st_I_le = struct.Struct("<I")

TCP_BACKOFF_INITIAL = 30.0
TCP_BACKOFF_MAX = 3600.0
_tcp_failures: Dict[Tuple[str, int], int] = {}
_tcp_retry_after: Dict[Tuple[str, int], float] = {}
_tcp_connecting: Set[Tuple[str, int]] = set()


def reset_tcp_backoff() -> None:
    _tcp_failures.clear()
    _tcp_retry_after.clear()
    _tcp_connecting.clear()


class CryptoCtx:
    __slots__ = ("clt_dec", "clt_enc", "tg_enc", "tg_dec")

    def __init__(self, clt_dec, clt_enc, tg_enc, tg_dec):
        self.clt_dec = clt_dec  # decrypt from client
        self.clt_enc = clt_enc  # encrypt to client
        self.tg_enc = tg_enc  # encrypt to telegram
        self.tg_dec = tg_dec  # decrypt from telegram


def generate_relay_init(proto_tag: bytes, dc_idx: int) -> bytes:
    """
    Fresh Obfuscated2 handshake for the upstream (relay) side. Keys/iv are raw
    (no proxy secret), matching how Telegram's WS gateways expect a direct
    obfuscated connection.
    """
    while True:
        rnd = bytearray(os.urandom(HANDSHAKE_LEN))
        if rnd[0] in RESERVED_FIRST_BYTES:
            continue
        if bytes(rnd[:4]) in RESERVED_STARTS:
            continue
        if rnd[4:8] == RESERVED_CONTINUE:
            continue
        break

    rnd_bytes = bytes(rnd)

    enc_key = rnd_bytes[SKIP_LEN : SKIP_LEN + PREKEY_LEN]
    enc_iv = rnd_bytes[SKIP_LEN + PREKEY_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]

    encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()

    dc_bytes = struct.pack("<h", dc_idx)
    tail_plain = proto_tag + dc_bytes + os.urandom(2)

    encrypted_full = encryptor.update(rnd_bytes)
    keystream_tail = bytes(encrypted_full[i] ^ rnd_bytes[i] for i in range(56, 64))
    encrypted_tail = bytes(tail_plain[i] ^ keystream_tail[i] for i in range(8))

    result = bytearray(rnd_bytes)
    result[PROTO_TAG_POS:HANDSHAKE_LEN] = encrypted_tail
    return bytes(result)


def build_crypto_ctx(client_prekey_iv: bytes, relay_init: bytes) -> CryptoCtx:
    """
    Build the re-encryption context for a TRANSPARENT (secretless) client.

    The intercepted client is a real Telegram app connecting directly, so its
    handshake has NO proxy secret: the AES key is the raw prekey (not
    SHA256(prekey + secret)). The relay side uses a fresh generated init and
    also uses raw keys.
    """
    # Client side: decrypt data FROM the client, encrypt data TO the client.
    clt_dec_key = client_prekey_iv[:PREKEY_LEN]
    clt_dec_iv = client_prekey_iv[PREKEY_LEN:]

    clt_enc_prekey_iv = client_prekey_iv[::-1]
    clt_enc_key = clt_enc_prekey_iv[:PREKEY_LEN]
    clt_enc_iv = clt_enc_prekey_iv[PREKEY_LEN:]

    clt_decryptor = Cipher(
        algorithms.AES(clt_dec_key), modes.CTR(clt_dec_iv)
    ).encryptor()
    # fast-forward client decryptor past the 64-byte init
    clt_decryptor.update(ZERO_64)
    clt_encryptor = Cipher(
        algorithms.AES(clt_enc_key), modes.CTR(clt_enc_iv)
    ).encryptor()

    # relay side: standard obfuscation (no secret hash, raw key)
    relay_enc_key = relay_init[SKIP_LEN : SKIP_LEN + PREKEY_LEN]
    relay_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]

    relay_dec_prekey_iv = relay_init[SKIP_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN][::-1]
    relay_dec_key = relay_dec_prekey_iv[:KEY_LEN]
    relay_dec_iv = relay_dec_prekey_iv[KEY_LEN:]

    tg_encryptor = Cipher(
        algorithms.AES(relay_enc_key), modes.CTR(relay_enc_iv)
    ).encryptor()
    tg_decryptor = Cipher(
        algorithms.AES(relay_dec_key), modes.CTR(relay_dec_iv)
    ).encryptor()

    tg_encryptor.update(ZERO_64)

    return CryptoCtx(clt_decryptor, clt_encryptor, tg_encryptor, tg_decryptor)


class MsgSplitter:
    """
    Splits TCP stream data into individual MTProto transport packets
    so each can be sent as a separate WS frame.
    """

    __slots__ = ("_proto", "_cipher_buf", "_plain_buf", "_disabled")

    def __init__(self, proto_int: int):
        self._proto = proto_int
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes, plain: bytes) -> List[bytes]:
        if not chunk:
            return []
        if self._disabled:
            return [chunk]

        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(plain)

        parts = []
        offset = 0
        buf_len = len(self._cipher_buf)
        while offset < buf_len:
            packet_len = self._next_packet_len(offset, buf_len - offset)
            if packet_len is None:
                break
            if packet_len <= 0:
                parts.append(
                    bytes(self._cipher_buf)
                    if offset == 0
                    else bytes(self._cipher_buf[offset:])
                )
                offset = buf_len
                self._disabled = True
                break
            if offset == 0 and packet_len == buf_len:
                parts.append(bytes(self._cipher_buf))
            else:
                parts.append(bytes(self._cipher_buf[offset : offset + packet_len]))
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
        if self._proto in (PROTO_INTERMEDIATE_INT, PROTO_PADDED_INTERMEDIATE_INT):
            return self._next_intermediate_len(offset, avail)
        return 0

    def _next_abridged_len(self, offset: int, avail: int) -> Optional[int]:
        first = self._plain_buf[offset]
        if first in (0x7F, 0xFF):
            if avail < 4:
                return None
            payload_len = (
                int.from_bytes(self._plain_buf[offset + 1 : offset + 4], "little") * 4
            )
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


async def do_fallback(
    reader,
    writer,
    relay_init,
    label,
    dc: int,
    is_test_dc: bool,
    is_media: bool,
    media_tag: str,
    ctx: CryptoCtx,
    splitter=None,
    *,
    h2_pool=None,
    proto_tag=None,
    fallback_dst_override: Optional[str] = None,
):
    ip_table = DC_TEST_IPS if is_test_dc else DC_DEFAULT_IPS
    fallback_dst = fallback_dst_override or ip_table.get(dc)
    use_cf = proxy_config.fallback_cfproxy and not is_test_dc
    worker_domains = proxy_config.cfproxy_worker_domains

    methods: List[str] = []

    if is_media:
        # Media prefers the CF H2 multiplexer (the whole point of the cf
        # fallback for media): a personal CF worker dialing the raw media
        # DC IP returns a stub transport error (~89B) and the download dies.
        if use_cf:
            methods.append("cf")
        if worker_domains and fallback_dst:
            methods.append("cf_worker")
    else:
        if worker_domains and fallback_dst:
            methods.append("cf_worker")
        if use_cf:
            methods.append("cf")
    if fallback_dst:
        methods.append("tcp")

    for method in methods:
        if method == "cf_worker" and fallback_dst:
            ok = await _cfproxy_worker_fallback(
                reader,
                writer,
                relay_init,
                label,
                ctx,
                dc=dc,
                is_test_dc=is_test_dc,
                is_media=is_media,
                fallback_dst=fallback_dst,
                splitter=splitter,
            )
            if ok:
                return True
        elif method == "cf":
            if is_media and h2_pool is not None and proto_tag is not None:
                channel = await h2_pool.open(dc, label)
                if channel is not None:
                    await bridge_h2(reader, writer, channel, ctx, proto_tag)
                    return True
            ok = await _cfproxy_fallback(
                reader,
                writer,
                relay_init,
                label,
                ctx,
                dc=dc,
                is_media=is_media,
                splitter=splitter,
            )
            if ok:
                return True
        elif method == "tcp" and fallback_dst:
            ok = await _tcp_fallback(
                reader, writer, fallback_dst, 443, relay_init, label, ctx
            )
            if ok:
                return True
    return False


async def _cfproxy_worker_fallback(
    reader,
    writer,
    relay_init,
    label,
    ctx: CryptoCtx,
    dc: int,
    is_test_dc: bool,
    is_media: bool,
    fallback_dst: str,
    splitter=None,
):
    worker_domains = proxy_config.cfproxy_worker_domains
    if not worker_domains:
        return False

    pooled = (
        None
        if is_test_dc
        else await cf_worker_pool.get(dc, fallback_dst, worker_domains)
    )
    if pooled:
        ws, worker_domain = pooled
    else:
        query = urlencode(
            {
                "dst": fallback_dst,
                "dc": str(dc),
            }
        )
        path = f"/apiws?{query}"

        ws = None
        for worker_domain in cf_worker_pool.available_domains(worker_domains):
            try:
                ws = await RawWebSocket.connect(
                    worker_domain,
                    worker_domain,
                    timeout=10.0,
                    path=path,
                    secure=not proxy_config.disable_secure,
                )
                break
            except Exception as exc:
                cf_worker_pool.report_failure(worker_domain, exc)
                continue

        if ws is None:
            return False

    await ws.send(relay_init)
    await bridge_ws_reencrypt(
        reader, writer, ws, label, ctx, dc=dc, is_media=is_media, splitter=None
    )
    return True


async def _cfproxy_fallback(
    reader,
    writer,
    relay_init,
    label,
    ctx: CryptoCtx,
    dc: int,
    is_media: bool,
    splitter=None,
):
    ws = None
    chosen_domain = None

    for base_domain in balancer.get_domains_for_dc(dc):
        # Media clients ride the -1 (media) WS gateways when available;
        # fall back to the main gateway subdomain otherwise.
        ws_dc = 2 if dc == 203 else dc
        candidates = (
            [f"kws{ws_dc}-1.{base_domain}", f"kws{ws_dc}.{base_domain}"]
            if is_media
            else [f"kws{ws_dc}.{base_domain}"]
        )
        for domain in candidates:
            try:
                ws = await RawWebSocket.connect(
                    domain, domain, timeout=10.0, secure=not proxy_config.disable_secure
                )
                chosen_domain = base_domain
                break
            except Exception:
                pass
        if ws is not None:
            break

    if ws is None:
        return False

    if chosen_domain:
        balancer.update_domain_for_dc(dc, chosen_domain)

    await ws.send(relay_init)
    await bridge_ws_reencrypt(
        reader, writer, ws, label, ctx, dc=dc, is_media=is_media, splitter=splitter
    )
    return True


async def _tcp_fallback(reader, writer, dst, port, relay_init, label, ctx: CryptoCtx):
    key = (dst, port)
    if key in _tcp_connecting or time.monotonic() < _tcp_retry_after.get(key, 0):
        return False

    _tcp_connecting.add(key)
    rw = None
    try:
        try:
            rr, rw = await asyncio.wait_for(
                asyncio.open_connection(dst, port), timeout=10
            )
            rw.write(relay_init)
            await rw.drain()
        except Exception:
            failures = _tcp_failures.get(key, 0) + 1
            _tcp_failures[key] = failures
            delay = min(
                TCP_BACKOFF_INITIAL * 2 ** min(failures - 1, 7), TCP_BACKOFF_MAX
            )
            _tcp_retry_after[key] = time.monotonic() + delay
            return False
        finally:
            _tcp_connecting.discard(key)

        _tcp_failures.pop(key, None)
        _tcp_retry_after.pop(key, None)
        await _bridge_tcp_reencrypt(reader, writer, rr, rw, label, ctx)
        return True
    finally:
        if rw is not None:
            rw.close()
            try:
                await rw.wait_closed()
            except (OSError, ConnectionError):
                pass


async def bridge_ws_reencrypt(
    reader,
    writer,
    ws: RawWebSocket,
    label,
    ctx: CryptoCtx,
    dc=None,
    is_media=False,
    splitter: Optional[MsgSplitter] = None,
):
    """
    Bidirectional TCP(client) <-> WS(telegram) with re-encryption.
    client ciphertext → decrypt(clt_key) → encrypt(tg_key) → WS
    WS data → decrypt(tg_key) → encrypt(clt_key) → client TCP
    """

    async def tcp_to_ws():
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    if splitter:
                        tail = splitter.flush()
                        if tail:
                            await ws.send(tail[0])
                    break
                plain = ctx.clt_dec.update(chunk)
                chunk = ctx.tg_enc.update(plain)
                if splitter:
                    parts = splitter.split(chunk, plain)
                    if not parts:
                        continue
                    if len(parts) > 1:
                        await ws.send_batch(parts)
                    else:
                        await ws.send(parts[0])
                else:
                    await ws.send(chunk)
        except asyncio.CancelledError:
            return
        except (ConnectionError, OSError):
            pass
        except Exception:
            pass

    async def ws_to_tcp():
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    break
                plain = ctx.tg_dec.update(data)
                data = ctx.clt_enc.update(plain)
                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            return
        except (ConnectionError, OSError):
            pass
        except asyncio.IncompleteReadError:
            pass
        except Exception:
            pass

    tasks = [asyncio.create_task(tcp_to_ws()), asyncio.create_task(ws_to_tcp())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
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


async def _bridge_tcp_reencrypt(
    reader, writer, remote_reader, remote_writer, label, ctx: CryptoCtx
):
    """Bidirectional TCP <-> TCP with re-encryption."""

    async def forward(src, dst_w, is_up):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                if is_up:
                    plain = ctx.clt_dec.update(data)
                    data = ctx.tg_enc.update(plain)
                else:
                    plain = ctx.tg_dec.update(data)
                    data = ctx.clt_enc.update(plain)
                dst_w.write(data)
                await dst_w.drain()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    tasks = [
        asyncio.create_task(forward(reader, remote_writer, True)),
        asyncio.create_task(forward(remote_reader, writer, False)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        for w in (writer, remote_writer):
            try:
                w.close()
                await w.wait_closed()
            except BaseException:
                pass


async def bridge_tcp_plain(reader, writer, remote_reader, remote_writer, label):
    """Bidirectional raw TCP relay (no re-encryption)."""

    async def forward(src, dst_w):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst_w.write(data)
                await dst_w.drain()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    tasks = [
        asyncio.create_task(forward(reader, remote_writer)),
        asyncio.create_task(forward(remote_reader, writer)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        for w in (writer, remote_writer):
            try:
                w.close()
                await w.wait_closed()
            except BaseException:
                pass
