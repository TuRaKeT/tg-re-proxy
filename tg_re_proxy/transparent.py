from __future__ import annotations

import asyncio
import logging
import socket
import sys
import struct

from typing import Optional, Set, Tuple

from .utils import *
from ._aes import Cipher, algorithms, modes
from .balancer import balancer
from .config import load_from_env, proxy_config, CFPROXY_DEFAULT_DOMAINS
from .bridge import (
    MsgSplitter,
    do_fallback,
    bridge_ws_reencrypt,
    build_crypto_ctx,
    generate_relay_init,
    reset_tcp_backoff,
)
from .raw_websocket import set_sock_opts
from .pool import ws_pool, cf_worker_pool
from .cf_h2 import CfH2Pool
from .event_loop import install_self_pipe_guard
from .socks_relay import relay_via_socks


SOL_IP = 0
SO_ORIGINAL_DST = 80

LISTENER_CHECK_INTERVAL = 5.0
LISTENER_RESTART_DELAY = 1.0
cf_h2_pool: Optional[CfH2Pool] = None


def try_handshake(handshake: bytes) -> Optional[Tuple[int, bool, bytes, bytes]]:
    """
    Parse a TRANSPARENT (secretless) Obfuscated2 handshake.

    The intercepted client is a real Telegram app connecting directly, so the
    AES key is the raw prekey (no SHA256(prekey + secret)). Returns
    (dc_id, is_media, proto_tag, client_prekey_iv).
    """
    if len(handshake) < HANDSHAKE_LEN:
        return None

    prekey = handshake[SKIP_LEN : SKIP_LEN + PREKEY_LEN]
    iv = handshake[SKIP_LEN + PREKEY_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]

    decryptor = Cipher(algorithms.AES(prekey), modes.CTR(iv)).encryptor()
    decrypted = decryptor.update(handshake)

    proto_tag = decrypted[PROTO_TAG_POS : PROTO_TAG_POS + 4]
    if proto_tag not in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
        return None

    dc_idx = int.from_bytes(
        decrypted[DC_IDX_POS : DC_IDX_POS + 2], "little", signed=True
    )

    dc_id = abs(dc_idx)
    is_media = dc_idx < 0

    return (
        dc_id,
        is_media,
        proto_tag,
        handshake[SKIP_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN],
    )


def get_original_dst(writer) -> Optional[Tuple[str, int]]:
    """Original destination of a redirected connection (nft/ufw REDIRECT)."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return None
    try:
        dst = sock.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        port, ip = struct.unpack("!H4s", dst[2:8])
        return socket.inet_ntoa(ip), port
    except Exception:
        return None


async def _handle_client(reader, writer):
    label = "connection"

    set_sock_opts(writer.transport, proxy_config.buffer_size)

    try:
        try:
            handshake = await asyncio.wait_for(
                reader.readexactly(HANDSHAKE_LEN), timeout=10
            )
        except asyncio.IncompleteReadError:
            return

        orig_dst = get_original_dst(writer)
        dest_ip, dest_port = orig_dst if orig_dst else ("unknown", 0)

        result = try_handshake(handshake)
        if result is None:
            if orig_dst:
                # Non-MTProto traffic to a Telegram IP (Bot API TLS etc.)
                # cannot be re-encrypted here; hand the raw stream to the
                # local Xray socks inbound so its SNI-based routing
                # (VPN_DOMAINS -> telegram.org) still applies.
                if await relay_via_socks(
                    reader, writer, dest_ip, dest_port, label, first_data=handshake
                ):
                    return
            return
        dc, is_media, proto_tag, client_prekey_iv = result

        is_test_dc = proxy_config.force_test_dc or dc >= 10000
        if dc >= 10000:
            dc -= 10000

        if proto_tag == PROTO_TAG_ABRIDGED:
            proto_int = PROTO_ABRIDGED_INT
        elif proto_tag == PROTO_TAG_INTERMEDIATE:
            proto_int = PROTO_INTERMEDIATE_INT
        else:
            proto_int = PROTO_PADDED_INTERMEDIATE_INT

        dc_idx = -dc if is_media else dc

        relay_init = generate_relay_init(proto_tag, dc_idx)
        ctx = build_crypto_ctx(client_prekey_iv, relay_init)

        media_tag = " media" if is_media else ""
        # DC203 uses the DC2 WS hostname, but remains DC203 in MTProto.
        # Keep the requested DC in relay_init and all fallback destinations.
        ws_dc = 2 if dc == 203 else dc
        ws = await ws_pool.get(ws_dc, is_media, is_test_dc=is_test_dc)
        if ws is None:
            splitter_fb = None
            try:
                splitter_fb = MsgSplitter(proto_int)
            except Exception:
                pass
            ok = await do_fallback(
                reader,
                writer,
                relay_init,
                label,
                dc,
                is_test_dc,
                is_media,
                media_tag,
                ctx,
                splitter=splitter_fb,
                h2_pool=cf_h2_pool,
                proto_tag=proto_tag,
                fallback_dst_override=(dest_ip if orig_dst else None),
            )
            if ok:
                pass
            else:
                pass
            return

        splitter = None
        try:
            splitter = MsgSplitter(proto_int)
        except Exception:
            pass

        await ws.send(relay_init)

        await bridge_ws_reencrypt(
            reader, writer, ws, label, ctx, dc=dc, is_media=is_media, splitter=splitter
        )

    except asyncio.TimeoutError:
        pass
    except asyncio.IncompleteReadError:
        pass
    except asyncio.CancelledError:
        pass
    except ConnectionResetError:
        pass
    except OSError:
        pass
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except BaseException:
            pass


_client_tasks: Set[asyncio.Task] = set()


async def _run(stop_event: Optional[asyncio.Event] = None):
    global cf_h2_pool
    install_self_pipe_guard(asyncio.get_running_loop())

    reset_tcp_backoff()
    ws_pool.reset()
    cf_worker_pool.reset()
    _client_tasks.clear()
    cf_h2_pool = CfH2Pool() if proxy_config.h2_enabled else None

    user_cf_domains = proxy_config.cfproxy_user_domains
    balancer.update_domains_list(user_cf_domains or CFPROXY_DEFAULT_DOMAINS)

    stopping = False

    def client_cb(r, w):
        if stopping:
            w.close()
            return
        task = asyncio.create_task(_handle_client(r, w))
        _client_tasks.add(task)
        task.add_done_callback(_client_tasks.discard)

    server = await asyncio.start_server(
        client_cb, proxy_config.host, proxy_config.port, reuse_port=True
    )

    for sock in server.sockets:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

    await ws_pool.warmup()
    await cf_worker_pool.warmup()

    async def _quiet_cancel(t):
        if not t.done():
            t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass

    serve_task = stop_task = watchdog_task = None
    try:
        while True:
            serve_task = asyncio.create_task(server.serve_forever())
            stop_task = asyncio.create_task(stop_event.wait()) if stop_event else None

            async def _listener_watchdog():
                while True:
                    await asyncio.sleep(LISTENER_CHECK_INTERVAL)
                    socks = server.sockets
                    if not socks or all(s.fileno() < 0 for s in socks):
                        return

            watchdog_task = asyncio.create_task(_listener_watchdog())
            waiters = [serve_task, watchdog_task]
            if stop_task is not None:
                waiters.append(stop_task)

            done, _ = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)

            if stop_task is not None and stop_task in done:
                break

            await _quiet_cancel(watchdog_task)
            await _quiet_cancel(serve_task)
            if stop_task is not None:
                await _quiet_cancel(stop_task)
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass
            await asyncio.sleep(LISTENER_RESTART_DELAY)
            try:
                server = await asyncio.start_server(
                    client_cb, proxy_config.host, proxy_config.port, reuse_port=True
                )
            except OSError:
                break
            for sock in server.sockets:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except (OSError, AttributeError):
                    pass
    finally:
        stopping = True
        server.close()
        clients = list(_client_tasks)
        for task in clients:
            task.cancel()
        await asyncio.gather(*clients, return_exceptions=True)
        for task in (serve_task, watchdog_task, stop_task):
            if task is not None:
                await _quiet_cancel(task)
        await server.wait_closed()
        await ws_pool.close()
        await cf_worker_pool.close()
        if cf_h2_pool is not None:
            await cf_h2_pool.close()
            cf_h2_pool = None
        try:
            server.close()
            await server.wait_closed()
        except Exception:
            pass


def run_proxy(stop_event: Optional[asyncio.Event] = None):
    logging.disable(logging.CRITICAL)
    asyncio.run(_run(stop_event))


def main():
    # Dependencies must not emit peer addresses, request URLs or tracebacks.
    logging.disable(logging.CRITICAL)
    try:
        load_from_env()
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    except Exception:
        print(
            "Unable to start proxy; check the configuration and listener.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
