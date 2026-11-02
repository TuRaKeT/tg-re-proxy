import asyncio
import socket
import struct

from .bridge import bridge_tcp_plain
from .config import proxy_config


async def relay_via_socks(
    reader, writer, dst_ip: str, dst_port: int, label: str, first_data: bytes = b""
) -> bool:
    """Relay non-MTProto bytes to an explicitly configured SOCKS5 server.

    This path is disabled unless TG_RE_PROXY_SOCKS is configured. The proxy
    forwards bytes without recording the connection or inspecting its content.
    """
    if not proxy_config.socks_relay:
        return False
    shost, sport = proxy_config.socks_relay
    try:
        sr, sw = await asyncio.wait_for(asyncio.open_connection(shost, sport), 5)

        sw.write(b"\x05\x01\x00")  # VER=5, one method: NO-AUTH
        await sw.drain()
        resp = await asyncio.wait_for(sr.readexactly(2), 5)
        if resp[0] != 5 or resp[1] != 0:
            raise ConnectionError(f"method negotiation failed: {resp.hex()}")

        sw.write(
            b"\x05\x01\x00\x01" + socket.inet_aton(dst_ip) + struct.pack(">H", dst_port)
        )
        await sw.drain()
        head = await asyncio.wait_for(sr.readexactly(4), 10)
        if head[1] != 0:
            raise ConnectionError(f"CONNECT rejected, rep={head[1]}")
        atyp = head[3]
        if atyp == 1:
            await sr.readexactly(6)
        elif atyp == 3:
            n = (await sr.readexactly(1))[0]
            await sr.readexactly(n + 2)
        elif atyp == 4:
            await sr.readexactly(18)
        else:
            raise ConnectionError(f"bad ATYP {atyp}")
    except Exception:
        return False

    if first_data:
        sw.write(first_data)
        await sw.drain()
    await bridge_tcp_plain(reader, writer, sr, sw, label)
    return True
