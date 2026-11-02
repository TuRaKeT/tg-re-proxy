import os
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tg_re_proxy._aes import Cipher, algorithms, modes
from tg_re_proxy.bridge import MsgSplitter, build_crypto_ctx, generate_relay_init
from tg_re_proxy.transparent import try_handshake
from tg_re_proxy import transparent, bridge
from tg_re_proxy.utils import (
    PROTO_ABRIDGED_INT,
    PROTO_INTERMEDIATE_INT,
    PROTO_PADDED_INTERMEDIATE_INT,
    PROTO_TAG_ABRIDGED,
    PROTO_TAG_INTERMEDIATE,
    PROTO_TAG_SECURE,
)


def _obfuscator():
    """Cipher mimicking a fresh obfuscation keystream (64-byte init skip)."""
    enc = Cipher(algorithms.AES(os.urandom(32)), modes.CTR(os.urandom(16))).encryptor()
    enc.update(b"\x00" * 64)
    return enc


def _abridged(payload: bytes) -> bytes:
    words = len(payload) // 4
    if words < 0x7F:
        return bytes([words]) + payload
    return b"\x7f" + words.to_bytes(3, "little") + payload


def _intermediate(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


def _client_handshake(proto_tag: bytes, dc: int, is_media: bool = False) -> bytes:
    """Build a secretless Obfuscated2 handshake like a real Telegram client."""
    import struct

    while True:
        rnd = bytearray(os.urandom(64))
        if rnd[0] in {0xEF}:
            continue
        if bytes(rnd[:4]) in {
            b"\x48\x45\x41\x44",
            b"\x50\x4f\x53\x54",
            b"\x47\x45\x54\x20",
            b"\xee\xee\xee\xee",
            b"\xdd\xdd\xdd\xdd",
            b"\x16\x03\x01\x02",
        }:
            continue
        if rnd[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    enc_key = rnd[8:40]
    enc_iv = rnd[40:56]
    enc = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
    full = enc.update(bytes(rnd))
    dc_idx = -dc if is_media else dc
    tail_plain = proto_tag + struct.pack("<h", dc_idx) + os.urandom(2)
    keystream_tail = bytes(full[i] ^ rnd[i] for i in range(56, 64))
    encrypted_tail = bytes(tail_plain[i] ^ keystream_tail[i] for i in range(8))
    result = bytearray(rnd)
    result[56:64] = encrypted_tail
    return bytes(result)


class MsgSplitterTest(unittest.TestCase):
    def _split(self, proto_int, packets, chunk_sizes=None):
        plain_stream = b"".join(packets)
        cipher_stream = _obfuscator().update(plain_stream)

        splitter = MsgSplitter(proto_int)
        chunks = []
        if chunk_sizes is None:
            chunks = [(cipher_stream, plain_stream)]
        else:
            offset = 0
            for size in chunk_sizes:
                chunks.append(
                    (
                        cipher_stream[offset : offset + size],
                        plain_stream[offset : offset + size],
                    )
                )
                offset += size
            if offset < len(cipher_stream):
                chunks.append((cipher_stream[offset:], plain_stream[offset:]))

        parts = []
        for chunk, plain in chunks:
            parts.extend(splitter.split(chunk, plain))
        return splitter, cipher_stream, parts

    def test_abridged_stream_splits_into_packets(self):
        packets = [_abridged(b"a" * 4), _abridged(b"b" * 16), _abridged(b"c" * 40)]
        _, stream, parts = self._split(PROTO_ABRIDGED_INT, packets)
        self.assertEqual(len(parts), 3)
        self.assertEqual(b"".join(parts), stream)
        self.assertEqual([len(p) for p in parts], [5, 17, 41])

    def test_intermediate_stream_splits_into_packets(self):
        packets = [_intermediate(b"a" * 8), _intermediate(b"b" * 12)]
        _, stream, parts = self._split(PROTO_INTERMEDIATE_INT, packets)
        self.assertEqual(len(parts), 2)
        self.assertEqual(b"".join(parts), stream)

    def test_padded_intermediate_uses_intermediate_framing(self):
        packets = [_intermediate(b"z" * 20)]
        _, stream, parts = self._split(PROTO_PADDED_INTERMEDIATE_INT, packets)
        self.assertEqual(parts, [stream])

    def test_partial_packet_is_buffered_until_complete(self):
        packets = [_abridged(b"a" * 20)]
        _, stream, parts = self._split(
            PROTO_ABRIDGED_INT, packets, chunk_sizes=[1] * (len(packets[0]) - 1)
        )
        self.assertEqual(parts, [stream])

    def test_split_preserves_stream_across_arbitrary_chunking(self):
        packets = [_intermediate(bytes([i]) * 16) for i in range(8)]
        _, stream, parts = self._split(
            PROTO_INTERMEDIATE_INT, packets, chunk_sizes=[7, 3, 50, 11]
        )
        self.assertEqual(b"".join(parts), stream)
        self.assertEqual(len(parts), 8)

    def test_empty_chunk_yields_nothing(self):
        splitter = MsgSplitter(PROTO_INTERMEDIATE_INT)
        self.assertEqual(splitter.split(b"", b""), [])

    def test_zero_length_packet_disables_splitting(self):
        plain = (0).to_bytes(4, "little") + b"tail"
        stream = _obfuscator().update(plain)
        splitter = MsgSplitter(PROTO_INTERMEDIATE_INT)
        parts = splitter.split(stream, plain)
        self.assertEqual(parts, [stream])
        self.assertEqual(splitter.split(b"raw", b"raw"), [b"raw"])

    def test_flush_returns_buffered_tail_once(self):
        plain = _intermediate(b"x" * 32)
        partial = _obfuscator().update(plain)[:10]
        splitter = MsgSplitter(PROTO_INTERMEDIATE_INT)
        self.assertEqual(splitter.split(partial, plain[:10]), [])
        self.assertEqual(splitter.flush(), [partial])
        self.assertEqual(splitter.flush(), [])


class TransparentHandshakeTest(unittest.TestCase):
    def test_abridged_handshake_parses_dc_and_media(self):
        hs = _client_handshake(PROTO_TAG_ABRIDGED, 2)
        result = try_handshake(hs)
        self.assertIsNotNone(result)
        dc, is_media, proto_tag, prekey_iv = result
        self.assertEqual(dc, 2)
        self.assertFalse(is_media)
        self.assertEqual(proto_tag, PROTO_TAG_ABRIDGED)
        self.assertEqual(prekey_iv, hs[8:56])

    def test_negative_dc_idx_marks_media(self):
        hs = _client_handshake(PROTO_TAG_INTERMEDIATE, 4, is_media=True)
        result = try_handshake(hs)
        self.assertIsNotNone(result)
        dc, is_media, proto_tag, _ = result
        self.assertEqual(dc, 4)
        self.assertTrue(is_media)
        self.assertEqual(proto_tag, PROTO_TAG_INTERMEDIATE)

    def test_secure_proto_tag_parses(self):
        hs = _client_handshake(PROTO_TAG_SECURE, 1)
        result = try_handshake(hs)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 1)
        self.assertEqual(result[2], PROTO_TAG_SECURE)

    def test_short_handshake_rejected(self):
        self.assertIsNone(try_handshake(os.urandom(20)))

    def test_garbage_rejected(self):
        self.assertIsNone(try_handshake(os.urandom(64)))


class Dc203RoutingTest(unittest.IsolatedAsyncioTestCase):
    async def _handle(self, dc, media, pool_hit):
        reader = Mock()
        reader.readexactly = AsyncMock(
            return_value=_client_handshake(PROTO_TAG_INTERMEDIATE, dc, is_media=media)
        )
        writer = Mock()
        writer.get_extra_info.return_value = ("192.0.2.10", 50000)
        writer.wait_closed = AsyncMock()
        ws = Mock()
        ws.send = AsyncMock()
        with (
            patch.object(transparent, "set_sock_opts"),
            patch.object(
                transparent, "get_original_dst", return_value=("91.105.192.100", 443)
            ),
            patch.object(
                transparent.ws_pool,
                "get",
                new_callable=AsyncMock,
                return_value=ws if pool_hit else None,
            ) as get,
            patch.object(transparent, "bridge_ws_reencrypt", new_callable=AsyncMock),
            patch.object(
                transparent, "do_fallback", new_callable=AsyncMock, return_value=True
            ) as fallback,
        ):
            await transparent._handle_client(reader, writer)
        get.assert_awaited_once_with(2 if dc == 203 else dc, media, is_test_dc=False)
        relay_init = (
            ws.send.call_args.args[0] if pool_hit else fallback.call_args.args[2]
        )
        self.assertEqual(try_handshake(relay_init)[:2], (dc, media))
        if not pool_hit:
            self.assertEqual(fallback.call_args.args[4], dc)
            self.assertEqual(
                fallback.call_args.kwargs["fallback_dst_override"], "91.105.192.100"
            )

    async def test_pool_preserves_requested_dc_in_relay_handshake(self):
        for dc in (2, 4, 203):
            for media in (False, True):
                with self.subTest(dc=dc, media=media):
                    await self._handle(dc, media, True)

    async def test_fallback_preserves_dc203_and_original_destination(self):
        for media in (False, True):
            with self.subTest(media=media):
                await self._handle(203, media, False)

    async def test_cf_uses_dc2_hostname_without_rewriting_dc203(self):
        ws = Mock()
        ws.send = AsyncMock()
        relay_init = generate_relay_init(PROTO_TAG_INTERMEDIATE, 203)
        with (
            patch.object(
                bridge.balancer,
                "get_domains_for_dc",
                return_value=iter(["example.com"]),
            ),
            patch.object(bridge.balancer, "update_domain_for_dc"),
            patch.object(
                bridge.RawWebSocket, "connect", new_callable=AsyncMock, return_value=ws
            ) as connect,
            patch.object(
                bridge, "bridge_ws_reencrypt", new_callable=AsyncMock
            ) as relay,
        ):
            self.assertTrue(
                await bridge._cfproxy_fallback(
                    Mock(), Mock(), relay_init, "test", Mock(), dc=203, is_media=False
                )
            )
        self.assertEqual(
            connect.call_args.args[:2], ("kws2.example.com", "kws2.example.com")
        )
        ws.send.assert_awaited_once_with(relay_init)
        self.assertEqual(relay.call_args.kwargs["dc"], 203)


class ReencryptionRoundtripTest(unittest.TestCase):
    """Verify client plaintext is preserved through the full relay pipeline."""

    def test_roundtrip_preserves_plaintext(self):
        # Build a real client handshake (secretless, abridged, DC 2).
        hs = _client_handshake(PROTO_TAG_ABRIDGED, 2)
        result = try_handshake(hs)
        self.assertIsNotNone(result)
        dc, is_media, proto_tag, client_prekey_iv = result

        relay_init = generate_relay_init(proto_tag, -dc if is_media else dc)
        ctx = build_crypto_ctx(client_prekey_iv, relay_init)

        # Client sends one abridged packet, obfuscated with its own keys.
        plaintext = b"hello-telegram-world"
        client_up_enc = Cipher(
            algorithms.AES(hs[8:40]), modes.CTR(hs[40:56])
        ).encryptor()
        client_up_enc.update(b"\x00" * 64)  # skip handshake keystream
        client_stream = client_up_enc.update(_abridged(plaintext))

        # Proxy: decrypt client ciphertext -> re-encrypt for relay.
        plain = ctx.clt_dec.update(client_stream)
        relay_stream = ctx.tg_enc.update(plain)

        # Relay side (gateway) decrypts using the relay_init keys.
        gateway_dec = Cipher(
            algorithms.AES(relay_init[8:40]), modes.CTR(relay_init[40:56])
        ).encryptor()
        gateway_dec.update(b"\x00" * 64)
        gateway_plain = gateway_dec.update(relay_stream)
        self.assertIn(plaintext, gateway_plain)

        # And the reverse direction: gateway -> client.
        reply_plain = _abridged(b"reply-from-server")
        gateway_enc = Cipher(
            algorithms.AES(relay_init[8:56][::-1][:32]),
            modes.CTR(relay_init[8:56][::-1][32:]),
        ).encryptor()
        gateway_down = gateway_enc.update(reply_plain)

        plain = ctx.tg_dec.update(gateway_down)
        client_down = ctx.clt_enc.update(plain)

        # Client decrypts using reversed prekey/iv (server direction).
        client_dec = Cipher(
            algorithms.AES(hs[8:56][::-1][:32]), modes.CTR(hs[8:56][::-1][32:])
        ).encryptor()
        client_plain = client_dec.update(client_down)
        self.assertEqual(client_plain, reply_plain)


class SplitterRelayStreamTest(unittest.TestCase):
    """MsgSplitter must slice the RELAY (re-encrypted) stream using the
    plaintext for length headers, mirroring bridge_ws_reencrypt usage."""

    def test_relay_stream_sliced_per_packet(self):
        packets = [_abridged(b"a" * 12), _abridged(b"b" * 32)]
        plain_stream = b"".join(packets)
        relay_stream = _obfuscator().update(plain_stream)

        splitter = MsgSplitter(PROTO_ABRIDGED_INT)
        parts = []
        for chunk, plain in zip(
            (relay_stream[:9], relay_stream[9:20], relay_stream[20:]),
            (plain_stream[:9], plain_stream[9:20], plain_stream[20:]),
            strict=True,
        ):
            parts.extend(splitter.split(chunk, plain))
        self.assertEqual(b"".join(parts), relay_stream)
        self.assertEqual([len(p) for p in parts], [13, 33])


if __name__ == "__main__":
    unittest.main()
