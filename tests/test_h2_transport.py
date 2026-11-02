"""Wire-level regressions: real TLS sockets, ALPN and HTTP/2 flow control."""

import asyncio
import datetime
import ipaddress
import ssl
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset
from h2.settings import SettingCodes

from tg_re_proxy.h2_transport import H2Transport, STREAM_RECEIVE_WINDOW, _Connection
from tg_re_proxy.cf_h2 import _HttpChannel, _HttpLane, bridge_h2
from tg_re_proxy.utils import PROTO_TAG_INTERMEDIATE


class H2ContextTest(unittest.IsolatedAsyncioTestCase):
    async def test_lanes_reuse_verified_context_without_changing_websocket_contexts(
        self,
    ):
        from tg_re_proxy.h2_transport import _default_ssl_context
        from tg_re_proxy.raw_websocket import _ssl_ctx, _ssl_ctx_fronting
        from tg_re_proxy.utils import create_ssl_context

        _default_ssl_context.cache_clear()
        self.addCleanup(_default_ssl_context.cache_clear)
        lanes = []
        try:
            with patch(
                "tg_re_proxy.h2_transport.create_ssl_context", wraps=create_ssl_context
            ) as create:
                lanes = [
                    _HttpLane("kws4.example.org", 1),
                    _HttpLane("kws2.example.net", 2),
                ]
                create.assert_called_once_with()
            first, second = (lane.client._transport.ssl_context for lane in lanes)
            self.assertIs(first, second)
            self.assertIsNot(first, _ssl_ctx)
            self.assertIsNot(first, _ssl_ctx_fronting)
            self.assertTrue(first.check_hostname)
            self.assertEqual(first.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(_ssl_ctx.check_hostname)
            self.assertFalse(_ssl_ctx_fronting.check_hostname)
            self.assertEqual(
                set(first.get_ca_certs(binary_form=True)),
                set(_ssl_ctx.get_ca_certs(binary_form=True)),
            )

            custom = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            custom.check_hostname = False
            transport = H2Transport(custom)
            self.assertIs(transport.ssl_context, custom)
            self.assertTrue(first.check_hostname)
            await transport.aclose()
        finally:
            await asyncio.gather(*(lane.close() for lane in lanes))


class H2WireTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        cls.folder = tempfile.TemporaryDirectory(prefix="tg-h2-tests-")
        cls.addClassCleanup(cls.folder.cleanup)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cls.cert_path = Path(cls.folder.name) / "cert.pem"
        key_path = Path(cls.folder.name) / "key.pem"
        cls.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        cls.server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_ssl.load_cert_chain(str(cls.cert_path), str(key_path))
        cls.server_ssl.set_alpn_protocols(["h2"])

    async def asyncSetUp(self):
        self.requests = asyncio.Queue()
        self.resets = asyncio.Queue()
        self.connections = []
        self.handlers = []
        self.tasks = []
        self.server_max_streams = 64
        self.server = await asyncio.start_server(
            self.serve, "127.0.0.1", 0, ssl=self.server_ssl
        )
        port = self.server.sockets[0].getsockname()[1]
        self.lane = _HttpLane("127.0.0.1:%d" % port, 1)
        await self.lane.client.aclose()
        self.transport = H2Transport(
            ssl.create_default_context(cafile=str(self.cert_path))
        )
        self.lane.client = httpx.AsyncClient(
            transport=self.transport, trust_env=False, timeout=httpx.Timeout(2, read=1)
        )

    async def asyncTearDown(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.lane.close()
        self.server.close()
        await self.server.wait_closed()
        for connection in self.connections:
            connection.writer.close()
        await asyncio.wait_for(asyncio.gather(*self.handlers), 3)

    async def serve(self, reader, writer):
        self.handlers.append(asyncio.current_task())
        conn = SimpleNamespace(
            h2=H2Connection(config=H2Configuration(client_side=False)),
            writer=writer,
            bodies={},
            pending={},
        )
        self.connections.append(conn)
        conn.h2.initiate_connection()
        conn.h2.update_settings(
            {SettingCodes.MAX_CONCURRENT_STREAMS: self.server_max_streams}
        )
        writer.write(conn.h2.data_to_send())
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                for event in conn.h2.receive_data(data):
                    if isinstance(event, RequestReceived):
                        conn.bodies[event.stream_id] = bytearray()
                    elif isinstance(event, DataReceived):
                        conn.bodies[event.stream_id].extend(event.data)
                        conn.h2.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, StreamEnded):
                        await self.requests.put(
                            (conn, event.stream_id, bytes(conn.bodies[event.stream_id]))
                        )
                    elif isinstance(event, StreamReset):
                        conn.pending.pop(event.stream_id, None)
                        await self.resets.put((event.stream_id, event.error_code))
                self.flush(conn)
                await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

    def flush(self, conn):
        for sid, (body, end) in list(conn.pending.items()):
            while body:
                count = min(
                    len(body),
                    conn.h2.max_outbound_frame_size,
                    conn.h2.local_flow_control_window(sid),
                )
                if count <= 0:
                    break
                chunk, body = body[:count], body[count:]
                conn.h2.send_data(sid, chunk, end_stream=end and not body)
            if body:
                conn.pending[sid] = (body, end)
            else:
                del conn.pending[sid]
        conn.writer.write(conn.h2.data_to_send())

    def respond(self, request, body=b"r" * 40, *, end=True, length=None, status=200):
        conn, sid, _ = request
        conn.h2.send_headers(
            sid,
            [
                (b":status", str(status).encode()),
                (b"content-type", b"application/octet-stream"),
                (
                    b"content-length",
                    str(len(body) if length is None else length).encode(),
                ),
            ],
            end_stream=end and not body,
        )
        if body:
            conn.pending[sid] = (body, end)
        self.flush(conn)

    async def post(self, body=b"x" * 40):
        task = asyncio.create_task(self.lane._post(body, len(self.tasks) + 1))
        self.tasks.append(task)
        request = await asyncio.wait_for(self.requests.get(), 2)
        self.assertEqual(request[2], body)
        return task, request

    async def test_fast_response_does_not_wait_for_unrelated_long_polls(self):
        slow1, request1 = await self.post()
        slow2, request2 = await self.post()
        fast, request3 = await self.post()
        self.respond(request3)
        self.assertEqual(await asyncio.wait_for(fast, 0.5), b"r" * 40)
        self.assertFalse(slow1.done())
        self.assertFalse(slow2.done())
        self.respond(request1)
        self.respond(request2)
        await asyncio.gather(slow1, slow2)
        self.assertEqual(len(self.connections), 1)

    async def test_shared_default_context_rejects_untrusted_certificate(self):
        async with httpx.AsyncClient(
            transport=H2Transport(), trust_env=False
        ) as client:
            with self.assertRaises(httpx.ConnectError):
                await client.get("https://" + self.lane.host + "/api")
        task, request = await self.post()
        self.respond(request)
        self.assertEqual(await asyncio.wait_for(task, 1), b"r" * 40)

    async def test_recovery_deadline_starts_after_original_upload_finishes(self):
        channel = _HttpChannel(self.lane, 1, "unfinished-upload-test")
        body = b"samekey!" + b"q" * 32
        started, resume = asyncio.Event(), asyncio.Event()
        send_body = _Connection.send_body

        async def paused_send(connection, request, stream):
            started.set()
            await resume.wait()
            await send_body(connection, request, stream)

        with (
            patch.object(_Connection, "send_body", paused_send),
            patch("tg_re_proxy.cf_h2.REPLAY_REQUEST_SECONDS", 0.02),
            patch("tg_re_proxy.cf_h2.REPLAY_CHECK_SECONDS", 0.005),
        ):
            await channel.send(body, False)
            await asyncio.wait_for(started.wait(), 0.5)
            self.tasks.append(asyncio.create_task(channel._recover()))
            await asyncio.sleep(0.06)
            self.assertEqual(len(channel.pending), 1, "unsent original was duplicated")
            self.assertTrue(self.requests.empty())
            resume.set()
            original = await asyncio.wait_for(self.requests.get(), 0.5)
            probe = await asyncio.wait_for(self.requests.get(), 0.5)
            self.assertEqual(original[2], body)
            self.assertEqual(probe[2], body)
            self.respond(probe)
            self.assertEqual(await asyncio.wait_for(channel.receive(), 0.5), b"r" * 40)
            self.assertTrue(self.resets.empty())

    async def test_body_tail_does_not_wait_for_unrelated_long_polls(self):
        slow1, _ = await self.post()
        slow2, _ = await self.post()
        fast, request = await self.post()
        self.respond(request, b"a" * 20, end=False, length=40)
        await asyncio.sleep(0.03)
        self.assertFalse(fast.done())
        conn, sid, _ = request
        conn.h2.send_data(sid, b"b" * 20, end_stream=True)
        self.flush(conn)
        self.assertEqual(await asyncio.wait_for(fast, 0.5), b"a" * 20 + b"b" * 20)
        self.assertFalse(slow1.done())
        self.assertFalse(slow2.done())

    async def test_receiving_body_is_marked_before_request_coroutine_resumes(self):
        channel = _HttpChannel(self.lane, 1, "early-headers-test")
        resume = asyncio.Event()
        send_body = _Connection.send_body

        async def paused_send(connection, request, stream):
            await send_body(connection, request, stream)
            await resume.wait()

        with patch.object(_Connection, "send_body", paused_send):
            await channel.send(b"k" * 40, False)
            request = await asyncio.wait_for(self.requests.get(), 1)
            self.respond(request, b"a" * 20, end=False, length=40)

            async def headers_received():
                while channel.receiving_http == 0:
                    await asyncio.sleep(0.005)

            try:
                await asyncio.wait_for(headers_received(), 0.5)
                self.assertEqual(channel.receiving_http, 1)
                self.assertTrue(channel.queue.empty())
            finally:
                resume.set()
            conn, sid, _ = request
            conn.h2.send_data(sid, b"b" * 20, end_stream=True)
            self.flush(conn)
            self.assertEqual(
                await asyncio.wait_for(channel.receive(), 1), b"a" * 20 + b"b" * 20
            )
            self.assertEqual(channel.receiving_http, 0)

    async def test_parallel_first_windows_do_not_wait_for_connection_credit(self):
        first, request1 = await self.post()
        second, request2 = await self.post()
        self.respond(request1, b"a" * 65532)
        self.respond(request2, b"b" * 65532)
        # No event-loop yield between responses: the server has not received
        # any WINDOW_UPDATE credit for either body yet.
        self.assertFalse(request1[0].pending)
        self.assertEqual(await first, b"a" * 65532)
        self.assertEqual(await second, b"b" * 65532)

    async def test_http_404_is_forwarded_while_other_native_channel_keeps_working(self):
        class Cipher:
            def update(self, data):
                return data

        class Writer:
            def __init__(self):
                self.data = bytearray()
                self.changed = asyncio.Event()

            def write(self, data):
                self.data.extend(data)

            async def drain(self):
                self.changed.set()

        channel = _HttpChannel(self.lane, 1, "bad-key-test")
        reader, writer = asyncio.StreamReader(), Writer()
        ctx = SimpleNamespace(clt_dec=Cipher(), clt_enc=Cipher())
        bridge = asyncio.create_task(
            bridge_h2(reader, writer, channel, ctx, PROTO_TAG_INTERMEDIATE)
        )
        self.tasks.append(bridge)
        reader.feed_data(struct.pack("<I", 40) + b"\x00" * 40)
        self.respond(await asyncio.wait_for(self.requests.get(), 1), b"p" * 84)
        await asyncio.wait_for(writer.changed.wait(), 1)
        reader.feed_data((struct.pack("<I", 40) + b"k" * 40) * 2)
        bad = await asyncio.wait_for(self.requests.get(), 1)
        pending = await asyncio.wait_for(self.requests.get(), 1)
        healthy = _HttpChannel(self.lane, 2, "healthy-key-test")
        await healthy.send(b"h" * 40, False)
        good = await asyncio.wait_for(self.requests.get(), 1)
        self.respond(bad, b"<html>not found</html>", status=404, end=False)
        await asyncio.wait_for(bridge, 1)
        self.assertEqual(
            writer.data, struct.pack("<I", 84) + b"p" * 84 + struct.pack("<Ii", 4, -404)
        )
        self.assertTrue(channel.close_done)
        self.assertFalse(channel.pending)
        self.assertNotIn(pending[1], self.transport.connection.streams)
        self.assertFalse(healthy.closed)
        self.respond(good, b"g" * 40)
        self.assertEqual(await asyncio.wait_for(healthy.receive(), 1), b"g" * 40)
        recovered = _HttpChannel(self.lane, 3, "replacement-key-test")
        await recovered.send(b"n" * 40, False)
        self.respond(await asyncio.wait_for(self.requests.get(), 1), b"r" * 40)
        self.assertEqual(await asyncio.wait_for(recovered.receive(), 1), b"r" * 40)
        self.assertEqual(len(self.connections), 1)
        self.assertEqual(self.lane.failed_until, 0)

    async def test_binary_transport_error_is_terminal_without_domain_cooldown(self):
        channel = _HttpChannel(self.lane, 1, "binary-error-test")
        await channel.send(b"k" * 40, False)
        self.respond(
            await asyncio.wait_for(self.requests.get(), 1), struct.pack("<i", -404)
        )
        await asyncio.gather(*list(channel.pending))
        self.assertTrue(channel.closed)
        self.assertEqual(channel.transport_error, -404)
        self.assertEqual(self.lane.failed_until, 0)
        self.assertEqual(self.lane.reply_buffer_bytes, 0)
        await channel.close()

    async def test_preflight_and_posts_use_same_tls_connection(self):
        preflight = asyncio.create_task(self.lane._preflight())
        self.tasks.append(preflight)
        request = await asyncio.wait_for(self.requests.get(), 2)
        self.respond(request, b"", status=501)
        await preflight
        task, request = await self.post()
        self.respond(request)
        await task
        self.assertEqual(len(self.connections), 1)

    async def test_concurrent_waiters_respect_remote_stream_limit(self):
        self.server_max_streams = 2
        pending = [
            asyncio.create_task(self.lane._post(b"x" * 40, i)) for i in range(12)
        ]
        self.tasks.extend(pending)
        for _ in range(6):
            batch = [await asyncio.wait_for(self.requests.get(), 2) for _ in range(2)]
            await asyncio.sleep(0.01)
            self.assertTrue(self.requests.empty())
            for request in batch:
                self.respond(request)
        self.assertEqual(await asyncio.gather(*pending), [b"r" * 40] * 12)
        self.assertEqual(len(self.connections), 1)

    async def test_cancellation_resets_stream_and_reuses_server_capacity(self):
        self.server_max_streams = 2
        healthy, healthy_request = await self.post()
        for _ in range(5):
            task, request = await self.post()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            self.assertEqual(
                await asyncio.wait_for(self.resets.get(), 0.5), (request[1], 8)
            )
        self.respond(healthy_request)
        self.assertEqual(await asyncio.wait_for(healthy, 0.5), b"r" * 40)
        self.assertEqual(len(self.connections), 1)

    async def test_cancel_while_waiting_for_stream_slot_does_not_leak_capacity(self):
        self.server_max_streams = 1
        first, request = await self.post()
        waiting = asyncio.create_task(self.lane._post(b"w" * 40, 2))
        self.tasks.append(waiting)
        await asyncio.sleep(0.03)
        self.assertTrue(self.requests.empty())
        waiting.cancel()
        await asyncio.gather(waiting, return_exceptions=True)
        self.respond(request)
        await first
        next_task, next_request = await self.post()
        self.respond(next_request)
        await next_task
        self.assertFalse(self.transport.connection.streams)

    async def test_large_upload_and_download_cross_flow_control_windows(self):
        body = b"x" * (256 * 1024)
        task, request = await self.post(body)
        self.respond(request, body)
        self.assertEqual(await asyncio.wait_for(task, 2), body)
        self.assertEqual(len(self.connections), 1)

    async def test_stalled_body_consumer_does_not_block_other_streams(self):
        # Keep a streaming response open without reading it. Its window must
        # bound buffering while other responses can exceed a connection window.
        opening = asyncio.create_task(
            self.lane.client.send(
                self.lane.client.build_request(
                    "POST", "https://" + self.lane.host + "/api", content=b"x" * 40
                ),
                stream=True,
            )
        )
        self.tasks.append(opening)
        request = await asyncio.wait_for(self.requests.get(), 2)
        self.respond(request, b"s" * (1024 * 1024))
        response = await opening
        fast, fast_request = await self.post()
        self.respond(fast_request, b"f" * (4 * 1024 * 1024))
        self.assertEqual(await asyncio.wait_for(fast, 2), b"f" * (4 * 1024 * 1024))
        stream = self.transport.connection.streams[request[1]]
        self.assertLessEqual(
            sum(len(data) for data, _ in stream.chunks), STREAM_RECEIVE_WINDOW
        )
        await response.aclose()
        self.assertEqual(
            await asyncio.wait_for(self.resets.get(), 0.5), (request[1], 8)
        )

    async def test_read_timeout_resets_only_its_stream(self):
        self.lane.client.timeout = httpx.Timeout(2, read=0.15)
        stalled, request = await self.post()
        self.lane.client.timeout = httpx.Timeout(2, read=1)
        healthy, healthy_request = await self.post()
        with self.assertRaises(httpx.ReadTimeout):
            await stalled
        self.assertEqual(
            await asyncio.wait_for(self.resets.get(), 0.5), (request[1], 8)
        )
        self.assertIsNone(self.transport.connection.error)
        self.respond(healthy_request)
        self.assertEqual(await healthy, b"r" * 40)
        self.assertEqual(len(self.connections), 1)

    async def test_last_stream_timeout_reconnects_instead_of_reusing_silent_connection(
        self,
    ):
        self.lane.client.timeout = httpx.Timeout(2, read=0.05)
        stalled, _ = await self.post()
        old_connection = self.transport.connection
        with self.assertRaises(httpx.ReadTimeout):
            await stalled
        self.assertIsNotNone(old_connection.error)
        self.assertTrue(old_connection.writer.is_closing())
        self.assertFalse(old_connection.streams)
        self.lane.client.timeout = httpx.Timeout(2, read=1)
        recovered, request = await self.post()
        self.respond(request)
        self.assertEqual(await recovered, b"r" * 40)
        self.assertIsNot(self.transport.connection, old_connection)
        self.assertEqual(len(self.connections), 2)

    async def test_peer_reset_does_not_break_other_streams(self):
        bad, request = await self.post()
        good, good_request = await self.post()
        conn, sid, _ = request
        conn.h2.reset_stream(sid, error_code=8)
        self.flush(conn)
        with self.assertRaises(httpx.RemoteProtocolError):
            await bad
        self.respond(good_request)
        self.assertEqual(await good, b"r" * 40)

    async def test_reset_during_response_closes_native_bridge_without_escaping(self):
        cipher = SimpleNamespace(update=lambda data: data)
        ctx = SimpleNamespace(clt_dec=cipher, clt_enc=cipher)
        output = bytearray()
        writer = SimpleNamespace(write=output.extend, drain=AsyncMock())
        reader = asyncio.StreamReader()
        reader.feed_data(struct.pack("<I", 40) + b"k" * 40)
        channel = _HttpChannel(self.lane, 1, "reset-during-body")

        with (
            patch.object(channel, "_recover", side_effect=asyncio.Event().wait),
            self.assertNoLogs("tg-re-proxy", level="DEBUG"),
        ):
            bridge = asyncio.create_task(
                bridge_h2(reader, writer, channel, ctx, PROTO_TAG_INTERMEDIATE)
            )
            self.tasks.append(bridge)
            request = await asyncio.wait_for(self.requests.get(), 1)
            healthy, good_request = await self.post(b"h" * 40)
            self.respond(request, b"partial-response!!!!", end=False, length=40)

            async def body_received():
                while self.lane.reply_buffer_bytes != 20:
                    await asyncio.sleep(0.001)

            await asyncio.wait_for(body_received(), 1)
            conn, sid, _ = request
            conn.h2.reset_stream(sid, error_code=2)
            self.flush(conn)
            await asyncio.wait_for(bridge, 1)
            self.assertTrue(channel.close_done)
            self.assertFalse(channel.pending)
            self.assertIsNone(channel.transport_error)
            self.assertFalse(
                output, "A partial HTTP response must never reach the native client"
            )
            self.assertEqual(self.lane.reply_buffer_bytes, 0)
            self.assertIsNone(self.transport.connection.error)
            self.respond(good_request)
            self.assertEqual(await asyncio.wait_for(healthy, 1), b"r" * 40)
            self.assertEqual(len(self.connections), 1)

    async def test_connection_loss_fails_waiters_and_next_request_reconnects(self):
        tasks = [await self.post() for _ in range(3)]
        self.connections[0].writer.close()
        for task, _ in tasks:
            with self.assertRaises(httpx.HTTPError):
                await asyncio.wait_for(task, 0.5)
        task, request = await self.post()
        self.respond(request)
        self.assertEqual(await task, b"r" * 40)
        self.assertEqual(len(self.connections), 2)

    async def test_goaway_fails_pending_without_replaying_and_reconnects(self):
        task, request = await self.post()
        conn, _, _ = request
        conn.h2.close_connection(error_code=0)
        self.flush(conn)
        with self.assertRaisesRegex(httpx.RemoteProtocolError, "GOAWAY"):
            await task
        self.assertTrue(self.requests.empty())
        next_task, next_request = await self.post()
        self.respond(next_request)
        await next_task
        self.assertEqual(len(self.connections), 2)

    async def test_close_stops_reader_and_wakes_pending_requests(self):
        task, _ = await self.post()
        connection = self.transport.connection
        await self.lane.close()
        with self.assertRaises(httpx.HTTPError):
            await asyncio.wait_for(task, 0.5)
        self.assertTrue(connection.reader_task.done())
        self.assertTrue(connection.writer.is_closing())


if __name__ == "__main__":
    unittest.main()
