from __future__ import annotations

import asyncio
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import httpx

from .balancer import balancer
from .h2_transport import H2Transport
from .utils import (
    DC_DEFAULT_IPS,
    PROTO_TAG_ABRIDGED,
    PROTO_TAG_SECURE,
)

MAX_PACKET = 4 * 1024 * 1024
MAX_PLAIN_PADDING = 256
MAX_CHANNEL_REQUESTS = 8
MAX_CHANNEL_BYTES = 8 * 1024 * 1024
MAX_LANE_REQUESTS = 64
MAX_LANE_BYTES = 32 * 1024 * 1024
MAX_LANE_REPLY_BYTES = 32 * 1024 * 1024
DOMAIN_COOLDOWN = 30.0
REQUEST_TIMEOUT = 65.0
SETUP_TIMEOUT = 8.0
REPLAY_IDLE_SECONDS = 1.0
REPLAY_REQUEST_SECONDS = 3.0
REPLAY_CHECK_SECONDS = 0.25
REPLAY_MAX_AGE = 30.0
REPLAY_HISTORY_BYTES = 64 * 1024
REPLAY_HISTORY_PACKETS = 16
MAX_CHANNEL_REPLAYS = 2
REPLAY_SLOT_SECONDS = 30.0
REPLAY_RETRY_SECONDS = 2.0
REPLAY_MAX_ATTEMPTS = 3


class _NativeDeliveryError(ConnectionError):
    """The local receiver disconnected"""


class _ReplyBufferFull(BufferError):
    """A local memory limit"""


class _MTProtoTransportError(Exception):
    """An endpoint error that the native client must receive, not just EOF."""

    def __init__(self, code: int, source: str):
        super().__init__("%d (%s)" % (code, source))
        self.code = code


@dataclass
class _ReplayPacket:
    sent_at: float
    body: bytes
    sequence: int
    attempts: int = 0
    last_attempt_at: float = 0.0
    pending: Optional[asyncio.Task] = None
    originals: Set[asyncio.Task] = field(default_factory=set, repr=False)
    retired: bool = False
    reply_id: Optional[bytes] = None

    @property
    def replayed(self) -> bool:
        return self.last_attempt_at > 0 or self.attempts > 0


async def _read_packet(reader, decryptor, tag: bytes) -> Tuple[bytes, bool]:
    async def plaintext(count: int) -> bytes:
        return decryptor.update(await reader.readexactly(count))

    if tag == PROTO_TAG_ABRIDGED:
        first = (await plaintext(1))[0]
        quick, words = bool(first & 0x80), first & 0x7F
        if words == 0x7F:
            words = int.from_bytes(await plaintext(3), "little")
        length = words * 4
    else:
        (value,) = struct.unpack("<I", await plaintext(4))
        quick, length = bool(value & 0x80000000), value & 0x7FFFFFFF
    if (
        not 24
        <= length
        <= MAX_PACKET + (MAX_PLAIN_PADDING if tag == PROTO_TAG_SECURE else 0)
    ):
        raise ValueError("native packet length outside supported range: %d" % length)
    body = await plaintext(length)
    if tag == PROTO_TAG_SECURE:
        if body[:8] == b"\x00" * 8:
            packet_length = 20 + int.from_bytes(body[16:20], "little")
            max_padding = MAX_PLAIN_PADDING
        else:
            packet_length = 24 + ((length - 24) // 16) * 16
            max_padding = 15
        padding = length - packet_length
        if not 24 <= packet_length <= length or padding > max_padding:
            raise ValueError(
                "invalid padded native packet: frame=%d packet=%d padding=%d limit=%d"
                % (length, packet_length, padding, max_padding)
            )
        body = body[:packet_length]
    if len(body) % 4 or len(body) > MAX_PACKET:
        raise ValueError("invalid native packet alignment or size")
    return body, quick


def _encode_reply(body: bytes, tag: bytes) -> bytes:
    if not body or len(body) % 4 or len(body) > MAX_PACKET:
        raise ValueError("invalid HTTP MTProto response length: %d" % len(body))
    if tag == PROTO_TAG_ABRIDGED:
        words = len(body) // 4
        prefix = (
            bytes([words]) if words < 0x7F else b"\x7f" + words.to_bytes(3, "little")
        )
        return prefix + body
    padding = os.urandom(os.urandom(1)[0] % 4) if tag == PROTO_TAG_SECURE else b""
    return struct.pack("<I", len(body) + len(padding)) + body + padding


class _HttpChannel:
    def __init__(self, lane, channel_id: int, label: str):
        self.lane, self.channel_id = lane, channel_id
        self.closed = False
        self.transport_error: Optional[int] = None
        self.pending: Dict[asyncio.Task, int] = {}
        self.sent_since: Dict[asyncio.Task, float] = {}
        self.next_sequence = 0
        self.pending_bytes = 0
        self.reply_bytes = 0
        self.queue = asyncio.Queue(maxsize=16)
        self.capacity = asyncio.Condition()
        self.recovery_wakeup = asyncio.Event()
        self.receiving_tasks: Set[asyncio.Task] = set()
        self.delivering = False
        self.replay_pending: Set[asyncio.Task] = set()
        self.replay_history: List[_ReplayPacket] = []
        self.replay_key: Optional[bytes] = None
        self.last_progress = time.monotonic()
        self.close_lock = asyncio.Lock()
        self.send_lock = asyncio.Lock()
        self.close_done = False
        self.upload_waiting = False
        self.upload_wait_phase = "-"
        self.upload_wait_bytes = 0
        lane.channels.add(self)

    @property
    def receiving_http(self) -> int:
        return len(self.receiving_tasks)

    @property
    def native_backpressure(self) -> bool:
        return bool(self.reply_bytes) or self.delivering

    def _has_capacity(self, length: int) -> bool:
        return (
            len(self.pending) < MAX_CHANNEL_REQUESTS
            and self.pending_bytes + length <= MAX_CHANNEL_BYTES
        )

    def _wake_receiver(self) -> None:
        if not self.closed and not self.pending and not self.native_backpressure:
            self.recovery_wakeup.set()

    def _overdue_original(self, entry: _ReplayPacket, now: float) -> bool:
        return entry.retired or any(
            task in self.sent_since
            and task not in self.receiving_tasks
            and now - self.sent_since[task] >= REPLAY_REQUEST_SECONDS
            for task in entry.originals
        )

    def _replay_limit(self, entry: _ReplayPacket) -> int:
        return (
            REPLAY_MAX_ATTEMPTS
            if entry.originals or entry.retired or entry is self.replay_history[-1]
            else 0
        )

    def _capacity_candidate(self, now: float):
        for task, sent in sorted(
            self.sent_since.items(),
            key=lambda pair: (pair[0] not in self.replay_pending, pair[1]),
        ):
            if (
                task.done()
                or task in self.receiving_tasks
                or now - sent < REPLAY_REQUEST_SECONDS
            ):
                continue
            if task in self.replay_pending:
                return task, None
            entry = next(
                (entry for entry in self.replay_history if task in entry.originals),
                None,
            )
            if entry is not None and now - entry.sent_at <= REPLAY_MAX_AGE:
                return task, entry
        return None

    async def _make_upload_room(self, now: float) -> None:
        if self.closed or not self.upload_waiting:
            return
        if self.upload_wait_phase == "channel-capacity":
            if self._has_capacity(self.upload_wait_bytes):
                return
            channels = [self]
        elif self.upload_wait_phase == "lane-capacity":
            if self.lane._has_capacity(self.upload_wait_bytes):
                return
            channels = sorted(
                self.lane.channels,
                key=lambda channel: min(channel.sent_since.values(), default=now),
            )
        else:
            return
        for channel in channels:
            candidate = channel._capacity_candidate(now)
            if candidate is None:
                continue
            task, entry = candidate
            channel.sent_since.pop(task, None)
            if entry is not None:
                entry.retired = True
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return

    def _replay_blocker(self, entry: _ReplayPacket, now: float) -> Optional[str]:
        if not 0 <= now - entry.sent_at <= REPLAY_MAX_AGE:
            return "expired"
        if entry.attempts >= self._replay_limit(entry):
            return "budget-used"
        if self.native_backpressure:
            return "native-backpressure"
        if entry.originals.intersection(self.receiving_tasks):
            return "original-body"
        if entry.pending in self.receiving_tasks:
            return "replay-body"
        if entry.replayed and now - entry.last_attempt_at < REPLAY_RETRY_SECONDS:
            return "backoff-or-progress"
        if self._overdue_original(entry, now):
            return None
        if entry is not self.replay_history[-1] or any(
            task is not entry.pending for task in self.pending
        ):
            return "receiver-active"
        if entry.replayed and now - self.last_progress < REPLAY_IDLE_SECONDS:
            return "backoff-or-progress"
        return None

    def _replay_due(self, entry: _ReplayPacket, now: float) -> bool:
        return self._replay_blocker(entry, now) is None

    def _fail(self, error: Exception) -> None:
        if self.closed:
            return
        if isinstance(error, _MTProtoTransportError):
            self.transport_error = error.code
        self.closed = True
        self.recovery_wakeup.set()
        while not self.queue.empty():
            self.queue.get_nowait()
        self.reply_bytes = 0
        self.queue.put_nowait(error)

    async def send(self, body: bytes, quick: bool, replay: bool = False) -> bool:
        if replay and self.send_lock.locked():
            return False
        if not replay:
            self.upload_waiting = True
            self.upload_wait_phase = "send-lock"
            self.upload_wait_bytes = len(body)
        try:
            async with self.send_lock:
                return await self._send(body, quick, replay)
        finally:
            if not replay:
                self.upload_waiting = False
                self.upload_wait_phase = "-"
                self.upload_wait_bytes = 0

    async def _send(self, body: bytes, quick: bool, replay: bool) -> bool:
        async with self.capacity:
            if replay and not self._has_capacity(len(body)):
                return False
            if not replay:
                self.upload_wait_phase = "channel-capacity"
                await asyncio.wait_for(
                    self.capacity.wait_for(
                        lambda: self.closed or self._has_capacity(len(body))
                    ),
                    REQUEST_TIMEOUT,
                )
        if self.closed:
            raise ConnectionError("H2 channel closed")
        if not replay:
            self.upload_wait_phase = "lane-capacity"
        if not await self.lane._reserve(len(body), wait=not replay):
            return False
        if self.closed:
            await self.lane._release(len(body))
            raise ConnectionError("H2 channel closed")
        replay_packet = self._find_packet(body) if replay else None
        now = time.monotonic()
        if replay and (
            replay_packet is None
            or replay_packet.pending is not None
            or not self._replay_due(replay_packet, now)
        ):
            await self.lane._release(len(body))
            return False
        self.pending_bytes += len(body)
        self.next_sequence += 1
        native_packet = self._remember_packet(body, now) if not replay else None
        packet = replay_packet or native_packet
        task = asyncio.create_task(self._run_request(body, replay, packet))
        self.pending[task] = len(body)
        if native_packet is not None:
            native_packet.originals.add(task)
            self._trim_history(now)
        if replay:
            self.replay_pending.add(task)
            replay_packet.attempts += 1
            replay_packet.last_attempt_at = now
            replay_packet.pending = task
        return True

    def _find_packet(self, body: bytes) -> Optional[_ReplayPacket]:
        return next(
            (entry for entry in self.replay_history if entry.body == body), None
        )

    def _remember_packet(self, body: bytes, now: float) -> Optional[_ReplayPacket]:
        key = body[:8]
        if key == b"\x00" * 8:
            return None
        if self.replay_key != key:
            self.replay_history.clear()
            self.replay_key = key
        if len(body) > REPLAY_HISTORY_BYTES:
            return None
        packet = self._find_packet(body)
        if packet is None:
            packet = _ReplayPacket(now, body, self.next_sequence)
            self.replay_history.append(packet)
        return packet

    def _trim_history(self, now: float) -> None:
        retained_bytes = sum(len(entry.body) for entry in self.replay_history)
        while (
            len(self.replay_history) > REPLAY_HISTORY_PACKETS
            or retained_bytes > REPLAY_HISTORY_BYTES
        ):
            victim = next(
                (
                    entry
                    for entry in self.replay_history
                    if not entry.originals
                    and not (
                        entry.retired
                        and entry.attempts < REPLAY_MAX_ATTEMPTS
                        and now - entry.sent_at <= REPLAY_MAX_AGE
                    )
                ),
                self.replay_history[0],
            )
            self.replay_history.remove(victim)
            retained_bytes -= len(victim.body)

    async def _run_request(
        self, body: bytes, replay: bool, packet: Optional[_ReplayPacket]
    ) -> None:
        task = asyncio.current_task()
        try:
            reply = await self.lane._post(
                body, self.channel_id, replay=replay, channel=self
            )
            self.last_progress = time.monotonic()
            if reply and not self.closed:
                if packet is not None and reply[:24] != packet.reply_id:
                    packet.reply_id = reply[:24]
                    packet.attempts = 0
                if (
                    self.queue.full()
                    or self.reply_bytes + len(reply) > MAX_CHANNEL_BYTES
                ):
                    raise BufferError("H2 client response queue exceeded bound")
                self.reply_bytes += len(reply)
                self.queue.put_nowait(reply)
        except asyncio.CancelledError:
            raise
        except _MTProtoTransportError as exc:
            if not self.closed:
                pass
            self._fail(exc)
        except Exception as exc:
            if isinstance(exc, (httpx.HTTPError, OSError, ValueError, BufferError)):
                pass
            else:
                pass
            self._fail(exc)
        finally:
            await self._finish_request(task, packet)

    async def _finish_request(
        self, task: asyncio.Task, packet: Optional[_ReplayPacket] = None
    ) -> None:
        length = self.pending.pop(task, None)
        if length is None:
            return
        self.pending_bytes -= length
        self.sent_since.pop(task, None)
        self.replay_pending.discard(task)
        if packet is None:
            packet = next(
                (
                    entry
                    for entry in self.replay_history
                    if task in entry.originals or entry.pending is task
                ),
                None,
            )
        if packet is not None:
            packet.originals.discard(task)
            if packet.pending is task:
                packet.pending = None
        await self.lane._release(length)
        async with self.capacity:
            self.capacity.notify_all()
        self._wake_receiver()

    async def _recover(self) -> None:
        while not self.closed:
            wakeup = asyncio.create_task(self.recovery_wakeup.wait())
            try:
                # wait_for can swallow cancellation when the wakeup completes
                # at the same time on Python 3.8-3.11 (CPython #86296).
                await asyncio.wait((wakeup,), timeout=REPLAY_CHECK_SECONDS)
            finally:
                wakeup.cancel()
                await asyncio.gather(wakeup, return_exceptions=True)
            self.recovery_wakeup.clear()
            now = time.monotonic()
            await self._make_upload_room(now)
            if self.closed or self.native_backpressure:
                continue

            def priority(entry):
                overdue = self._overdue_original(entry, now)
                return (not overdue, entry.sequence if overdue else -entry.sequence)

            candidates = sorted(self.replay_history, key=priority)
            for entry in candidates:
                if not self._replay_due(entry, now):
                    continue
                replace = entry.pending
                if replace is None and len(self.replay_pending) >= MAX_CHANNEL_REPLAYS:
                    replace = next(
                        (
                            task
                            for task in self.pending
                            if task in self.replay_pending
                            and task not in self.receiving_tasks
                        ),
                        None,
                    )
                    if replace is None:
                        continue
                if replace is not None:
                    sent = self.sent_since.get(replace)
                    if (
                        replace in self.receiving_tasks
                        or sent is None
                        or now - sent < REPLAY_SLOT_SECONDS
                    ):
                        continue
                    replace.cancel()
                    await asyncio.gather(replace, return_exceptions=True)
                await self.send(entry.body, False, replay=True)
                break

    async def receive(self) -> bytes:
        value = await self.queue.get()
        if isinstance(value, Exception):
            raise value
        self.reply_bytes -= len(value)
        self._wake_receiver()
        return value

    async def close(self) -> None:
        async with self.close_lock:
            if self.close_done:
                return
            self._fail(ConnectionError("H2 channel closed"))
            self.closed = True
            tasks = list(self.pending)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for task in list(self.pending):
                await self._finish_request(task)
            self.replay_pending.clear()
            self.replay_history.clear()
            self.sent_since.clear()
            self.lane.channels.discard(self)
            self.close_done = True


class _HttpLane:
    def __init__(self, host: str, lane_id: int):
        self.host, self.lane_id = host, lane_id
        self.channels: Set[_HttpChannel] = set()
        self.failed_until = 0.0
        self.closed = False
        self.inflight = self.queued_bytes = 0
        self.reply_buffer_bytes = 0
        self.capacity = asyncio.Condition()
        self.client = httpx.AsyncClient(
            transport=H2Transport(max_streams=MAX_LANE_REQUESTS),
            trust_env=False,
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=8, pool=REQUEST_TIMEOUT),
        )

    async def _preflight(self) -> None:
        async with self.client.stream(
            "HEAD", "https://" + self.host + "/api"
        ) as response:
            if response.http_version != "HTTP/2":
                raise ValueError(
                    "CF /api preflight negotiated " + response.http_version
                )
            if not (
                200 <= response.status_code < 300 or response.status_code in (405, 501)
            ):
                raise ConnectionError("CF HTTP request failed")

    def _has_capacity(self, length: int) -> bool:
        return (
            self.inflight < MAX_LANE_REQUESTS
            and self.queued_bytes + length <= MAX_LANE_BYTES
        )

    async def _reserve(self, length: int, wait: bool = True) -> bool:
        async with self.capacity:
            if not wait and not self._has_capacity(length):
                return False
            if wait:
                await asyncio.wait_for(
                    self.capacity.wait_for(
                        lambda: self.closed or self._has_capacity(length)
                    ),
                    REQUEST_TIMEOUT,
                )
            if self.closed:
                raise ConnectionError("H2 lane closed")
            self.inflight += 1
            self.queued_bytes += length
            return True

    async def _release(self, length: int) -> None:
        async with self.capacity:
            self.inflight -= 1
            self.queued_bytes -= length
            self.capacity.notify_all()

    async def _post(
        self,
        body: bytes,
        channel_id: int,
        replay: bool = False,
        channel: Optional[_HttpChannel] = None,
    ) -> bytes:
        buffered = 0
        receiving = False
        request_task = asyncio.current_task()

        def upload_complete():
            # The retry scheduler needs to know when the upload finished.
            if channel is not None:
                channel.sent_since[request_task] = time.monotonic()

        def response_started():
            nonlocal receiving
            if channel is not None and not receiving:
                channel.receiving_tasks.add(request_task)
                channel.last_progress = time.monotonic()
                receiving = True

        try:
            async with self.client.stream(
                "POST",
                "https://" + self.host + "/api",
                content=body,
                headers={
                    "content-type": "application/octet-stream",
                    "accept-encoding": "identity",
                },
                extensions={
                    "h2_upload_complete": upload_complete,
                    "h2_response_started": response_started,
                },
            ) as response:
                if response.http_version != "HTTP/2":
                    raise ValueError("CF /api downgraded to " + response.http_version)
                if response.status_code in (403, 404, 429, 444):
                    raise _MTProtoTransportError(
                        -response.status_code, "HTTP transport"
                    )
                if response.status_code != 200:
                    raise ConnectionError("CF HTTP request failed")
                if "text/html" in response.headers.get("content-type", "").lower():
                    raise ValueError("CF /api returned HTML instead of MTProto")
                response_started()
                length_header = response.headers.get("content-length")
                declared_length = (
                    int(length_header) if length_header is not None else None
                )
                if (
                    declared_length is not None
                    and not 0 <= declared_length <= MAX_PACKET
                ):
                    raise BufferError(
                        "H2 response Content-Length exceeds native packet bound"
                    )
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > MAX_PACKET:
                        raise BufferError("H2 response exceeds native packet bound")
                    if self.reply_buffer_bytes + len(chunk) > MAX_LANE_REPLY_BYTES:
                        raise _ReplyBufferFull(
                            "H2 lane response buffers exceeded bound"
                        )
                    self.reply_buffer_bytes += len(chunk)
                    buffered += len(chunk)
                    content.extend(chunk)
                    if channel is not None:
                        channel.last_progress = time.monotonic()
                received = len(content)
                if (
                    declared_length is not None
                    and response.headers.get("content-encoding", "identity")
                    == "identity"
                    and received != declared_length
                ):
                    raise ValueError("incomplete H2 response body")
                if content and len(content) % 4:
                    raise ValueError(
                        "CF /api response is not an aligned MTProto packet"
                    )
                if len(content) == 4:
                    (code,) = struct.unpack("<i", content)
                    if code < 0:
                        raise _MTProtoTransportError(code, "HTTP 200 payload")
                if channel is not None:
                    pass
                return bytes(content)
        except _MTProtoTransportError:
            raise
        except _ReplyBufferFull:
            raise
        except (httpx.HTTPError, OSError, ValueError, BufferError):
            self.failed_until = time.monotonic() + DOMAIN_COOLDOWN
            raise
        finally:
            self.reply_buffer_bytes -= buffered
            if receiving:
                channel.receiving_tasks.discard(request_task)

    async def close(self) -> None:
        self.closed = True
        async with self.capacity:
            self.capacity.notify_all()
        await asyncio.gather(*(channel.close() for channel in list(self.channels)))
        await self.client.aclose()


class CfH2Pool:
    def __init__(self):
        self.lanes: Dict[str, _HttpLane] = {}
        self.locks: Dict[str, asyncio.Lock] = {}
        self.failed_until: Dict[str, float] = {}
        self.setup_retry_after: Dict[int, float] = {}
        self.next_lane = self.next_channel = 0
        self.closed = False

    async def open(self, dc: int, label: str) -> Optional[_HttpChannel]:
        if self.closed:
            raise ConnectionError("H2 pool closed")
        if time.monotonic() < self.setup_retry_after.get(dc, 0):
            return None
        try:
            return await asyncio.wait_for(self._open(dc, label), SETUP_TIMEOUT)
        except asyncio.TimeoutError:
            self.setup_retry_after[dc] = time.monotonic() + DOMAIN_COOLDOWN
            return None

    async def _open(self, dc: int, label: str) -> Optional[_HttpChannel]:
        if self.closed:
            raise ConnectionError("H2 pool closed")
        if dc not in DC_DEFAULT_IPS:
            return None
        for base_domain in balancer.get_domains_for_dc(dc):
            host = "kws%d.%s" % (dc, base_domain)
            async with self.locks.setdefault(host, asyncio.Lock()):
                if self.closed:
                    raise ConnectionError("H2 pool closed")
                lane = self.lanes.get(host)
                if time.monotonic() < max(
                    self.failed_until.get(host, 0), lane.failed_until if lane else 0
                ):
                    continue
                if lane is None:
                    self.next_lane += 1
                    lane = _HttpLane(host, self.next_lane)
                    try:
                        await lane._preflight()
                    except (httpx.HTTPError, OSError, ValueError):
                        self.failed_until[host] = time.monotonic() + DOMAIN_COOLDOWN
                        await lane.close()
                        continue
                    except asyncio.CancelledError:
                        await lane.close()
                        raise
                    if self.closed:
                        await lane.close()
                        raise ConnectionError("H2 pool closed during preflight")
                    self.lanes[host] = lane
                self.next_channel += 1
                channel = _HttpChannel(lane, self.next_channel, label)
                balancer.update_domain_for_dc(dc, base_domain)
                return channel
        return None

    async def close(self) -> None:
        self.closed = True
        await asyncio.gather(*(lane.close() for lane in self.lanes.values()))
        self.lanes.clear()


async def bridge_h2(reader, writer, channel: _HttpChannel, ctx, tag: bytes) -> None:
    async def write_native(data):
        try:
            writer.write(ctx.clt_enc.update(data))
            await writer.drain()
        except OSError as exc:
            raise _NativeDeliveryError(str(exc)) from exc

    async def upload() -> None:
        while True:
            try:
                body, quick = await _read_packet(reader, ctx.clt_dec, tag)
            except OSError as exc:
                raise _NativeDeliveryError(str(exc)) from exc
            await channel.send(body, quick)

    async def download() -> None:
        while True:
            body = await channel.receive()
            if channel.closed:
                raise _NativeDeliveryError("H2 channel closed before native response")
            channel.delivering = True
            try:
                await write_native(_encode_reply(body, tag))
            finally:
                channel.delivering = False
            channel.last_progress = time.monotonic()
            channel._wake_receiver()

    tasks = [
        asyncio.create_task(upload()),
        asyncio.create_task(download()),
        asyncio.create_task(channel._recover()),
    ]
    try:
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        if channel.transport_error is not None:
            await write_native(
                _encode_reply(struct.pack("<i", channel.transport_error), tag)
            )
        else:
            for task in done:
                task.result()
    except asyncio.IncompleteReadError:
        pass
    except _NativeDeliveryError:
        pass
    except (httpx.HTTPError, OSError, ValueError, BufferError, asyncio.TimeoutError):
        if not channel.closed:
            pass
    finally:
        await channel.close()
