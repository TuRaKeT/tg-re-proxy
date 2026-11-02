import asyncio
import random
import time

from collections import deque
from urllib.parse import urlencode
from typing import Dict, List, Optional, Tuple

from .raw_websocket import RawWebSocket, WsHandshakeError
from .config import proxy_config
from .utils import ws_domains, DC_DEFAULT_IPS, WS_PATH, WS_PATH_TEST


class _WsPool:
    WS_POOL_MAX_AGE = 120.0
    WS_POOL_CHECK_INTERVAL = 5.0
    REFILL_BACKOFF_INITIAL = 1.0
    REFILL_BACKOFF_MAX = 3600.0

    def __init__(self):
        self._idle: Dict[Tuple[int, bool, bool], deque] = {}
        self._refilling: Dict[Tuple[int, bool, bool], asyncio.Task] = {}
        self._rotating: Dict[Tuple[int, bool, bool], asyncio.Task] = {}
        self._refill_failures: Dict[Tuple[int, bool, bool], int] = {}
        self._refill_after: Dict[Tuple[int, bool, bool], float] = {}
        self.try_fronting_first = False

    async def get(
        self, dc: int, is_media: bool, *, is_test_dc: bool = False
    ) -> Optional[RawWebSocket]:
        target_ip = proxy_config.dc_redirects.get(dc)
        if not target_ip or proxy_config.pool_size <= 0:
            return None
        key = (dc, is_media, is_test_dc)
        domains = ws_domains(dc, is_media)
        now = time.monotonic()

        bucket = self._idle.get(key)
        if bucket is None:
            bucket = deque()
            self._idle[key] = bucket
        while bucket:
            ws, created = bucket.popleft()
            if self._is_stale(ws, created, now):
                asyncio.create_task(self._quiet_close(ws))
                continue
            self._schedule_refill(key, target_ip, domains)
            return ws

        self._schedule_refill(key, target_ip, domains)
        return None

    def _is_stale(self, ws, created, now):
        return (
            now - created >= self.WS_POOL_MAX_AGE
            or ws._closed
            or ws.writer.transport.is_closing()
            or ws.reader.at_eof()
            or ws.reader.exception() is not None
        )

    def _schedule_refill(self, key, target_ip, domains):
        if proxy_config.pool_size <= 0:
            return
        self._schedule_rotation(key, target_ip, domains)
        if key in self._refilling or time.monotonic() < self._refill_after.get(key, 0):
            return
        self._refilling[key] = asyncio.create_task(
            self._refill(key, target_ip, domains)
        )

    async def _refill(self, key, target_ip, domains):
        dc, is_media, is_test_dc = key
        tasks = []
        adopted = set()
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = proxy_config.pool_size - len(bucket)
            if needed <= 0:
                return
            connected = 0
            tasks = [
                asyncio.create_task(
                    self._connect_one(
                        target_ip, domains, WS_PATH_TEST if is_test_dc else WS_PATH
                    )
                )
                for _ in range(needed)
            ]
            for t in asyncio.as_completed(tasks):
                try:
                    ws = await t
                    if ws:
                        if self._refilling.get(key) is not asyncio.current_task():
                            return
                        bucket.append((ws, time.monotonic()))
                        adopted.add(ws)
                        connected += 1
                except Exception:
                    pass
            if connected:
                self._refill_failures.pop(key, None)
                self._refill_after.pop(key, None)
            else:
                failures = self._refill_failures.get(key, 0) + 1
                self._refill_failures[key] = failures
                delay = min(
                    self.REFILL_BACKOFF_INITIAL * (2 ** min(failures - 1, 12)),
                    self.REFILL_BACKOFF_MAX,
                )
                self._refill_after[key] = time.monotonic() + delay
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for ws in results:
                if (
                    ws is not None
                    and not isinstance(ws, BaseException)
                    and ws not in adopted
                ):
                    await self._quiet_close(ws)
            if self._refilling.get(key) is asyncio.current_task():
                self._refilling.pop(key, None)

    def _schedule_rotation(self, key, target_ip, domains):
        if key in self._rotating:
            return
        self._rotating[key] = asyncio.create_task(self._rotate(key, target_ip, domains))

    async def _rotate(self, key, target_ip, domains):
        dc, is_media, is_test_dc = key
        try:
            while proxy_config.pool_size > 0:
                bucket = self._idle.setdefault(key, deque())
                now = time.monotonic()
                expired = []
                ready = deque()
                while bucket:
                    ws, created = bucket.popleft()
                    if self._is_stale(ws, created, now):
                        expired.append(ws)
                    else:
                        ready.append((ws, created))
                bucket.extend(ready)

                if expired:
                    for ws in expired:
                        asyncio.create_task(self._quiet_close(ws))

                if len(bucket) < proxy_config.pool_size:
                    self._schedule_refill(key, target_ip, domains)

                wake_at = now + self.WS_POOL_CHECK_INTERVAL
                if bucket:
                    wake_at = min(
                        wake_at,
                        min(created + self.WS_POOL_MAX_AGE for _, created in bucket),
                    )
                if key not in self._refilling and self._refill_after.get(key, 0) > now:
                    wake_at = min(wake_at, self._refill_after[key])
                await asyncio.sleep(max(0, wake_at - time.monotonic()))
        finally:
            if self._rotating.get(key) is asyncio.current_task():
                self._rotating.pop(key, None)

    async def _connect_one(
        self, target_ip, domains, path=WS_PATH
    ) -> Optional[RawWebSocket]:
        for domain in domains:
            modes = (True, False) if self.try_fronting_first else (False, True)
            for fronted in modes:
                try:
                    ws = await RawWebSocket.connect(
                        target_ip,
                        domain,
                        timeout=7 if fronted else 8,
                        path=path,
                        sni="sprinthost.ru" if fronted else None,
                    )
                except Exception:
                    continue
                self.try_fronting_first = fronted
                if fronted:
                    pass
                return ws
        return None

    async def _quiet_close(self, ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self):
        for dc, target_ip in proxy_config.dc_redirects.items():
            if target_ip is None:
                continue
            for is_media in (False, True):
                domains = ws_domains(dc, is_media)
                key = (dc, is_media, proxy_config.force_test_dc)
                self._schedule_refill(key, target_ip, domains)

    def reset(self):
        loop = asyncio.get_running_loop()
        for task in list(self._rotating.values()) + list(self._refilling.values()):
            if not task.done() and task.get_loop() is loop:
                task.cancel()
        for bucket in self._idle.values():
            for ws, _ in bucket:
                try:
                    ws.writer.close()
                except Exception:
                    pass
        self._idle.clear()
        self._refilling.clear()
        self._rotating.clear()
        self._refill_failures.clear()
        self._refill_after.clear()
        self.try_fronting_first = False

    async def close(self):
        tasks = list(self._rotating.values()) + list(self._refilling.values())
        self.reset()
        await asyncio.gather(*tasks, return_exceptions=True)


class _CfWorkerPool:
    WS_POOL_MAX_AGE = 100.0
    PER_DC_LIMIT = 1

    def __init__(self):
        # Keyed by (dc, dst): a media client must never get a pooled
        # connection dialed to the main DC IP (and vice versa).
        self._idle: Dict[Tuple[int, str], deque] = {}
        self._refilling: Dict[Tuple[int, str], asyncio.Task] = {}
        self._exhausted_until: Dict[str, float] = {}

    async def get(
        self, dc: int, fallback_dst: str, worker_domains: List[str]
    ) -> Optional[Tuple[RawWebSocket, str]]:
        now = time.monotonic()
        key = (dc, fallback_dst)

        bucket = self._idle.get(key)
        if bucket is None:
            bucket = deque()
            self._idle[key] = bucket
        while bucket:
            ws, created, worker_domain = bucket.popleft()
            age = now - created
            if (
                age > self.WS_POOL_MAX_AGE
                or ws._closed
                or ws.writer.transport.is_closing()
            ):
                asyncio.create_task(self._quiet_close(ws))
                continue
            self._schedule_refill(dc, fallback_dst, worker_domains)
            return ws, worker_domain

        return None

    def _schedule_refill(self, dc, fallback_dst, worker_domains):
        key = (dc, fallback_dst)
        if key in self._refilling:
            return
        self._refilling[key] = asyncio.create_task(
            self._refill(key, fallback_dst, list(worker_domains))
        )

    async def _refill(self, key, fallback_dst, worker_domains):
        dc = key[0]
        try:
            bucket = self._idle.setdefault(key, deque())
            target_size = min(proxy_config.pool_size, self.PER_DC_LIMIT)
            needed = target_size - len(bucket)
            if needed <= 0:
                return

            for _ in range(needed):
                connected = await self._connect_one(worker_domains, fallback_dst, dc)
                if connected is None:
                    break
                ws, worker_domain = connected
                if self._refilling.get(key) is not asyncio.current_task():
                    await self._quiet_close(ws)
                    return
                bucket.append((ws, time.monotonic(), worker_domain))
        finally:
            if self._refilling.get(key) is asyncio.current_task():
                self._refilling.pop(key, None)

    async def _connect_one(self, worker_domains, fallback_dst, dc):
        query = urlencode(
            {
                "dst": fallback_dst,
                "dc": str(dc),
            }
        )
        path = f"/apiws?{query}"
        for worker_domain in self.available_domains(worker_domains):
            try:
                ws = await RawWebSocket.connect(
                    worker_domain,
                    worker_domain,
                    timeout=8,
                    path=path,
                    secure=not proxy_config.disable_secure,
                )
                return ws, worker_domain
            except Exception as exc:
                self.report_failure(worker_domain, exc)
        return None

    def available_domains(self, worker_domains: List[str]) -> List[str]:
        now = time.time()
        domains = []
        for domain in worker_domains:
            if domain in domains:
                continue
            exhausted_until = self._exhausted_until.get(domain, 0)
            if exhausted_until > now:
                continue
            if exhausted_until:
                self._exhausted_until.pop(domain, None)
            domains.append(domain)
        random.shuffle(domains)
        return domains

    def report_failure(self, worker_domain: str, exc: Exception) -> None:
        return  # TODO: check status code after daily limit reached
        if not isinstance(exc, WsHandshakeError) or exc.status_code != 429:
            return

        now = time.time()
        if self._exhausted_until.get(worker_domain, 0) > now:
            return
        exhausted_until = now + (86400 - (now % 86400))
        self._exhausted_until[worker_domain] = exhausted_until

    async def _quiet_close(self, ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self):
        cf_fallbacks = {
            dc: ip
            for dc, ip in DC_DEFAULT_IPS.items()
            if dc not in proxy_config.dc_redirects
        }

        if not cf_fallbacks or not proxy_config.cfproxy_worker_domains:
            return

        worker_domains = list(proxy_config.cfproxy_worker_domains)
        for dc, fallback_dst in cf_fallbacks.items():
            self._schedule_refill(dc, fallback_dst, worker_domains)

    def reset(self):
        loop = asyncio.get_running_loop()
        for task in self._refilling.values():
            if not task.done() and task.get_loop() is loop:
                task.cancel()
        for bucket in self._idle.values():
            for ws, _, _ in bucket:
                try:
                    ws.writer.close()
                except Exception:
                    pass
        self._idle.clear()
        self._refilling.clear()
        self._exhausted_until.clear()

    async def close(self):
        tasks = list(self._refilling.values())
        self.reset()
        await asyncio.gather(*tasks, return_exceptions=True)


ws_pool = _WsPool()
cf_worker_pool = _CfWorkerPool()
