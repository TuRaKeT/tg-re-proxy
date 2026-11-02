"""Privacy regressions use synthetic addresses and data only."""

import ast
import asyncio
import contextlib
import io
import logging
import os
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from tg_re_proxy import config, transparent


class PrivacyTest(unittest.TestCase):
    def test_runtime_has_no_logging_statistics_or_persistence(self):
        runtime = Path(transparent.__file__).parent
        self.assertFalse((runtime / "stats.py").exists())
        self.assertFalse((runtime / "network_debug.py").exists())
        for path in runtime.glob("*.py"):
            with self.subTest(module=path.name):
                tree = ast.parse(path.read_text())
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    func = node.func
                    if isinstance(func, ast.Name):
                        self.assertNotIn(func.id, {"open", "gethostname", "getuser"})
                    if isinstance(func, ast.Attribute):
                        self.assertNotIn(
                            func.attr,
                            {
                                "getLogger",
                                "FileHandler",
                                "RotatingFileHandler",
                                "Thread",
                                "write_text",
                                "write_bytes",
                                "peername",
                            },
                        )
                        if (
                            func.attr == "get_extra_info"
                            and node.args
                            and isinstance(node.args[0], ast.Constant)
                        ):
                            self.assertNotEqual(
                                ast.literal_eval(node.args[0]), "peername"
                            )

    def test_entrypoint_never_emits_dependency_urls_or_tracebacks(self):
        previous = logging.root.manager.disable
        self.addCleanup(logging.disable, previous)
        output, errors = io.StringIO(), io.StringIO()

        def fail(coroutine):
            coroutine.close()
            logging.getLogger("httpx").critical(
                "https://private.example.invalid/request"
            )
            raise OSError("client 192.0.2.123; private.example.invalid")

        with (
            patch.dict(os.environ, {"TG_RE_PROXY_DEBUG": "1"}),
            patch.object(transparent, "load_from_env"),
            patch.object(asyncio, "run", side_effect=fail),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            with self.assertRaises(SystemExit) as exit_result:
                transparent.main()
        self.assertEqual(exit_result.exception.code, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(
            errors.getvalue(),
            "Unable to start proxy; check the configuration and listener.\n",
        )

    def test_socks_relay_requires_explicit_configuration(self):
        previous = config.proxy_config.socks_relay
        self.addCleanup(setattr, config.proxy_config, "socks_relay", previous)
        with patch.dict(os.environ, {}, clear=True):
            config.load_from_env()
        self.assertIsNone(config.proxy_config.socks_relay)


class ConnectionPrivacyTest(unittest.IsolatedAsyncioTestCase):
    async def test_handshake_failure_does_not_read_or_log_client_address(self):
        reader = Mock()
        reader.readexactly = AsyncMock(side_effect=OSError("client 192.0.2.123"))
        writer = Mock()
        writer.wait_closed = AsyncMock()
        with (
            patch.object(transparent, "set_sock_opts"),
            self.assertNoLogs(level="DEBUG"),
        ):
            await transparent._handle_client(reader, writer)
        writer.get_extra_info.assert_not_called()
        writer.close.assert_called_once()

    async def test_disabling_cf_fallback_stops_domain_list_requests(self):
        previous = (
            config.proxy_config.fallback_cfproxy,
            config.proxy_config.cfproxy_user_domains,
        )
        self.addCleanup(setattr, config.proxy_config, "fallback_cfproxy", previous[0])
        self.addCleanup(
            setattr, config.proxy_config, "cfproxy_user_domains", previous[1]
        )
        config.proxy_config.fallback_cfproxy = False
        config.proxy_config.cfproxy_user_domains = []
        stop = asyncio.Event()
        stop.set()
        server = Mock()
        server.sockets = []
        server.serve_forever = AsyncMock(side_effect=asyncio.Event().wait)
        server.wait_closed = AsyncMock()
        with (
            patch.object(
                asyncio, "start_server", new_callable=AsyncMock, return_value=server
            ),
            patch("urllib.request.urlopen") as request,
            patch("threading.Thread") as background_thread,
            patch.object(transparent.ws_pool, "warmup", new_callable=AsyncMock),
            patch.object(transparent.cf_worker_pool, "warmup", new_callable=AsyncMock),
        ):
            await transparent._run(stop)
        request.assert_not_called()
        background_thread.assert_not_called()


if __name__ == "__main__":
    unittest.main()
