#!/usr/bin/env python3
"""
Thin entrypoint for tg-re-proxy (transparent Telegram WS bridge proxy).

Delegates to the `tg_re_proxy` package. The real implementation lives in
`tg_re_proxy/`, which mirrors the modern tg-ws-proxy architecture (re-encryption
relay, WS/CF-worker pools, CF-proxy domain balancer and cooldowns) adapted
for transparent (secretless, SO_ORIGINAL_DST) interception.

Run directly:    python3 transparent.py
Run as module:   python3 -m tg_re_proxy.transparent
Docker:          python3 -m tg_re_proxy.transparent
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tg_re_proxy.transparent import main

if __name__ == "__main__":
    main()
