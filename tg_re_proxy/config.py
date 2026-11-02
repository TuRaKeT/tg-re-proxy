import os
import socket as _socket

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# Public fallback endpoints inherited from tg-ws-proxy. No runtime downloads.
CFPROXY_DEFAULT_DOMAINS: List[str] = [
    "pclead.co.uk",
    "offshor.co.uk",
    "cakeisalie.co.uk",
    "noskomnadzor.co.uk",
    "lovetrue.co.uk",
    "sorokdva.co.uk",
    "pyatdesyatdva.co.uk",
    "kartoshka.co.uk",
    "sorokodin.co.uk",
    "pyatdesyatodin.co.uk",
    "notelega.co.uk",
    "ebally.co.uk",
    "nebally.co.uk",
    "havegreatday.co.uk",
    "pomogite.co.uk",
    "fixtelega.co.uk",
    "sadnews.co.uk",
    "onedaychamp.co.uk",
    "stopblocking.co.uk",
    "nothingthere.co.uk",
]


@dataclass
class ProxyConfig:
    # Transparent interceptor: listen on all interfaces so LAN clients
    # redirected by nft/ufw reach it; no MTProto secret (real clients).
    port: int = 1444
    host: str = "0.0.0.0"
    dc_redirects: Dict[int, str] = field(
        default_factory=lambda: {2: "149.154.167.220", 4: "149.154.167.220"}
    )
    buffer_size: int = 256 * 1024
    pool_size: int = 4
    fallback_cfproxy: bool = True
    cfproxy_user_domains: List[str] = field(default_factory=list)
    cfproxy_worker_domains: List[str] = field(default_factory=list)
    cfproxy_h2_media: bool = True
    disable_secure: bool = False
    force_test_dc: bool = False
    # Optional SOCKS5 destination for non-MTProto connections. Disabled by default.
    socks_relay: Optional[tuple] = None

    @property
    def h2_enabled(self) -> bool:
        return (
            self.cfproxy_h2_media
            and self.fallback_cfproxy
            and not self.disable_secure
            and not self.force_test_dc
        )


proxy_config = ProxyConfig()


def coerce_domain_list(value) -> List[str]:
    if isinstance(value, str):
        items = value.replace(",", " ").replace(";", " ").split()
    elif isinstance(value, (list, tuple)):
        items: List[str] = []
        for entry in value:
            if isinstance(entry, str):
                items.extend(entry.replace(",", " ").replace(";", " ").split())
    else:
        return []
    seen = set()
    result: List[str] = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, str]:
    dc_redirects: Dict[int, str] = {}
    for entry in dc_ip_list:
        if ":" not in entry:
            err = ValueError(f"Invalid --dc-ip format {entry!r}, expected DC:IP")
            err.entry = entry
            err.kind = "format"
            raise err
        dc_s, ip_s = entry.split(":", 1)
        try:
            dc_n = int(dc_s)
            _socket.inet_pton(_socket.AF_INET, ip_s)
        except (ValueError, OSError):
            err = ValueError(f"Invalid --dc-ip {entry!r}")
            err.entry = entry
            err.kind = "invalid"
            raise err from None
        dc_redirects[dc_n] = ip_s
    return dc_redirects


def load_from_env() -> None:
    """Populate proxy_config from TG_RE_PROXY_* environment variables."""
    cfg = proxy_config

    host = os.environ.get("TG_RE_PROXY_HOST", "0.0.0.0").strip()
    if host:
        cfg.host = host

    try:
        cfg.port = int(os.environ.get("TG_RE_PROXY_PORT", "1444"))
    except ValueError:
        cfg.port = 1444

    dc_raw = os.environ.get("TG_RE_PROXY_DC_IPS", "2:149.154.167.220 4:149.154.167.220")
    try:
        cfg.dc_redirects = parse_dc_ip_list(dc_raw.replace(",", " ").split())
    except ValueError:
        cfg.dc_redirects = {2: "149.154.167.220", 4: "149.154.167.220"}

    try:
        cfg.pool_size = max(0, int(os.environ.get("TG_RE_PROXY_POOL_SIZE", "4")))
    except ValueError:
        cfg.pool_size = 4

    try:
        cfg.buffer_size = (
            max(4, int(os.environ.get("TG_RE_PROXY_BUF_KB", "256"))) * 1024
        )
    except ValueError:
        cfg.buffer_size = 256 * 1024

    cfg.fallback_cfproxy = not bool(os.environ.get("TG_RE_PROXY_NO_CFPROXY", ""))

    cfg.cfproxy_user_domains = coerce_domain_list(
        os.environ.get("TG_RE_PROXY_CFPROXY_DOMAINS", "")
    )
    cfg.cfproxy_worker_domains = coerce_domain_list(
        os.environ.get("TG_RE_PROXY_CF_WORKER", "")
    )

    cfg.cfproxy_h2_media = not bool(os.environ.get("TG_RE_PROXY_NO_H2", ""))
    cfg.disable_secure = bool(os.environ.get("TG_RE_PROXY_NO_SECURE", ""))
    cfg.force_test_dc = bool(os.environ.get("TG_RE_PROXY_FORCE_TEST_DC", ""))

    socks_raw = os.environ.get("TG_RE_PROXY_SOCKS", "").strip()
    if socks_raw in ("", "0", "off", "disabled"):
        cfg.socks_relay = None
    else:
        try:
            shost, sport = socks_raw.rsplit(":", 1)
            cfg.socks_relay = (shost, int(sport))
        except ValueError:
            cfg.socks_relay = None
