import ssl
import os
import sys

import certifi

from typing import Dict, List


ZERO_64 = b"\x00" * 64
HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_TAG_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_TAG_SECURE = b"\xdd\xdd\xdd\xdd"

PROTO_ABRIDGED_INT = 0xEFEFEFEF
PROTO_INTERMEDIATE_INT = 0xEEEEEEEE
PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD

RESERVED_FIRST_BYTES = {0xEF}
RESERVED_STARTS = {
    b"\x48\x45\x41\x44",
    b"\x50\x4f\x53\x54",
    b"\x47\x45\x54\x20",
    b"\xee\xee\xee\xee",
    b"\xdd\xdd\xdd\xdd",
    b"\x16\x03\x01\x02",
    b"\x4f\x50\x54\x49",
}
RESERVED_CONTINUE = b"\x00\x00\x00\x00"

DC_DEFAULT_IPS: Dict[int, str] = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
    203: "91.105.192.100",
}

DC_TEST_IPS: Dict[int, str] = {
    1: "149.154.175.10",
    2: "149.154.167.40",
    3: "149.154.175.117",
}

WS_PATH = "/apiws"
WS_PATH_TEST = WS_PATH + "_test"


def ws_domains(dc: int, is_media: bool) -> List[str]:
    if dc == 203:
        dc = 2
    if not is_media:
        return [f"kws{dc}.web.telegram.org"]
    return [f"kws{dc}-1.web.telegram.org", f"kws{dc}.web.telegram.org"]


def create_ssl_context(*, check_hostname: bool = True) -> ssl.SSLContext:
    bundle_dir = getattr(sys, "_MEIPASS", None)
    cafile = (
        os.path.join(bundle_dir, "certifi", "cacert.pem")
        if bundle_dir
        else certifi.where()
    )
    context = ssl.create_default_context(cafile=cafile)
    context.load_default_certs()
    context.check_hostname = check_hostname
    return context
