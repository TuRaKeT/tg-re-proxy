# tg-re-proxy

[Русский](README.md)

A transparent Telegram transport proxy for Linux gateways, based on
[tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy). Clients use their normal
gateway connection; no proxy configuration inside Telegram is required.

## How it works

1. `nftables` or `iptables` redirects a TCP connection to the proxy.
2. `SO_ORIGINAL_DST` supplies the destination; the Obfuscated2 handshake supplies the DC.
3. The proxy forwards the stream over Telegram WebSocket, CF transport or TCP fallback.
4. DC203 is preserved in the MTProto handshake; its WS hostname uses DC2.

The proxy replaces **transport obfuscation**, not Telegram's message encryption.
It reads transport headers to route connections and preserve packet boundaries.
It does not analyze message or file contents.

## Privacy

- No telemetry, analytics, installation identifiers or reports to the developer.
- No client, IP address, request, traffic-volume or session-duration logs.
- No statistics or diagnostic modules, traffic recording mode or files containing
  user data. `TG_RE_PROXY_DEBUG` does not enable tracking.
- No background configuration-update requests. CF endpoints are listed in plain
  text in `tg_re_proxy/config.py` and can be replaced through environment variables.
- Only active connection state remains in memory: queues, buffer limits and a
  bounded encrypted-packet buffer for retransmission. These support delivery and
  are released when the connection closes.

Network connections go to Telegram and the selected CF gateways. The optional
SOCKS relay requires explicit configuration. Those network operators see normal
transport traffic; the proxy sends no additional usage information. Availability
depends on the selected gateways.

## Run

Requires Linux, Python 3.12+ and traffic redirection on the gateway.
The implementation is a package: downloading `transparent.py` alone is insufficient.

```sh
git clone https://github.com/TuRaKeT/tg-re-proxy.git
cd tg-re-proxy
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -B transparent.py
```

Docker:

```sh
docker build -t tg-re-proxy .
docker run --rm --name tg-re-proxy --network host tg-re-proxy
```

The listener uses TCP port 1444. Transparent interception requires Linux host
networking to recover the original destination. The program does not install or
change network rules.

## Configuration

| Variable | Default / purpose |
|---|---|
| `TG_RE_PROXY_HOST` | `0.0.0.0` — listener address |
| `TG_RE_PROXY_PORT` | `1444` |
| `TG_RE_PROXY_DC_IPS` | `2:149.154.167.220 4:149.154.167.220` — public Telegram WS gateway addresses |
| `TG_RE_PROXY_POOL_SIZE` | `4` — WS pool size |
| `TG_RE_PROXY_BUF_KB` | `256` — socket buffer size in KiB |
| `TG_RE_PROXY_CFPROXY_DOMAINS` | Custom CF domains replacing the built-in list |
| `TG_RE_PROXY_CF_WORKER` | Custom worker; unset by default |
| `TG_RE_PROXY_NO_CFPROXY` | `1` — disable CF fallback |
| `TG_RE_PROXY_NO_H2` | `1` — disable HTTP/2 media transport |
| `TG_RE_PROXY_NO_SECURE` | `1` — use unencrypted HTTP for CF transport; TLS is the default |
| `TG_RE_PROXY_SOCKS` | Unset: non-MTProto relay disabled. Set `HOST:PORT` to enable |
| `TG_RE_PROXY_FORCE_TEST_DC` | `1` — use test DCs |

## Gateway integration

Clients must send traffic through the Linux gateway running the proxy. Configure
TCP redirects for the relevant Telegram networks and ports 80, 443, 5222 to port
1444. Outgoing connections from the proxy itself must not enter the redirect.
Account for IPv6 separately if your network provides it.

Transparent Obfuscated2 transport is supported. UDP calls and arbitrary
protocols are not automatically converted into WS traffic. Unrecognized
connections are closed when the optional SOCKS relay is disabled.

## Tests

```sh
python -B -m unittest discover -s tests
```

Tests cover transport encryption and forwarding, DC203, HTTP/2 flow control,
cancellation and absence of logging. They use synthetic data and a local TLS
server; no Telegram connection is required.

MIT license; original implementation by Flowseal/tg-ws-proxy.
