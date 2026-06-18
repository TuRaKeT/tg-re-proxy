# tg-re-proxy

[Читать на русском](README.md)

**tg-re-proxy** is a fork of the original [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy), adapted to run in transparent proxy mode (via `iptables`/`ufw` redirection) as a standalone script with a minimal resource footprint.

It intercepts and bypasses Telegram blocks at the network gateway level, requiring zero configuration on client devices.

### Supported Platforms:
* **Raspberry Pi** (or any other single-board computer)
* **Compatible routers** (OpenWRT, Keenetic with Entware, MikroTik RouterOS v7+)
* **Personal computers (Linux)** (for redirecting local or shared network traffic)

---

## ❓ Differences from Original tg-ws-proxy

The original project requires configuring SOCKS5/HTTP/MTProto proxy settings in the Telegram client on each device. This leads to critical issues:
1. **Inability to Install on iOS/iPadOS:** Unlike Android (via Termux) or PC, iOS restrictions make it impossible to run the proxy server locally on the device. The only option is to run it on an external device (e.g., Raspberry Pi).
2. **"Leaving Network" UX Issue:** Since the proxy runs on an external home server, the local IP address configured in Telegram (e.g., `192.168.0.24`) is only reachable within your home network. When you leave the house and switch to cellular networks (LTE/5G), the local proxy becomes unavailable. Telegram hangs on connecting, requiring you to manually disable the proxy in settings.
3. **iOS Background Mode Issues:** Telegram on iOS often handles manually configured proxies poorly in the background, leading to push notification delays and slow reconnection times when opening the app.

### Advantages of `tg-re-proxy`
`tg-re-proxy` eliminates these limitations by operating in **transparent proxy mode** at the network gateway:
* **Revives Telegram for All LAN Devices with Zero-Config:** Proxy settings inside Telegram are completely disabled on all devices. Traffic from all clients in the home network is intercepted by the gateway automatically and transparently, bypassing blocks. Devices work with Telegram out-of-the-box without any manual setup.
* **Native iOS Integration:** The iOS operating system treats the connection as direct. Telegram connects instantly in the background without push notification delays.
* **Happy Eyeballs Bypass:** Blocking Telegram's IPv6 ranges at the gateway forces iOS clients to fall back to IPv4, ensuring successful traffic interception.

The gateway transparently intercepts outgoing Telegram TCP connections, parses the Obfuscated2 handshake to identify the target Datacenter (DC), and routes the traffic as follows:
* **DC 2, 4:** Directly to Telegram's official WebSocket gateways (e.g., `wss://kws2.web.telegram.org/apiws`).
* **DC 1, 3, 5:** Through a personal Cloudflare Worker (to bypass blocked DC IP addresses).

---

## ☁️ Cloudflare Worker (for DC 1, 3, 5)

Deploy your **own** worker to avoid daily free tier limits (100k requests/day) and protect metadata privacy. Worker script (requires `cloudflare:sockets` support):

```javascript
import { connect } from "cloudflare:sockets";

function toBytes(data) {
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (typeof data === "string") return new TextEncoder().encode(data);
    if (data && typeof data.arrayBuffer === "function") return data.arrayBuffer().then((ab) => new Uint8Array(ab));
    return new Uint8Array();
}

export default {
    async fetch(request) {
        if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
            return new Response("Expected websocket", { status: 426 });
        }
        const url = new URL(request.url);
        if (url.pathname !== "/apiws") return new Response("Not found", { status: 404 });

        const dst = url.searchParams.get("dst");
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();

        const socket = connect({ hostname: dst, port: 443 });
        const tcpReader = socket.readable.getReader();
        const tcpWriter = socket.writable.getWriter();

        server.addEventListener("message", async (event) => {
            try {
                await tcpWriter.write(await toBytes(event.data));
            } catch {
                try { server.close(1011, "tcp write failed"); } catch {}
            }
        });

        server.addEventListener("close", async () => {
            try { await tcpWriter.close(); } catch {}
            try { socket.close(); } catch {}
        });

        (async () => {
            try {
                while (true) {
                    const { value, done } = await tcpReader.read();
                    if (done) break;
                    if (value) server.send(value);
                }
            } catch {
            } finally {
                try { server.close(); } catch {}
                try { tcpReader.releaseLock(); } catch {}
                try { socket.close(); } catch {}
            }
        })();

        return new Response(null, { status: 101, webSocket: client });
    },
};
```

---

## 🚀 Deployment

### 1. Run via Docker Compose

```yaml
version: '3.8'

services:
  tg-re-proxy:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: tg-re-proxy
    restart: unless-stopped
    network_mode: host # Crucial for SO_ORIGINAL_DST
    environment:
      - TZ=Europe/Moscow
      - TG_RE_PROXY_HOST=0.0.0.0
      - TG_RE_PROXY_PORT=1444
      - TG_RE_PROXY_CF_WORKER=your-worker.your-username.workers.dev # Your worker domain from the step above
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
```

### 2. Run Directly on a Router (Without Docker)

With native OpenSSL (`libcrypto.so`) auto-loading via `ctypes`, `transparent.py` runs with zero external Python dependencies on any Linux-based router.

#### OpenWRT / Entware:
1. Install Python: `opkg update && opkg install python3-light`
2. Download the script: `curl -Lo /opt/bin/transparent.py https://raw.githubusercontent.com/TuRaKeT/tg-re-proxy/main/transparent.py`
3. Create init.d script `/etc/init.d/tg-re-proxy`:
```bash
#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command python3 /opt/bin/transparent.py
    procd_set_param env TG_RE_PROXY_HOST=0.0.0.0 TG_RE_PROXY_PORT=1444 TG_RE_PROXY_CF_WORKER=your-worker.your-username.workers.dev
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param respawn
    procd_close_instance
}
```
4. Enable and start: `chmod +x /etc/init.d/tg-re-proxy && /etc/init.d/tg-re-proxy enable && /etc/init.d/tg-re-proxy start`

#### MikroTik (RouterOS v7+ Container):
1. Import the `tg-re-proxy` image (built using the repository's Dockerfile).
2. Configure the container in `Host` network mode with port `1444` and `TG_RE_PROXY_CF_WORKER` environment variable.

---

## 🔒 Routing and Firewall Configuration

Apply these rules on the device acting as the Default Gateway for your LAN clients.

### 1. Enable IP Forwarding (Kernel)
Enable IPv4 packet routing:
```ini
# /etc/sysctl.conf
net.ipv4.ip_forward = 1
```
Apply: `sudo sysctl -p`

### 2. Port Redirection (iptables / UFW)
Append TCP traffic redirection rules to `/etc/ufw/before.rules` before the `*filter` section:

```text
*nat
:PREROUTING ACCEPT [0:0]
# Redirect Telegram traffic to tg-re-proxy
-A PREROUTING -p tcp -d 149.154.160.0/20 --dport 443 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 149.154.160.0/20 --dport 80 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 91.108.4.0/22 --dport 443 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 91.108.4.0/22 --dport 80 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 91.108.8.0/22 --dport 443 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 91.108.8.0/22 --dport 80 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 91.108.56.0/22 --dport 443 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 91.108.56.0/22 --dport 80 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 149.154.164.0/22 --dport 443 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 149.154.164.0/22 --dport 80 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 194.221.250.0/24 --dport 443 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 194.221.250.0/24 --dport 80 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 91.105.192.0/23 --dport 443 -j REDIRECT --to-ports 1444
-A PREROUTING -p tcp -d 91.105.192.0/23 --dport 80 -j REDIRECT --to-ports 1444
COMMIT
```

### 3. Disable IPv6 for Telegram
To prevent IPv6 traffic from bypassing the proxy (iOS Happy Eyeballs algorithm), reject Telegram's IPv6 subnets:
```bash
sudo ufw reject out to 2001:b28:f23d::/48
sudo ufw reject out to 2001:67c:4e8::/48
sudo ufw reject out to 2001:b28:f23f::/48
sudo ufw reject out to 2001:b28:f23c::/48
sudo ufw reject out to 2a0a:f280::/32
```

---

## ⚖️ License
This project is licensed under the MIT License, matching the original [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).
