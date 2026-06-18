# tg-re-proxy

[Читать на русском](README.md)

**tg-re-proxy** (Telegram Redirect Proxy) is a transparent proxy server designed to bypass Telegram blocks at the router level (e.g., Raspberry Pi) without any configuration needed on client devices (mobiles, PCs) within your home network.

This project is a fork of the original [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy), adapted for transparent proxying (via `iptables`/`ufw` redirect) with minimal resource consumption.

---

## ❓ Problem and Advantages (Compared to tg-ws-proxy)

### Limitations of the Original `tg-ws-proxy`
The original `tg-ws-proxy` operates as a classic proxy server (SOCKS5/HTTP/MTProto). To use it, you must manually enter the proxy details in the Telegram settings on **each** client device (phone, tablet, computer).
This creates critical usability (UX) issues:
1. **Inability to Install on iOS:** It is impossible to run the server part of the proxy locally on an iPhone/iPad due to OS restrictions, making router/Pi installation the only option. However, manual client configuration in the app leads to the next problem.
2. **UX Disaster When Leaving Home:** When you configure the MTProto proxy in Telegram to work via a home Raspberry Pi (e.g., at local IP `192.168.0.24`), everything works perfectly while you are at home. But as soon as you step outside and switch to mobile data (LTE/5G) or another Wi-Fi network, the local IP becomes unreachable. Telegram hangs on connecting. You have to manually go to Telegram settings and turn off the proxy. When you return home, you must repeat the process.
3. **Background Mode Issues on iOS:** Telegram on iOS in the background often handles manually configured proxies poorly, leading to push notification delays and slow reconnection times when opening the app.

### Advantages of `tg-re-proxy`
`tg-re-proxy` solves these problems by operating in **transparent proxy mode** at the network gateway (router):

1. **"Leaving Home" Problem Solved (Zero-config on Clients):** Proxy settings inside the Telegram app on all your devices are **turned off**.
   - **At home:** The router intercepts Telegram traffic on the fly and transparently proxies it via WebSocket.
   - **Outside home:** Your mobile device connects directly through the cellular network without any connection hangs or the need to toggle settings.
2. **Seamless iOS Integration:**
   - Because the proxy operates invisibly at the gateway level, the iOS operating system treats it as a direct connection. Telegram on iPhone/iPad connects instantly, never gets stuck on "Updating," and reliably receives background push notifications.
   - To bypass the **Happy Eyeballs** mechanism (where iOS tries to connect quickly via IPv6, bypassing IPv4-only proxy rules), the setup blocks Telegram's IPv6 subnets at the router. This forces a soft fallback to IPv4, which is guaranteed to be intercepted and proxied.

---

## 🛠 How It Works

1. **Traffic Interception:** The router's firewall (UFW/iptables) intercepts outgoing TCP connections to Telegram IP ranges on ports `80` and `443` and redirects them to the transparent proxy port (default `1444`).
2. **Handshake Parsing:** The proxy reads the first 64 bytes of the client's Obfuscated2 handshake, decrypts the headers, and determines the protocol type and target Datacenter (DC).
3. **Packet Splitting (MsgSplitter):** Unlike a simple TCP bridge, `tg-re-proxy` integrates the original `MsgSplitter` parser to slice the incoming TCP stream back into original MTProto transport packets (Abridged, Intermediate, or Padded). This is critical because Telegram's WebSocket gateways strictly require each WebSocket frame to contain exactly one complete MTProto packet.
4. **Proxying via WebSocket:**
   - Connections to **DC 2** and **DC 4** are proxied directly to Telegram's original WebSocket gateways (e.g., `wss://kws2.web.telegram.org/apiws`).
   - Connections to **DC 1, 3, and 5** are proxied through your personal **Cloudflare Worker** to bypass ISP blocking.

---

## ☁️ Cloudflare Worker Setup (for DC 1, 3, 5)

ISPs often block the direct IP addresses of certain Telegram datacenters. To bypass this, traffic for DC 1, 3, and 5 is routed through a Cloudflare Worker.

### Why You Must Use Your Own (Personal) Cloudflare Worker:
1. **Free Tier Limits:** A free Cloudflare account has a limit of **100,000 requests per day**. If multiple people share a single worker, this limit is quickly exhausted, and the proxy will stop working for everyone.
2. **Privacy & Security:** Routing traffic through someone else's Cloudflare Worker theoretically allows the owner to inspect metadata and see your IP activity (even though Telegram traffic itself is encrypted via MTProto). Your own worker ensures complete privacy.
3. **Dedicated Performance:** A personal worker guarantees maximum connection speed and no latency since resources are allocated solely to your devices.

---

## 🚀 Step-by-Step Installation and Setup Guide

### Step 1. Create and Configure a Cloudflare Worker
1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. In the left panel, select **Compute** ➔ **Workers & Pages**.
3. Click **Create application** ➔ **Create Worker**.
4. Name your worker (e.g., `tg-re-proxy`) and click **Deploy**.
5. Once deployed, click **Edit code** in the top-right corner.
6. Replace the entire code in `worker.js` (or `index.js`) with the following script:

```javascript
import { connect } from "cloudflare:sockets";

function toBytes(data) {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    if (typeof data === "string") {
        return new TextEncoder().encode(data);
    }
    if (data && typeof data.arrayBuffer === "function") {
        return data.arrayBuffer().then((ab) => new Uint8Array(ab));
    }
    return new Uint8Array();
}

export default {
    async fetch(request) {
        if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
            return new Response("Expected websocket", { status: 426 });
        }

        const url = new URL(request.url);
        if (url.pathname !== "/apiws") {
            return new Response("Not found", { status: 404 });
        }

        const dst = url.searchParams.get("dst");
        const pair = new WebSocketPair();
        const client = pair[0];
        const server = pair[1];
        server.accept();

        // Open a direct TCP connection from the Worker
        const socket = connect({ hostname: dst, port: 443 });
        const tcpReader = socket.readable.getReader();
        const tcpWriter = socket.writable.getWriter();

        server.addEventListener("message", async (event) => {
            try {
                await tcpWriter.write(await toBytes(event.data));
            } catch {
                try {
                    server.close(1011, "tcp write failed");
                } catch {}
            }
        });

        server.addEventListener("close", async () => {
            try {
                await tcpWriter.close();
            } catch {}
            try {
                socket.close();
            } catch {}
        });

        (async () => {
            try {
                while (true) {
                    const { value, done } = await tcpReader.read();
                    if (done) {
                        break;
                    }
                    if (value) {
                        server.send(value);
                    }
                }
            } catch {
            } finally {
                try {
                    server.close();
                } catch {}
                try {
                    tcpReader.releaseLock();
                } catch {}
                try {
                    socket.close();
                } catch {}
            }
        })();

        return new Response(null, { status: 101, webSocket: client });
    },
};
```

7. Click **Deploy** in the top-right corner.
8. Copy the generated worker domain (e.g., `tg-re-proxy.your-username.workers.dev`).

### Step 2. Deploy tg-re-proxy on the Gateway (Raspberry Pi)
1. Clone the repository to your gateway device (e.g., Raspberry Pi):
   ```bash
   git clone https://github.com/your-username/tg-re-proxy.git
   cd tg-re-proxy
   ```
2. Create a `docker-compose.yml` file in the project directory:
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
         - TG_RE_PROXY_CF_WORKER=your-worker.your-username.workers.dev # Your domain from Step 1
       deploy:
         resources:
           limits:
             cpus: '0.5'
             memory: 256M
   ```
3. Start the container:
   ```bash
   docker compose up -d --build
   ```

### Step 3. Firewall and Routing Configuration on the Gateway
To automatically redirect Telegram traffic from home network clients to the proxy server, configure network routing on the gateway device (in this example, the Raspberry Pi):

> [!NOTE]
> For home devices (phones, PCs) to route their traffic through this gateway, you must configure your main Wi-Fi Router's DHCP server settings to specify the local IP address of your Raspberry Pi as the **Default Gateway**.

#### 1. Enable IP Forwarding
Ensure kernel routing is enabled. In `/etc/sysctl.conf`, add or uncomment:
```ini
net.ipv4.ip_forward = 1
```
Apply the changes: `sudo sysctl -p`.

#### 2. Configure Redirection Rules in UFW
Add rules to redirect TCP traffic destined for Telegram IP ranges to the proxy port. Insert the following at the beginning of `/etc/ufw/before.rules` (before the `*filter` section):

```text
*nat
:PREROUTING ACCEPT [0:0]
# Redirect Telegram traffic to port 1444 (tg-re-proxy)
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
Reload the firewall: `sudo ufw reload`.

#### 3. Block IPv6 for Telegram
To prevent mobile clients (specifically iOS using Happy Eyeballs) from bypassing the proxy via IPv6, reject Telegram's IPv6 ranges:
```bash
sudo ufw reject out to 2001:b28:f23d::/48
sudo ufw reject out to 2001:67c:4e8::/48
sudo ufw reject out to 2001:b28:f23f::/48
sudo ufw reject out to 2001:b28:f23c::/48
sudo ufw reject out to 2a0a:f280::/32
```

---

## 📟 Installation Directly on a Router (Without Docker / Raspberry Pi)

Thanks to the zero-dependency design (the script can automatically fallback to using system OpenSSL via `ctypes`), `tg-re-proxy` can be deployed directly on Linux-based routers (OpenWRT, KeeneticOS with Entware, ASUSWRT-Merlin, etc.) without Docker. This saves resources and eliminates the need for a separate single-board computer.

### 1. OpenWRT / Entware-based Routers (Keenetic, ASUS, etc.)

1. Connect to your router via SSH.
2. Install Python 3 using the package manager (`opkg`):
   ```bash
   opkg update
   opkg install python3-light
   ```
3. Download the standalone `transparent.py` script to your router (e.g., to `/opt/bin/` or `/usr/bin/`):
   ```bash
   curl -Lo /opt/bin/transparent.py https://raw.githubusercontent.com/TuRaKeT/tg-re-proxy/main/transparent.py
   chmod +x /opt/bin/transparent.py
   ```
4. To run it as a system service, create an init script. For OpenWRT, create `/etc/init.d/tg-re-proxy`:
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
   Enable and start the service:
   ```bash
   chmod +x /etc/init.d/tg-re-proxy
   /etc/init.d/tg-re-proxy enable
   /etc/init.d/tg-re-proxy start
   ```
5. Configure `iptables`/`nftables` redirection rules in your router's firewall configuration files.

### 2. MikroTik (RouterOS v7+)
If your router supports containers (ARM/x86 architecture with the `container` package enabled), you can run `tg-re-proxy` as a RouterOS container:
1. Pull the container image (or build your own using the repository's Dockerfile).
2. Configure the container in RouterOS with `TG_RE_PROXY_CF_WORKER` environment variable, exposing port `1444` in `Host` network mode.
3. Configure traffic redirection under `/ip firewall nat` using `redirect` action to port `1444`.

---

## ⚖️ License
This project is licensed under the MIT License, matching the original [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).
