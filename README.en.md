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

### Step 2. Deploy tg-re-proxy on the Router via Docker Compose
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

### Step 3. Firewall and Routing Configuration
Configure network routing on your gateway (Raspberry Pi) to automatically redirect Telegram traffic:

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

## ⚖️ License
This project is licensed under the MIT License, matching the original [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).
