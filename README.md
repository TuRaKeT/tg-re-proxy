# tg-re-proxy

[Read in English](README.en.md)

**tg-re-proxy** (Telegram Redirect Proxy) — прозрачный прокси-сервер для перехвата и обхода блокировок Telegram на уровне сетевого шлюза (роутера) без настройки клиентских устройств. 

Форк оригинального [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy), адаптированный для работы в режиме Transparent Proxy (через перенаправление `iptables`/`ufw`) в виде автономного скрипта с минимальным потреблением ресурсов.

---

## ❓ Отличия от оригинального tg-ws-proxy

Оригинальный проект требует ручной настройки SOCKS5/HTTP/MTProto прокси в клиенте Telegram на каждом устройстве. Это приводит к критическим проблемам:
1. **Невозможность установки на iOS/iPadOS:** В отличие от Android (через Termux) или ПК, на iOS из-за ограничений системы невозможно запустить серверную часть прокси локально на самом устройстве. Единственный вариант — ставить прокси на внешнее устройство (например, Raspberry Pi).
2. **Проблема "выхода из сети" (UX-катастрофа):** Из-за необходимости держать прокси на внешнем сервере (Pi), прописанный в Telegram локальный IP-адрес (например, `192.168.0.24`) работает только в домашней сети. При выходе из дома и переключении на мобильную сеть (LTE/5G) прокси становится недоступен, Telegram зависает на подключении, и его приходится отключать в настройках приложения вручную.
3. **Проблемы фонового режима на iOS:** Telegram в фоновом режиме на iOS часто некорректно работает с настроенным вручную прокси, что приводит к задержкам push-уведомлений и долгому переподключению при открытии приложения.

### Преимущества `tg-re-proxy`
`tg-re-proxy` устраняет эти ограничения за счет работы в режиме **прозрачного проксирования (Transparent Proxy)** на уровне сетевого шлюза:
* **Оживление Telegram для всех устройств в сети с нулевыми настройками:** Прокси-сервер в Telegram на устройствах полностью выключен. Трафик всех клиентов домашней сети перехватывается шлюзом автоматически и прозрачно направляется в обход блокировок. Устройства работают с Telegram "из коробки" без изменения настроек.
* **Нативная интеграция с iOS:** Операционная система iOS считает подключение прямым. Telegram мгновенно подключается в фоновом режиме без задержек push-уведомлений.
* **Обход Happy Eyeballs:** Блокировка IPv6-подсетей Telegram на шлюзе принудительно переводит iOS-клиентов на IPv4, гарантируя перехват трафика.

Шлюз прозрачно перехватывает TCP-соединения Telegram, парсит рукопожатие Obfuscated2 для определения DC и перенаправляет трафик:
* **DC 2, 4:** Напрямую в оригинальные WebSocket-шлюзы Telegram (например, `wss://kws2.web.telegram.org/apiws`).
* **DC 1, 3, 5:** Через персональный Cloudflare Worker (для обхода блокировок IP-адресов DC).

---

## ☁️ Cloudflare Worker (для DC 1, 3, 5)

Используйте **собственный** воркер для избежания лимитов бесплатного тарифа (100k запросов/день) и обеспечения приватности метаданных трафика. Скрипт воркера (требуется поддержка `cloudflare:sockets`):

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

## 🚀 Деплой

### 1. Запуск через Docker Compose

```yaml
version: '3.8'

services:
  tg-re-proxy:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: tg-re-proxy
    restart: unless-stopped
    network_mode: host # Важно для SO_ORIGINAL_DST
    environment:
      - TZ=Europe/Moscow
      - TG_RE_PROXY_HOST=0.0.0.0
      - TG_RE_PROXY_PORT=1444
      - TG_RE_PROXY_CF_WORKER=your-worker.your-username.workers.dev # Домен воркера из шага выше
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
```

### 2. Запуск напрямую на роутере (без Docker)

Благодаря автозагрузке OpenSSL (`libcrypto.so`) через `ctypes`, `transparent.py` работает без внешних Python-зависимостей на любом Linux-устройстве.

#### OpenWRT / Entware:
1. Установите интерпретатор: `opkg update && opkg install python3-light`
2. Скачайте скрипт: `curl -Lo /opt/bin/transparent.py https://raw.githubusercontent.com/TuRaKeT/tg-re-proxy/main/transparent.py`
3. Создайте init-скрипт автозапуска `/etc/init.d/tg-re-proxy`:
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
4. Разрешите запуск: `chmod +x /etc/init.d/tg-re-proxy && /etc/init.d/tg-re-proxy enable && /etc/init.d/tg-re-proxy start`

#### MikroTik (RouterOS v7+ Container):
1. Импортируйте образ `tg-re-proxy` (собранный на базе Dockerfile из репозитория).
2. Настройте запуск контейнера в режиме `Host` с пробросом порта `1444` и переменной `TG_RE_PROXY_CF_WORKER`.

---

## 🔒 Настройка маршрутизации и брандмауэра

Настройки применяются на устройстве, выступающем в роли шлюза по умолчанию (Default Gateway) для клиентов локальной сети.

### 1. Системные настройки (sysctl)
Включите форвардинг пакетов на уровне ядра Linux:
```ini
# /etc/sysctl.conf
net.ipv4.ip_forward = 1
```
Примените изменения: `sudo sysctl -p`

### 2. Правила перенаправления (iptables / UFW)
Добавьте правила перенаправления TCP-трафика Telegram на локальный порт прокси (`1444`) в файл `/etc/ufw/before.rules` перед секцией `*filter`:

```text
*nat
:PREROUTING ACCEPT [0:0]
# Перенаправление Telegram -> tg-re-proxy
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

### 3. Отключение IPv6 для Telegram
Чтобы исключить обход прокси через IPv6 (алгоритм Happy Eyeballs на iOS), заблокируйте IPv6-диапазоны Telegram:
```bash
sudo ufw reject out to 2001:b28:f23d::/48
sudo ufw reject out to 2001:67c:4e8::/48
sudo ufw reject out to 2001:b28:f23f::/48
sudo ufw reject out to 2001:b28:f23c::/48
sudo ufw reject out to 2a0a:f280::/32
```

---

## ⚖️ Лицензия
Этот проект распространяется под лицензией MIT, как и оригинальный [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).
