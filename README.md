# tg-re-proxy

**tg-re-proxy** (Telegram Redirect Proxy) — это прозрачный прокси-сервер для обхода блокировок Telegram на уровне роутера (например, Raspberry Pi) без необходимости настройки клиентов (мобильных устройств, ПК) в домашней сети.

Этот проект является форком оригинального [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy), адаптированным для работы в режиме прозрачного прокси (Transparent Proxy через `iptables`/`ufw` redirect) с минимальным потреблением ресурсов.

---

## ❓ Проблематика и преимущества (по сравнению с tg-ws-proxy)

### Ограничения оригинального `tg-ws-proxy`
Оригинальный прокси `tg-ws-proxy` работает в качестве классического прокси-сервера (SOCKS5/HTTP/MTProto). Чтобы им пользоваться, на **каждом** клиентском устройстве (телефоне, планшете или компьютере) необходимо вручную прописывать адрес прокси в настройках Telegram.
Это создает критические проблемы с удобством использования (UX):
1. **UX-катастрофа при выходе из дома:** Когда вы настраиваете MTProto-прокси в Telegram на работу через домашнюю Raspberry Pi (например, по локальному адресу `192.168.0.24`), всё отлично работает, пока вы дома. Но стоит вам выйти на улицу и переключиться на мобильный интернет (LTE/5G) или другой Wi-Fi, локальный адрес Pi становится недоступен. Telegram зависает без подключения. Вам приходится вручную заходить в настройки Telegram и отключать прокси. По возвращении домой процедуру нужно повторять.
2. **Невозможность установки на iOS:** На iPhone/iPad невозможно запустить серверную часть прокси локально на самом устройстве из-за ограничений ОС, поэтому установка на роутер/Pi — единственный выход. Но ручная настройка прокси-клиента в приложении приводит к проблеме №1.
3. **Проблемы с фоновым режимом на iOS:** Telegram в фоновом режиме на iOS часто некорректно работает с прописанными вручную прокси. Это приводит к задержкам push-уведомлений и долгому переподключению при открытии приложения.
4. **Обнаружение трафика:** Ручные MTProto-прокси легко обнаруживаются провайдерами по характерным сигнатурам подключения.

### Преимущества `tg-re-proxy`
`tg-re-proxy` решает эти проблемы за счет работы в режиме **прозрачного проксирования (Transparent Proxy)** на уровне сетевого шлюза (роутера):

1. **Решение проблемы «выхода из дома» (Zero-config на клиенте):** На ваших устройствах в Telegram прокси-сервер **выключен**. 
   - **Дома:** роутер сам на лету перехватывает трафик Telegram и незаметно проксирует его через WebSocket.
   - **Вне дома:** мобильное устройство подключается через сотовую сеть напрямую, без каких-либо зависаний и необходимости переключать настройки.
2. **Идеальная интеграция с iOS:** 
   - Поскольку прокси работает прозрачно на уровне роутера, операционная система iOS "думает", что работает с Telegram напрямую. В результате Telegram мгновенно подключается, не висит на «Обновлении» и стабильно получает фоновые push-уведомления.
   - Для обхода механизма **Happy Eyeballs** (когда iOS пытается быстро подключиться по IPv6 в обход IPv4-правил) в нашей схеме настраивается блокировка IPv6-подсетей Telegram на роутере. Это заставляет устройство сделать мягкий откат (fallback) на IPv4, который гарантированно перехватывается и проксируется.
3. **Монолитность и легковесность:** 
   - Весь функционал `tg-re-proxy` упакован в один компактный python-скрипт (`transparent.py`) весом всего ~23 КБ.
   - Для работы не требуются сторонние тяжелые библиотеки (скрипт умеет работать напрямую через встроенные библиотеки и системный OpenSSL).
   - Потребление оперативной памяти контейнером жестко ограничено 256 МБ (по факту потребляет значительно меньше).

---

## 🛠 Принцип работы

1. **Перехват трафика:** Сетевой экран роутера (UFW/iptables) перехватывает исходящие TCP-соединения к IP-адресам Telegram на портах `80` и `443` и перенаправляет их на порт прозрачного прокси (по умолчанию `1444`).
2. **Анализ рукопожатия (Handshake):** Прокси считывает первые 64 байта рукопожатия Obfuscated2, расшифровывает заголовки и определяет тип протокола и целевой дата-центр (DC).
3. **Разделение пакетов (MsgSplitter):** В отличие от простого TCP-моста, `tg-re-proxy` использует оригинальный парсер `MsgSplitter` для нарезки входящего TCP-потока на исходные транспортные пакеты MTProto (Abridged, Intermediate или Padded). Это критически важно, так как WebSocket-шлюзы Telegram требуют, чтобы каждый WebSocket-кадр содержал ровно один полный пакет MTProto.
4. **Проксирование через WebSocket:**
   - Соединения к **DC 2** и **DC 4** проксируются напрямую через оригинальные WebSocket-шлюзы Telegram (например, `wss://kws2.web.telegram.org/apiws`).
   - Соединения к **DC 1, 3, 5** проксируются через ваш личный **Cloudflare Worker**, чтобы обойти блокировки провайдеров.

---

## ☁️ Настройка Cloudflare Worker (для DC 1, 3, 5)

По умолчанию провайдеры могут блокировать IP-адреса некоторых дата-центров Telegram. Для обхода этой проблемы трафик к DC 1, 3 и 5 направляется через промежуточный Cloudflare Worker.

### Как развернуть Worker за 2 минуты:

1. Зарегистрируйтесь или войдите в панель [Cloudflare](https://dash.cloudflare.com/).
2. В левом меню перейдите в **Compute** ➔ **Workers & Pages**.
3. Нажмите кнопку **Create application** ➔ **Start with Hello World!** ➔ **Deploy**.
4. После успешного деплоя нажмите кнопку **Edit code** (Редактировать код) в верхнем правом углу.
5. Замените весь стандартный код в файле `worker.js` (или `index.js`) на следующий JS-скрипт:

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

        // Открываем TCP-соединение прямо из Worker
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

6. Нажмите **Deploy** в верхнем правом углу.
7. Скопируйте полученный адрес воркера (например, `your-worker.your-username.workers.dev`). Этот адрес нужно передать в прокси в переменной окружения `TG_RE_PROXY_CF_WORKER`.

---

## 🚀 Запуск через Docker Compose

Добавьте сервис в ваш `docker-compose.yml`:

```yaml
version: '3.8'

services:
  tg-re-proxy:
    image: remedycold/tg-re-proxy:latest # или соберите локально из репозитория
    build:
      context: ./tg-re-proxy
      dockerfile: Dockerfile
    container_name: tg-re-proxy
    restart: unless-stopped
    network_mode: host # Важно для перехвата трафика и SO_ORIGINAL_DST
    environment:
      - TZ=Europe/Moscow
      - TG_RE_PROXY_HOST=0.0.0.0
      - TG_RE_PROXY_PORT=1444
      - TG_RE_PROXY_CF_WORKER=your-worker.your-username.workers.dev # Ваш скопированный домен воркера
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
```

---

## 🔒 Сетевая настройка (Маршрутизация на роутере/Pi)

Для автоматического перехвата трафика клиентов без настройки VPN/прокси выполните следующие настройки:

### 1. Включение IP Forwarding (в Linux)
Убедитесь, что ядро разрешает маршрутизацию трафика. В `/etc/sysctl.conf` раскомментируйте или добавьте:
```ini
net.ipv4.ip_forward = 1
```
Примените настройки: `sudo sysctl -p`.

### 2. Правила перенаправления в Firewall (UFW)
Добавьте перехват TCP-трафика к диапазонам IP-адресов Telegram в файл правил до фильтрации (например, в `/etc/ufw/before.rules` перед секцией `*filter`):

```text
*nat
:PREROUTING ACCEPT [0:0]
# Перенаправляем трафик Telegram на порт 1444 (tg-re-proxy)
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

### 3. Блокировка IPv6 для Telegram
Чтобы клиенты (особенно iOS/macOS с протоколом Happy Eyeballs) принудительно делали откат на IPv4, заблокируйте IPv6-диапазоны Telegram в Firewall:
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
