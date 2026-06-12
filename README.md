# Simple Forward Auth

Сервис **forward authentication** для защиты веб-приложений PIN-кодом.
Работает только с **Caddy** через директиву `forward_auth`.

Стек: Next.js 16 + HeroUI v3 + Tailwind v4 + pnpm. Образ на distroless.

## Как это работает

Caddy отправляет каждый входящий запрос на `forward-auth`. Если токен
валиден — сервис возвращает `200` и запрос проходит дальше. Если нет —
редирект на страницу входа. После ввода PIN браузер получает
`httpOnly`-cookie на корневом домене, которая даёт доступ ко всем
поддоменам.

> Cookie выставляется на регистрируемый домен (для `auth.example.com` это
> `.example.com`), поэтому одна авторизация открывает доступ ко **всем**
> поддоменам. Не размещайте за этим контуром приложения с XSS или
> недоверенный код — утечка cookie на любом поддомене означает доступ ко
> всему контуру.

## Безопасность

- **`SESSION_SECRET`** — случайные 32+ байта, уникальные для каждого деплоя.
  Сгенерировать: `openssl rand -base64 48`. Сервис не стартует без него или
  с плейсхолдером.
- Подпись cookie зависит **только** от `SESSION_SECRET`. Ротация секрета
  мгновенно инвалидирует все токены, включая поддельные. Смена `AUTH_PASSWORD`
  сессии **не сбрасывает**.
- **`AUTH_TOKEN_EPOCH`** — аварийный рубильник. Установите в `date +%s`, чтобы
  мгновенно разлогинить всех без ротации секрета.
- **`AUTH_PASSWORD`** — минимум 6 символов. На `/api/login`: per-IP rate-limit
  (5 попыток/мин в Caddy + 5/15мин в Node), глобальный лимит (100/15мин),
  задержка 400мс на неверную попытку.
- IP для rate-limit берётся из `X-Real-IP`, который Caddy перезаписывает
  авторитетно. Клиент не может подменить ключ лимитирования.
- Токен читается только из cookie (`httpOnly`, `SameSite=Lax`, `Secure` в проде).
  Альтернативных каналов нет.
- Образ на `gcr.io/distroless/nodejs20-debian12:nonroot`: нет shell, apt,
  setuid-бинарников. Контейнер: non-root (uid 65532), `cap_drop: ALL`,
  `no-new-privileges`, `read_only`.

## Требования

- **Caddy** с модулями `caddy-ratelimit` и доступом к сети контейнера.
- Docker и docker compose.
- Внешняя docker-сеть `caddy` (создаётся один раз: `docker network create caddy`).

## Деплой

### 1. Заполнить секреты в `docker-compose.yaml`

```bash
# SESSION_SECRET — генерируется автоматически
sed -i "s|SESSION_SECRET: \"\"|SESSION_SECRET: \"$(openssl rand -base64 48)\"|" docker-compose.yaml

# AUTH_PASSWORD — задать вручную (минимум 6 символов)
sed -i 's|AUTH_PASSWORD: ""|AUTH_PASSWORD: "your-password-here"|' docker-compose.yaml

# AUTH_DOMAIN — заменить на свой домен
sed -i 's|AUTH_DOMAIN: "https://auth.example.com"|AUTH_DOMAIN: "https://auth.yourdomain.com"|' docker-compose.yaml
```

### 2. Запустить

```bash
docker network create caddy   # если ещё не создана
docker compose up -d
```

### 3. Caddyfile

```caddy
# Security headers — добавлять на все сайты.
(security_headers) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        X-Frame-Options "SAMEORIGIN"
        -Server
    }
}

# Gate — импортировать на каждый защищённый сайт.
(auth) {
    forward_auth forward-auth:8080 {
        uri /
    }
}

# Сам сервис авторизации.
auth.example.com {
    import security_headers

    @login path /api/login
    rate_limit @login {
        zone login_per_ip {
            key    {client_ip}
            events 5
            window 1m
        }
    }

    reverse_proxy forward-auth:8080 {
        header_up X-Real-IP {client_ip}
    }
}

# Защищённый сервис.
app.example.com {
    import security_headers
    import auth
    reverse_proxy your-app:3000
}

# Открытый сервис — без import auth.
public.example.com {
    import security_headers
    reverse_proxy your-public-app:3000
}
```

`header_up X-Real-IP {client_ip}` обязателен — на нём держится per-IP
rate-limit в Node. `{client_ip}` в Caddy — реальный TCP-пир, клиент его
не может подделать.

## Конфигурация

| Переменная         | Описание                                                              | По умолчанию            |
| ------------------ | --------------------------------------------------------------------- | ----------------------- |
| `AUTH_PASSWORD`    | PIN-код, минимум 6 символов, обязателен                               | — (fail-closed)         |
| `SESSION_SECRET`   | Ключ подписи cookie, минимум 32 байта, уникальный, обязателен         | — (fail-closed)         |
| `AUTH_DOMAIN`      | URL сервиса входа, например `https://auth.example.com`                | `http://localhost:8080` |
| `AUTH_TOKEN_EPOCH` | Unix-время (сек). Токены до этого момента отклоняются. По умолчанию `0` | `0` (отключено)       |

Cookie domain вычисляется из `AUTH_DOMAIN`: для `auth.example.com` → `.example.com`.

## Хостовая безопасность (чек-лист)

- **Никогда** не монтируйте `/var/run/docker.sock` в контейнеры.
- Включите **rootless Docker** или `userns-remap` в `/etc/docker/daemon.json`.
- `daemon.json`: `"no-new-privileges": true`, `"icc": false`, `"live-restore": true`,
  лимиты логов (`max-size`/`max-file`).
- Обновляйте **ядро хоста** и Docker Engine (breakout-эксплойты бьют по kernel/runc).
- Не запускайте контейнеры с `--privileged` и лишними `--cap-add`.
- Защищаемые сервисы — только во внутренних docker-сетях, без публикации портов.
- SSH: только по ключам, `PasswordAuthentication no`, root-login off, fail2ban.

## Разработка

```bash
pnpm install
pnpm dev    # http://localhost:8080
pnpm build
```
