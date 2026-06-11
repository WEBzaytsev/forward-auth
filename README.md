# Simple Forward Auth

Open-source **forward authentication** service for protecting self-hosted web apps with a PIN.
Works only with **Caddy** via the `forward_auth` directive.

Stack: Next.js 16 + HeroUI v3 + Tailwind v4 + pnpm. Runtime image: distroless, non-root.

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
  (5 попыток/мин в Caddy + 5/15мин в Node), глобальный прогрессивный штраф
  (задержка растёт с числом глобальных неудач, потолок 5 с), базовая задержка
  400мс на неверную попытку. Верный PIN не задерживается.
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

### 1. Создать файл секретов `.env`

```bash
cp .env.example .env
chmod 600 .env  # только владелец может читать
```

Открыть `.env` и заполнить обязательные поля:

```bash
# SESSION_SECRET — случайный ключ (генерируется автоматически):
sed -i "s|^SESSION_SECRET=.*|SESSION_SECRET=$(openssl rand -base64 48)|" .env

# AUTH_PASSWORD — ввести вручную (минимум 6 символов):
#   nano .env   → AUTH_PASSWORD=your-strong-passphrase

# AUTH_DOMAIN — заменить example.com на свой домен:
#   nano .env   → AUTH_DOMAIN=https://auth.example.com
```

> **Почему `.env`, а не `docker-compose.yaml`?**  
> Секреты в `docker-compose.yaml` попадают в git-историю при случайном коммите.  
> Файл `.env` исключён из репозитория (`.gitignore`) и имеет ограниченные права  
> доступа `600`. Docker Compose читает его автоматически через `env_file:`.  
> Никогда не коммитьте `.env` с реальными секретами.

### 2. Запустить

По умолчанию `docker-compose.yaml` собирает образ локально из `Dockerfile`:

```bash
docker network create caddy   # если ещё не создана
docker compose up -d --build
```

Если вы публикуете или используете готовый образ из GHCR, замените в
`docker-compose.yaml` секцию `build:` на:

```yaml
image: ghcr.io/<owner>/forward-auth:latest
```

где `<owner>` — GitHub user или organization, откуда берёте образ.

### 3. Caddyfile

Пример в репозитории: [`Caddyfile`](Caddyfile). Минимальная схема:

```caddy
# Security headers — добавлять на все сайты.
(security_headers) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        X-Frame-Options "DENY"
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
| `AUTH_TOKEN_EPOCH` | Unix-время (сек). Токены до этого момента отклоняются. По умолчанию `0` | `0` (отключено)      |
| `COOKIE_DOMAIN`    | Явный домен cookie. Нужен при многосоставных TLD (`example.co.uk`). Без ведущей точки. | вычисляется из `AUTH_DOMAIN` |

Cookie domain вычисляется из `AUTH_DOMAIN`: для `auth.example.com` → `example.com`.  
При многосоставных TLD (`.co.uk`, `.com.br` и т.п.) задайте `COOKIE_DOMAIN` явно, иначе
эвристика вернёт публичный суффикс и браузеры откажутся устанавливать cookie.

## CI и Docker-образ

GitHub Actions (`.github/workflows/docker.yml`) при push в `main`:

- сканирует исходники и `Dockerfile` (Trivy);
- собирает multi-arch образ (`linux/amd64`, `linux/arm64`);
- публикует в `ghcr.io/<owner>/forward-auth:latest`, где `<owner>` — владелец репозитория.

Dependabot следит за npm, GitHub Actions и базовыми образами в `Dockerfile`.

## Хостовая безопасность (чек-лист)

- **Никогда** не монтируйте `/var/run/docker.sock` в контейнеры.
- Включите **rootless Docker** или `userns-remap` в `/etc/docker/daemon.json`.
- `daemon.json`: `"no-new-privileges": true`, `"icc": false`, `"live-restore": true`,
  лимиты логов (`max-size`/`max-file`).
- Обновляйте **ядро хоста** и Docker Engine (breakout-эксплойты бьют по kernel/runc).
- Не запускайте контейнеры с `--privileged` и лишними `--cap-add`.
- **Никогда** не публикуйте порт `forward-auth` наружу (`ports:` в compose).
  Прямой доступ обходит Caddy, ломает `X-Real-IP` и per-IP rate-limit.
  `forward-auth` и защищаемые сервисы — только во внутренних docker-сетях.
- SSH: только по ключам, `PasswordAuthentication no`, root-login off, fail2ban.

## Разработка

```bash
pnpm install
cp .env.example .env.local   # заполнить AUTH_PASSWORD и SESSION_SECRET
pnpm dev    # http://localhost:8080
pnpm build
```
