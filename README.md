# Simple Forward Auth

Сервис **forward authentication** для защиты self-hosted веб-приложений общим кодом доступа.
Работает только с **Caddy** через директиву `forward_auth`.

Стек: Next.js 16, HeroUI v3, Tailwind v4, pnpm. Образ: distroless, non-root.

## Путь пользователя

Типичный сценарий — сотрудник открывает защищённый сервис (например `app.example.com`):

1. Caddy перехватывает запрос и спрашивает forward-auth: «есть ли сессия?»
2. Сессии нет — браузер перенаправляется на сервис входа (`auth.example.com`)
3. Пользователь видит экран «Подтвердите доступ» и вводит код доступа
4. После проверки браузер получает `httpOnly`-cookie и возвращается в запрошенный сервис
5. Дальше защищённые сервисы на том же домене открываются без повторного ввода кода

Прямой заход на `auth.example.com` с активной сессией показывает экран «Доступ открыт» с кнопкой «Выйти».

## Что видит пользователь

| Ситуация | Экран | Действие |
| -------- | ----- | -------- |
| Нет сессии, редирект с защищённого сервиса | Подтвердите доступ | Ввести код доступа |
| Неверный код | Красные ячейки + текст ошибки | Проверить ввод и повторить |
| Слишком много попыток | Сообщение о лимите | Подождать минуту |
| Сессия активна, прямой заход на auth-URL | Доступ открыт | Выйти при необходимости |
| Успешный вход | — | Автоматический возврат в сервис |

Термины в интерфейсе: **код доступа** (то, что вводит пользователь), **защищённые сервисы**, **сессия**. В конфигурации тот же код задаётся переменной `AUTH_PASSWORD`.

## Как это устроено

Caddy отправляет каждый входящий запрос на `forward-auth`. Если токен валиден — сервис отвечает `200`, и запрос идёт в приложение. Если нет — редирект на страницу входа.

Cookie выставляется на регистрируемый домен (для `auth.example.com` это `.example.com`), поэтому одна сессия открывает доступ ко **всем** поддоменам контура.

> Не размещайте за этим контуром приложения с XSS или недоверенный код. Утечка cookie на любом поддомене даёт доступ ко всему контуру.

## Безопасность

- **`SESSION_SECRET`** — случайные 32+ байта, уникальные для каждого деплоя. Сгенерировать: `openssl rand -base64 48`. Сервис не стартует без ключа или с плейсхолдером.
- Подпись cookie зависит **только** от `SESSION_SECRET`. Ротация секрета мгновенно инвалидирует все токены, включая поддельные. Смена `AUTH_PASSWORD` сессии **не сбрасывает**.
- **`AUTH_TOKEN_EPOCH`** — аварийный рубильник. Установите в `date +%s`, чтобы мгновенно завершить все сессии без ротации секрета.
- **`AUTH_PASSWORD`** — минимум 6 символов. На `/api/login`: per-IP rate-limit (5 попыток/мин в Caddy + 5/15 мин в Node), глобальный прогрессивный штраф (задержка растёт с числом глобальных неудач, потолок 5 с), базовая задержка 400 мс на неверную попытку. Верный код не задерживается.
- IP для rate-limit берётся из `X-Real-IP`, который Caddy перезаписывает авторитетно. Клиент не может подменить ключ лимитирования.
- **Фильтр User-Agent** в middleware (три политики, без env): на `POST /api/login` блокируются пустой UA, CLI-инструменты, сканеры и headless-браузеры; на `forward_auth` без токена — CLI и сканеры (`403`, без redirect); на остальных маршрутах — только сканеры. Пустой UA на `GET /` разрешён (Docker HEALTHCHECK). С валидным `auth-token` UA не проверяется. Дополнительный слой, не замена rate-limit — UA легко подделать.
- Токен читается только из cookie (`httpOnly`, `SameSite=Lax`, `Secure` в проде). Альтернативных каналов нет.
- Образ на `gcr.io/distroless/nodejs20-debian12:nonroot`: нет shell, apt, setuid-бинарников. Контейнер: non-root (uid 65532), `cap_drop: ALL`, `no-new-privileges`, `read_only`.

## Требования

- **Caddy** с модулем `caddy-ratelimit` и доступом к сети контейнера.
- Docker и docker compose.
- Внешняя docker-сеть `caddy` (создаётся один раз: `docker network create caddy`).

## Деплой

### 1. Создать файл секретов `.env`

```bash
cp .env.example .env
chmod 600 .env
```

Заполнить обязательные поля:

```bash
# SESSION_SECRET — случайный ключ (генерируется автоматически):
sed -i "s|^SESSION_SECRET=.*|SESSION_SECRET=$(openssl rand -base64 48)|" .env

# AUTH_PASSWORD — код доступа для пользователей (минимум 6 символов):
#   nano .env   → AUTH_PASSWORD=ваш-надёжный-код

# AUTH_DOMAIN — ваш домен сервиса входа:
#   nano .env   → AUTH_DOMAIN=https://auth.example.com
```

> **Почему `.env`, а не `docker-compose.yaml`?**  
> Секреты в `docker-compose.yaml` попадают в git-историю при случайном коммите.  
> Файл `.env` исключён из репозитория (`.gitignore`) и имеет права `600`.  
> Docker Compose читает его через `env_file:`.  
> Не коммитьте `.env` с реальными секретами.

### 2. Запустить

По умолчанию `docker-compose.yaml` собирает образ локально:

```bash
docker network create caddy   # если ещё не создана
docker compose up -d --build
```

Для готового образа из GHCR замените в `docker-compose.yaml` секцию `build:` на:

```yaml
image: ghcr.io/WEBzaytsev/forward-auth:latest
```

Путь образа совпадает с репозиторием на GitHub (`ghcr.io/<владелец>/<имя-репо>`). После push в `main` CI публикует `:latest` автоматически.

### 3. Caddyfile

Пример в репозитории: [`Caddyfile`](Caddyfile). Минимальная схема:

```caddy
# Заголовки безопасности — на все сайты.
(security_headers) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        X-Frame-Options "DENY"
        -Server
    }
}

# Проверка доступа — на каждый защищённый сайт.
(auth) {
    forward_auth forward-auth:8080 {
        uri /
    }
}

# Сервис входа (страница с кодом доступа).
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

`header_up X-Real-IP {client_ip}` обязателен — на нём держится per-IP rate-limit в Node. `{client_ip}` в Caddy — реальный TCP-пир, клиент его не может подделать.

## Конфигурация

| Переменная | Описание | По умолчанию |
| ---------- | -------- | ------------ |
| `AUTH_PASSWORD` | Код доступа, минимум 6 символов, обязателен | — (fail-closed) |
| `SESSION_SECRET` | Ключ подписи cookie, минимум 32 байта, уникальный, обязателен | — (fail-closed) |
| `AUTH_DOMAIN` | URL сервиса входа, например `https://auth.example.com` | `http://localhost:8080` |
| `AUTH_TOKEN_EPOCH` | Unix-время (сек). Токены до этого момента отклоняются | `0` (отключено) |
| `COOKIE_DOMAIN` | Явный домен cookie для многосоставных TLD (`example.co.uk`). Без ведущей точки | вычисляется из `AUTH_DOMAIN` |

Домен cookie вычисляется из `AUTH_DOMAIN`: для `auth.example.com` → `example.com`.  
При многосоставных TLD (`.co.uk`, `.com.br` и т. п.) задайте `COOKIE_DOMAIN` явно, иначе эвристика вернёт публичный суффикс и браузеры откажутся устанавливать cookie.

## CI и Docker-образ

GitHub Actions (`.github/workflows/docker.yml`) при push в `main`:

- сканирует исходники и `Dockerfile` (Trivy);
- собирает multi-arch образ (`linux/amd64`, `linux/arm64`);
- публикует в `ghcr.io/${{ github.repository }}:latest` (для этого репо — `ghcr.io/WEBzaytsev/forward-auth:latest`).

Dependabot следит за npm, GitHub Actions и базовыми образами в `Dockerfile`.

## Хостовая безопасность (чек-лист)

- **Никогда** не монтируйте `/var/run/docker.sock` в контейнеры.
- Включите **rootless Docker** или `userns-remap` в `/etc/docker/daemon.json`.
- `daemon.json`: `"no-new-privileges": true`, `"icc": false`, `"live-restore": true`, лимиты логов (`max-size`/`max-file`).
- Обновляйте **ядро хоста** и Docker Engine.
- Не запускайте контейнеры с `--privileged` и лишними `--cap-add`.
- **Никогда** не публикуйте порт `forward-auth` наружу (`ports:` в compose). Прямой доступ обходит Caddy, ломает `X-Real-IP` и per-IP rate-limit. Сервис входа и защищаемые приложения — только во внутренних docker-сетях.
- SSH: только по ключам, `PasswordAuthentication no`, root-login off, fail2ban.

## Разработка

```bash
pnpm install
cp .env.example .env.local   # заполнить AUTH_PASSWORD и SESSION_SECRET
pnpm dev    # http://localhost:8080
pnpm build
```
