# Simple Forward Auth

Сервис **forward authentication** для защиты self-hosted веб-приложений общим кодом доступа.
Работает только с **Caddy** через директиву `forward_auth`.

Стек: Next.js 16, HeroUI v3, Tailwind v4, pnpm. Образ: distroless, non-root.

## Путь пользователя

Типичный сценарий — сотрудник открывает защищённый сервис (например `app.example.com`):

1. Caddy перехватывает запрос и спрашивает forward-auth: «есть ли сессия?»
2. Сессии нет — браузер перенаправляется на сервис входа (`auth.example.com`)
3. Пользователь видит экран «Подтвердите доступ» и вводит код доступа
4. Если включён TOTP (`TOTP_SECRET`) — второй шаг: 6-значный код из приложения-аутентификатора
5. После проверки браузер получает `httpOnly`-cookie и возвращается в запрошенный сервис
6. Дальше защищённые сервисы на том же домене открываются без повторного ввода кода

Прямой заход на `auth.example.com` с активной сессией показывает экран «Доступ открыт» с кнопкой «Выйти».

## Что видит пользователь

| Ситуация | Экран | Действие |
| -------- | ----- | -------- |
| Нет сессии, редирект с защищённого сервиса | Подтвердите доступ | Ввести код доступа |
| TOTP включён | Второй шаг после кода | Ввести код из аутентификатора |
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
- **`AUTH_TOKEN_EPOCH`** — аварийный рубильник. Установите в `date +%s`, чтобы мгновенно завершить все сессии без ротации секрета. Это основной способ реагирования на компрометацию инфраструктуры.
- **`TOTP_SECRET`** (опционально) — второй фактор при входе. Base32-секрет для приложения-аутентификатора (Google Authenticator, Aegis и т. п.). Если задан — после кода доступа требуется 6-значный TOTP. Защищает от кражи или фишинга кода доступа. Без секрета поведение как раньше — только код доступа.
- **`AUTH_PASSWORD`** — минимум 6 символов. На `/api/login`: per-IP rate-limit в Caddy (5/мин + 15/10 мин) и в Node (5/15 мин с lockout), глобальный прогрессивный штраф (задержка растёт с числом глобальных неудач, потолок 5 с), базовая задержка 400 мс на неверную попытку. Верный код не задерживается.
- IP для rate-limit: Caddy считает по `{client_ip}`, в Node — по `X-Real-IP`, который Caddy передаёт через `header_up`. За прокси (Cloudflare и т. п.) нужен `trusted_proxies`, иначе `{client_ip}` схлопнется в адрес edge-ноды. Подробнее — [Rate limit в Caddy](https://zaitsv.dev/blog/nastraivaem-rate-limit-v-caddy).
- **Фильтр сканеров** в `proxy.ts`: без валидной сессии блокируются известные сканеры по User-Agent (`403`). Пустой UA разрешён (Docker HEALTHCHECK). Дополнительный слой, не замена rate-limit — UA легко подделать.
- Токен читается только из cookie (`httpOnly`, `SameSite=Lax`, `Secure` в проде). Альтернативных каналов нет.
- **Заголовки безопасности** на edge выставляет Caddy (`security_headers`); приложение добавляет CSP (nonce в `proxy.ts`) и `Permissions-Policy`.
- Образ на `gcr.io/distroless/nodejs20-debian12:nonroot`: нет shell, apt, setuid-бинарников. Контейнер: non-root (uid 65532), `cap_drop: ALL`, `no-new-privileges`, `read_only`.

### Что намеренно не добавляли

- **Серверный реестр сессий** — вносит состояние в stateless/read-only дизайн, теряется при рестарте, не работает при нескольких репликах. Глобальный отзыв уже даёт `AUTH_TOKEN_EPOCH`.
- **Привязка токена к отпечатку браузера** — не защищает от XSS в том же браузере, а смена User-Agent разлогинивает легитимных пользователей.

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

Скопируйте [`Caddyfile`](Caddyfile) из репозитория — там сниппеты `(security_headers)`, `(rl)`, `(rl_login)`, `(auth)` и глобальный `order rate_limit before basicauth`. Замените `example.com` на свой домен.

Подключение forward-auth:

```caddy
(auth) {
    forward_auth forward-auth:8080 {
        uri /
    }
}

auth.example.com {
    import security_headers
    import rl auth_ui 120
    import rl_login auth
    reverse_proxy forward-auth:8080 {
        header_up X-Real-IP {client_ip}
    }
}

app.example.com {
    import security_headers
    import auth
    reverse_proxy your-app:3000
}
```

`header_up X-Real-IP {client_ip}` обязателен — Node rate-limit читает IP только из этого заголовка. За Cloudflare раскомментируйте `trusted_proxies` в глобальном блоке [`Caddyfile`](Caddyfile), иначе `{client_ip}` будет адресом edge, а не клиента. Подробнее — [Rate limit в Caddy](https://zaitsv.dev/blog/nastraivaem-rate-limit-v-caddy).

## Конфигурация

| Переменная | Описание | По умолчанию |
| ---------- | -------- | ------------ |
| `AUTH_PASSWORD` | Код доступа, минимум 6 символов, обязателен | — (fail-closed) |
| `SESSION_SECRET` | Ключ подписи cookie, минимум 32 байта, уникальный, обязателен | — (fail-closed) |
| `AUTH_DOMAIN` | URL сервиса входа, например `https://auth.example.com` | `http://localhost:8080` |
| `AUTH_TOKEN_EPOCH` | Unix-время (сек). Токены до этого момента отклоняются | `0` (отключено) |
| `TOTP_SECRET` | Base32-секрет для второго фактора (TOTP). Пусто = выключен | — (выключено) |
| `COOKIE_DOMAIN` | Явный домен cookie для многосоставных TLD (`example.co.uk`). Без ведущей точки | вычисляется из `AUTH_DOMAIN` |

Домен cookie вычисляется из `AUTH_DOMAIN`: для `auth.example.com` → `example.com`.  
При многосоставных TLD (`.co.uk`, `.com.br` и т. п.) задайте `COOKIE_DOMAIN` явно, иначе эвристика вернёт публичный суффикс и браузеры откажутся устанавливать cookie.

### Включение TOTP

```bash
# Сгенерировать base32-секрет (пример):
python3 -c "import base64, os; print(base64.b32encode(os.urandom(20)).decode())"

# Добавить в .env:
# TOTP_SECRET=JBSWY3DPEHPK3PXP...
```

Добавьте секрет в приложение-аутентификатор (тип: Time-based, 6 цифр, 30 с). После перезапуска сервиса вход потребует код доступа и TOTP.

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
