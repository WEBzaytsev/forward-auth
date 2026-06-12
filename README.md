# Simple Forward Auth

Простой сервис **forward authentication** для защиты веб-приложений PIN-кодом. Интегрируется с Caddy через директиву `forward_auth`.

Стек: Next.js + HeroUI v3 + Tailwind v4 + pnpm.

## Особенности

- Один PIN-код на все защищённые сайты
- Настройка через переменные окружения
- Docker-образ: `ghcr.io/webzaytsev/forward-auth:latest`
- Cookie на корневом домене — после входа на `auth.*` доступ открывается на всех поддоменах

> Cookie выставляется на регистрируемый домен (для `auth.example.com` это
> `.example.com`), поэтому одна авторизация открывает доступ ко **всем**
> поддоменам. Это осознанный компромисс: не размещайте за этим контуром
> приложения с XSS или недоверенный код — утечка cookie на любом поддомене
> означает доступ ко всему контуру.

## Безопасность (обязательно к прочтению)

- **`SESSION_SECRET`** — случайные 32+ байта, **уникальные для каждого
  деплоя**. Сгенерировать: `openssl rand -base64 48`. Сервис не запустится с
  пустым, коротким или известным плейсхолдер-значением.
- Подпись cookie зависит **только** от `SESSION_SECRET`. Ротация секрета
  немедленно инвалидирует все выданные и любые поддельные токены. Смена одного
  лишь `AUTH_PASSWORD` сессии не сбрасывает.
- **`AUTH_PASSWORD`** — минимум 6 символов, не используйте тривиальные значения
  (`1234`, `123456`). На `/api/login` включён rate-limit с блокировкой по IP.
- Никогда не коммитьте секреты. Используйте `.env` (см. `.env.example`).
- Не публикуйте порт сервиса на хост — он должен быть доступен только Caddy
  через внутреннюю сеть `proxy`. Защищаемые backend-сервисы тоже не должны
  слушать публичные порты в обход Caddy.

## Быстрый старт

### .env

```env
AUTH_PASSWORD=<минимум 6 символов>
SESSION_SECRET=<openssl rand -base64 48>
AUTH_DOMAIN=https://auth.example.com
```

### docker-compose.yml

```yaml
services:
  forward-auth:
    image: ghcr.io/webzaytsev/forward-auth:latest
    container_name: forward-auth
    restart: unless-stopped
    environment:
      AUTH_PASSWORD: ${AUTH_PASSWORD:?set AUTH_PASSWORD in .env}
      SESSION_SECRET: ${SESSION_SECRET:?set SESSION_SECRET in .env}
      AUTH_DOMAIN: ${AUTH_DOMAIN:?set AUTH_DOMAIN in .env}
    networks:
      - proxy

networks:
  proxy:
    external: true
```

`AUTH_DOMAIN` должен совпадать с доменом, на который проксируется сам сервис, и
использовать `https` в проде, чтобы cookie передавалась только по TLS.

### Caddyfile

```caddy
(auth) {
  forward_auth forward-auth:8080 {
    uri /
  }
}

auth.example.com {
  reverse_proxy forward-auth:8080
}

# Защищённый сервис
logs.example.com {
  reverse_proxy dozzle:8080
  import auth
}

# Открытый сервис — без import auth
git.example.com {
  reverse_proxy forgejo:3000
}
```

### Заполнить секреты в docker-compose.yml

```bash
# Сгенерировать SESSION_SECRET и вставить в файл
sed -i "s|SESSION_SECRET: \"\"|SESSION_SECRET: \"$(openssl rand -base64 48)\"|" docker-compose.yaml

# AUTH_PASSWORD — задать вручную (минимум 6 символов)
sed -i 's|AUTH_PASSWORD: ""|AUTH_PASSWORD: "your-password-here"|' docker-compose.yml

# AUTH_DOMAIN — заменить на свой домен
sed -i 's|AUTH_DOMAIN: "https://auth.example.com"|AUTH_DOMAIN: "https://auth.yourdomain.com"|' docker-compose.yml
```

### Запуск

```bash
docker network create proxy   # если ещё не создана
docker compose up -d
```

## Разработка

```bash
pnpm install
pnpm dev        # http://localhost:8080
pnpm build
pnpm start
```

## Конфигурация

| Переменная       | Описание                                                          | По умолчанию          |
| ---------------- | ----------------------------------------------------------------- | --------------------- |
| `AUTH_PASSWORD`  | PIN-код, минимум 6 символов, обязателен                           | — (нет, fail-closed)  |
| `SESSION_SECRET` | Ключ подписи cookie, минимум 32 байта, уникальный, обязателен      | — (нет, fail-closed)  |
| `AUTH_DOMAIN`    | URL сервиса входа, например `https://auth.example.com`            | `http://localhost:8080` |

Cookie domain вычисляется из `AUTH_DOMAIN`: для `auth.example.com` будет `.example.com`.

## Хостовая безопасность (чек-лист)

Образ собран на distroless (нет shell/apt/setuid), запускается под non-root,
с `cap_drop: ALL`, `no-new-privileges`, `read_only` и лимитами. Побег из такого
контейнера упирается в хост и Docker-демон, поэтому проверьте на сервере:

- **Никогда** не монтируйте `/var/run/docker.sock` в контейнеры — это прямой
  путь к root на хосте. Проверьте все сервисы.
- Включите **rootless Docker** или `userns-remap` в `/etc/docker/daemon.json` —
  чтобы root внутри контейнера не совпадал с root на хосте.
- `daemon.json`: `"no-new-privileges": true`, `"icc": false`,
  `"live-restore": true`, лимиты логов (`max-size`/`max-file`).
- Регулярно обновляйте **ядро хоста** и Docker Engine — реальные breakout-эксплойты
  бьют по kernel/runc (класс CVE-2019-5736 и подобные).
- Не запускайте контейнеры с `--privileged` и лишними `--cap-add`.
- Сетевая сегментация: защищаемые сервисы — только во внутренних docker-сетях,
  без публикации портов; снаружи доступ только через Caddy.
- SSH: только по ключам (`PasswordAuthentication no`), root-login off, fail2ban.

## Участие в разработке

Issues и PR приветствуются: [github.com/WEBzaytsev/forward-auth](https://github.com/WEBzaytsev/forward-auth).
