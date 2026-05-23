# Simple Forward Auth

Простой сервис **forward authentication** для защиты веб-приложений PIN-кодом. Интегрируется с Caddy через директиву `forward_auth`.

Стек: Next.js + HeroUI v3 + Tailwind v4 + pnpm.

## Особенности

- Один PIN-код на все защищённые сайты
- Настройка через переменные окружения
- Docker-образ: `ghcr.io/owner/forward-auth:latest`
- Cookie на корневом домене — после входа на `auth.*` доступ открывается на всех поддоменах

## Быстрый старт

### docker-compose.yml

```yaml
services:
  forward-auth:
    image: ghcr.io/owner/forward-auth:latest
    container_name: forward-auth
    restart: unless-stopped
    environment:
      AUTH_PASSWORD: "1234"
      SESSION_SECRET: your-super-secret-key-32-bytes-long
      AUTH_DOMAIN: https://auth.example.com
    networks:
      - proxy

networks:
  proxy:
    external: true
```

`AUTH_DOMAIN` должен совпадать с доменом, на который проксируется сам сервис.

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

| Переменная       | Описание                                              | По умолчанию                           |
| ---------------- | ----------------------------------------------------- | -------------------------------------- |
| `AUTH_PASSWORD`  | PIN-код, минимум 4 символа                            | `1234`                                 |
| `SESSION_SECRET` | Ключ подписи cookie, минимум 32 байта                 | `secret-key-32-bytes-long-minimum`     |
| `AUTH_DOMAIN`    | URL сервиса входа, например `https://auth.example.com` | `http://localhost:8080`              |

Cookie domain вычисляется из `AUTH_DOMAIN`: для `auth.example.com` будет `.example.com`.

## Участие в разработке

Issues и PR приветствуются: [github.com/WEBzaytsev/forward-auth](https://github.com/WEBzaytsev/forward-auth).
