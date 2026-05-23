# Simple Forward Auth

Простой сервис **forward authentication** для защиты веб-приложений PIN-кодом. Интегрируется с Caddy через директиву `forward_auth`.

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

`AUTH_DOMAIN` должен совпадать с доменом, на который проксируется сам сервис (блок `auth.*` в Caddyfile).

### Caddyfile

Общий snippet для переиспользования:

```caddy
(auth) {
	forward_auth forward-auth:8080 {
		uri /
	}
}
```

Пример:

```caddy
(auth) {
	forward_auth forward-auth:8080 {
		uri /
	}
}

auth.example.com {
	reverse_proxy forward-auth:8080
}

logs.example.com {
	reverse_proxy dozzle:8080
	import auth
}

git.example.com {
	reverse_proxy forgejo:3000
}

task.example.com {
	reverse_proxy youtrack:8080
}

stats.example.com {
	reverse_proxy umami:3000
}
```

В `docker-compose.yml` для этого случая: `AUTH_DOMAIN=https://auth.example.com`.

Защита только там, где нужна — `import auth`. Остальные сайты (`git`, `task`, `stats`) остаются открытыми.

Как это работает:

1. Запрос на защищённый сайт (`logs.example.com`) уходит в `forward-auth`.
2. Если cookie нет — редирект на `auth.example.com/?redirect=...`.
3. После ввода PIN cookie ставится на `.example.com` и работает на всех поддоменах.
4. Повторный запрос проходит, Caddy проксирует трафик в приложение.

`copy_headers` не нужен — Caddy сам передаёт `X-Forwarded-Proto`, `X-Forwarded-Host` и `X-Forwarded-Uri`.

### Запуск

```bash
docker network create proxy   # если ещё не создана
docker compose up -d
```

## Конфигурация

| Переменная       | Описание                                              | По умолчанию                         |
| ---------------- | ----------------------------------------------------- | ------------------------------------ |
| `AUTH_PASSWORD`  | PIN-код, минимум 4 цифры                              | `1234`                               |
| `SESSION_SECRET` | Ключ подписи cookie, минимум 32 байта                 | `secret-key-32-bytes-long-minimum`   |
| `AUTH_DOMAIN`    | URL сервиса входа, например `https://auth.example.com` | `http://auth.example.com`          |

Cookie domain вычисляется из `AUTH_DOMAIN`: для `auth.example.com` будет `.example.com`.

## Участие в разработке

Issues и PR приветствуются: [github.com/WEBzaytsev/forward-auth](https://github.com/WEBzaytsev/forward-auth).
