# Forward Auth Service

Минималистичный forward auth сервис для защиты selfhosted приложений на разных доменах.

## Как работает

1. Сервис проверяет токен в заголовке или куки
2. При отсутствии - редирект на AUTH_DOMAIN/login
3. После ввода пароля - редирект обратно через /callback с токеном
4. Токен сохраняется в куки на целевом домене

## Запуск

```bash
docker-compose up -d
```

## Переменные окружения

- `AUTH_PASSWORD` - пароль для авторизации (по умолчанию: 1234)
- `SESSION_SECRET` - секретный ключ для токенов (минимум 32 символа)
- `AUTH_DOMAIN` - домен авторизации (по умолчанию: http://auth.zaitsv.dev)

## Использование с Caddy

См. `Caddyfile`

## Использование с Nginx  

См. `nginx.conf`

## GitHub Actions

### GitHub Container Registry (ghcr.io)

Используйте `.github/workflows/docker.yml` - работает автоматически с GITHUB_TOKEN.

### Приватный Docker Registry

Используйте `.github/workflows/docker-private.yml` и настройте секреты:
- `DOCKER_REGISTRY` - адрес вашего registry
- `DOCKER_USERNAME` - логин
- `DOCKER_PASSWORD` - пароль или токен 