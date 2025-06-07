# Simple Forward Auth

Это простой сервис **forward authentication**, который позволяет защитить ваши веб-приложения паролем. Он легко интегрируется с обратными прокси, такими как Caddy, Traefik или Nginx.

## ✨ Особенности

- **Простая защита**: Защита любого количества сайтов одним паролем (PIN-кодом).
- **Легкая настройка**: Настройка с помощью переменных окружения.
- **Интеграция с Docker**: Готовый к использованию Docker-образ.
- **Современный UI**: Приятный и адаптивный интерфейс для страницы входа.
- **Поддержка поддоменов**: Автоматическая настройка cookie для работы на всех поддоменах основного домена.

## 🚀 Начало работы

Сервис предназначен для запуска в качестве Docker-контейнера.

### 1. docker-compose.yml

Создайте файл `docker-compose.yml` со следующим содержимым:

```yaml
version: '3.8'

services:
  forward-auth:
    image: ghcr.io/webzaytsev/forward-auth:latest # Используйте этот образ
    build: . # Или соберите локально
    container_name: forward-auth
    restart: unless-stopped
    environment:
      - AUTH_PASSWORD=1234
      - SESSION_SECRET=your-super-secret-key-32-bytes-long
      - AUTH_DOMAIN=https://auth.example.com
    networks:
      - proxy

networks:
  proxy:
    external: true
```

### 2. Настройка обратного прокси

Вам потребуется обратный прокси для управления трафиком.

#### Пример для Caddy (`Caddyfile`)

Caddy - это современный веб-сервер с автоматическим HTTPS.

```caddy
# Домен для самого сервиса аутентификации
auth.example.com {
    reverse_proxy forward-auth:8080
}

# Пример защищенного приложения
app.example.com {
    forward_auth forward-auth:8080 {
        uri / # Проверяет все запросы к этому сайту
        copy_headers X-Forwarded-Proto X-Forwarded-Host X-Forwarded-Uri
    }
    
    # Ваше приложение
    reverse_proxy my-app:3000
}
```

- `auth.example.com` - это домен, на котором будет доступна страница входа. Он должен соответствовать переменной `AUTH_DOMAIN`.
- `app.example.com` - это ваше приложение, которое вы хотите защитить. Директива `forward_auth` отправляет запрос на проверку в сервис `forward-auth`.

### 3. Запуск

1.  Убедитесь, что у вас создана внешняя сеть `proxy` для Caddy (`docker network create proxy`).
2.  Запустите сервисы:

```bash
docker-compose up -d
```

Теперь при попытке доступа к `app.example.com` вас перенаправит на `auth.example.com` для ввода PIN-кода. После успешного входа вы получите доступ к приложению.

## ⚙️ Конфигурация

Сервис настраивается с помощью переменных окружения:

| Переменная       | Описание                                                                                                   | Значение по умолчанию                |
| ---------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `AUTH_PASSWORD`  | Пароль (PIN-код) для доступа.                                                                              | `1234`                               |
| `SESSION_SECRET` | Секретный ключ для подписи сессионных cookie. **Обязательно измените на надежное значение (минимум 32 байта)!** | `secret-key-32-bytes-long-minimum` |
| `AUTH_DOMAIN`    | Полный URL-адрес, по которому доступен сервис аутентификации (например, `https://auth.example.com`).         | `http://auth.zaitsv.dev`             |

## 🤝 Участие в разработке

Приветствую любой вклад! Если у вас есть идеи по улучшению или вы нашли ошибку, пожалуйста, создайте [issue](https://github.com/WEBzaytsev/forward-auth/issues) или [pull request](https://github.com/WEBzaytsev/forward-auth/pulls). 