package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"net"
)

var (
	password     = getEnv("AUTH_PASSWORD", "1234")
	secret       = []byte(getEnv("SESSION_SECRET", "secret-key-32-bytes-long-minimum"))
	authDomain   = getEnv("AUTH_DOMAIN", "http://auth.zaitsv.dev")
	cookieDomain string
)

func init() {
	parsedAuthURL, err := url.Parse(authDomain)
	if err != nil {
		cookieDomain = ""
		return
	}
	hostname := parsedAuthURL.Hostname()

	if hostname == "localhost" || net.ParseIP(hostname) != nil {
		cookieDomain = hostname
	} else {
		parts := strings.Split(hostname, ".")
		if len(parts) >= 2 {
			cookieDomain = parts[len(parts)-2] + "." + parts[len(parts)-1]
		} else {
			cookieDomain = hostname
		}
	}
}

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.ListenAndServe(":8080", nil)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		cookie, _ := r.Cookie("auth-token")
		if cookie != nil {
			token = cookie.Value
		}
	}
	
	if validateToken(token) {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	originalURL := r.Header.Get("X-Original-URL")
	if originalURL == "" {
		originalURL = r.Header.Get("X-Forwarded-Proto") + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
	}
	
	loginURL := authDomain + "/login?redirect=" + url.QueryEscape(originalURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		token := ""
		cookie, err := r.Cookie("auth-token")
		if err == nil && cookie != nil {
			token = cookie.Value
		}
		if token == "" {
			token = r.Header.Get("X-Auth-Token")
		}

		if validateToken(token) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Статус</title>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f5f5f5; }
        div { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        h1 { margin-top: 0; }
        form { margin-top: 1rem; }
        button { width: 100%; padding: 0.5rem; font-size: 1rem; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #c82333; }
    </style>
</head>
<body>
    <div>
        <h1>Авторизован</h1>
        <form method="POST" action="/logout">
            <button type="submit">Выйти</button>
        </form>
    </div>
</body>
</html>`))
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход</title>
    <style>
        body { font-family: -apple-system, system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f5f5f5; }
        form { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        input { width: 200px; padding: 0.5rem; font-size: 1rem; border: 1px solid #ddd; border-radius: 4px; }
        button { margin-top: 1rem; width: 100%; padding: 0.5rem; font-size: 1rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <form method="POST">
        <input type="password" name="password" placeholder="Пароль" autofocus required>
        <button type="submit">Войти</button>
    </form>
</body>
</html>`))
	}
	
	if r.Method == "POST" {
		r.ParseForm()
		if r.FormValue("password") == password {
			originalRedirect := r.URL.Query().Get("redirect")
			
			token := generateToken()
			var callbackURL *url.URL
			var finalRedirectURL string

			// Попытка распарсить originalRedirect, чтобы понять, абсолютный ли он
			parsedOriginalRedirect, err := url.Parse(originalRedirect)

			if err == nil && parsedOriginalRedirect.IsAbs() {
				// Если originalRedirect - абсолютный URL (например, https://app-test.zaitsv.dev/)
				// Коллбэк должен быть на этом же хосте.
				callbackURL = &url.URL{
					Scheme: parsedOriginalRedirect.Scheme,
					Host:   parsedOriginalRedirect.Host,
					Path:   "/callback",
				}
				finalRedirectURL = originalRedirect // Конечный редирект - это и есть исходный URL
			} else {
				// Если originalRedirect относительный (например, "/") или отсутствует,
				// или если это был прямой заход на auth.zaitsv.dev/login
				// Коллбэк будет на authDomain.
				parsedAuthDomain, authDomainErr := url.Parse(authDomain)
				if (authDomainErr != nil) {
					// Критическая ошибка, если не можем распарсить собственный authDomain
					http.Error(w, "Internal server error: authDomain misconfiguration", http.StatusInternalServerError)
					return
				}
				callbackURL = &url.URL{
					Scheme: parsedAuthDomain.Scheme,
					Host:   parsedAuthDomain.Host,
					Path:   "/callback",
				}
				// Формируем конечный URL для редиректа. 
				// Если originalRedirect был пустым или "/", редиректим на корень authDomain.
				// Иначе, пытаемся скомбинировать authDomain с относительным путем из originalRedirect.
				if originalRedirect == "" || originalRedirect == "/" {
					finalRedirectURL = parsedAuthDomain.Scheme + "://" + parsedAuthDomain.Host + "/"
				} else {
					// Пытаемся разрешить originalRedirect относительно authDomain
					// Это полезно, если originalRedirect был, например, "/some/path"
					resolvedRedirect := parsedAuthDomain.ResolveReference(&url.URL{Path: originalRedirect})
					finalRedirectURL = resolvedRedirect.String()
				}
			}

			query := callbackURL.Query()
			query.Set("token", token)
			query.Set("redirect", finalRedirectURL) // всегда используем finalRedirectURL как значение для 'redirect' в callback
			callbackURL.RawQuery = query.Encode()
			
			http.Redirect(w, r, callbackURL.String(), http.StatusFound)
			return
		}
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		cookieToExpire := http.Cookie{
			Name:     "auth-token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1, // Expire immediately
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		if cookieDomain != "" { // Set domain if calculated
			cookieToExpire.Domain = cookieDomain
		}
		http.SetCookie(w, &cookieToExpire)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusMethodNotAllowed)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	redirect := r.URL.Query().Get("redirect")
	
	if validateToken(token) {
		cookieToSet := http.Cookie{
			Name:     "auth-token",
			Value:    token,
			Path:     "/",
			MaxAge:   86400 * 7,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		if cookieDomain != "" {
			cookieToSet.Domain = cookieDomain
		}
		http.SetCookie(w, &cookieToSet)
		
		if redirect == "" {
			redirect = "/"
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	
	http.Error(w, "Invalid token", http.StatusUnauthorized)
}

func generateToken() string {
	timestamp := time.Now().Unix()
	data := []byte(strconv.FormatInt(timestamp, 10))
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return base64.URLEncoding.EncodeToString(data) + "." + signature
}

func validateToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	
	data, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	expectedSignature := base64.URLEncoding.EncodeToString(h.Sum(nil))
	
	return hmac.Equal([]byte(parts[1]), []byte(expectedSignature))
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
} 