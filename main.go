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
	http.HandleFunc("/", comprehensiveRootHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.ListenAndServe(":8080", nil)
}

func comprehensiveRootHandler(w http.ResponseWriter, r *http.Request) {
	token := ""
	cookie, err := r.Cookie("auth-token")
	if err == nil && cookie != nil {
		token = cookie.Value
	}
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}
	isTokenValid := validateToken(token)

	originalURL := ""
	if r.URL.Query().Get("redirect") != "" {
		originalURL = r.URL.Query().Get("redirect")
	} else if r.Header.Get("X-Forwarded-Uri") != "" { 
		scheme := r.Header.Get("X-Forwarded-Proto")
		host := r.Header.Get("X-Forwarded-Host")
		uri := r.Header.Get("X-Forwarded-Uri")
		if scheme != "" && host != "" {
			originalURL = scheme + "://" + host + uri
		} else {
			parsedAuthDomain, _ := url.Parse(authDomain)
			if parsedAuthDomain != nil {
				originalURL = parsedAuthDomain.Scheme + "://" + parsedAuthDomain.Host + "/"
			}
		}
	} else {
		parsedAuthDomain, _ := url.Parse(authDomain)
		if parsedAuthDomain != nil {
			originalURL = parsedAuthDomain.Scheme + "://" + parsedAuthDomain.Host + "/"
		} else {
			originalURL = "/"
		}
	}

	if r.Method == "POST" {
		r.ParseForm()
		if r.FormValue("password") == password {
			newToken := generateToken()
			cookieToSet := http.Cookie{
				Name:     "auth-token",
				Value:    newToken,
				Path:     "/",
				MaxAge:   86400 * 7,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			if cookieDomain != "" {
				cookieToSet.Domain = cookieDomain
			}
			http.SetCookie(w, &cookieToSet)
			postRedirectURL := r.FormValue("redirect_url")
			if postRedirectURL == "" { 
				postRedirectURL = "/"
				parsedAuthDomain, _ := url.Parse(authDomain)
				if parsedAuthDomain != nil {
					postRedirectURL = parsedAuthDomain.Scheme + "://" + parsedAuthDomain.Host + "/"
				}
			}
			http.Redirect(w, r, postRedirectURL, http.StatusFound)
			return
		} else {
			errorMessage := "Invalid password"
			redirectURLFromForm := r.FormValue("redirect_url")
			if redirectURLFromForm == "" {
			    redirectURLFromForm = originalURL
			}
			serveLoginPage(w, redirectURLFromForm, errorMessage)
			return
		}
	}

	if isTokenValid {
		if r.Header.Get("X-Forwarded-Uri") != "" {
			w.WriteHeader(http.StatusOK)
			return
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Статус</title><style>body{font-family:-apple-system,system-ui,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5}div{background:white;padding:2rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);text-align:center}h1{margin-top:0}form{margin-top:1rem}button{width:100%;padding:0.5rem;font-size:1rem;background:#dc3545;color:white;border:none;border-radius:4px;cursor:pointer}button:hover{background:#c82333}</style></head>
<body><div><h1>Авторизован</h1><form method="POST" action="/logout"><button type="submit">Выйти</button></form></div></body></html>`))
			return
		}
	}

	parsedAuthURL, _ := url.Parse(authDomain)
	isOnAuthDomainRoot := false
	if parsedAuthURL != nil && r.Host == parsedAuthURL.Host && r.URL.Path == "/" {
		isOnAuthDomainRoot = true
	}

	if isOnAuthDomainRoot {
		serveLoginPage(w, originalURL, "") 
	} else if r.Header.Get("X-Forwarded-Uri") != "" && (parsedAuthURL == nil || r.Host != parsedAuthURL.Host) {
		loginRedirectURL := authDomain + "/?redirect=" + url.QueryEscape(originalURL)
		http.Redirect(w, r, loginRedirectURL, http.StatusFound)
	} else {
		if parsedAuthURL != nil && strings.HasPrefix(originalURL, authDomain) {
		    serveLoginPage(w, originalURL, "")
		} else {
		    loginRedirectURL := authDomain + "/?redirect=" + url.QueryEscape(originalURL)
		    http.Redirect(w, r, loginRedirectURL, http.StatusFound)
		}
	}
}

func serveLoginPage(w http.ResponseWriter, redirectUrl string, errorMessage string) {
	w.Header().Set("Content-Type", "text/html")
	errorHTML := ""
	if errorMessage != "" {
		errorHTML = "<p style='color:red;'>" + errorMessage + "</p>"
	}

	htmlEscapedRedirectUrl := strings.ReplaceAll(redirectUrl, "\"", "&quot;")

	w.Write([]byte(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Вход</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5}form{background:white;padding:2rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}input[type=password]{width:200px;padding:0.5rem;font-size:1rem;border:1px solid #ddd;border-radius:4px;margin-bottom:0.5rem}input[type=hidden]{display:none}button{margin-top:1rem;width:100%;padding:0.5rem;font-size:1rem;background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer}button:hover{background:#0056b3}</style></head>
<body><form method="POST">` + errorHTML + 
`<input type="password" name="password" placeholder="Пароль" autofocus required>
<input type="hidden" name="redirect_url" value="` + htmlEscapedRedirectUrl + `">
<button type="submit">Войти</button></form></body></html>`))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		cookieToExpire := http.Cookie{
			Name:     "auth-token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		if cookieDomain != "" {
			cookieToExpire.Domain = cookieDomain
		}
		http.SetCookie(w, &cookieToExpire)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
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