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
	// Check for token from cookie first
	token := ""
	cookie, err := r.Cookie("auth-token")
	if err == nil && cookie != nil {
		token = cookie.Value
	}

	// Try header if cookie is not found (less common for direct browser interaction, but good for API/programmatic checks)
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}

	isTokenValid := validateToken(token)

	// Determine the original URL the user was trying to access.
	// This is important for redirecting after successful login.
	originalURL := ""
	if r.URL.Query().Get("redirect") != "" {
		originalURL = r.URL.Query().Get("redirect")
	} else if r.Header.Get("X-Forwarded-Uri") != "" { // Check headers from reverse proxy
		scheme := r.Header.Get("X-Forwarded-Proto")
		host := r.Header.Get("X-Forwarded-Host")
		uri := r.Header.Get("X-Forwarded-Uri")
		if scheme != "" && host != "" {
			originalURL = scheme + "://" + host + uri
		} else {
			// Fallback or if it's a direct access to auth service without full proxy headers
			parsedAuthDomain, _ := url.Parse(authDomain)
			if parsedAuthDomain != nil {
				originalURL = parsedAuthDomain.Scheme + "://" + parsedAuthDomain.Host + "/" // Default to auth domain root
			}
		}
	} else {
		// If no redirect param and no proxy headers, assume direct access to auth service root.
		parsedAuthDomain, _ := url.Parse(authDomain)
		if parsedAuthDomain != nil {
			originalURL = parsedAuthDomain.Scheme + "://" + parsedAuthDomain.Host + "/"
		} else {
			originalURL = "/" // Absolute fallback
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

			// Redirect to the original URL after successful login
			// The 'originalURL' was submitted as a hidden field from the GET request's form
			postRedirectURL := r.FormValue("redirect_url")
			if postRedirectURL == "" { // Fallback if hidden field was missing
				postRedirectURL = "/"
				parsedAuthDomain, _ := url.Parse(authDomain)
				if parsedAuthDomain != nil {
					postRedirectURL = parsedAuthDomain.Scheme + "://" + parsedAuthDomain.Host + "/"
				}
			}
			http.Redirect(w, r, postRedirectURL, http.StatusFound)
			return
		} else {
			// Password incorrect - Show login form again with an error message
			// We need to pass the originalURL again to the template/form
			errorMessage := "Invalid password"
			serveLoginPage(w, originalURL, errorMessage)
			return
		}
	}

	// GET Request Logic from here
	if isTokenValid {
		// If X-Forwarded-Uri is present, it's likely an auth check from Caddy's forward_auth
		if r.Header.Get("X-Forwarded-Uri") != "" {
			w.WriteHeader(http.StatusOK)
			return
		} else {
			// Direct access to the auth service by an already authenticated user
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Статус</title><style>body{font-family:-apple-system,system-ui,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5}div{background:white;padding:2rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);text-align:center}h1{margin-top:0}form{margin-top:1rem}button{width:100%;padding:0.5rem;font-size:1rem;background:#dc3545;color:white;border:none;border-radius:4px;cursor:pointer}button:hover{background:#c82333}</style></head>
<body><div><h1>Авторизован</h1><form method="POST" action="/logout"><button type="submit">Выйти</button></form></div></body></html>`))
			return
		}
	}

	// If token is not valid or not present, and it's a GET request, show login page
	serveLoginPage(w, originalURL, "") // No error message initially
}

// Helper function to serve the login page HTML
func serveLoginPage(w http.ResponseWriter, redirectUrl string, errorMessage string) {
	w.Header().Set("Content-Type", "text/html")
	// Basic error display, can be improved
	errorHTML := ""
	if errorMessage != "" {
		errorHTML = "<p style='color:red;'>" + errorMessage + "</p>"
	}

	// Ensure redirectUrl is properly escaped if it's going into an HTML attribute like value
	htmlEscapedRedirectUrl := strings.ReplaceAll(redirectUrl, "\"", "&quot;") // Basic escaping for value attribute

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