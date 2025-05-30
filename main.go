package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorHTML := ""
	if errorMessage != "" {
		errorHTML = "<p class=\"error-message\">" + errorMessage + "</p>"
	}

	htmlEscapedRedirectUrl := strings.ReplaceAll(redirectUrl, "\"", "&quot;")

	w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background-color: #FFDAB9;
        }
        .login-container {
            background-color: rgba(255, 228, 196, 0.8);
            padding: 30px 40px;
            border-radius: 20px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.1);
            text-align: center;
            width: 340px; /* Немного шире для 4х инпутов */
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            color: #333;
            margin-bottom: 10px;
        }
        p.subtitle {
            font-size: 14px;
            color: #555;
            margin-bottom: 25px;
        }
        .pin-input-container {
            display: flex;
            justify-content: center; /* Распределяем инпуты по центру */
            gap: 10px; /* Промежуток между инпутами */
            margin-bottom: 25px;
        }
        .pin-digit-input {
            width: 50px;  /* Ширина каждого блока */
            height: 60px; /* Высота каждого блока */
            font-size: 24px;
            text-align: center;
            border: 1px solid #ddd;
            border-radius: 10px; /* Скругление углов */
            box-sizing: border-box;
            caret-color: transparent; /* Скрываем курсор, если точка уже есть */
        }
        .pin-digit-input:focus {
            border-color: #FF8C00; /* Оранжевая рамка при фокусе */
            outline: none;
            box-shadow: 0 0 5px rgba(255, 140, 0, 0.5);
        }
        /* Стилизация для заполненного поля, похожего на точку */
        .pin-digit-input.filled {
            font-size: 30px; /* Размер точки */
            line-height: 60px; /* Вертикальное выравнивание точки */
        }

        input[type="hidden"] { display: none; }
        button[type="submit"] {
            width: 100%%;
            padding: 12px;
            font-size: 16px;
            font-weight: 600;
            background-color: #FF8C00;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
            margin-top: 10px; 
        }
        button[type="submit"]:hover {
            background-color: #FFA500;
        }
        .error-message {
            color: #D8000C;
            background-color: #FFD2D2;
            border: 1px solid #D8000C;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 15px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Здравствуйте!</h1> 
        <p class="subtitle">Введите PIN-код для входа</p>
        <form method="POST">
            %s 
            <div class="pin-input-container">
                <input type="text" class="pin-digit-input" id="pin1" maxlength="1" pattern="[0-9]" inputmode="numeric">
                <input type="text" class="pin-digit-input" id="pin2" maxlength="1" pattern="[0-9]" inputmode="numeric">
                <input type="text" class="pin-digit-input" id="pin3" maxlength="1" pattern="[0-9]" inputmode="numeric">
                <input type="text" class="pin-digit-input" id="pin4" maxlength="1" pattern="[0-9]" inputmode="numeric">
            </div>
            <input type="hidden" name="password" id="actualPasswordInput"> <!-- Сюда JS будет класть PIN -->
            <input type="hidden" name="redirect_url" value="%s">
            <button type="submit">Войти</button>
        </form>
    </div>

    <script>
        const pinInputs = [document.getElementById('pin1'), document.getElementById('pin2'), document.getElementById('pin3'), document.getElementById('pin4')];
        const actualPasswordInput = document.getElementById('actualPasswordInput');

        pinInputs.forEach((input, idx) => {
            input.addEventListener('input', (e) => {
                let value = e.target.value;
                if (value.match(/^[0-9]$/)) { // Если введена цифра
                    // Вместо цифры показать точку (или оставить цифру, если так нужно)
                    // e.target.value = '●'; // Если хотим маскировать сразу точкой
                    // e.target.classList.add('filled');
                    if (idx < pinInputs.length - 1) {
                        pinInputs[idx + 1].focus();
                    }
                } else { // Если введено что-то не то (или пусто)
                    e.target.value = ''; // Очистить, если не цифра
                    // e.target.classList.remove('filled');
                }
                updateActualPassword();
            });

            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace') {
                    if (input.value === '' && idx > 0) {
                        // Если поле уже пустое и это не первое поле, перейти к предыдущему
                        pinInputs[idx - 1].focus();
                        pinInputs[idx - 1].value = ''; // Очищаем предыдущее для повторного ввода
                        // pinInputs[idx - 1].classList.remove('filled');
                    } else {
                        // Если поле не пустое, Backspace его очистит. 
                        // 'input' событие после этого не всегда надежно на некоторых браузерах для Backspace,
                        // поэтому можно добавить небольшую задержку для обновления.
                        setTimeout(() => {
                            // input.classList.remove('filled');
                            updateActualPassword();
                        }, 0);
                    }
                }
            });
            
            // Предотвращаем ввод нечисловых символов, если pattern и inputmode не сработали
            input.addEventListener('keypress', (e) => {
                if (!e.key.match(/^[0-9]$/) && !e.ctrlKey && !e.metaKey && e.key !== 'Backspace' && e.key !== 'Delete' && e.key !== 'ArrowLeft' && e.key !== 'ArrowRight' && e.key !== 'Tab') {
                    e.preventDefault();
                }
            });
        });

        function updateActualPassword() {
            let pin = '';
            pinInputs.forEach(input => {
                // Если мы использовали '●' для маскировки, нужно брать data-value или что-то такое.
                // Сейчас берем прямое значение, предполагая, что там цифры.
                pin += input.value; 
            });
            actualPasswordInput.value = pin;
        }

        // Начальный фокус
        if (pinInputs.length > 0) {
            pinInputs[0].focus();
        }
    </script>
</body>
</html>`, errorHTML, htmlEscapedRedirectUrl)))
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