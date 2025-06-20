package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	password     = getEnv("AUTH_PASSWORD", "1234")
	secret       = []byte(getEnv("SESSION_SECRET", "secret-key-32-bytes-long-minimum"))
	authDomain   = getEnv("AUTH_DOMAIN", "http://auth.zaitsv.dev")
	cookieDomain string
)

func init() {
	if len(password) < 4 {
		log.Fatal("AUTH_PASSWORD must be at least 4 characters long")
	}

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
	fmt.Println("Starting forward-auth service on port 8080...")
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
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Статус Авторизации</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background-color: #F6F7F8; /* Такой же фон, как у страницы логина */
        }
        .status-container {
            background-color: #FFFFFF; /* Белый фон блока */
            padding: 30px 40px;
            border-radius: 20px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.1);
            text-align: center;
            width: 320px;
        }
        .status-container h1 {
            font-size: 24px;
            font-weight: 600;
            color: #333;
            margin-bottom: 20px;
        }
        .status-container p {
            font-size: 16px;
            color: #555;
            margin-bottom: 25px;
        }
        .status-container button {
            width: 100%;
            padding: 12px;
            font-size: 16px;
            font-weight: 600;
            background-color: #FF8C00; /* Оранжевая кнопка, как на логине */
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .status-container button:hover {
            background-color: #FFA500; /* Светлее при наведении */
        }
    </style>
</head>
<body>
    <div class="status-container">
        <h1>Авторизован</h1>
        <p>Вы успешно вошли в систему.</p>
        <form method="POST" action="/logout">
            <button type="submit">Выйти</button>
        </form>
    </div>
</body>
</html>`))
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

	var pinInputsHTMLBuilder strings.Builder
	for i := 0; i < len(password); i++ {
		pinInputsHTMLBuilder.WriteString(`<input type="text" class="pin-digit-input" maxlength="1" pattern="[0-9]" inputmode="numeric">`)
	}
	pinInputsHTML := pinInputsHTMLBuilder.String()

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
            background-color: #F6F7F8; /* Новый фон страницы */
        }
        .login-container {
            background-color: #FFFFFF; /* Новый фон блока с формой */
            padding: 30px 40px;
            border-radius: 20px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.1);
            text-align: center;
            width: 340px; 
            box-sizing: border-box;
        }
        @media (max-width: 480px) {
            .login-container {
                width: auto;
                margin-left: 20px;
                margin-right: 20px;
                padding-left: 20px;
                padding-right: 20px;
            }
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
            justify-content: center; 
            gap: 10px; 
            margin-bottom: 25px;
        }
        .pin-digit-input {
            width: 50px;  
            height: 60px; 
            font-size: 24px;
            text-align: center;
            border: 1px solid #ddd;
            border-radius: 10px; 
            box-sizing: border-box;
            caret-color: transparent; 
        }
        .pin-digit-input:focus {
            border-color: #FF8C00; 
            outline: none;
            box-shadow: 0 0 5px rgba(255, 140, 0, 0.5);
        }
        .pin-digit-input.filled {
            font-size: 30px; 
            line-height: 60px; 
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
        <p class="subtitle">Введите пароль для входа</p>
        <form method="POST" id="loginForm">
            %s 
            <div class="pin-input-container">
				%s
            </div>
            <input type="hidden" name="password" id="actualPasswordInput">
            <input type="hidden" name="redirect_url" value="%s">
            <button type="submit">Войти</button>
        </form>
    </div>

    <script>
        const pinInputs = document.querySelectorAll('.pin-digit-input');
        const actualPasswordInput = document.getElementById('actualPasswordInput');
        const loginForm = document.getElementById('loginForm'); 

        pinInputs.forEach((input, idx) => {
            input.addEventListener('input', (e) => {
                let value = e.target.value;
                
                if (value.match(/^[0-9]$/)) {
                    updateActualPassword(); 
                    if (idx < pinInputs.length - 1) {
                        pinInputs[idx + 1].focus();
                    } else {
                        if (actualPasswordInput.value.length === pinInputs.length) {
                            loginForm.submit(); 
                        }
                    }
                } else { 
                    if (value.length > 1 && value.match(/^[0-9]/)) {
                         e.target.value = value[0];
                         updateActualPassword();
                         if (idx < pinInputs.length - 1) {
                            pinInputs[idx + 1].focus();
                         } else {
                            if (actualPasswordInput.value.length === pinInputs.length) {
                                loginForm.submit();
                            }
                         }
                    } else {
                        e.target.value = ''; 
                    }
                    updateActualPassword(); 
                }
            });

            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace') {
                    if (input.value === '' && idx > 0) {
                        pinInputs[idx - 1].focus();
                        pinInputs[idx - 1].value = ''; 
                    }
                    setTimeout(() => {
                        updateActualPassword();
                    }, 0);
                }
            });
            
            input.addEventListener('keypress', (e) => {
                if (!e.key.match(/^[0-9]$/) && !e.ctrlKey && !e.metaKey && e.key !== 'Backspace' && e.key !== 'Delete' && e.key !== 'ArrowLeft' && e.key !== 'ArrowRight' && e.key !== 'Tab') {
                    e.preventDefault();
                }
            });
        });

        function updateActualPassword() {
            let pin = '';
            pinInputs.forEach(inputField => { 
                pin += inputField.value; 
            });
            actualPasswordInput.value = pin;
        }

        if (pinInputs.length > 0) {
            pinInputs[0].focus();
        }
    </script>
</body>
</html>`, errorHTML, pinInputsHTML, htmlEscapedRedirectUrl)))
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
