package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jech/galene/group"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	_ "modernc.org/sqlite"
)

type ProviderConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type SMTPRelayConfig struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	From     string `json:"from"`
}

type Config struct {
	ListenAddr    string            `json:"listen_addr"`
	JWTSecret     string            `json:"jwt_secret"`
	RPDisplayName string            `json:"rp_display_name"`
	RPID          string            `json:"rp_id"`
	RPOrigin      string            `json:"rp_origin"`
	DBPath        string            `json:"db_path"`
	Google        ProviderConfig    `json:"google"`
	Microsoft     ProviderConfig    `json:"microsoft"`
	Apple         ProviderConfig    `json:"apple"`
	SMTPRelays    []SMTPRelayConfig `json:"smtp_relays"`
}

type User struct {
	ID          []byte
	Email       string
	DisplayName string
	Picture     string
	Credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Email }
func (u *User) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type OAuthSession struct {
	Provider  string
	CreatedAt time.Time
	ReturnTo  string
}

type OIDCClient struct {
	Key         string
	DisplayName string
	ButtonClass string
	Config      *oauth2.Config
	Verifier    *oidc.IDTokenVerifier
}

type RateLimiter struct {
	mu        sync.Mutex
	ipHits    map[string][]time.Time
	emailHits map[string]time.Time
}

func newRateLimiter() *RateLimiter {
	return &RateLimiter{
		ipHits:    make(map[string][]time.Time),
		emailHits: make(map[string]time.Time),
	}
}

func (rl *RateLimiter) Check(ip, email string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if last, exists := rl.emailHits[email]; exists {
		if now.Sub(last) < 2*time.Minute {
			return fmt.Errorf("please wait 2 minutes before requesting another verification email")
		}
	}

	hits := rl.ipHits[ip]
	cutoff := now.Add(-1 * time.Hour)
	var validHits []time.Time
	for _, t := range hits {
		if t.After(cutoff) {
			validHits = append(validHits, t)
		}
	}

	if len(validHits) >= 5 {
		return fmt.Errorf("too many verification requests from this network. please try again later")
	}

	validHits = append(validHits, now)
	rl.ipHits[ip] = validHits
	rl.emailHits[email] = now
	return nil
}

type App struct {
	cfg          *Config
	groupsPath   string
	db           *sql.DB
	webAuthn     *webauthn.WebAuthn
	oidcClients  map[string]*OIDCClient
	tmplLogin    *template.Template
	tmplVerify   *template.Template
	limiter      *RateLimiter
	sessionStore sync.Map
}

type TemplateButton struct {
	DisplayName string
	URL         string
	Class       string
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Off-Script Mamas</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/theme.css">
  <style>
    :root {
      --primary: #d85c7a;
      --bg: #fdfaf8;
      --card-bg: #ffffff;
      --text: #2b2b2b;
      --border: #e8e2de;
    }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: grid;
      place-content: center;
      min-height: 90vh;
      margin: 0;
      padding: 1rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 2.5rem 2rem;
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.04);
      width: 100%;
      max-width: 320px;
      box-sizing: border-box;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    h1 {
      font-size: 1.4rem;
      font-weight: 700;
      text-align: center;
      margin: 0 0 0.5rem 0;
      color: var(--text);
    }
    .action-btn, .oauth-btn {
      display: block;
      width: 100%;
      box-sizing: border-box;
      text-align: center;
      padding: 12px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      text-decoration: none;
      transition: opacity 0.15s ease;
    }
    .action-btn:hover, .oauth-btn:hover {
      opacity: 0.9;
    }
    .btn-passkey {
      background: var(--primary);
      color: #fff;
      border: none;
    }
    .oauth-btn {
      background: #fff;
      color: #3c4043;
      border: 1px solid #dadce0;
    }
    .btn-apple {
      background: #000;
      color: #fff;
      border: 1px solid #000;
    }
    .btn-microsoft {
      background: #2f2f2f;
      color: #fff;
      border: 1px solid #2f2f2f;
    }
    .divider {
      text-align: center;
      font-size: 12px;
      color: #888;
      margin: 0.25rem 0;
    }
    .register-box {
      border-top: 1px solid var(--border);
      padding-top: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    input[type="email"] {
      padding: 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 14px;
      box-sizing: border-box;
      width: 100%;
    }
    .btn-register {
      background: transparent;
      border: 1px solid var(--primary);
      color: var(--primary);
    }
    .msg-box {
      font-size: 12px;
      text-align: center;
      line-height: 1.4;
    }
    .msg-success { color: #2e7d32; }
    .msg-error { color: #c62828; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Off-Script Mamas</h1>
    
    <button class="action-btn btn-passkey" id="btn-login-passkey">Sign in with Passkey</button>

    {{ range .Buttons }}
      <a class="oauth-btn {{ .Class }}" href="{{ .URL }}">Sign in with {{ .DisplayName }}</a>
    {{ end }}

    <div class="register-box">
      <div class="divider">Register a new Passkey account</div>
      <input type="email" id="reg-email" placeholder="Enter your email" />
      <button class="action-btn btn-register" id="btn-send-email">Send Setup Link</button>
      <div id="status-msg" class="msg-box" style="display:none;"></div>
    </div>
  </div>

  <script>
    const returnTo = {{ .ReturnTo }};

    function bufferToBase64URL(buf) {
      return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function base64URLToBuffer(base64) {
      const padding = '='.repeat((4 - (base64.length % 4)) % 4);
      const str = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
      return Uint8Array.from(atob(str), c => c.charCodeAt(0));
    }

    document.getElementById('btn-login-passkey').addEventListener('click', async () => {
      try {
        const res = await fetch('/auth/passkey/login/begin', { method: 'POST' });
        if (!res.ok) throw new Error('Failed to initiate login');
        const options = await res.json();

        options.publicKey.challenge = base64URLToBuffer(options.publicKey.challenge);

        const assertion = await navigator.credentials.get({ publicKey: options.publicKey });
        const finishRes = await fetch('/auth/passkey/login/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: assertion.id,
            rawId: bufferToBase64URL(assertion.rawId),
            type: assertion.type,
            response: {
              authenticatorData: bufferToBase64URL(assertion.response.authenticatorData),
              clientDataJSON: bufferToBase64URL(assertion.response.clientDataJSON),
              signature: bufferToBase64URL(assertion.response.signature),
              userHandle: assertion.response.userHandle ? bufferToBase64URL(assertion.response.userHandle) : null
            }
          })
        });

        if (finishRes.ok) {
          window.location.href = returnTo;
        } else {
          const errText = await finishRes.text();
          alert('Passkey verification failed: ' + errText);
        }
      } catch (err) {
        console.error(err);
        alert('Client error: ' + err.message);
      }
    });

    document.getElementById('btn-send-email').addEventListener('click', async () => {
      const email = document.getElementById('reg-email').value.trim();
      const status = document.getElementById('status-msg');
      if (!email) {
        alert('Please enter an email address');
        return;
      }

      status.style.display = 'block';
      status.className = 'msg-box';
      status.innerText = 'Sending email...';

      try {
        const res = await fetch('/auth/register/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email })
        });

        if (res.ok) {
          status.className = 'msg-box msg-success';
          status.innerText = 'Verification email sent! Check your inbox to complete setup.';
        } else {
          const errText = await res.text();
          status.className = 'msg-box msg-error';
          status.innerText = errText || 'Failed to send verification email.';
        }
      } catch (err) {
        status.className = 'msg-box msg-error';
        status.innerText = 'Network error. Please try again.';
      }
    });
  </script>
</body>
</html>`

const verifyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Complete Setup - Off-Script Mamas</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/theme.css">
  <style>
    :root {
      --primary: #d85c7a;
      --bg: #fdfaf8;
      --card-bg: #ffffff;
      --text: #2b2b2b;
      --border: #e8e2de;
    }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: grid;
      place-content: center;
      min-height: 90vh;
      margin: 0;
      padding: 1rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 2.5rem 2rem;
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.04);
      width: 100%;
      max-width: 320px;
      box-sizing: border-box;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    h1 {
      font-size: 1.3rem;
      font-weight: 700;
      text-align: center;
      margin: 0;
      color: var(--text);
    }
    p {
      font-size: 13px;
      text-align: center;
      color: #666;
      margin: 0;
    }
    .action-btn {
      display: block;
      width: 100%;
      box-sizing: border-box;
      text-align: center;
      padding: 12px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      text-decoration: none;
      background: var(--primary);
      color: #fff;
      border: none;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>Activate Device</h1>
    <p>Email verified: <strong>{{ .Email }}</strong></p>
    <p>Create a passkey on this device to finalize your account.</p>
    <button class="action-btn" id="btn-finish-reg">Create Passkey</button>
  </div>

  <script>
    const token = {{ .Token }};

    function bufferToBase64URL(buf) {
      return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function base64URLToBuffer(base64) {
      const padding = '='.repeat((4 - (base64.length % 4)) % 4);
      const str = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
      return Uint8Array.from(atob(str), c => c.charCodeAt(0));
    }

    document.getElementById('btn-finish-reg').addEventListener('click', async () => {
      try {
        const res = await fetch('/auth/passkey/register/begin?token=' + encodeURIComponent(token), { method: 'POST' });
        if (!res.ok) {
          const err = await res.text();
          alert('Registration initiation failed: ' + err);
          return;
        }
        const options = await res.json();

        options.publicKey.challenge = base64URLToBuffer(options.publicKey.challenge);
        options.publicKey.user.id = base64URLToBuffer(options.publicKey.user.id);

        const cred = await navigator.credentials.create({ publicKey: options.publicKey });
        const finishRes = await fetch('/auth/passkey/register/finish?token=' + encodeURIComponent(token), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: cred.id,
            rawId: bufferToBase64URL(cred.rawId),
            type: cred.type,
            response: {
              attestationObject: bufferToBase64URL(cred.response.attestationObject),
              clientDataJSON: bufferToBase64URL(cred.response.clientDataJSON)
            }
          })
        });

        if (finishRes.ok) {
          window.location.href = returnTo;
        } else {
          alert('Passkey registration failed');
        }
      } catch (err) {
        console.error(err);
      }
    });
  </script>
</body>
</html>`

func main() {
	configPath := flag.String("config", "config.json", "path to configuration file")
	groupsPath := flag.String("groups", "../groups", "path to directory containing group config files for galene")
	flag.Parse()

	cfgData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("failed to read config file: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		log.Fatalf("failed to parse config JSON: %v", err)
	}

	app, err := newApp(&cfg, *groupsPath)
	if err != nil {
		log.Fatalf("initialization failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", app.handleLogin)
	mux.HandleFunc("/auth/oidc/", app.handleOIDCLogin)
	mux.HandleFunc("/auth/callback/", app.handleOIDCCallback)
	mux.HandleFunc("/auth/register/send", app.handleRegisterSend)
	mux.HandleFunc("/auth/verify", app.handleVerify)
	mux.HandleFunc("/auth/passkey/login/begin", app.handlePasskeyLoginBegin)
	mux.HandleFunc("/auth/passkey/login/finish", app.handlePasskeyLoginFinish)
	mux.HandleFunc("/auth/passkey/register/begin", app.handlePasskeyRegisterBegin)
	mux.HandleFunc("/auth/passkey/register/finish", app.handlePasskeyRegisterFinish)
	mux.HandleFunc("/auth/refresh", app.handleRefresh)

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("Off-Script Mamas auth listening on %s", cfg.ListenAddr)
	log.Fatal(server.ListenAndServe())
}

func newApp(cfg *Config, groupsPath string) (*App, error) {
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		return nil, err
	}

	if err := initDB(db); err != nil {
		return nil, err
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.RPOrigin},
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	clients := make(map[string]*OIDCClient)

	providers := []struct {
		key         string
		name        string
		issuer      string
		buttonClass string
		pcfg        ProviderConfig
		scopes      []string
	}{
		{
			key:         "google",
			name:        "Google",
			issuer:      "https://accounts.google.com",
			buttonClass: "",
			pcfg:        cfg.Google,
			scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
		},
		{
			key:         "microsoft",
			name:        "Microsoft",
			issuer:      "https://login.microsoftonline.com/common/v2.0",
			buttonClass: "btn-microsoft",
			pcfg:        cfg.Microsoft,
			scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
		},
		{
			key:         "apple",
			name:        "Apple",
			issuer:      "https://appleid.apple.com",
			buttonClass: "btn-apple",
			pcfg:        cfg.Apple,
			scopes:      []string{oidc.ScopeOpenID, "name", "email"},
		},
	}

	for _, p := range providers {
		if p.pcfg.ClientID == "" {
			continue
		}

		provider, err := oidc.NewProvider(ctx, p.issuer)
		if err != nil {
			log.Printf("failed to initialize provider %s: %v", p.key, err)
			continue
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: p.pcfg.ClientID})
		oauthCfg := &oauth2.Config{
			ClientID:     p.pcfg.ClientID,
			ClientSecret: p.pcfg.ClientSecret,
			RedirectURL:  cfg.RPOrigin + "/auth/callback/" + p.key,
			Scopes:       p.scopes,
			Endpoint:     provider.Endpoint(),
		}

		clients[p.key] = &OIDCClient{
			Key:         p.key,
			DisplayName: p.name,
			ButtonClass: p.buttonClass,
			Config:      oauthCfg,
			Verifier:    verifier,
		}
	}

	tmplLogin, err := template.New("login").Parse(loginHTML)
	if err != nil {
		return nil, err
	}

	tmplVerify, err := template.New("verify").Parse(verifyHTML)
	if err != nil {
		return nil, err
	}

	return &App{
		cfg:         cfg,
		groupsPath:  groupsPath,
		db:          db,
		webAuthn:    wa,
		oidcClients: clients,
		tmplLogin:   tmplLogin,
		tmplVerify:  tmplVerify,
		limiter:     newRateLimiter(),
	}, nil
}

func initDB(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		display_name TEXT,
		picture TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS federated_identities (
		provider TEXT NOT NULL,
		subject TEXT NOT NULL,
		user_id TEXT NOT NULL,
		email TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY(provider, subject),
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id BLOB PRIMARY KEY,
		user_id TEXT NOT NULL,
		public_key BLOB NOT NULL,
		attestation_type TEXT NOT NULL,
		transport TEXT,
		sign_count INTEGER NOT NULL,
		flags TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS email_verifications (
		token TEXT PRIMARY KEY,
		email TEXT NOT NULL,
		expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_fed_user ON federated_identities(user_id);
	CREATE INDEX IF NOT EXISTS idx_cred_user ON webauthn_credentials(user_id);`
	_, err := db.Exec(schema)
	return err
}

func getClientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return strings.TrimSpace(cf)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (a *App) scanGroupsForUser(userEmail string) ([]string, error) {
	files, err := os.ReadDir(a.groupsPath)
	if err != nil {
		return nil, err
	}

	ret := []string{}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		fp := filepath.Join(a.groupsPath, f.Name())
		data, err := os.ReadFile(fp)

		if err != nil {
			log.Printf("Error reading %s: %s - continuing with the next file", fp, err)
			continue
		}

		g := group.Description{}
		if err := json.Unmarshal(data, &g); err != nil {
			log.Printf("Error parsing %s: %s - continuing with the next file", fp, err)
			continue
		}

		g.FileName = fp
		found := false
		if ud, ok := g.Users[strings.ToLower(userEmail)]; ok {
			perms := ud.Permissions.Permissions(&g)
			for _, p := range perms {
				if p == "present" {
					ret = append(ret, fmt.Sprintf("/group/%s/", strings.TrimSuffix(f.Name(), ".json")))
					found = true
					break
				}
			}
		}
		if !found && g.WildcardUser != nil {
			perms := g.WildcardUser.Permissions.Permissions(&g)
			for _, p := range perms {
				if p == "present" {
					ret = append(ret, fmt.Sprintf("/group/%s/", strings.TrimSuffix(f.Name(), ".json")))
					break
				}
			}
		}
	}

	return ret, nil
}

func (a *App) sendVerificationEmail(to, verifyURL string) error {
	if len(a.cfg.SMTPRelays) == 0 {
		return fmt.Errorf("no smtp relays configured")
	}

	subject := "Verify your email for Off-Script Mamas"
	body := fmt.Sprintf("Hello,\r\n\r\nPlease click the link below to verify your email and complete device passkey setup:\r\n\r\n%s\r\n\r\nThis link will expire in 15 minutes.\r\n\r\nIf you did not request this, please disregard this email.\r\n", verifyURL)

	var errs []string
	for _, relay := range a.cfg.SMTPRelays {
		if relay.Host == "" {
			continue
		}

		auth := smtp.PlainAuth("", relay.User, relay.Password, relay.Host)
		addr := fmt.Sprintf("%s:%d", relay.Host, relay.Port)
		msg := []byte(fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", to, relay.From, subject, body))

		err := smtp.SendMail(addr, auth, relay.From, []string{to}, msg)
		if err == nil {
			log.Printf("delivered verification email to %s via %s", to, relay.Name)
			return nil
		}

		log.Printf("relay %s failed for %s: %v, attempting next relay...", relay.Name, to, err)
		errs = append(errs, fmt.Sprintf("%s: %v", relay.Name, err))
	}

	return fmt.Errorf("all smtp relays failed: %s", strings.Join(errs, "; "))
}

func (a *App) sanitizeReturnTo(target string) string {
	if target == "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return "/"
	}
	return target
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	rd := a.sanitizeReturnTo(r.URL.Query().Get("rd"))
	var buttons []TemplateButton

	for _, k := range []string{"google", "microsoft", "apple"} {
		client, exists := a.oidcClients[k]
		if !exists {
			continue
		}
		buttons = append(buttons, TemplateButton{
			DisplayName: client.DisplayName,
			URL:         fmt.Sprintf("/auth/oidc/%s?rd=%s", client.Key, rd),
			Class:       client.ButtonClass,
		})
	}

	data := struct {
		Buttons  []TemplateButton
		ReturnTo string
	}{
		Buttons:  buttons,
		ReturnTo: rd,
	}
	_ = a.tmplLogin.Execute(w, data)
}

func (a *App) handleRegisterSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))

	ip := getClientIP(r)
	if err := a.limiter.Check(ip, email); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	var existingID string
	err := a.db.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&existingID)
	if err == nil {
		http.Error(w, "An account with this email already exists. Please sign in.", http.StatusConflict)
		return
	}

	token := generateRandomString()
	expiresAt := time.Now().Add(15 * time.Minute)

	_, _ = a.db.Exec(`DELETE FROM email_verifications WHERE expires_at < CURRENT_TIMESTAMP`)
	_, err = a.db.Exec(`INSERT INTO email_verifications (token, email, expires_at) VALUES (?, ?, ?)`, token, email, expiresAt)
	if err != nil {
		http.Error(w, "internal database error", http.StatusInternalServerError)
		return
	}

	verifyURL := fmt.Sprintf("%s/auth/verify?token=%s", a.cfg.RPOrigin, token)

	go func() {
		if err := a.sendVerificationEmail(email, verifyURL); err != nil {
			log.Printf("failed to deliver verification email to %s: %v", email, err)
		}
	}()

	w.WriteHeader(http.StatusOK)
}

func (a *App) handleVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing verification token", http.StatusBadRequest)
		return
	}

	var email string
	var expiresAt time.Time
	err := a.db.QueryRow(`SELECT email, expires_at FROM email_verifications WHERE token = ?`, token).Scan(&email, &expiresAt)
	if err != nil || time.Now().After(expiresAt) {
		http.Error(w, "This verification link is invalid or has expired.", http.StatusBadRequest)
		return
	}

	data := struct {
		Email string
		Token string
	}{
		Email: email,
		Token: token,
	}
	_ = a.tmplVerify.Execute(w, data)
}

func (a *App) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	providerKey := strings.TrimPrefix(r.URL.Path, "/auth/oidc/")
	client, ok := a.oidcClients[providerKey]
	if !ok {
		http.Error(w, "unsupported provider", http.StatusBadRequest)
		return
	}

	state := generateRandomString()
	rd := a.sanitizeReturnTo(r.URL.Query().Get("rd"))
	a.sessionStore.Store("oauth_"+state, OAuthSession{
		Provider:  providerKey,
		CreatedAt: time.Now(),
		ReturnTo:  rd,
	})

	var opts []oauth2.AuthCodeOption
	if providerKey == "apple" {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}

	url := client.Config.AuthCodeURL(state, opts...)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *App) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
	}

	state := r.FormValue("state")
	val, ok := a.sessionStore.Load("oauth_" + state)
	if !ok {
		http.Error(w, "invalid or expired state parameter", http.StatusBadRequest)
		return
	}
	a.sessionStore.Delete("oauth_" + state)
	session := val.(OAuthSession)

	client, ok := a.oidcClients[session.Provider]
	if !ok {
		http.Error(w, "unknown provider context", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	token, err := client.Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "failed to exchange code", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		rawIDToken = r.FormValue("id_token")
		if rawIDToken == "" {
			http.Error(w, "missing id_token payload", http.StatusInternalServerError)
			return
		}
	}

	idToken, err := client.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "failed to verify id_token signature", http.StatusUnauthorized)
		return
	}

	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return
	}

	sub, _ := rawClaims["sub"].(string)
	email, _ := rawClaims["email"].(string)
	if email == "" {
		if pref, ok := rawClaims["preferred_username"].(string); ok {
			email = pref
		}
	}

	name, _ := rawClaims["name"].(string)
	picture, _ := rawClaims["picture"].(string)

	if session.Provider == "apple" && name == "" {
		if userPayload := r.FormValue("user"); userPayload != "" {
			var appleUser struct {
				Name struct {
					FirstName string `json:"firstName"`
					LastName  string `json:"lastName"`
				} `json:"name"`
			}
			if json.Unmarshal([]byte(userPayload), &appleUser) == nil {
				name = strings.TrimSpace(appleUser.Name.FirstName + " " + appleUser.Name.LastName)
			}
		}
	}

	user, err := a.resolveFederatedUser(session.Provider, sub, email, name, picture)
	if err != nil {
		http.Error(w, "identity resolution failed", http.StatusInternalServerError)
		return
	}

	a.setSessionCookie(w, string(user.ID), user.Email, user.Picture)
	http.Redirect(w, r, session.ReturnTo, http.StatusSeeOther)
}

func (a *App) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := a.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID := generateRandomString()
	a.sessionStore.Store("wa_"+sessionID, sessionData)

	http.SetCookie(w, &http.Cookie{
		Name:     "wa_session",
		Value:    sessionID,
		Path:     "/auth/passkey/",
		MaxAge:   300,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func (a *App) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("wa_session")
	if err != nil {
		http.Error(w, "missing session", http.StatusBadRequest)
		return
	}

	val, ok := a.sessionStore.Load("wa_" + cookie.Value)
	if !ok {
		http.Error(w, "expired session", http.StatusBadRequest)
		return
	}
	a.sessionStore.Delete("wa_" + cookie.Value)
	sessionData := val.(*webauthn.SessionData)

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := a.loadUserByCredentialID(parsedResponse.RawID)
	if err != nil {
		log.Printf("loadUserByCredentialID(%+v): %s\n", parsedResponse.RawID, err)
		http.Error(w, "unrecognized credential", http.StatusUnauthorized)
		return
	}

	cred, err := a.webAuthn.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		return user, nil
	}, *sessionData, parsedResponse)
	if err != nil {
		log.Printf("error processing user %+v\n", user)
		log.Printf("ValidateDiscoverableLogin(%+v, %+v): %s\n", *sessionData, parsedResponse, err)
		http.Error(w, "validation failed", http.StatusUnauthorized)
		return
	}

	_ = a.updateSignCount(cred.ID, cred.Authenticator.SignCount)
	a.setSessionCookie(w, string(user.ID), user.Email, user.Picture)
	w.WriteHeader(http.StatusOK)
}

func (a *App) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing verification token", http.StatusBadRequest)
		return
	}

	var email string
	var expiresAt time.Time
	err := a.db.QueryRow(`SELECT email, expires_at FROM email_verifications WHERE token = ?`, token).Scan(&email, &expiresAt)
	if err != nil || time.Now().After(expiresAt) {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	user, err := a.getOrCreateUserByEmail(email)
	if err != nil {
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}

	options, sessionData, err := a.webAuthn.BeginRegistration(
		user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID := generateRandomString()
	a.sessionStore.Store("wa_reg_"+sessionID, sessionData)
	a.sessionStore.Store("wa_user_"+sessionID, user)
	a.sessionStore.Store("wa_token_"+sessionID, token)

	http.SetCookie(w, &http.Cookie{
		Name:     "wa_reg_session",
		Value:    sessionID,
		Path:     "/auth/passkey/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(options)
}

func (a *App) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("wa_reg_session")
	if err != nil {
		http.Error(w, "missing registration session", http.StatusBadRequest)
		return
	}

	val, ok := a.sessionStore.Load("wa_reg_" + cookie.Value)
	userVal, okUser := a.sessionStore.Load("wa_user_" + cookie.Value)
	tokenVal, okToken := a.sessionStore.Load("wa_token_" + cookie.Value)
	if !ok || !okUser || !okToken {
		http.Error(w, "expired registration session", http.StatusBadRequest)
		return
	}

	a.sessionStore.Delete("wa_reg_" + cookie.Value)
	a.sessionStore.Delete("wa_user_" + cookie.Value)
	a.sessionStore.Delete("wa_token_" + cookie.Value)

	sessionData := val.(*webauthn.SessionData)
	user := userVal.(*User)
	token := tokenVal.(string)

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := a.webAuthn.CreateCredential(user, *sessionData, parsedResponse)
	if err != nil {
		http.Error(w, "credential creation failed", http.StatusBadRequest)
		return
	}

	if err := a.saveCredential(string(user.ID), credential); err != nil {
		http.Error(w, "failed to save credential", http.StatusInternalServerError)
		return
	}

	_, _ = a.db.Exec(`DELETE FROM email_verifications WHERE token = ?`, token)

	a.setSessionCookie(w, string(user.ID), user.Email, user.Picture)
	w.WriteHeader(http.StatusOK)
}

func (a *App) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var sub, email, picture string

	for _, c := range r.CookiesNamed("session_token") {
		token, err := jwt.Parse(c.Value, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(a.cfg.JWTSecret), nil
		})
		if err != nil || !token.Valid {
			log.Printf("session token failed to validate: err %s valid %s", err, token.Valid)
			// http.Error(w, "token invalid or expired", http.StatusUnauthorized)
			continue
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "invalid claims", http.StatusUnauthorized)
			return
		}
		s, _ := claims["orig_sub"].(string)
		e, _ := claims["email"].(string)
		p, _ := claims["picture"].(string)
		if s != "" && e != "" {
			sub = s
			email = e
			picture = p
			break
		}
	}
	if sub != "" && email != "" {
		a.setSessionCookie(w, sub, email, picture)
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "could not find a valid token", http.StatusUnauthorized)
	}
}

func (a *App) setSessionCookie(w http.ResponseWriter, sub, email, picture string) {
	displayName := email
	if user, err := a.loadUserByID(sub); err != nil {
		displayName = user.DisplayName
	}

	groups, err := a.scanGroupsForUser(email)
	if err != nil {
		groups = []string{}
	}

	claims := jwt.MapClaims{
		"sub":         displayName,
		"orig_sub":    sub,
		"email":       email,
		"picture":     picture,
		"permissions": []string{"present", "message"},
		"aud":         groups,
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "osm-auth"

	signed, err := token.SignedString([]byte(a.cfg.JWTSecret))
	if err != nil {
		http.Error(w, "signing error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    signed,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) resolveFederatedUser(provider, subject, email, name, picture string) (*User, error) {
	var userID string
	err := a.db.QueryRow(`
		SELECT user_id FROM federated_identities 
		WHERE provider = ? AND subject = ?`, provider, subject).Scan(&userID)

	if err == nil {
		if picture != "" {
			_, _ = a.db.Exec(`UPDATE users SET picture = ? WHERE id = ?`, picture, userID)
		}
		return a.loadUserByID(userID)
	}

	var existingUserID string
	err = a.db.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&existingUserID)
	if err == nil {
		_, err = a.db.Exec(`
			INSERT INTO federated_identities (provider, subject, user_id, email)
			VALUES (?, ?, ?, ?)`, provider, subject, existingUserID, email)
		if err != nil {
			return nil, err
		}
		if picture != "" {
			_, _ = a.db.Exec(`UPDATE users SET picture = ? WHERE id = ?`, picture, existingUserID)
		}
		return a.loadUserByID(existingUserID)
	}

	newID := generateRandomString()
	tx, err := a.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO users (id, email, display_name, picture)
		VALUES (?, ?, ?, ?)`, newID, email, name, picture)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(`
		INSERT INTO federated_identities (provider, subject, user_id, email)
		VALUES (?, ?, ?, ?)`, provider, subject, newID, email)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &User{
		ID:          []byte(newID),
		Email:       email,
		DisplayName: name,
		Picture:     picture,
	}, nil
}

func (a *App) getOrCreateUserByEmail(email string) (*User, error) {
	var idStr, name, pic sql.NullString
	err := a.db.QueryRow(`SELECT id, display_name, picture FROM users WHERE email = ?`, email).Scan(&idStr, &name, &pic)
	if err == nil {
		creds, _ := a.loadCredentialsForUser(idStr.String)
		return &User{
			ID:          []byte(idStr.String),
			Email:       email,
			DisplayName: name.String,
			Picture:     pic.String,
			Credentials: creds,
		}, nil
	}

	newID := generateRandomString()
	_, err = a.db.Exec(`INSERT INTO users (id, email, display_name, picture) VALUES (?, ?, '', '')`, newID, email)
	if err != nil {
		return nil, err
	}
	return &User{ID: []byte(newID), Email: email}, nil
}

func (a *App) loadUserByID(userID string) (*User, error) {
	var email, name, pic sql.NullString
	err := a.db.QueryRow(`SELECT email, display_name, picture FROM users WHERE id = ?`, userID).Scan(&email, &name, &pic)
	if err != nil {
		return nil, err
	}

	creds, err := a.loadCredentialsForUser(userID)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:          []byte(userID),
		Email:       email.String,
		DisplayName: name.String,
		Picture:     pic.String,
		Credentials: creds,
	}, nil
}

func (a *App) loadUserByCredentialID(credID []byte) (*User, error) {
	var userID string
	err := a.db.QueryRow(`SELECT user_id FROM webauthn_credentials WHERE id = ?`, credID).Scan(&userID)
	if err != nil {
		return nil, err
	}
	return a.loadUserByID(userID)
}

func (a *App) loadCredentialsForUser(userID string) ([]webauthn.Credential, error) {
	rows, err := a.db.Query(`
		SELECT id, public_key, attestation_type, transport, sign_count, flags 
		FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []webauthn.Credential
	for rows.Next() {
		var c webauthn.Credential
		var transportStr sql.NullString
		var flagsStr sql.NullString
		if err := rows.Scan(&c.ID, &c.PublicKey, &c.AttestationType, &transportStr, &c.Authenticator.SignCount, &flagsStr); err != nil {
			return nil, err
		}
		if transportStr.Valid && transportStr.String != "" {
			_ = json.Unmarshal([]byte(transportStr.String), &c.Transport)
		}
		if flagsStr.Valid && flagsStr.String != "" {
			_ = json.Unmarshal([]byte(flagsStr.String), &c.Flags)
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func (a *App) saveCredential(userID string, cred *webauthn.Credential) error {
	transports, _ := json.Marshal(cred.Transport)
	flags, _ := json.Marshal(cred.Flags)
	_, err := a.db.Exec(`
		INSERT INTO webauthn_credentials (id, user_id, public_key, attestation_type, transport, sign_count, flags)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		cred.ID, userID, cred.PublicKey, cred.AttestationType, string(transports), cred.Authenticator.SignCount, string(flags))
	return err
}

func (a *App) updateSignCount(credID []byte, count uint32) error {
	_, err := a.db.Exec(`UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?`, count, credID)
	return err
}

func generateRandomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
