package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ==========================================
// Simulation Data & Storage
// ==========================================

const (
	ClientID     = "demo-client"
	ClientSecret = "demo-secret"
	RedirectURI  = "http://localhost:8080/cb"
)

type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type AccessToken struct {
	Token     string
	ClientID  string
	ExpiresAt time.Time
}

var (
	codeStore  = make(map[string]AuthCode)
	tokenStore = make(map[string]AccessToken)
	mu         sync.Mutex
)

// ==========================================
// Handlers
// ==========================================

func main() {
	http.HandleFunc("/authorize", handleAuthorize)
	http.HandleFunc("/token", handleToken)
	http.HandleFunc("/userinfo", handleUserInfo)
	http.HandleFunc("/cb", handleCallback) // Helper for the demo

	fmt.Println("🔒 OAuth2 Server running on http://localhost:8080")
	fmt.Println("👉 Start here: http://localhost:8080/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/cb&scope=read&state=xyz123&code_challenge=LQZxoESZIZMv7j_6u2jBWnivm0jsDelp3OLcKeo64S4&code_challenge_method=S256")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// 1. Authorization Endpoint
// Role: Authorization Server
func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Validation
	if query.Get("client_id") != ClientID {
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}
	if query.Get("redirect_uri") != RedirectURI {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	if query.Get("response_type") != "code" {
		http.Error(w, "Unsupported response_type", http.StatusBadRequest)
		return
	}

	// PKCE Check
	challenge := query.Get("code_challenge")
	method := query.Get("code_challenge_method")
	if challenge == "" || method != "S256" {
		http.Error(w, "PKCE required (code_challenge + S256)", http.StatusBadRequest)
		return
	}

	// --- SIMULATE USER LOGIN SCREEN HERE ---
	// In a real app, a HTML form asking for username/password.
	// Here we assume the user is logged in and clicked "Approve".

	// Generate Authorization Code
	code := uuid.New().String()

	mu.Lock()
	codeStore[code] = AuthCode{
		Code:                code,
		ClientID:            ClientID,
		RedirectURI:         RedirectURI,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	mu.Unlock()

	// Redirect back to client with code and state
	state := query.Get("state")
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", RedirectURI, code, state)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// 2. Token Endpoint
// Role: Authorization Server
func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")

	if grantType != "authorization_code" {
		jsonError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	mu.Lock()
	authCode, exists := codeStore[code]
	delete(codeStore, code)
	mu.Unlock()

	if !exists {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	if time.Now().After(authCode.ExpiresAt) {
		jsonError(w, "code_expired", http.StatusBadRequest)
		return
	}
	if authCode.ClientID != clientID {
		jsonError(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	// PKCE Verification
	// S256: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	if !verifyPKCE(authCode.CodeChallenge, verifier) {
		jsonError(w, "invalid_request", http.StatusBadRequest)
		return
	}

	// Grant Access Token
	token := uuid.New().String()

	mu.Lock()
	tokenStore[token] = AccessToken{
		Token:     token,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	mu.Unlock()

	// Return JSON Response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// 3. Protected Resource Endpoint
// Role: Resource Server (e.g., Snap Store)
func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	mu.Lock()
	accessToken, exists := tokenStore[token]
	mu.Unlock()

	if !exists || time.Now().After(accessToken.ExpiresAt) {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"sub":   "user_123",
		"name":  "Alice Doe",
		"email": "alice@example.com",
		"role":  "admin",
		"data":  "Private Photos from Snap Store",
	})
}

// Helper: Callback handler (just to show the code in browser)
func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<h1>Callback Received!</h1>
		<p><b>Code:</b> %s</p>
		<p><b>State:</b> %s</p>
		<hr>
		<h3>Next Step: Exchange Code for Token</h3>
		<p>Run this command in your terminal:</p>
		<pre style="background: #eee; padding: 10px;">
curl -X POST http://localhost:8080/token \
  -d "grant_type=authorization_code" \
  -d "client_id=demo-client" \
  -d "code=%s" \
  -d "redirect_uri=http://localhost:8080/cb" \
  -d "code_verifier=secret-verifier-string"
		</pre>
	`, code, state, code)
}

// ==========================================
// Utilities
// ==========================================

func verifyPKCE(challenge string, verifier string) bool {
	// 1. SHA256 Hash the verifier
	hash := sha256.Sum256([]byte(verifier))

	// 2. Base64 URL Encode (no padding)
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])

	// 3. Compare with challenge
	return encoded == challenge
}

func jsonError(w http.ResponseWriter, err string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": err,
	})
}
