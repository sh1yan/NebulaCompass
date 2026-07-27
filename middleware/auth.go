package middleware

import (
	"NebulaCompass/database"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type contextKey string

const UserContextKey contextKey = "user_id"

type Session struct {
	UserID    int64
	ExpiresAt time.Time
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

var store *SessionStore
var storeOnce sync.Once

func GetSessionStore() *SessionStore {
	storeOnce.Do(func() {
		store = &SessionStore{
			sessions: make(map[string]*Session),
		}
		go store.cleanup()
	})
	return store
}

func (ss *SessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ss.mu.Lock()
		now := time.Now()
		for token, session := range ss.sessions {
			if now.After(session.ExpiresAt) {
				delete(ss.sessions, token)
			}
		}
		ss.mu.Unlock()
	}
}

func (ss *SessionStore) CreateSession(userID int64) string {
	token := generateToken()
	ss.mu.Lock()
	ss.sessions[token] = &Session{
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	ss.mu.Unlock()
	return token
}

func (ss *SessionStore) GetSession(token string) *Session {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	session, ok := ss.sessions[token]
	if !ok {
		return nil
	}
	if time.Now().After(session.ExpiresAt) {
		return nil
	}
	return session
}

func (ss *SessionStore) DeleteSession(token string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, token)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func HashPassword(password, salt string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func GenerateSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// 不需要鉴权的路径前缀列表
var publicPaths = []string{
	"/login",
	"/api/login",
	"/static/",
}

func isPublicPath(path string) bool {
	for _, p := range publicPaths {
		if len(path) >= len(p) && path[:len(p)] == p {
			return true
		}
	}
	return false
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开路径不需要鉴权
		if r.URL.Path == "/" || isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// 检查cookie中的session
		cookie, err := r.Cookie("session_token")
		if err != nil {
			// API路由返回JSON错误而非重定向，防止前端fetch拿到HTML
			isAPI := len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/"
			if isAPI {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "登录已过期"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session := GetSessionStore().GetSession(cookie.Value)
		if session == nil {
			// API路由返回JSON错误而非重定向，防止前端fetch拿到HTML
			isAPI := len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/"
			if isAPI {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "登录已过期"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// 将用户ID注入上下文
		ctx := context.WithValue(r.Context(), UserContextKey, session.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetCurrentUserID(r *http.Request) int64 {
	if userID, ok := r.Context().Value(UserContextKey).(int64); ok {
		return userID
	}
	return 0
}

func EnsureDefaultAdmin() {
	db := database.GetDB()
	admin := db.GetUserByUsername("admin")
	if admin == nil {
		salt := GenerateSalt()
		hash := HashPassword("admin123", salt)
		db.CreateUser("admin", hash, salt)
	}
}
