package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"NebulaCompass/database"
)

type contextKey string

const UserContextKey contextKey = "user_id"

// SessionCookieName 会话 Cookie 名称
const SessionCookieName = "session_token"

// SessionTTL 会话有效期
const SessionTTL = 24 * time.Hour

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

// cleanup 定期清理内存与数据库中的过期会话
func (ss *SessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		ss.mu.Lock()
		for token, session := range ss.sessions {
			if now.After(session.ExpiresAt) {
				delete(ss.sessions, token)
			}
		}
		ss.mu.Unlock()
		database.GetDB().PurgeExpiredSessions(now)
	}
}

// CreateSession 创建会话：内存缓存 + 落库（服务重启后仍可用）
func (ss *SessionStore) CreateSession(userID int64) string {
	token := generateToken()
	expires := time.Now().Add(SessionTTL)
	ss.mu.Lock()
	ss.sessions[token] = &Session{UserID: userID, ExpiresAt: expires}
	ss.mu.Unlock()
	database.GetDB().SaveSession(token, userID, expires)
	return token
}

func (ss *SessionStore) GetSession(token string) *Session {
	if token == "" {
		return nil
	}
	ss.mu.RLock()
	session, ok := ss.sessions[token]
	ss.mu.RUnlock()
	if ok {
		if time.Now().After(session.ExpiresAt) {
			ss.DeleteSession(token)
			return nil
		}
		return session
	}
	// 内存未命中：回查数据库（服务重启后的会话恢复）
	userID, expires, found := database.GetDB().LoadSession(token)
	if !found {
		return nil
	}
	if time.Now().After(expires) {
		database.GetDB().DeleteSession(token)
		return nil
	}
	recovered := &Session{UserID: userID, ExpiresAt: expires}
	ss.mu.Lock()
	ss.sessions[token] = recovered
	ss.mu.Unlock()
	return recovered
}

func (ss *SessionStore) DeleteSession(token string) {
	if token == "" {
		return
	}
	ss.mu.Lock()
	delete(ss.sessions, token)
	ss.mu.Unlock()
	database.GetDB().DeleteSession(token)
}

// DeleteByUser 吊销某用户的全部会话（keepToken 非空时保留该会话）
func (ss *SessionStore) DeleteByUser(userID int64, keepToken string) int {
	ss.mu.Lock()
	for token, session := range ss.sessions {
		if session.UserID == userID && token != keepToken {
			delete(ss.sessions, token)
		}
	}
	ss.mu.Unlock()
	return database.GetDB().DeleteSessionsByUser(userID, keepToken)
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// 极端情况下退化为时间戳 + 随机数组合，避免出现空 token
		return hex.EncodeToString([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())))
	}
	return hex.EncodeToString(b)
}

// ========== 密码哈希 ==========
// 采用 PBKDF2-HMAC-SHA256（标准库实现，无额外依赖）。
// 兼容历史格式：旧数据为 sha256(salt + password) 的 hex，登录成功后会就地升级。

const (
	pbkdf2Iterations = 120000
	pbkdf2KeyLen     = 32
	pbkdf2Prefix     = "pbkdf2$"
)

// HashPassword 生成 PBKDF2 哈希，格式：pbkdf2$<iter>$<hex>
func HashPassword(password, salt string) string {
	dk := pbkdf2SHA256([]byte(password), []byte(salt), pbkdf2Iterations, pbkdf2KeyLen)
	return fmt.Sprintf("%s%d$%s", pbkdf2Prefix, pbkdf2Iterations, hex.EncodeToString(dk))
}

// legacyHashPassword 历史格式（仅用于校验与自动升级）
func legacyHashPassword(password, salt string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyPassword 校验密码，兼容历史 sha256 格式
func VerifyPassword(password, salt, stored string) bool {
	if stored == "" {
		return false
	}
	if strings.HasPrefix(stored, pbkdf2Prefix) {
		parts := strings.SplitN(stored, "$", 3)
		if len(parts) != 3 {
			return false
		}
		iter, err := strconv.Atoi(parts[1])
		if err != nil || iter <= 0 {
			return false
		}
		dk := pbkdf2SHA256([]byte(password), []byte(salt), iter, pbkdf2KeyLen)
		want, err := hex.DecodeString(parts[2])
		if err != nil {
			return false
		}
		return subtle.ConstantTimeCompare(dk, want) == 1
	}
	legacy := legacyHashPassword(password, salt)
	return subtle.ConstantTimeCompare([]byte(legacy), []byte(stored)) == 1
}

// PasswordHashNeedsUpgrade 判断是否为历史哈希格式（需要在登录成功后升级）
func PasswordHashNeedsUpgrade(stored string) bool {
	return stored != "" && !strings.HasPrefix(stored, pbkdf2Prefix)
}

// pbkdf2SHA256 RFC 2898 PBKDF2-HMAC-SHA256
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	var idx [4]byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		idx[0] = byte(block >> 24)
		idx[1] = byte(block >> 16)
		idx[2] = byte(block >> 8)
		idx[3] = byte(block)
		prf.Write(idx[:])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

// ValidatePasswordStrength 校验新密码强度，返回错误文案（空表示通过）
func ValidatePasswordStrength(username, password string) string {
	if len(password) < 8 {
		return "新密码长度至少 8 位"
	}
	if len(password) > 128 {
		return "新密码长度不能超过 128 位"
	}
	lower := strings.ToLower(password)
	weak := map[string]bool{
		"12345678": true, "123456789": true, "password": true, "passw0rd": true,
		"admin123": true, "administrator": true, "qwertyui": true, "11111111": true,
	}
	if weak[lower] {
		return "新密码过于简单，请更换"
	}
	if username != "" && strings.EqualFold(password, username) {
		return "新密码不能与用户名相同"
	}
	return ""
}

// ========== 鉴权中间件 ==========

// 精确匹配的公开路径
var publicExactPaths = map[string]bool{
	"/login":     true,
	"/api/login": true,
}

// 前缀匹配的公开路径
var publicPrefixPaths = []string{"/static/"}

func isPublicPath(path string) bool {
	if publicExactPaths[path] {
		return true
	}
	for _, p := range publicPrefixPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func writeUnauthorized(w http.ResponseWriter, isAPI bool) {
	if isAPI {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "登录已过期"})
		return
	}
	w.Header().Set("Location", "/login")
	w.WriteHeader(http.StatusSeeOther)
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(SessionCookieName)
		if err != nil || cookie.Value == "" {
			// API 路由返回 JSON 错误而非重定向，防止前端 fetch 拿到 HTML
			writeUnauthorized(w, strings.HasPrefix(r.URL.Path, "/api/"))
			return
		}

		session := GetSessionStore().GetSession(cookie.Value)
		if session == nil {
			writeUnauthorized(w, strings.HasPrefix(r.URL.Path, "/api/"))
			return
		}

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

// GetSessionToken 读取当前请求的会话 token
func GetSessionToken(r *http.Request) string {
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

// SetSessionCookie 由服务端下发会话 Cookie（HttpOnly，避免被脚本读取）
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

// ClearSessionCookie 清除会话 Cookie
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

// GenerateSalt 生成 16 字节随机盐
func GenerateSalt() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
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
