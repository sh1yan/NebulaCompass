package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"NebulaCompass/database"
	"NebulaCompass/middleware"
)

type AuthHandler struct{}

func NewAuthHandler() *AuthHandler { return &AuthHandler{} }

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Token   string `json:"token,omitempty"`
}

// ========== 登录失败限速 ==========
// 同一来源 IP + 用户名连续失败 5 次后锁定 60 秒，缓解口令爆破

const (
	maxLoginFails    = 5
	loginBlockWindow = 60 * time.Second
	loginFailTTL     = 30 * time.Minute
)

type loginAttempt struct {
	fails     int
	firstFail time.Time
	blockedTo time.Time
}

var (
	loginMu       sync.Mutex
	loginAttempts = map[string]*loginAttempt{}
)

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func loginAttemptKey(r *http.Request, username string) string {
	return strings.ToLower(strings.TrimSpace(username)) + "|" + clientIP(r)
}

// loginBlockedRemain 返回剩余锁定秒数（0 表示未锁定）
func loginBlockedRemain(key string) int {
	loginMu.Lock()
	defer loginMu.Unlock()
	a, ok := loginAttempts[key]
	if !ok || a.blockedTo.IsZero() {
		return 0
	}
	remain := time.Until(a.blockedTo)
	if remain <= 0 {
		delete(loginAttempts, key)
		return 0
	}
	return int(remain.Seconds()) + 1
}

func noteLoginFailure(key string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	now := time.Now()
	a, ok := loginAttempts[key]
	if !ok || now.Sub(a.firstFail) > loginFailTTL {
		a = &loginAttempt{firstFail: now}
		loginAttempts[key] = a
	}
	a.fails++
	if a.fails >= maxLoginFails {
		a.blockedTo = now.Add(loginBlockWindow)
		a.fails = 0
		a.firstFail = now
	}
	// 简单的容量保护
	if len(loginAttempts) > 5000 {
		for k, v := range loginAttempts {
			if now.Sub(v.firstFail) > loginFailTTL {
				delete(loginAttempts, k)
			}
		}
	}
}

func noteLoginSuccess(key string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginAttempts, key)
}

// ========== 登录 / 退出 ==========

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		ServePage(w, r, "login.html")
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(loginResponse{Success: false, Message: "Invalid request"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		json.NewEncoder(w).Encode(loginResponse{Success: false, Message: "用户名或密码错误"})
		return
	}

	key := loginAttemptKey(r, req.Username)
	if remain := loginBlockedRemain(key); remain > 0 {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(loginResponse{
			Success: false,
			Message: "登录失败次数过多，请 " + itoaSeconds(remain) + " 秒后再试",
		})
		return
	}

	db := database.GetDB()
	user := db.GetUserByUsername(req.Username)
	if user == nil || !middleware.VerifyPassword(req.Password, user.Salt, user.PasswordHash) {
		noteLoginFailure(key)
		json.NewEncoder(w).Encode(loginResponse{Success: false, Message: "用户名或密码错误"})
		return
	}
	noteLoginSuccess(key)

	// 历史 sha256 哈希在登录成功后自动升级为 PBKDF2
	if middleware.PasswordHashNeedsUpgrade(user.PasswordHash) {
		newSalt := middleware.GenerateSalt()
		user.PasswordHash = middleware.HashPassword(req.Password, newSalt)
		user.Salt = newSalt
		db.UpdateUser(user)
	}

	token := middleware.GetSessionStore().CreateSession(user.ID)
	// 由服务端下发 HttpOnly Cookie（前端不再用 document.cookie 写入）
	middleware.SetSessionCookie(w, r, token, middleware.SessionTTL)
	json.NewEncoder(w).Encode(loginResponse{Success: true, Token: token})
}

func itoaSeconds(n int) string {
	if n <= 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if token := middleware.GetSessionToken(r); token != "" {
		middleware.GetSessionStore().DeleteSession(token)
	}
	middleware.ClearSessionCookie(w, r)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

type changePwdRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	userID := middleware.GetCurrentUserID(r)
	if userID == 0 {
		http.Error(w, "Unauthorized", 401)
		return
	}

	var req changePwdRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Invalid request"})
		return
	}

	// 新密码强度校验（空密码、过短、弱口令、与用户名相同都会被拒绝）
	if msg := middleware.ValidatePasswordStrength("", req.NewPassword); msg != "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": msg})
		return
	}

	db := database.GetDB()
	user := db.GetUserByID(userID)
	if user == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "User not found"})
		return
	}
	if msg := middleware.ValidatePasswordStrength(user.Username, req.NewPassword); msg != "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": msg})
		return
	}

	if !middleware.VerifyPassword(req.OldPassword, user.Salt, user.PasswordHash) {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "旧密码不正确"})
		return
	}
	if req.NewPassword == req.OldPassword {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "新密码不能与旧密码相同"})
		return
	}

	newSalt := middleware.GenerateSalt()
	user.PasswordHash = middleware.HashPassword(req.NewPassword, newSalt)
	user.Salt = newSalt
	db.UpdateUser(user)

	// 改密后：吊销该用户其它会话，并轮换当前会话 token
	oldToken := middleware.GetSessionToken(r)
	revoked := middleware.GetSessionStore().DeleteByUser(user.ID, oldToken)
	if oldToken != "" {
		middleware.GetSessionStore().DeleteSession(oldToken)
	}
	newToken := middleware.GetSessionStore().CreateSession(user.ID)
	middleware.SetSessionCookie(w, r, newToken, middleware.SessionTTL)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"message":          "密码修改成功",
		"token":            newToken,
		"revoked_sessions": revoked,
	})
}
