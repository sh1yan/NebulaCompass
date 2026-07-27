package handlers

import (
	"NebulaCompass/database"
	"NebulaCompass/middleware"
	"encoding/json"
	"net/http"
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

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.ServeFile(w, r, "templates/login.html")
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

	db := database.GetDB()
	user := db.GetUserByUsername(req.Username)
	if user == nil {
		json.NewEncoder(w).Encode(loginResponse{Success: false, Message: "User not found"})
		return
	}

	hash := middleware.HashPassword(req.Password, user.Salt)
	if hash != user.PasswordHash {
		json.NewEncoder(w).Encode(loginResponse{Success: false, Message: "Invalid password"})
		return
	}

	token := middleware.GetSessionStore().CreateSession(user.ID)
	json.NewEncoder(w).Encode(loginResponse{Success: true, Token: token})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_token")
	if cookie != nil {
		middleware.GetSessionStore().DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "session_token", Value: "", Path: "/",
		MaxAge: -1,
	})
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

	db := database.GetDB()
	user := db.GetUserByID(userID)
	if user == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "User not found"})
		return
	}

	if middleware.HashPassword(req.OldPassword, user.Salt) != user.PasswordHash {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Old password is incorrect"})
		return
	}

	newSalt := middleware.GenerateSalt()
	newHash := middleware.HashPassword(req.NewPassword, newSalt)
	user.PasswordHash = newHash
	user.Salt = newSalt
	db.UpdateUser(user)

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Password changed successfully"})
}
