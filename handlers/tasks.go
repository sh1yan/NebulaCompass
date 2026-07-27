package handlers

import (
	"NebulaCompass/database"
	"NebulaCompass/models"
	"NebulaCompass/scanner"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type TaskHandler struct{}

func NewTaskHandler() *TaskHandler { return &TaskHandler{} }

type createTaskRequest struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	PortRange string `json:"port_range"`
	ScanMode  string `json:"scan_mode"`
}

func (h *TaskHandler) List(w http.ResponseWriter, r *http.Request) {
	db := database.GetDB()
	tasks := db.GetAllTasks()
	json.NewEncoder(w).Encode(tasks)
}

func (h *TaskHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Invalid request"})
		return
	}

	if req.Name == "" || req.Target == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Name and target are required"})
		return
	}

	// Validate scan mode
	if req.ScanMode == "" {
		req.ScanMode = models.ScanModeFull
	}
	validModes := map[string]bool{models.ScanModeFull: true, models.ScanModeAliveOnly: true,
		models.ScanModePortOnly: true, models.ScanModeServiceOnly: true, models.ScanModeNmapPort: true}
	if !validModes[req.ScanMode] {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Invalid scan mode"})
		return
	}

	// For service_only mode, target must be in IP:port format
	if req.ScanMode == models.ScanModeServiceOnly {
		parts := strings.Split(req.Target, "\n")
		hasValid := false
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if strings.Contains(p, ":") {
				hasValid = true
				break
			}
		}
		if !hasValid {
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "服务扫描模式需要输入 IP:端口 格式的目标"})
			return
		}
	}

	if req.PortRange == "" {
		req.PortRange = "1-65535"
	}

	db := database.GetDB()
	task := db.CreateTaskWithMode(req.Name, req.Target, req.PortRange, req.ScanMode)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"task":    task,
	})
}

func (h *TaskHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	taskID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
		return
	}
	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		http.Error(w, "Task not found", 404)
		return
	}
	json.NewEncoder(w).Encode(task)
}

func (h *TaskHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	id := r.PathValue("id")
	taskID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
		return
	}
	db := database.GetDB()
	scanner.GetScanManager().CancelScan(taskID)
	db.DeleteTask(taskID)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (h *TaskHandler) Start(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	id := r.PathValue("id")
	taskID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
		return
	}

	if err := scanner.GetScanManager().StartScan(taskID); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (h *TaskHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	id := r.PathValue("id")
	taskID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
		return
	}

	scanner.GetScanManager().CancelScan(taskID)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (h *TaskHandler) PageList(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/tasks.html")
}

func (h *TaskHandler) PageDetail(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/task_detail.html")
}
