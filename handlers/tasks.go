package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"NebulaCompass/database"
	"NebulaCompass/models"
	"NebulaCompass/scanner"
)

type TaskHandler struct{}

func NewTaskHandler() *TaskHandler { return &TaskHandler{} }

type createTaskRequest struct {
	Name        string   `json:"name"`
	Target      string   `json:"target"`
	PortRange   string   `json:"port_range"`
	CustomPorts string   `json:"custom_ports"`
	PortPresets []string `json:"port_presets"`
	ScanMode    string   `json:"scan_mode"`
}

func (h *TaskHandler) List(w http.ResponseWriter, r *http.Request) {
	db := database.GetDB()
	tasks := db.GetAllTasks()
	if tasks == nil {
		tasks = []*models.Task{}
	}
	for _, t := range tasks {
		// 列表不返回大字段，避免响应过大。
		// ResultCount 已由 SQL 子查询带出（不再逐任务 COUNT(*)，历史缺陷 D-17/D-28）
		t.ScanLog = ""
		t.PingOutput = ""
		t.PortScanOutput = ""
		t.ServiceOutput = ""
		t.CmdRecords = ""
	}
	json.NewEncoder(w).Encode(tasks)
}

func (h *TaskHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "请求格式错误"})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Target = strings.TrimSpace(req.Target)
	if req.Name == "" || req.Target == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "任务名称与扫描目标不能为空"})
		return
	}

	if req.ScanMode == "" {
		req.ScanMode = models.ScanModeFull
	}
	validModes := map[string]bool{
		models.ScanModeFull: true, models.ScanModeAliveOnly: true,
		models.ScanModePortOnly: true, models.ScanModeServiceOnly: true, models.ScanModeNmapPort: true,
	}
	if !validModes[req.ScanMode] {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的扫描模式"})
		return
	}

	// 目标校验：阻止格式错误，以及把 nmap/masscan 选项当作目标传入
	if bad := models.ValidateTargets(req.Target); len(bad) > 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "扫描目标不合法：" + strings.Join(bad, "、"),
		})
		return
	}

	// 服务识别：只扫描目标里写明的 IP:端口，不使用端口范围 / 预置端口列表。
	// 因此这里先做目标形态校验，缺端口的目标直接拒绝，避免"建了任务却什么都没扫"。
	if req.ScanMode == models.ScanModeServiceOnly {
		if issues := models.ServiceTargetIssues(req.Target); len(issues) > 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "服务识别模式只扫描目标中写明的端口，请写成 IP:端口（例如 10.0.0.1:80）。以下目标需要修改：" +
					strings.Join(issues, "、"),
			})
			return
		}
	}

	// 端口范围：勾选的预置列表 + 自定义输入（非法输入必须报错，不能静默替换成 1-65535）
	// 服务识别模式完全不参与端口规约，直接跳过，避免遗留的端口输入把任务拦下来。
	var spec string
	usedPresets := []string{}
	if req.ScanMode != models.ScanModeServiceOnly {
		custom := req.CustomPorts
		if strings.TrimSpace(custom) == "" {
			custom = req.PortRange
		}
		composed := models.ComposePortSpecChecked(req.PortPresets, custom)
		if len(composed.UnknownPresets) > 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "不存在的预置端口列表：" + strings.Join(composed.UnknownPresets, "、"),
			})
			return
		}
		if len(composed.InvalidTokens) > 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "端口格式不合法：" + strings.Join(composed.InvalidTokens, "、") + "（支持 80 / 8000-8100 / U:53）",
			})
			return
		}
		spec = composed.Spec
		usedPresets = composed.UsedPresets
	}

	switch req.ScanMode {
	case models.ScanModeAliveOnly, models.ScanModeServiceOnly:
		// 存活探测不涉及端口；服务识别的端口来自目标本身（IP:端口）
		spec = ""
	default:
		if spec == "" {
			spec = "1-65535"
		}
	}
	if spec != "" {
		spec = models.NormalizePortSpec(spec)
	}

	db := database.GetDB()
	presetStr := strings.Join(usedPresets, ",")
	task := db.CreateTaskWithMode(req.Name, req.Target, spec, req.ScanMode, presetStr)
	if task == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "创建任务失败"})
		return
	}

	resp := map[string]interface{}{
		"success": true,
		"task":    task,
	}
	// 依赖 masscan 的模式在非 root 下必然失败，提前提示
	if (req.ScanMode == models.ScanModeFull || req.ScanMode == models.ScanModePortOnly) && os.Geteuid() != 0 {
		resp["warning"] = "当前进程不是 root，masscan 端口扫描会失败；可用 sudo 运行本程序，或改用「Nmap 端口扫描」模式"
	}
	json.NewEncoder(w).Encode(resp)
}

func (h *TaskHandler) Get(w http.ResponseWriter, r *http.Request) {
	taskID, ok := mustTaskID(w, r.PathValue("id"))
	if !ok {
		return
	}
	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		http.Error(w, "Task not found", 404)
		return
	}
	task.ScanLog = ""
	json.NewEncoder(w).Encode(task)
}

func (h *TaskHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	taskID, ok := mustTaskID(w, r.PathValue("id"))
	if !ok {
		return
	}
	db := database.GetDB()
	// 先停止扫描 goroutine，避免删除后仍有写入
	scanner.GetScanManager().StopAndWait(taskID, 5*time.Second)
	// 删除前先落一份存档，避免误删丢失结果
	if path, err := SnapshotTaskToDisk(taskID); err == nil && path != "" {
		log.Printf("task %d archived before delete: %s", taskID, path)
	}
	db.DeleteTask(taskID)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// Start 启动扫描；若任务是暂停状态则从断点续扫
func (h *TaskHandler) Start(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	taskID, ok := mustTaskID(w, r.PathValue("id"))
	if !ok {
		return
	}

	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		http.Error(w, "Task not found", 404)
		return
	}

	wasPaused := task.Status == models.StatusPaused
	if !wasPaused && task.Status != models.StatusPending {
		// 重新扫描前，先把上一轮结果存档到 ExportResults/history
		if path, err := SnapshotTaskToDisk(taskID); err == nil && path != "" {
			log.Printf("task %d archived before rerun: %s", taskID, path)
		}
	}

	resumed, err := scanner.GetScanManager().StartScan(taskID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"resumed":    resumed,
		"was_paused": wasPaused,
	})
}

// Pause 暂停扫描（保留断点，可继续）
func (h *TaskHandler) Pause(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	taskID, ok := mustTaskID(w, r.PathValue("id"))
	if !ok {
		return
	}
	if !scanner.GetScanManager().PauseScan(taskID) {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "任务当前不在运行中，无法暂停"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// Cancel 取消扫描（保留已获得的结果供导出）
func (h *TaskHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	taskID, ok := mustTaskID(w, r.PathValue("id"))
	if !ok {
		return
	}
	scanner.GetScanManager().CancelScan(taskID)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (h *TaskHandler) PageList(w http.ResponseWriter, r *http.Request) {
	ServePage(w, r, "tasks.html")
}

func (h *TaskHandler) PageDetail(w http.ResponseWriter, r *http.Request) {
	ServePage(w, r, "task_detail.html")
}
