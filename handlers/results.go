package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"NebulaCompass/database"
	"NebulaCompass/models"
)

type ResultHandler struct{}

func NewResultHandler() *ResultHandler { return &ResultHandler{} }

// asciiFileName 把任务名转成纯 ASCII 的兜底文件名（非 ASCII 字符替换为下划线）
func asciiFileName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 127 || r == '"' || r == '\\' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.Trim(b.String(), "_ ")
	if out == "" {
		out = "task"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

// sanitizeHeaderName 清洗用于 header 的任务名：去掉路径分隔符、控制字符与引号，保留中文与空格
func sanitizeHeaderName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r == '/' {
			b.WriteRune('_')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.Trim(b.String(), "_ ")
	if out == "" {
		return "task"
	}
	if r := []rune(out); len(r) > 60 {
		out = string(r[:60])
	}
	return out
}

// contentDisposition 同时提供 ASCII 兜底名与 RFC 5987 的 filename*，避免中文名在浏览器里乱码
func contentDisposition(name string, taskID int64, ext string) string {
	pretty := sanitizeHeaderName(name)
	utf8Name := fmt.Sprintf("%s_%d%s", pretty, taskID, ext)
	return fmt.Sprintf(`attachment; filename="%s_%d%s"; filename*=UTF-8''%s`,
		asciiFileName(name), taskID, ext, url.PathEscape(utf8Name))
}

func mustTaskID(w http.ResponseWriter, raw string) (int64, bool) {
	taskID, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
		return 0, false
	}
	return taskID, true
}

func (h *ResultHandler) List(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/")
	taskID, ok := mustTaskID(w, idStr)
	if !ok {
		return
	}

	db := database.GetDB()
	query := r.URL.Query().Get("search")
	var results []*models.ScanResult
	if query != "" {
		results = db.SearchOpenPorts(taskID, query)
	} else {
		results = db.GetResultsByTask(taskID)
	}
	if results == nil {
		results = []*models.ScanResult{}
	}
	json.NewEncoder(w).Encode(results)
}

func (h *ResultHandler) Summary(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/summary/")
	taskID, ok := mustTaskID(w, idStr)
	if !ok {
		return
	}

	db := database.GetDB()
	task := db.GetTask(taskID)
	summary := db.GetResultsSummary(taskID)
	hostSummary := db.GetHostPortSummary(taskID)

	aliveOnly := []string{}
	taskInfo := map[string]interface{}{}
	if task != nil {
		for _, ip := range task.AliveHosts {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			hasOpen := false
			for _, hs := range hostSummary {
				if hs.IP == ip {
					hasOpen = true
					break
				}
			}
			if !hasOpen {
				aliveOnly = append(aliveOnly, ip)
			}
		}
		taskInfo = map[string]interface{}{
			"id":            task.ID,
			"status":        task.Status,
			"status_text":   models.StatusLabel(task.Status),
			"scan_mode":     task.ScanMode,
			"mode_text":     models.ModeLabel(task.ScanMode),
			"current_phase": task.CurrentPhase,
			"progress_pct":  task.ProgressPct,
			"eta_seconds":   task.EtaSeconds,
			"eta_text":      task.EtaText,
			"scan_percent":  task.ScanPercent,
			"rate_kpps":     task.RateKpps,
			"resume_stage":  task.ResumeStage,
			"has_data":      len(hostSummary) > 0 || len(task.AliveHosts) > 0 || task.PortScanOutput != "" || task.PingOutput != "",
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"summary":    summary,
		"hosts":      hostSummary,
		"alive_only": aliveOnly,
		"task":       taskInfo,
	})
}

// ExportXLSX 导出扫描结果，支持 format=xlsx|csv|json，任意状态（含暂停/取消）均可导出
func (h *ResultHandler) ExportXLSX(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/export/")
	taskID, ok := mustTaskID(w, idStr)
	if !ok {
		return
	}

	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		http.Error(w, "Task not found", 404)
		return
	}

	results := db.GetResultsByTask(taskID)
	hostSummary := db.GetHostPortSummary(taskID)
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	base := task.Name

	switch format {
	case "csv":
		data := resultsCSV(results)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", contentDisposition(base, task.ID, ".csv"))
		w.Write(data)
		return
	case "json":
		data := resultsJSON(task, results, hostSummary)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", contentDisposition(base, task.ID, ".json"))
		w.Write(data)
		return
	}

	f, err := buildWorkbook(task, results, hostSummary)
	if err != nil {
		http.Error(w, fmt.Sprintf("Export failed: %v", err), 500)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", contentDisposition(base, task.ID, ".xlsx"))
	if err := f.Write(w); err != nil {
		http.Error(w, fmt.Sprintf("Export failed: %v", err), 500)
	}
}

// ExportArchive 导出完整过程存档（zip：结果 + 原始输出 + 过程日志 + 命令记录）
func (h *ResultHandler) ExportArchive(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/archive/")
	taskID, ok := mustTaskID(w, idStr)
	if !ok {
		return
	}

	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		http.Error(w, "Task not found", 404)
		return
	}
	results := db.GetResultsByTask(taskID)
	hostSummary := db.GetHostPortSummary(taskID)

	files, err := taskArchiveFiles(task, results, hostSummary)
	if err != nil {
		http.Error(w, fmt.Sprintf("Archive failed: %v", err), 500)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDisposition(task.Name, task.ID, "_archive.zip"))
	if err := writeZipTo(w, files); err != nil {
		http.Error(w, fmt.Sprintf("Archive failed: %v", err), 500)
	}
}

func (h *ResultHandler) GetOSSummary(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/os/")
	taskID, ok := mustTaskID(w, idStr)
	if !ok {
		return
	}

	db := database.GetDB()
	results := db.GetResultsByTask(taskID)
	osMap := make(map[string]int)
	for _, r := range results {
		if r.OSDetails != "" {
			osMap[r.OSDetails]++
		}
	}
	json.NewEncoder(w).Encode(osMap)
}

func (h *ResultHandler) GetServiceSummary(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/services/")
	taskID, ok := mustTaskID(w, idStr)
	if !ok {
		return
	}

	db := database.GetDB()
	results := db.GetResultsByTask(taskID)
	svcMap := make(map[string]int)
	for _, r := range results {
		if r.Service != "" {
			svcMap[r.Service]++
		}
	}
	json.NewEncoder(w).Encode(svcMap)
}

func (h *ResultHandler) PageResults(w http.ResponseWriter, r *http.Request) {
	ServePage(w, r, "results.html")
}
