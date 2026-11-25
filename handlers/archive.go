package handlers

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"NebulaCompass/database"
	"NebulaCompass/models"
)

const exportDir = "./ExportResults"

func ensureExportDir() string {
	os.MkdirAll(exportDir, 0700)
	return exportDir
}

func safeFileName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "task"
	}
	replacer := strings.NewReplacer(" ", "_", "/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", "\n", "_", "\t", "_")
	s = replacer.Replace(s)
	if r := []rune(s); len(r) > 60 {
		s = string(r[:60])
	}
	return s
}

// resultsCSV 生成结果 CSV
func resultsCSV(results []*models.ScanResult) []byte {
	var buf bytes.Buffer
	// UTF-8 BOM，方便 Excel 直接打开
	buf.WriteString("\xEF\xBB\xBF")
	w := csv.NewWriter(&buf)
	w.Write([]string{"IP", "端口", "协议", "状态", "服务", "产品", "版本", "额外信息", "操作系统", "采集时间"})
	for _, r := range results {
		w.Write([]string{
			r.IP, strconv.Itoa(r.Port), r.Protocol, r.State,
			r.Service, r.Product, r.Version, r.ExtraInfo, r.OSDetails, r.CreatedAt,
		})
	}
	w.Flush()
	return buf.Bytes()
}

// resultsJSON 生成结果 JSON
func resultsJSON(task *models.Task, results []*models.ScanResult, hostSummary []database.HostPortSummary) []byte {
	payload := map[string]interface{}{
		"task": map[string]interface{}{
			"id":              task.ID,
			"name":            task.Name,
			"target":          task.Target,
			"scan_mode":       task.ScanMode,
			"scan_mode_text":  models.ModeLabel(task.ScanMode),
			"port_range":      task.PortRange,
			"status":          task.Status,
			"status_text":     models.StatusLabel(task.Status),
			"current_phase":   task.CurrentPhase,
			"progress_pct":    task.ProgressPct,
			"created_at":      task.CreatedAt,
			"started_at":      task.StartedAt,
			"completed_at":    task.CompletedAt,
			"elapsed_seconds": task.ElapsedSeconds,
			"error_message":   task.ErrorMessage,
			"alive_hosts":     task.AliveHosts,
		},
		"host_summary": hostSummary,
		"results":      results,
		"exported_at":  time.Now().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	return data
}

// taskArchiveFiles 组装任务存档包内的所有文件
func taskArchiveFiles(task *models.Task, results []*models.ScanResult, hostSummary []database.HostPortSummary) (map[string][]byte, error) {
	files := make(map[string][]byte)

	// task.json：任务元数据（含断点、进度、命令记录）
	meta := map[string]interface{}{
		"id":                 task.ID,
		"name":               task.Name,
		"target":             task.Target,
		"scan_mode":          task.ScanMode,
		"scan_mode_text":     models.ModeLabel(task.ScanMode),
		"port_range":         task.PortRange,
		"port_presets":       task.PortPresets,
		"status":             task.Status,
		"status_text":        models.StatusLabel(task.Status),
		"current_phase":      task.CurrentPhase,
		"progress_pct":       task.ProgressPct,
		"resume_stage":       task.ResumeStage,
		"elapsed_seconds":    task.ElapsedSeconds,
		"created_at":         task.CreatedAt,
		"started_at":         task.StartedAt,
		"completed_at":       task.CompletedAt,
		"error_message":      task.ErrorMessage,
		"alive_hosts":        task.AliveHosts,
		"service_done_hosts": task.ServiceDoneHosts,
		"total_ports":        len(results),
		"exported_at":        time.Now().Format(time.RFC3339),
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	files["task.json"] = metaData
	files["results.csv"] = resultsCSV(results)
	files["results.json"] = resultsJSON(task, results, hostSummary)

	if f, err := buildWorkbook(task, results, hostSummary); err == nil {
		var buf bytes.Buffer
		if err := f.Write(&buf); err == nil {
			files["results.xlsx"] = buf.Bytes()
		}
		f.Close()
	}

	if len(task.AliveHosts) > 0 {
		files["alive_hosts.txt"] = []byte(strings.Join(task.AliveHosts, "\n"))
	}
	if strings.TrimSpace(task.PingOutput) != "" {
		files["ping_scan.xml"] = []byte(task.PingOutput)
	}
	if strings.TrimSpace(task.PortScanOutput) != "" {
		files["port_scan.txt"] = []byte(task.PortScanOutput)
	}
	if strings.TrimSpace(task.ServiceOutput) != "" {
		files["service_scan.xml"] = []byte(task.ServiceOutput)
	}
	if strings.TrimSpace(task.CmdRecords) != "" {
		files["commands.txt"] = []byte(task.CmdRecords)
	}
	if strings.TrimSpace(task.ScanLog) != "" {
		// 日志被截断时，扫描器已在尾部写入说明；这里只在缺失时补一行提示
		header := ""
		if strings.Contains(task.ScanLog, "过程日志已达上限") == false && len(task.ScanLog) >= 512*1024-2048 {
			header = "[说明] 过程日志上限 512KB，仅保留最后一段，早期日志已被截断。\n\n"
		}
		files["scan_log.txt"] = []byte(header + task.ScanLog)
	}

	readme := fmt.Sprintf(`星云罗盘 - 扫描任务存档
================================
任务ID     : %d
任务名称   : %s
扫描模式   : %s
扫描目标   : %s
端口范围   : %s
任务状态   : %s（进度 %.1f%%，阶段 %s）
创建时间   : %s
开始时间   : %s
结束时间   : %s
导出时间   : %s

结果统计
  存活主机   : %d
  开放端口主机: %d
  开放端口   : %d

包内文件
  results.xlsx       结构化扫描结果（含存活主机、主机端口概览）
  results.csv        端口结果（Excel 可直接打开）
  results.json       完整结果 JSON
  task.json          任务元数据与断点信息
  alive_hosts.txt    存活主机列表
  ping_scan.xml      存活探测原始 XML
  port_scan.txt      端口扫描原始输出
  service_scan.xml   服务识别原始 XML
  commands.txt       实际执行的命令行
  scan_log.txt       扫描过程日志（上限 512KB，超出时只保留尾部）

说明
  暂停 / 取消 / 失败的任务同样可以导出，此存档代表导出时刻已获得的最终结果。
  端口扫描阶段被暂停/取消时，已命中的端口同样会保留在 results.* 与 port_scan.txt 中。
  过程日志与 service_scan.xml 超过上限时会被截断，文件开头会标注截断提示。
`, task.ID, task.Name, models.ModeLabel(task.ScanMode), oneLine(task.Target, 200), task.PortRange,
		models.StatusLabel(task.Status), task.ProgressPct, phaseText(task.CurrentPhase),
		task.CreatedAt, task.StartedAt, task.CompletedAt, time.Now().Format(time.RFC3339),
		len(task.AliveHosts), len(hostSummary), len(results))
	files["README.txt"] = []byte(readme)

	return files, nil
}

// writeZipTo 把文件集合写成 zip
func writeZipTo(w io.Writer, files map[string][]byte) error {
	zw := zip.NewWriter(w)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fw, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := fw.Write(files[name]); err != nil {
			return err
		}
	}
	return zw.Close()
}

// SnapshotTaskToDisk 把任务当前结果存档到 ExportResults/history（重新扫描前自动调用）
func SnapshotTaskToDisk(taskID int64) (string, error) {
	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		return "", fmt.Errorf("任务不存在")
	}
	results := db.GetResultsByTask(taskID)
	hostSummary := db.GetHostPortSummary(taskID)
	if len(results) == 0 && strings.TrimSpace(task.PingOutput) == "" && strings.TrimSpace(task.PortScanOutput) == "" && strings.TrimSpace(task.ScanLog) == "" {
		return "", nil // 没有任何数据，无需存档
	}

	files, err := taskArchiveFiles(task, results, hostSummary)
	if err != nil {
		return "", err
	}

	dir := filepath.Join(ensureExportDir(), "history")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s_%d_%s_%s.zip", safeFileName(task.Name), task.ID, task.Status, time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := writeZipTo(f, files); err != nil {
		return "", err
	}
	return path, nil
}
