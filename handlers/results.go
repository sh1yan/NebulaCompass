package handlers

import (
	"NebulaCompass/database"
	"NebulaCompass/models"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

type ResultHandler struct{}

func NewResultHandler() *ResultHandler { return &ResultHandler{} }

func (h *ResultHandler) List(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/")
	taskID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
		return
	}

	db := database.GetDB()
	results := db.GetResultsByTask(taskID)
	if results == nil {
		results = []*models.ScanResult{}
	}

	query := r.URL.Query().Get("search")
	if query != "" {
		results = db.SearchOpenPorts(taskID, query)
	}

	json.NewEncoder(w).Encode(results)
}

func (h *ResultHandler) Summary(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/summary/")
	taskID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
		return
	}

	db := database.GetDB()
	task := db.GetTask(taskID)
	summary := db.GetResultsSummary(taskID)
	hostSummary := db.GetHostPortSummary(taskID)

	aliveOnly := []string{}
	if task != nil {
		for _, ip := range task.AliveHosts {
			hasOpen := false
			for _, h := range hostSummary {
				if h.IP == ip {
					hasOpen = true
					break
				}
			}
			if !hasOpen {
				aliveOnly = append(aliveOnly, ip)
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"summary":    summary,
		"hosts":      hostSummary,
		"alive_only": aliveOnly,
	})
}

func (h *ResultHandler) ExportXLSX(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/export/")
	taskID, err := strconv.ParseInt(idStr, 10, 64)
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

	results := db.GetResultsByTask(taskID)
	hostSummary := db.GetHostPortSummary(taskID)

	f := excelize.NewFile()
	defer f.Close()

	f.SetColWidth("Sheet1", "A", "J", 18)

	f.SetCellValue("Sheet1", "A1", "星云罗盘 - 资产测绘报告")
	f.SetCellValue("Sheet1", "A2", fmt.Sprintf("任务名称: %s", task.Name))
	f.SetCellValue("Sheet1", "A3", fmt.Sprintf("扫描目标: %s", task.Target))
	f.SetCellValue("Sheet1", "A4", fmt.Sprintf("扫描模式: %s", getModeLabel(task.ScanMode)))
	portRangeDisplay := task.PortRange
	if task.ScanMode == models.ScanModeServiceOnly {
		portRangeDisplay = "按目标指定"
	}
	f.SetCellValue("Sheet1", "A5", fmt.Sprintf("端口范围: %s", portRangeDisplay))
	f.SetCellValue("Sheet1", "A6", fmt.Sprintf("扫描时间: %s", task.CreatedAt))
	if task.CompletedAt != "" {
		f.SetCellValue("Sheet1", "A7", fmt.Sprintf("完成时间: %s", task.CompletedAt))
	}
	f.SetCellValue("Sheet1", "A8", fmt.Sprintf("存活主机数: %d", task.TotalHosts))
	f.SetCellValue("Sheet1", "A9", fmt.Sprintf("开放端口主机数: %d", len(hostSummary)))
	f.SetCellValue("Sheet1", "A10", fmt.Sprintf("开放端口数: %d", task.TotalPorts))

	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 16},
	})
	f.SetCellStyle("Sheet1", "A1", "A1", titleStyle)

	headers := []string{"IP", "端口", "协议", "状态", "服务", "产品", "版本", "额外信息", "操作系统"}
	headerRow := 11
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"4472C4"}},
	})
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, headerRow)
		f.SetCellValue("Sheet1", cell, h)
		f.SetCellStyle("Sheet1", cell, cell, headerStyle)
	}

	dataRow := headerRow + 1
	for _, r := range results {
		f.SetCellValue("Sheet1", fmt.Sprintf("A%d", dataRow), r.IP)
		f.SetCellValue("Sheet1", fmt.Sprintf("B%d", dataRow), r.Port)
		f.SetCellValue("Sheet1", fmt.Sprintf("C%d", dataRow), r.Protocol)
		f.SetCellValue("Sheet1", fmt.Sprintf("D%d", dataRow), r.State)
		f.SetCellValue("Sheet1", fmt.Sprintf("E%d", dataRow), r.Service)
		f.SetCellValue("Sheet1", fmt.Sprintf("F%d", dataRow), r.Product)
		f.SetCellValue("Sheet1", fmt.Sprintf("G%d", dataRow), r.Version)
		f.SetCellValue("Sheet1", fmt.Sprintf("H%d", dataRow), r.ExtraInfo)
		f.SetCellValue("Sheet1", fmt.Sprintf("I%d", dataRow), r.OSDetails)
		dataRow++
	}

	// 添加存活主机Sheet
	if len(task.AliveHosts) > 0 {
		f.NewSheet("存活主机")
		f.SetColWidth("存活主机", "A", "D", 20)

		f.SetCellValue("存活主机", "A1", "存活主机列表")
		aliveTitleStyle, _ := f.NewStyle(&excelize.Style{
			Font: &excelize.Font{Bold: true, Size: 14},
		})
		f.SetCellStyle("存活主机", "A1", "A1", aliveTitleStyle)

		f.SetCellValue("存活主机", "A2", "总数")
		f.SetCellValue("存活主机", "B2", len(task.AliveHosts))
		f.SetCellValue("存活主机", "A3", "有开放端口主机")
		f.SetCellValue("存活主机", "B3", len(hostSummary))
		aliveOnlyLabel := "仅存活无端口主机"
		if task.ScanMode == models.ScanModeAliveOnly {
			aliveOnlyLabel = "仅存活主机"
		}
		f.SetCellValue("存活主机", "A4", aliveOnlyLabel)
		onlyAlive := len(task.AliveHosts) - len(hostSummary)
		if onlyAlive < 0 {
			onlyAlive = 0
		}
		f.SetCellValue("存活主机", "B4", onlyAlive)

		aliveHeaders := []string{"序号", "IP地址", "状态", "开放端口"}
		aliveHeaderRow := 6
		for i, h := range aliveHeaders {
			cell, _ := excelize.CoordinatesToCellName(i+1, aliveHeaderRow)
			f.SetCellValue("存活主机", cell, h)
			f.SetCellStyle("存活主机", cell, cell, headerStyle)
		}

		// 构建有端口的主机map
		hostPortMap := make(map[string][]int)
		for _, h := range hostSummary {
			hostPortMap[h.IP] = h.Ports
		}

		aliveDataRow := aliveHeaderRow + 1
		for idx, ip := range task.AliveHosts {
			ports := hostPortMap[ip]
			f.SetCellValue("存活主机", fmt.Sprintf("A%d", aliveDataRow), idx+1)
			f.SetCellValue("存活主机", fmt.Sprintf("B%d", aliveDataRow), ip)
			if len(ports) > 0 {
				f.SetCellValue("存活主机", fmt.Sprintf("C%d", aliveDataRow), "存活+有开放端口")
				portStrs := make([]string, len(ports))
				for i, p := range ports {
					portStrs[i] = fmt.Sprintf("%d", p)
				}
				f.SetCellValue("存活主机", fmt.Sprintf("D%d", aliveDataRow), strings.Join(portStrs, ", "))
			} else {
				f.SetCellValue("存活主机", fmt.Sprintf("C%d", aliveDataRow), "存活")
				noPortLabel := "无开放端口"
				if task.ScanMode == models.ScanModeAliveOnly {
					noPortLabel = ""
				}
				f.SetCellValue("存活主机", fmt.Sprintf("D%d", aliveDataRow), noPortLabel)
			}
			aliveDataRow++
		}
	}

	exportDir := "./ExportResults"
	os.MkdirAll(exportDir, 0700)
	safeName := strings.ReplaceAll(task.Name, " ", "_")
	fileName := fmt.Sprintf("%s_%d.xlsx", safeName, task.ID)
	filePath := filepath.Join(exportDir, fileName)

	if err := f.SaveAs(filePath); err != nil {
		http.Error(w, fmt.Sprintf("Export failed: %v", err), 500)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	http.ServeFile(w, r, filePath)
}

func (h *ResultHandler) GetOSSummary(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/results/os/")
	taskID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
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
	taskID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
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
	http.ServeFile(w, r, "templates/results.html")
}

func getModeLabel(mode string) string {
	switch mode {
	case models.ScanModeFull:
		return "全套扫描"
	case models.ScanModeAliveOnly:
		return "存活探测"
	case models.ScanModePortOnly:
		return "端口扫描"
	case models.ScanModeServiceOnly:
		return "服务识别"
	case models.ScanModeNmapPort:
		return "Nmap端口扫描"
	default:
		return "全套扫描"
	}
}
