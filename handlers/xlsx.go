package handlers

import (
	"fmt"
	"strings"

	"NebulaCompass/database"
	"NebulaCompass/models"

	"github.com/xuri/excelize/v2"
)

// buildWorkbook 生成扫描结果工作簿（支持未完成/已暂停/已取消的部分结果）
func buildWorkbook(task *models.Task, results []*models.ScanResult, hostSummary []database.HostPortSummary) (*excelize.File, error) {
	if task == nil {
		return nil, fmt.Errorf("task not found")
	}
	f := excelize.NewFile()
	sheet := "扫描结果"
	if err := f.SetSheetName("Sheet1", sheet); err != nil {
		return nil, err
	}
	f.SetColWidth(sheet, "A", "J", 20)

	f.SetCellValue(sheet, "A1", "星云罗盘 - 资产测绘报告")
	f.SetCellValue(sheet, "A2", fmt.Sprintf("任务名称: %s", task.Name))
	f.SetCellValue(sheet, "A3", fmt.Sprintf("扫描目标: %s", oneLine(task.Target, 200)))
	f.SetCellValue(sheet, "A4", fmt.Sprintf("扫描模式: %s", models.ModeLabel(task.ScanMode)))
	portRangeDisplay := task.PortRange
	if task.ScanMode == models.ScanModeServiceOnly {
		portRangeDisplay = "按目标指定 / " + task.PortRange
	}
	if task.ScanMode == models.ScanModeAliveOnly {
		portRangeDisplay = "不适用（仅存活探测）"
	}
	f.SetCellValue(sheet, "A5", fmt.Sprintf("端口范围: %s", portRangeDisplay))
	f.SetCellValue(sheet, "A6", fmt.Sprintf("创建时间: %s", task.CreatedAt))
	if task.StartedAt != "" {
		f.SetCellValue(sheet, "A7", fmt.Sprintf("开始时间: %s", task.StartedAt))
	}
	if task.CompletedAt != "" {
		f.SetCellValue(sheet, "A8", fmt.Sprintf("结束时间: %s", task.CompletedAt))
	}
	f.SetCellValue(sheet, "A9", fmt.Sprintf("任务状态: %s", models.StatusLabel(task.Status)))
	f.SetCellValue(sheet, "A10", fmt.Sprintf("完成进度: %.1f%% （阶段: %s）", task.ProgressPct, phaseText(task.CurrentPhase)))
	f.SetCellValue(sheet, "A11", fmt.Sprintf("存活主机数: %d", len(task.AliveHosts)))
	f.SetCellValue(sheet, "A12", fmt.Sprintf("开放端口主机数: %d", len(hostSummary)))
	f.SetCellValue(sheet, "A13", fmt.Sprintf("开放端口数: %d", len(results)))
	if task.Status == models.StatusPaused || task.Status == models.StatusCancelled || task.Status == models.StatusFailed {
		f.SetCellValue(sheet, "A14", "说明: 该任务未完整执行完毕，以上为当前已获得的部分结果")
	}

	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 16},
	})
	f.SetCellStyle(sheet, "A1", "A1", titleStyle)

	headers := []string{"IP", "端口", "协议", "状态", "服务", "产品", "版本", "额外信息", "操作系统"}
	headerRow := 16
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"4472C4"}},
	})
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, headerRow)
		f.SetCellValue(sheet, cell, h)
		f.SetCellStyle(sheet, cell, cell, headerStyle)
	}

	dataRow := headerRow + 1
	for _, r := range results {
		f.SetCellValue(sheet, fmt.Sprintf("A%d", dataRow), r.IP)
		f.SetCellValue(sheet, fmt.Sprintf("B%d", dataRow), r.Port)
		f.SetCellValue(sheet, fmt.Sprintf("C%d", dataRow), r.Protocol)
		f.SetCellValue(sheet, fmt.Sprintf("D%d", dataRow), r.State)
		f.SetCellValue(sheet, fmt.Sprintf("E%d", dataRow), r.Service)
		f.SetCellValue(sheet, fmt.Sprintf("F%d", dataRow), r.Product)
		f.SetCellValue(sheet, fmt.Sprintf("G%d", dataRow), r.Version)
		f.SetCellValue(sheet, fmt.Sprintf("H%d", dataRow), r.ExtraInfo)
		f.SetCellValue(sheet, fmt.Sprintf("I%d", dataRow), r.OSDetails)
		dataRow++
	}
	f.AutoFilter(sheet, fmt.Sprintf("A%d:I%d", headerRow, maxInt(dataRow-1, headerRow)), nil)

	// 存活主机 Sheet
	if len(task.AliveHosts) > 0 {
		aliveSheet := "存活主机"
		f.NewSheet(aliveSheet)
		f.SetColWidth(aliveSheet, "A", "D", 22)
		f.SetCellValue(aliveSheet, "A1", "存活主机列表")
		aliveTitleStyle, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true, Size: 14}})
		f.SetCellStyle(aliveSheet, "A1", "A1", aliveTitleStyle)

		f.SetCellValue(aliveSheet, "A2", "总数")
		f.SetCellValue(aliveSheet, "B2", len(task.AliveHosts))
		f.SetCellValue(aliveSheet, "A3", "有开放端口主机")
		f.SetCellValue(aliveSheet, "B3", len(hostSummary))
		aliveOnlyLabel := "仅存活无端口主机"
		if task.ScanMode == models.ScanModeAliveOnly {
			aliveOnlyLabel = "仅存活主机"
		}
		f.SetCellValue(aliveSheet, "A4", aliveOnlyLabel)
		onlyAlive := len(task.AliveHosts) - len(hostSummary)
		if onlyAlive < 0 {
			onlyAlive = 0
		}
		f.SetCellValue(aliveSheet, "B4", onlyAlive)

		aliveHeaders := []string{"序号", "IP地址", "状态", "开放端口"}
		aliveHeaderRow := 6
		for i, h := range aliveHeaders {
			cell, _ := excelize.CoordinatesToCellName(i+1, aliveHeaderRow)
			f.SetCellValue(aliveSheet, cell, h)
			f.SetCellStyle(aliveSheet, cell, cell, headerStyle)
		}

		hostPortMap := make(map[string][]int)
		for _, h := range hostSummary {
			hostPortMap[h.IP] = h.Ports
		}
		aliveDataRow := aliveHeaderRow + 1
		for idx, ip := range task.AliveHosts {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			ports := hostPortMap[ip]
			f.SetCellValue(aliveSheet, fmt.Sprintf("A%d", aliveDataRow), idx+1)
			f.SetCellValue(aliveSheet, fmt.Sprintf("B%d", aliveDataRow), ip)
			if len(ports) > 0 {
				f.SetCellValue(aliveSheet, fmt.Sprintf("C%d", aliveDataRow), "存活+有开放端口")
				portStrs := make([]string, len(ports))
				for i, p := range ports {
					portStrs[i] = fmt.Sprintf("%d", p)
				}
				f.SetCellValue(aliveSheet, fmt.Sprintf("D%d", aliveDataRow), strings.Join(portStrs, ", "))
			} else {
				f.SetCellValue(aliveSheet, fmt.Sprintf("C%d", aliveDataRow), "存活")
				noPortLabel := "无开放端口"
				if task.ScanMode == models.ScanModeAliveOnly || task.ScanMode == models.ScanModeServiceOnly {
					noPortLabel = ""
				}
				f.SetCellValue(aliveSheet, fmt.Sprintf("D%d", aliveDataRow), noPortLabel)
			}
			aliveDataRow++
		}
	}

	// 主机端口概览 Sheet
	if len(hostSummary) > 0 {
		hostSheet := "主机端口概览"
		f.NewSheet(hostSheet)
		f.SetColWidth(hostSheet, "A", "C", 30)
		f.SetCellValue(hostSheet, "A1", "IP地址")
		f.SetCellValue(hostSheet, "B1", "开放端口数")
		f.SetCellValue(hostSheet, "C1", "开放端口")
		f.SetCellStyle(hostSheet, "A1", "C1", headerStyle)
		row := 2
		for _, h := range hostSummary {
			portStrs := make([]string, len(h.Ports))
			for i, p := range h.Ports {
				portStrs[i] = fmt.Sprintf("%d", p)
			}
			f.SetCellValue(hostSheet, fmt.Sprintf("A%d", row), h.IP)
			f.SetCellValue(hostSheet, fmt.Sprintf("B%d", row), len(h.Ports))
			f.SetCellValue(hostSheet, fmt.Sprintf("C%d", row), strings.Join(portStrs, ", "))
			row++
		}
	}

	f.SetActiveSheet(0)
	return f, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func oneLine(s string, limit int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}

func phaseText(p string) string {
	switch p {
	case models.PhaseIdle:
		return "等待"
	case models.PhasePingScan:
		return "存活探测"
	case models.PhasePortScan:
		return "端口扫描"
	case models.PhaseServiceScan:
		return "服务识别"
	case models.PhaseNmapScan:
		return "Nmap端口扫描"
	case models.PhaseCompleted:
		return "完成"
	default:
		return p
	}
}
