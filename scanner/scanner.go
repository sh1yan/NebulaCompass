package scanner

import (
	"NebulaCompass/database"
	"NebulaCompass/models"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProgressEvent struct {
	TaskID         int64   `json:"task_id"`
	Status         string  `json:"status"`
	CurrentPhase   string  `json:"current_phase"`
	ProgressPct    float64 `json:"progress_pct"`
	ElapsedSeconds int64   `json:"elapsed_seconds"`
	Message        string  `json:"message"`
	OutputLine     string  `json:"output_line,omitempty"`
	OutputSource   string  `json:"output_source,omitempty"`
	EventType      string  `json:"event_type,omitempty"`
}

type EventBus struct {
	mu          sync.RWMutex
	subscribers map[int64][]chan ProgressEvent
}

var globalBus *EventBus
var busOnce sync.Once

func GetEventBus() *EventBus {
	busOnce.Do(func() {
		globalBus = &EventBus{
			subscribers: make(map[int64][]chan ProgressEvent),
		}
	})
	return globalBus
}

func (eb *EventBus) Subscribe(taskID int64) chan ProgressEvent {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	ch := make(chan ProgressEvent, 500)
	eb.subscribers[taskID] = append(eb.subscribers[taskID], ch)
	return ch
}

func (eb *EventBus) Unsubscribe(taskID int64, ch chan ProgressEvent) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	subs := eb.subscribers[taskID]
	for i, s := range subs {
		if s == ch {
			eb.subscribers[taskID] = append(subs[:i], subs[i+1:]...)
			close(ch)
			break
		}
	}
}

func (eb *EventBus) Publish(event ProgressEvent) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("EventBus.Publish recovered: %v (task=%d, type=%s)", rec, event.TaskID, event.EventType)
		}
	}()
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	for _, ch := range eb.subscribers[event.TaskID] {
		select {
		case ch <- event:
		default:
		}
	}
}

type ScanManager struct {
	mu      sync.Mutex
	running map[int64]scanCtx
}

type scanCtx struct {
	taskID int64
	cancel chan struct{}
}

var globalManager *ScanManager
var managerOnce sync.Once

func GetScanManager() *ScanManager {
	managerOnce.Do(func() {
		globalManager = &ScanManager{
			running: make(map[int64]scanCtx),
		}
	})
	return globalManager
}

func (sm *ScanManager) StartScan(taskID int64) error {
	sm.mu.Lock()
	if _, ok := sm.running[taskID]; ok {
		sm.mu.Unlock()
		return fmt.Errorf("task %d is already running", taskID)
	}
	ctx := scanCtx{taskID: taskID, cancel: make(chan struct{})}
	sm.running[taskID] = ctx
	sm.mu.Unlock()
	go sm.runScan(taskID, ctx.cancel)
	return nil
}

func (sm *ScanManager) CancelScan(taskID int64) {
	sm.mu.Lock()
	if ctx, ok := sm.running[taskID]; ok {
		close(ctx.cancel)
		delete(sm.running, taskID)
	}
	sm.mu.Unlock()

	db := database.GetDB()
	task := db.GetTask(taskID)
	if task != nil && (task.Status == models.StatusRunning || task.Status == models.StatusPending) {
		task.Status = models.StatusCancelled
		task.CompletedAt = time.Now().Format(time.RFC3339)
		db.UpdateTask(task)
	}
	GetEventBus().Publish(ProgressEvent{
		TaskID: taskID, Status: models.StatusCancelled, EventType: "progress",
		Message: "Task cancelled by user",
	})
}

func (sm *ScanManager) runScan(taskID int64, cancel chan struct{}) {
	defer func() {
		sm.mu.Lock()
		delete(sm.running, taskID)
		sm.mu.Unlock()
	}()

	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		log.Printf("Task %d not found", taskID)
		return
	}

	task.Status = models.StatusRunning
	task.StartedAt = time.Now().Format(time.RFC3339)
	db.UpdateTask(task)

	startTime := time.Now()

	// Elapsed timer
	scanDone := make(chan struct{})
	defer close(scanDone)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("Timer goroutine panic recovered for task %d: %v", taskID, rec)
			}
		}()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-scanDone:
				return
			case <-ticker.C:
				t := db.GetTask(taskID)
				if t == nil {
					return
				}
				t.ElapsedSeconds = int64(time.Since(startTime).Seconds())
				db.UpdateTask(t)
				GetEventBus().Publish(ProgressEvent{
					TaskID: taskID, Status: t.Status, CurrentPhase: t.CurrentPhase,
					ProgressPct: t.ProgressPct, ElapsedSeconds: t.ElapsedSeconds, EventType: "progress",
				})
			case <-cancel:
				return
			}
		}
	}()

	scanMode := task.ScanMode
	if scanMode == "" {
		scanMode = models.ScanModeFull
	}
	nmapPath := db.GetSetting(models.SettingNmapPath)
	masscanPath := db.GetSetting(models.SettingMasscanPath)
	nmapPingArgs := db.GetSetting(models.SettingNmapPingArgs)
	masscanArgs := db.GetSetting(models.SettingMasscanArgs)
	nmapServiceArgs := db.GetSetting(models.SettingNmapServiceArgs)
	nmapNmapPortArgs := db.GetSetting(models.SettingNmapPortArgs)
	portRange := task.PortRange
	if portRange == "" {
		portRange = "1-65535"
	}

	// Handle nmap-only port scan mode 仅执行 nmap 端口扫描，非 masscan 的扫描
	if scanMode == models.ScanModeNmapPort {
		select {
		case <-cancel:
			return
		default:
		}
		publishEvent(db, taskID, models.PhaseNmapScan, 0, "Starting nmap port scan...", "")

		// 加载 nmap 端口扫描的参数
		nmapScanArgs := parseNmapPortArgs(nmapNmapPortArgs)
		nmapResult, err := RunNmapPortScan(task.Target, portRange, nmapPath, nmapScanArgs, taskID)
		if err != nil {
			failTask(db, taskID, cancel, err)
			return
		}

		task = db.GetTask(taskID)
		if task == nil {
			return
		}
		task.PortScanOutput = nmapResult.RawXML

		if len(nmapResult.Results) > 0 {

			for _, r := range nmapResult.Results {
				r.TaskID = taskID
			}
			db.AddResults(nmapResult.Results)
		}

		// task.TotalPorts = len(nmapResult.Results)
		// db.UpdateTask(task)

		hostSummary := db.GetHostPortSummary(taskID) // 用于解决nmap扫描结果中，无法获取到存活主机IP数量 2026.8.6
		aliveIPs := make([]string, 0, len(hostSummary))
		for _, h := range hostSummary {
			aliveIPs = append(aliveIPs, h.IP)
		}

		task.AliveHosts = aliveIPs
		task.TotalHosts = len(aliveIPs)
		task.ScannedHosts = len(aliveIPs)
		task.TotalPorts = len(nmapResult.Results)
		db.UpdateTask(task)

		doneTask(db, taskID, fmt.Sprintf("Nmap port scan complete: %d open ports found", len(nmapResult.Results)))
		return
	}

	// Handle service-only mode: skip ping scan, parse target as IP:port pairs
	if scanMode == models.ScanModeServiceOnly {
		select {
		case <-cancel:
			return
		default:
		}
		publishEvent(db, taskID, models.PhaseServiceScan, 0, "Starting service scan from IP:port targets...", "")

		ipPorts := parseServiceTargets(task.Target)
		task = db.GetTask(taskID)
		if task == nil {
			return
		}
		task.TotalHosts = len(ipPorts)
		db.UpdateTask(task)

		hostIndex := 0
		totalTargets := len(ipPorts)
		for ip, ports := range ipPorts {
			select {
			case <-cancel:
				log.Printf("Task %d cancelled during service-only scan", taskID)
				return
			default:
			}

			progress := float64(hostIndex) / float64(totalTargets) * 100.0
			publishEvent(db, taskID, models.PhaseServiceScan, progress,
				fmt.Sprintf("Scanning %s (%d/%d)", ip, hostIndex+1, totalTargets), "")

			serviceResult, err := RunServiceScan(ip, ports, nmapPath, nmapServiceArgs, taskID)
			if err != nil {
				log.Printf("Task %d: Service scan failed for %s: %v", taskID, ip, err)
				hostIndex++
				continue
			}

			if len(serviceResult.Results) > 0 {
				for _, r := range serviceResult.Results {
					r.TaskID = taskID
				}
				db.AddResults(serviceResult.Results)
			}

			task = db.GetTask(taskID)
			if task == nil {
				return
			}
			task.ServiceOutput += serviceResult.RawXML + "\n"
			task.ScannedHosts = hostIndex + 1
			db.UpdateTask(task)
			hostIndex++
		}

		doneTask(db, taskID, fmt.Sprintf("Service scan complete: %d targets scanned", totalTargets))
		return
	}

	// Phase 1: Ping Scan
	select {
	case <-cancel:
		return
	default:
	}
	publishEvent(db, taskID, models.PhasePingScan, 0, "Starting ping scan...", "")
	nmapResult, err := RunPingScan(task.Target, nmapPath, nmapPingArgs, taskID)
	if err != nil {
		failTask(db, taskID, cancel, err)
		return
	}

	task = db.GetTask(taskID)
	if task == nil {
		log.Printf("Task %d deleted during ping scan, aborting", taskID)
		return
	}
	task.AliveHosts = nmapResult.AliveIPs
	task.PingOutput = nmapResult.RawXML
	task.TotalHosts = len(nmapResult.AliveIPs)

	// For alive-only mode, stop after ping scan and save results
	if scanMode == models.ScanModeAliveOnly {
		db.UpdateTask(task)
		doneTask(db, taskID, fmt.Sprintf("Alive scan complete: %d hosts found", len(nmapResult.AliveIPs)))
		return
	}
	db.UpdateTask(task)

	if len(nmapResult.AliveIPs) == 0 {
		doneTask(db, taskID, "No alive hosts found")
		return
	}
	log.Printf("Task %d: Found %d alive hosts", taskID, len(nmapResult.AliveIPs))

	publishEvent(db, taskID, models.PhasePortScan, 25,
		fmt.Sprintf("Found %d alive hosts", len(nmapResult.AliveIPs)), "")

	// Phase 2: Port Scan
	select {
	case <-cancel:
		return
	default:
	}
	masscanResult, err := RunMasscanWithFile(nmapResult.AliveIPs, portRange, masscanPath, masscanArgs, taskID)
	if err != nil {
		failTask(db, taskID, cancel, err)
		return
	}

	task = db.GetTask(taskID)
	if task == nil {
		log.Printf("Task %d deleted during masscan, aborting", taskID)
		return
	}
	task.PortScanOutput = masscanResult.RawOutput
	totalOpenPorts := 0
	for _, ports := range masscanResult.OpenPorts {
		totalOpenPorts += len(ports)
	}
	task.TotalPorts = totalOpenPorts
	db.UpdateTask(task)

	if totalOpenPorts == 0 {
		doneTask(db, taskID, "No open ports found")
		return
	}

	// For port-only mode, stop after masscan
	if scanMode == models.ScanModePortOnly {
		// Save masscan results to scan_results table
		results := make([]*models.ScanResult, 0)
		for ip, ports := range masscanResult.OpenPorts {
			for _, port := range ports {
				results = append(results, &models.ScanResult{
					TaskID:   taskID,
					IP:       ip,
					Port:     port,
					Protocol: "tcp",
					State:    "open",
				})
			}
		}
		if len(results) > 0 {
			db.AddResults(results)
		}
		doneTask(db, taskID, fmt.Sprintf("Port scan complete: %d open ports found", totalOpenPorts))
		return
	}

	publishEvent(db, taskID, models.PhaseServiceScan, 50,
		fmt.Sprintf("Found %d open ports", totalOpenPorts), "")

	// Phase 3: Service Scan
	hostIndex := 0
	totalHosts := len(masscanResult.OpenPorts)
	for ip, ports := range masscanResult.OpenPorts {
		select {
		case <-cancel:
			log.Printf("Task %d cancelled during service scan for %s", taskID, ip)
			return
		default:
		}

		progress := 50.0 + float64(hostIndex)/float64(totalHosts)*50.0
		publishEvent(db, taskID, models.PhaseServiceScan, progress,
			fmt.Sprintf("Scanning %s (%d/%d)", ip, hostIndex+1, totalHosts), "")

		serviceResult, err := RunServiceScan(ip, ports, nmapPath, nmapServiceArgs, taskID)
		if err != nil {
			log.Printf("Task %d: Service scan failed for %s: %v", taskID, ip, err)
			hostIndex++
			continue
		}

		if len(serviceResult.Results) > 0 {
			for _, r := range serviceResult.Results {
				r.TaskID = taskID
			}
			db.AddResults(serviceResult.Results)
		}

		task = db.GetTask(taskID)
		if task == nil {
			log.Printf("Task %d deleted during service scan of %s, aborting", taskID, ip)
			return
		}
		task.ServiceOutput += serviceResult.RawXML + "\n"
		task.ScannedHosts = hostIndex + 1
		db.UpdateTask(task)
		hostIndex++
	}

	doneTask(db, taskID, fmt.Sprintf("Scan complete: %d hosts, %d ports", hostIndex, totalOpenPorts))
}

func publishEvent(db *database.DB, taskID int64, phase string, progress float64, message string, output string) {
	t := db.GetTask(taskID)
	if t == nil {
		return
	}
	t.CurrentPhase = phase
	t.ProgressPct = progress
	db.UpdateTask(t)
	GetEventBus().Publish(ProgressEvent{
		TaskID: taskID, Status: t.Status, CurrentPhase: phase,
		ProgressPct: progress, ElapsedSeconds: t.ElapsedSeconds,
		EventType: "progress", Message: message, OutputLine: output,
	})
}

func doneTask(db *database.DB, taskID int64, message string) {
	t := db.GetTask(taskID)
	if t == nil {
		return
	}
	t.Status = models.StatusCompleted
	t.CurrentPhase = models.PhaseCompleted
	t.ProgressPct = 100
	t.CompletedAt = time.Now().Format(time.RFC3339)
	db.UpdateTask(t)
	GetEventBus().Publish(ProgressEvent{
		TaskID: taskID, Status: models.StatusCompleted, CurrentPhase: models.PhaseCompleted,
		ProgressPct: 100, EventType: "progress", Message: message,
	})
}

func failTask(db *database.DB, taskID int64, cancel chan struct{}, err error) {
	select {
	case <-cancel:
		return
	default:
	}
	t := db.GetTask(taskID)
	if t == nil {
		return
	}
	t.Status = models.StatusFailed
	t.ErrorMessage = err.Error()
	t.CompletedAt = time.Now().Format(time.RFC3339)
	db.UpdateTask(t)
	GetEventBus().Publish(ProgressEvent{
		TaskID: taskID, Status: models.StatusFailed, EventType: "progress",
		Message: err.Error(),
	})
	log.Printf("Task %d failed: %v", taskID, err)
}

// saveCmdRecord 保存命令记录到数据库
func saveCmdRecord(taskID int64, cmd string) {
	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		return
	}
	if task.CmdRecords != "" {
		task.CmdRecords += "\n"
	}
	task.CmdRecords += cmd
	db.UpdateTask(task)
}

// parseServiceTargets 解析 IP:端口 格式的目标列表
func parseServiceTargets(target string) map[string][]int {
	result := make(map[string][]int)
	parts := strings.Split(target, "\n")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		colonPos := strings.LastIndex(p, ":")
		if colonPos < 0 {
			continue
		}
		ip := strings.TrimSpace(p[:colonPos])
		portStr := strings.TrimSpace(p[colonPos+1:])
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		result[ip] = append(result[ip], port)
	}
	return result
}

// parseNmapPortArgs 为 nmap 端口扫描构建参数
func parseNmapPortArgs(serviceArgs string) string {
	// 移除 -sV 参数，替换为 -sS 或 -sT
	// args := strings.ReplaceAll(serviceArgs, "-sV", "-sS")
	args := serviceArgs
	// 如果没指定扫描类型，使用 -sS
	if !strings.Contains(args, "-sS") && !strings.Contains(args, "-sT") {
		args = "-sS" + args
	}
	if !strings.Contains(args, "-Pn") {
		args = "-Pn" + args
	}
	if !strings.Contains(args, "-n") {
		args = "-n" + args
	}

	return args
}

// RunNmapPortResult 存储 nmap 端口扫描结果
type NmapPortResult struct {
	Results []*models.ScanResult
	RawXML  string
}

// RunNmapPortScan 使用 nmap 进行端口扫描（跳过 masscan）
func RunNmapPortScan(target string, portRange string, nmapPath string, nmapArgs string, taskID int64) (*NmapPortResult, error) {
	args := parseArgs(nmapArgs)
	args = append(args, "-oX", "-", "-p", portRange)

	// 将多行目标拆分为单个 IP
	targets := strings.Fields(strings.ReplaceAll(target, "\n", " "))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t != "" {
			args = append(args, t)
		}
	}

	cmd := exec.Command(nmapPath, args...)
	GetEventBus().Publish(ProgressEvent{
		TaskID:       taskID,
		EventType:    "command",
		OutputSource: "port_scan",
		OutputLine:   strings.Join(cmd.Args, " "),
	})
	saveCmdRecord(taskID, strings.Join(cmd.Args, " "))

	raw, err := execCmdStream(cmd, taskID, "port_scan")
	if err != nil {
		return nil, fmt.Errorf("nmap port scan failed: %v\noutput: %s", err, raw)
	}

	results := parseServiceXML([]byte(raw), "")
	return &NmapPortResult{
		Results: results,
		RawXML:  raw,
	}, nil
}
