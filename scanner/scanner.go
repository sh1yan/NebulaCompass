package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"NebulaCompass/database"
	"NebulaCompass/models"
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
	// 端口扫描阶段的实时预估（masscan 自带）
	EtaSeconds  int64   `json:"eta_seconds,omitempty"`
	EtaText     string  `json:"eta_text,omitempty"`
	ScanPercent float64 `json:"scan_percent,omitempty"`
	RateKpps    float64 `json:"rate_kpps,omitempty"`
}

type EventBus struct {
	mu          sync.RWMutex
	subscribers map[int64][]chan ProgressEvent
	dropped     uint64
	lastDropLog int64
}

// eventBufferSize 订阅缓冲；输出行密集时留出足够余量，避免慢客户端丢事件
const eventBufferSize = 4096

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

// DroppedCount 累计被丢弃的事件数（订阅缓冲写满时）
func (eb *EventBus) DroppedCount() uint64 {
	return atomic.LoadUint64(&eb.dropped)
}

func (eb *EventBus) Subscribe(taskID int64) chan ProgressEvent {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	ch := make(chan ProgressEvent, eventBufferSize)
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
			// 订阅端消费太慢：丢弃并（限频）告警，避免静默丢事件无从排查
			n := atomic.AddUint64(&eb.dropped, 1)
			now := time.Now().Unix()
			last := atomic.LoadInt64(&eb.lastDropLog)
			if now-last >= 5 && atomic.CompareAndSwapInt64(&eb.lastDropLog, last, now) {
				log.Printf("EventBus: 订阅缓冲已满，累计丢弃 %d 条事件（task=%d）", n, event.TaskID)
			}
		}
	}
}

// ========== 任务运行管理 / 暂停 / 续扫 ==========

type runHandle struct {
	taskID int64
	ctx    context.Context
	cancel context.CancelFunc
	intent atomic.Value // "run" | "pause" | "cancel"
	done   chan struct{}
}

func (h *runHandle) setIntent(s string) { h.intent.Store(s) }

func (h *runHandle) getIntent() string {
	if v, ok := h.intent.Load().(string); ok && v != "" {
		return v
	}
	return "run"
}

type ScanManager struct {
	mu      sync.Mutex
	running map[int64]*runHandle
}

var globalManager *ScanManager
var managerOnce sync.Once

func GetScanManager() *ScanManager {
	managerOnce.Do(func() {
		globalManager = &ScanManager{
			running: make(map[int64]*runHandle),
		}
	})
	return globalManager
}

// IsRunning 任务是否正在运行
func (sm *ScanManager) IsRunning(taskID int64) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	_, ok := sm.running[taskID]
	return ok
}

// StartScan 启动或续跑一个扫描任务，返回是否真正从断点续跑
func (sm *ScanManager) StartScan(taskID int64) (bool, error) {
	db := database.GetDB()

	// 上一个执行句柄可能正在收尾（暂停/取消后子进程尚未退出）：短暂等待，避免误报“正在运行中”
	waitDeadline := time.Now().Add(5 * time.Second)
	for {
		sm.mu.Lock()
		_, busy := sm.running[taskID]
		sm.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(waitDeadline) {
			return false, fmt.Errorf("任务 %d 正在运行中", taskID)
		}
		time.Sleep(50 * time.Millisecond)
	}

	task := db.GetTask(taskID)
	if task == nil {
		return false, fmt.Errorf("任务 %d 不存在", taskID)
	}

	// 暂停中的任务：续扫；其它状态：全新扫描
	resumed := task.Status == models.StatusPaused &&
		(task.ResumeStage != "" || len(task.ServiceDoneHosts) > 0 || task.PingOutput != "" || task.PortScanOutput != "")

	ctx, cancel := context.WithCancel(context.Background())
	h := &runHandle{taskID: taskID, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	h.setIntent("run")
	sm.mu.Lock()
	if _, ok := sm.running[taskID]; ok {
		sm.mu.Unlock()
		cancel()
		return false, fmt.Errorf("任务 %d 正在运行中", taskID)
	}
	sm.running[taskID] = h
	sm.mu.Unlock()

	if !resumed && task.Status != models.StatusPending {
		// 重新扫描：清空上一轮的扫描数据（调用方负责先做存档）
		db.ResetTaskForRerun(taskID)
	}

	go sm.runScan(taskID, h, resumed)
	return resumed, nil
}

// PauseScan 暂停任务：中断当前子进程，保留已完成阶段的断点
func (sm *ScanManager) PauseScan(taskID int64) bool {
	sm.mu.Lock()
	h, ok := sm.running[taskID]
	sm.mu.Unlock()
	if ok {
		h.setIntent("pause")
		h.cancel()
		// 等扫描协程真正退出（子进程被终止 + 状态落库 + 句柄注销），
		// 否则用户立刻点“继续扫描”会撞上“任务正在运行中”
		select {
		case <-h.done:
		case <-time.After(15 * time.Second):
			log.Printf("task %d pause wait timeout", taskID)
		}
		return true
	}

	// 不在运行但在 running 状态（例如进程已退出），直接置为暂停
	db := database.GetDB()
	if t := db.GetTask(taskID); t != nil && t.Status == models.StatusRunning {
		t.Status = models.StatusPaused
		t.EtaSeconds = 0
		t.EtaText = ""
		t.RateKpps = 0
		db.UpdateTask(t)
		GetEventBus().Publish(ProgressEvent{
			TaskID: taskID, Status: models.StatusPaused, CurrentPhase: t.CurrentPhase,
			ProgressPct: t.ProgressPct, ElapsedSeconds: t.ElapsedSeconds,
			EventType: "progress", Message: "任务已暂停",
		})
		return true
	}
	return false
}

// CancelScan 取消任务：中断子进程，保留已有数据供导出
func (sm *ScanManager) CancelScan(taskID int64) {
	sm.mu.Lock()
	h, ok := sm.running[taskID]
	sm.mu.Unlock()
	if ok {
		h.setIntent("cancel")
		h.cancel()
		return
	}

	db := database.GetDB()
	task := db.GetTask(taskID)
	if task == nil {
		return
	}
	if task.Status == models.StatusRunning || task.Status == models.StatusPending || task.Status == models.StatusPaused {
		task.Status = models.StatusCancelled
		task.CompletedAt = time.Now().Format(time.RFC3339)
		task.ResumeStage = ""
		task.EtaSeconds = 0
		task.EtaText = ""
		task.RateKpps = 0
		db.UpdateTask(task)
	}
	GetEventBus().Publish(ProgressEvent{
		TaskID: taskID, Status: models.StatusCancelled, EventType: "progress",
		CurrentPhase: task.CurrentPhase, ProgressPct: task.ProgressPct,
		ElapsedSeconds: task.ElapsedSeconds, Message: "任务已取消，已有结果可导出",
	})
}

// StopAndWait 取消并等待扫描 goroutine 退出（删除任务前调用，避免残留写入）
func (sm *ScanManager) StopAndWait(taskID int64, timeout time.Duration) {
	sm.mu.Lock()
	h, ok := sm.running[taskID]
	sm.mu.Unlock()
	if !ok {
		return
	}
	h.setIntent("cancel")
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(timeout):
		log.Printf("task %d still stopping after %s, continue anyway", taskID, timeout)
	}
}

// ========== 扫描上下文 ==========

const (
	maxScanLogBytes        = 512 * 1024
	maxPortScanOutputBytes = 4 << 20
	maxServiceOutputBytes  = 4 << 20
)

type runCtx struct {
	db     *database.DB
	taskID int64
	ctx    context.Context
	h      *runHandle
	mode   string
	task   *models.Task

	mu sync.Mutex // 保护 task 结构

	nmapPath     string
	masscanPath  string
	pingArgs     string
	masscanArgs  string
	serviceArgs  string
	nmapPortArgs string

	startedAt   time.Time
	baseElapsed int64

	logMu          sync.Mutex
	logBuf         strings.Builder
	logOverflow    bool // 过程日志达到上限，后续内容不再记录
	logTotal       int  // 本次扫描累计产出过的日志字节数（不受 buffer/flush 时机影响）
	logNoteFlushed bool // 上一次 flush 是否已把截断说明写在尾部
}

func (r *runCtx) mutate(fn func(t *models.Task)) {
	r.mu.Lock()
	if fn != nil {
		fn(r.task)
	}
	cp := *r.task
	r.mu.Unlock()
	r.db.UpdateTask(&cp)
}

func (r *runCtx) snapshot() models.Task {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *r.task
	cp.AliveHosts = append([]string{}, r.task.AliveHosts...)
	cp.ServiceDoneHosts = append([]string{}, r.task.ServiceDoneHosts...)
	return cp
}

func (r *runCtx) appendLog(s string) {
	if s == "" {
		return
	}
	r.logMu.Lock()
	r.logTotal += len(s)
	if r.logBuf.Len()+len(s) <= maxScanLogBytes {
		r.logBuf.WriteString(s)
	} else if !r.logOverflow {
		// 首次超限：标记并在本次 flush 时把说明写到数据库尾部（DB 侧只保留最后一段，尾部说明才不会被挤掉）
		r.logOverflow = true
	}
	r.logMu.Unlock()
}

// logTruncatedNote 日志被截断时写入数据库尾部的说明。
// DB 侧只保留最后 512KB，所以每次 flush 都必须在尾部重申一次，
// 否则“第一次超限”写下的说明会被后续日志挤出保留窗口，导出时看不到提示。
const logTruncatedNote = "\n[说明] 过程日志已达上限（512KB），早期日志已被截断，后续日志不再记录\n"

func (r *runCtx) flushLog() {
	r.logMu.Lock()
	empty := r.logBuf.Len() == 0
	chunk := r.logBuf.String()
	r.logBuf.Reset()
	// 用「累计产出字节数」判断是否超限：只看 logBuf 会漏判——
	// 日志刷得勤（每 3 秒一次）时 buffer 永远到不了 512KB，
	// 但数据库侧 AppendScanLog 只保留最后一段，早期日志会被静默丢掉，
	// 导出存档时就看不到任何"已截断"的说明。
	overflow := r.logOverflow || r.logTotal > maxScanLogBytes
	noteAlready := r.logNoteFlushed
	if empty && (!overflow || noteAlready) {
		r.logMu.Unlock()
		return
	}
	r.logMu.Unlock()

	if empty {
		// 缓冲区已空但确实发生过截断：只补一条说明，保证最终导出能看到提示
		r.db.AppendScanLog(r.taskID, logTruncatedNote, maxScanLogBytes)
		r.logMu.Lock()
		r.logNoteFlushed = true
		r.logMu.Unlock()
		return
	}
	if overflow {
		chunk += logTruncatedNote
	}
	r.db.AppendScanLog(r.taskID, chunk, maxScanLogBytes)
	r.logMu.Lock()
	r.logNoteFlushed = overflow
	r.logMu.Unlock()
}

func (r *runCtx) emitFor(source string) lineEmitter {
	return func(line string, isErr bool) {
		display := line
		if isErr && !strings.HasPrefix(line, "[stderr]") {
			display = "[stderr] " + line
		}
		GetEventBus().Publish(ProgressEvent{
			TaskID:       r.taskID,
			EventType:    "output",
			OutputSource: source,
			OutputLine:   display,
		})
		r.appendLog(fmt.Sprintf("[%s] %s\n", source, display))
	}
}

// nmap --stats-every 输出的进度行，例如：
//
//	SYN Stealth Scan Timing: About 12.34% done; ETC: 0:00:41 (0:00:28 remaining)
//
// 用它把 nmap 阶段的真实进度换算成整体进度与预估剩余时间。
var (
	nmapStatsPercentRe = regexp.MustCompile(`About\s+([0-9]+(?:\.[0-9]+)?)%\s*done`)
	nmapStatsRemainRe  = regexp.MustCompile(`\(([0-9]+:[0-9]{2}(?::[0-9]{2})?)\s+remaining\)`)
	nmapStatsEtcRe     = regexp.MustCompile(`ETC:\s*([0-9]+:[0-9]{2}(?::[0-9]{2})?)`)
)

// parseNmapStatLine 从 nmap 进度行中解析百分比与剩余秒数
func parseNmapStatLine(line string) (pct float64, eta int64, ok bool) {
	m := nmapStatsPercentRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return 0, 0, false
	}
	p, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, 0, false
	}
	etaLine := ""
	if mm := nmapStatsRemainRe.FindStringSubmatch(line); len(mm) >= 2 {
		etaLine = mm[1]
	} else if mm := nmapStatsEtcRe.FindStringSubmatch(line); len(mm) >= 2 {
		etaLine = mm[1]
	}
	return p, parseClockSeconds(etaLine), true
}

// parseClockSeconds 解析 h:mm:ss / mm:ss / s 形式的时长
func parseClockSeconds(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	parts := strings.Split(s, ":")
	var total int64
	for _, p := range parts {
		n, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
		if err != nil {
			return 0
		}
		total = total*60 + n
	}
	return total
}

// nmapEmitter 在普通输出回传之外，额外解析 nmap 自己的进度行，
// 按阶段区间 [from,to] 换算整体进度并推送 eta 事件（nmap 阶段不再“卡在 3%”）。
func (r *runCtx) nmapEmitter(source, phase string, from, to float64) lineEmitter {
	base := r.emitFor(source)
	var mu sync.Mutex
	var lastPersist time.Time
	return func(line string, isErr bool) {
		base(line, isErr)
		pct, eta, ok := parseNmapStatLine(line)
		if !ok {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if time.Since(lastPersist) < 500*time.Millisecond && pct < 100 {
			return
		}
		lastPersist = time.Now()
		overall := from + (to-from)*(pct/100.0)
		if overall < from {
			overall = from
		}
		if overall > to {
			overall = to
		}
		r.mutate(func(t *models.Task) {
			t.CurrentPhase = phase
			t.ProgressPct = overall
			t.ScanPercent = pct
			t.EtaSeconds = eta
			t.EtaText = formatDuration(eta)
		})
		msg := fmt.Sprintf("%s中 %s", phaseShortName(phase), formatPercent(pct))
		if eta > 0 {
			msg += "，预计剩余 " + formatDuration(eta)
		}
		GetEventBus().Publish(ProgressEvent{
			TaskID: r.taskID, Status: models.StatusRunning, CurrentPhase: phase,
			ProgressPct: overall, EventType: "eta", Message: msg,
			EtaSeconds: eta, EtaText: formatDuration(eta), ScanPercent: pct,
		})
	}
}

func phaseShortName(phase string) string {
	switch phase {
	case models.PhasePingScan:
		return "存活探测"
	case models.PhasePortScan:
		return "端口扫描"
	case models.PhaseServiceScan:
		return "服务识别"
	case models.PhaseNmapScan:
		return "Nmap端口扫描"
	default:
		return "扫描"
	}
}

func (r *runCtx) logCmd(cmd string) {
	if cmd == "" {
		return
	}
	r.mutate(func(t *models.Task) {
		if t.CmdRecords != "" {
			t.CmdRecords += "\n"
		}
		t.CmdRecords += cmd
	})
	r.appendLog("[cmd] " + cmd + "\n")
}

func (r *runCtx) checkCtx() error {
	select {
	case <-r.ctx.Done():
		return ErrInterrupted
	default:
		return nil
	}
}

func (r *runCtx) setPhase(phase string, pct float64, msg string) {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	r.mutate(func(t *models.Task) {
		t.CurrentPhase = phase
		t.ProgressPct = pct
	})
	snap := r.snapshot()
	GetEventBus().Publish(ProgressEvent{
		TaskID: r.taskID, Status: snap.Status, CurrentPhase: phase, ProgressPct: pct,
		ElapsedSeconds: snap.ElapsedSeconds, EventType: "progress", Message: msg,
		EtaSeconds: snap.EtaSeconds, EtaText: snap.EtaText, ScanPercent: snap.ScanPercent, RateKpps: snap.RateKpps,
	})
	if msg != "" {
		r.appendLog("[phase] " + msg + "\n")
	}
}

func (r *runCtx) setResume(stage string) {
	r.mutate(func(t *models.Task) { t.ResumeStage = stage })
}

func (r *runCtx) markServiceDone(ip string) {
	r.mutate(func(t *models.Task) {
		if !t.HasServiceDone(ip) {
			t.ServiceDoneHosts = append(t.ServiceDoneHosts, ip)
		}
	})
}

func (r *runCtx) hasServiceDone(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.task.HasServiceDone(ip)
}

func (r *runCtx) resumeStage() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.task.ResumeStage
}

func (r *runCtx) aliveHosts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.task.AliveHosts...)
}

func (r *runCtx) portScanOutput() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.task.PortScanOutput
}

// ========== 主流程 ==========

func (sm *ScanManager) runScan(taskID int64, h *runHandle, resumed bool) {
	db := database.GetDB()

	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("task %d panic recovered: %v\n%s", taskID, rec, debug.Stack())
			if t := db.GetTask(taskID); t != nil && t.Status == models.StatusRunning {
				t.Status = models.StatusFailed
				t.ErrorMessage = fmt.Sprintf("扫描内部错误: %v", rec)
				t.CompletedAt = time.Now().Format(time.RFC3339)
				t.ResumeStage = ""
				db.UpdateTask(t)
			}
			GetEventBus().Publish(ProgressEvent{
				TaskID: taskID, Status: models.StatusFailed, EventType: "progress",
				Message: fmt.Sprintf("扫描内部错误: %v", rec),
			})
		}
		sm.mu.Lock()
		if cur, ok := sm.running[taskID]; ok && cur == h {
			delete(sm.running, taskID)
		}
		sm.mu.Unlock()
		h.cancel()
		close(h.done)
	}()

	task := db.GetTask(taskID)
	if task == nil {
		log.Printf("Task %d not found", taskID)
		return
	}

	mode := task.ScanMode
	if mode == "" {
		mode = models.ScanModeFull
	}

	r := &runCtx{
		db: db, taskID: taskID, ctx: h.ctx, h: h, mode: mode, task: task,
		nmapPath:     db.GetSetting(models.SettingNmapPath),
		masscanPath:  db.GetSetting(models.SettingMasscanPath),
		pingArgs:     db.GetSetting(models.SettingNmapPingArgs),
		masscanArgs:  db.GetSetting(models.SettingMasscanArgs),
		serviceArgs:  db.GetSetting(models.SettingNmapServiceArgs),
		nmapPortArgs: db.GetSetting(models.SettingNmapPortArgs),
	}
	if r.nmapPath == "" {
		r.nmapPath = "nmap"
	}
	if r.masscanPath == "" {
		r.masscanPath = "masscan"
	}
	r.startedAt = time.Now()
	if resumed {
		r.baseElapsed = task.ElapsedSeconds
	}

	r.mutate(func(t *models.Task) {
		t.Status = models.StatusRunning
		if !resumed || t.StartedAt == "" {
			t.StartedAt = r.startedAt.Format(time.RFC3339)
		}
		t.CompletedAt = ""
		t.ErrorMessage = ""
		if !resumed {
			t.CurrentPhase = models.PhaseIdle
			t.ProgressPct = 0
			t.ElapsedSeconds = 0
			t.ServiceDoneHosts = nil
			t.ServiceDoneStr = ""
			t.ResumeStage = ""
		}
		t.EtaSeconds = 0
		t.EtaText = ""
		t.ScanPercent = 0
		t.RateKpps = 0
		// 存活探测与服务识别都不吃端口规约：
		// 服务识别的端口来自目标里的 IP:端口，若在这里把空值规范化成 1-65535，
		// 纯 IP 目标就会被误判成"用户指定了全端口"而遭到 1-65535 的 -sV 扫描。
		if mode != models.ScanModeAliveOnly && mode != models.ScanModeServiceOnly {
			t.PortRange = models.NormalizePortSpec(t.PortRange)
		}
	})

	// 立刻广播“已开始”，避免详情页/任务列表在扫描启动后仍显示“等待/排队”
	startSnap := r.snapshot()
	GetEventBus().Publish(ProgressEvent{
		TaskID: taskID, Status: models.StatusRunning, CurrentPhase: startSnap.CurrentPhase,
		ProgressPct: startSnap.ProgressPct, ElapsedSeconds: startSnap.ElapsedSeconds,
		EventType: "progress", Message: "任务已开始执行",
	})

	stopCh := make(chan struct{})
	go r.backgroundLoop(stopCh)

	var runErr error
	switch mode {
	case models.ScanModeAliveOnly:
		runErr = r.runAliveOnly()
	case models.ScanModePortOnly:
		runErr = r.runPortOnly()
	case models.ScanModeServiceOnly:
		runErr = r.runServiceOnly()
	case models.ScanModeNmapPort:
		runErr = r.runNmapPort()
	default:
		runErr = r.runFull()
	}

	close(stopCh)
	r.flushLog()

	interrupted := errors.Is(runErr, ErrInterrupted) || h.ctx.Err() != nil || h.getIntent() != "run"
	if interrupted {
		r.finishInterrupted()
		return
	}
	if runErr != nil {
		r.fail(runErr)
		return
	}
	r.finish()
}

func (r *runCtx) backgroundLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastFlush := time.Now()
	for {
		select {
		case <-stop:
			return
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			elapsed := r.baseElapsed + int64(time.Since(r.startedAt).Seconds())
			r.mu.Lock()
			r.task.ElapsedSeconds = elapsed
			r.mu.Unlock()
			r.db.UpdateElapsed(r.taskID, elapsed)

			snap := r.snapshot()
			GetEventBus().Publish(ProgressEvent{
				TaskID: r.taskID, Status: snap.Status, CurrentPhase: snap.CurrentPhase,
				ProgressPct: snap.ProgressPct, ElapsedSeconds: elapsed, EventType: "progress",
				EtaSeconds: snap.EtaSeconds, EtaText: snap.EtaText,
				ScanPercent: snap.ScanPercent, RateKpps: snap.RateKpps,
			})
			if time.Since(lastFlush) >= 3*time.Second {
				r.flushLog()
				lastFlush = time.Now()
			}
		}
	}
}

func (r *runCtx) finish() {
	now := time.Now().Format(time.RFC3339)
	r.mutate(func(t *models.Task) {
		t.Status = models.StatusCompleted
		t.CurrentPhase = models.PhaseCompleted
		t.ProgressPct = 100
		t.CompletedAt = now
		t.EtaSeconds = 0
		t.EtaText = ""
		t.ScanPercent = 100
		t.RateKpps = 0
		t.ResumeStage = ""
	})
	snap := r.snapshot()
	GetEventBus().Publish(ProgressEvent{
		TaskID: r.taskID, Status: models.StatusCompleted, CurrentPhase: models.PhaseCompleted,
		ProgressPct: 100, ElapsedSeconds: snap.ElapsedSeconds, EventType: "progress",
		Message: "扫描完成",
	})
	r.appendLog("[done] 扫描完成\n")
	r.flushLog()
}

func (r *runCtx) finishInterrupted() {
	intent := r.h.getIntent()
	now := time.Now().Format(time.RFC3339)
	status := models.StatusPaused
	msg := "扫描已暂停，可点击「继续扫描」从断点续跑"
	if intent == "cancel" {
		status = models.StatusCancelled
		msg = "扫描已取消，已有结果可导出"
	}
	r.mutate(func(t *models.Task) {
		t.Status = status
		t.EtaSeconds = 0
		t.EtaText = ""
		t.RateKpps = 0
		if status == models.StatusCancelled {
			t.ResumeStage = ""
			t.CompletedAt = now
		}
	})
	snap := r.snapshot()
	GetEventBus().Publish(ProgressEvent{
		TaskID: r.taskID, Status: status, CurrentPhase: snap.CurrentPhase,
		ProgressPct: snap.ProgressPct, ElapsedSeconds: snap.ElapsedSeconds,
		EventType: "progress", Message: msg,
	})
	r.appendLog("[state] " + msg + "\n")
	r.flushLog()
}

func (r *runCtx) fail(err error) {
	now := time.Now().Format(time.RFC3339)
	r.mutate(func(t *models.Task) {
		t.Status = models.StatusFailed
		t.ErrorMessage = err.Error()
		t.CompletedAt = now
		t.EtaSeconds = 0
		t.EtaText = ""
		t.RateKpps = 0
		t.ResumeStage = ""
	})
	snap := r.snapshot()
	GetEventBus().Publish(ProgressEvent{
		TaskID: r.taskID, Status: models.StatusFailed, EventType: "progress",
		Message: err.Error(), CurrentPhase: snap.CurrentPhase, ProgressPct: snap.ProgressPct,
	})
	r.appendLog("[error] " + err.Error() + "\n")
	r.flushLog()
	log.Printf("Task %d failed: %v", r.taskID, err)
}

// ========== 各扫描模式（严格按模式执行） ==========

// runAliveOnly 存活探测：只做 nmap -sn
func (r *runCtx) runAliveOnly() error {
	r.setPhase(models.PhasePingScan, 5, "开始存活探测（仅 nmap -sn）")
	alive, err := r.pingPhase()
	if err != nil {
		return err
	}
	r.mutate(func(t *models.Task) {
		t.AliveHosts = alive
		t.TotalHosts = len(alive)
		t.ScannedHosts = len(alive)
		t.TotalPorts = 0
		t.CurrentPhase = models.PhasePingScan
		t.ProgressPct = 100
	})
	r.setPhase(models.PhasePingScan, 100, fmt.Sprintf("存活探测完成：%d 台主机存活", len(alive)))
	return nil
}

// runPortOnly 端口扫描：只做 masscan，不做存活探测、不做服务识别
func (r *runCtx) runPortOnly() error {
	hosts := splitTargets(r.task.Target)
	if len(hosts) == 0 {
		return fmt.Errorf("扫描目标为空")
	}
	// 已完成端口扫描（续扫场景）则直接收尾
	if r.resumeStage() == models.ResumeStagePort {
		hits := rebuildHits(r.portScanOutput(), r.db, r.taskID)
		if r.db.CountResults(r.taskID) == 0 {
			r.saveHits(hits)
		}
		r.setPhase(models.PhasePortScan, 100, fmt.Sprintf("端口扫描完成：%d 个开放端口", len(hits)))
		return nil
	}

	r.mutate(func(t *models.Task) { t.TotalHosts = len(hosts) })
	hits, err := r.masscanPhase(hosts, 2, 95)
	if err != nil {
		return err
	}
	liveHosts := distinctHosts(hits)
	r.mutate(func(t *models.Task) {
		t.TotalPorts = len(hits)
		t.TotalHosts = len(liveHosts)
		t.ScannedHosts = len(liveHosts)
		if len(liveHosts) > 0 {
			t.AliveHosts = liveHosts
		}
	})
	r.setResume(models.ResumeStagePort)
	r.setPhase(models.PhasePortScan, 100, fmt.Sprintf("端口扫描完成：发现 %d 个开放端口（%d 台主机）", len(hits), len(liveHosts)))
	return nil
}

// runFull 全套：存活探测 → masscan 端口扫描 → nmap 服务识别
func (r *runCtx) runFull() error {
	var alive []string
	stage := r.resumeStage()

	// 断点含义：ping_scan/port_scan/service_scan 都表示存活探测已完成，可直接复用已存活主机
	if stage != models.ResumeStageNone {
		alive = r.aliveHosts()
	}
	if len(alive) == 0 {
		r.setPhase(models.PhasePingScan, 2, "开始存活探测（nmap -sn）")
		hosts, err := r.pingPhase()
		if err != nil {
			return err
		}
		alive = hosts
		if len(alive) == 0 {
			r.setPhase(models.PhasePingScan, 100, "未发现存活主机，扫描结束")
			return nil
		}
		r.setResume(models.ResumeStagePing)
	} else {
		r.setPhase(models.PhasePortScan, 22, fmt.Sprintf("续扫：跳过存活探测，复用 %d 台存活主机", len(alive)))
	}

	// 端口扫描阶段
	var hits []MasscanHit
	if r.resumeStage() == models.ResumeStagePort || r.resumeStage() == models.ResumeStageService {
		hits = rebuildHits(r.portScanOutput(), r.db, r.taskID)
		if len(hits) > 0 {
			r.setPhase(models.PhasePortScan, 45, fmt.Sprintf("续扫：跳过端口扫描，复用 %d 个开放端口", len(hits)))
		}
	}
	if r.resumeStage() == models.ResumeStagePortRunning {
		r.appendLog("[info] 端口扫描阶段不支持精确断点（masscan 无 checkpoint），本次将重新扫描该阶段；已发现的结果会保留\n")
		r.setPhase(models.PhasePortScan, 30, "续扫：端口扫描阶段将重新执行（已发现结果保留）")
	}
	if len(hits) == 0 {
		var err error
		hits, err = r.masscanPhase(alive, 22, 45)
		if err != nil {
			return err
		}
		r.setResume(models.ResumeStagePort)
	}

	r.mutate(func(t *models.Task) { t.TotalPorts = len(hits) })
	if len(hits) == 0 {
		r.setPhase(models.PhasePortScan, 45, "未发现开放端口，扫描结束")
		return nil
	}

	// 服务识别阶段
	return r.servicePhase(hits, 45, 99)
}

// runServiceOnly 服务识别：只做 nmap -sV，不存活探测、不端口扫描
func (r *runCtx) runServiceOnly() error {
	spec := strings.TrimSpace(r.task.PortRange)
	targets, skipped := parseServiceTargets(r.task.Target, spec)
	if len(skipped) > 0 {
		r.appendLog("[warn] 以下目标没有写明端口，服务识别已跳过：" + strings.Join(skipped, "、") + "\n")
	}
	if len(targets) == 0 {
		return fmt.Errorf("服务识别只扫描目标中写明的端口，请把目标写成 IP:端口（例如 10.0.0.1:80）")
	}
	r.setResume(models.ResumeStageService)
	r.mutate(func(t *models.Task) {
		t.TotalHosts = len(targets)
		t.ScannedHosts = 0
	})

	total := len(targets)
	done := 0
	for i, tg := range targets {
		if err := r.checkCtx(); err != nil {
			return err
		}
		if r.hasServiceDone(tg.label) {
			done++
			continue
		}
		pct := 2.0
		nextPct := 98.0
		if total > 0 {
			pct = 2 + 96*float64(i)/float64(total)
			nextPct = 2 + 96*float64(i+1)/float64(total)
		}
		r.setPhase(models.PhaseServiceScan, pct, fmt.Sprintf("服务识别 %s (%d/%d)", tg.label, i+1, total))

		res, err := RunServiceScan(r.ctx, tg.label, tg.portsArg, tg.needUDP, r.nmapPath, r.serviceArgs,
			r.taskID, r.nmapEmitter(models.OutputSourceService, models.PhaseServiceScan, pct, nextPct), r.logCmd)
		if err != nil {
			if errors.Is(err, ErrInterrupted) {
				return err
			}
			r.appendLog("[error] 服务识别失败 " + tg.label + ": " + err.Error() + "\n")
			r.markServiceDone(tg.label)
			continue
		}
		for _, item := range res.Results {
			item.TaskID = r.taskID
		}
		if len(res.Results) > 0 {
			for _, item := range res.Results {
				item.TaskID = r.taskID
			}
			r.db.ReplaceHostResults(r.taskID, tg.label, res.Results)
		}
		r.mutate(func(t *models.Task) {
			t.ServiceOutput = capText(t.ServiceOutput+res.RawXML+"\n", maxServiceOutputBytes)
			t.ScannedHosts++
		})
		r.markServiceDone(tg.label)
		done++
	}

	// 有开放端口的目标视为存活，并补齐端口统计（历史缺陷 D-16：服务识别模式下 total_ports 恒为 0）
	rows := r.db.GetResultsByTask(r.taskID)
	if len(rows) > 0 {
		alive := make([]string, 0, len(rows))
		seen := make(map[string]bool)
		for _, row := range rows {
			if !seen[row.IP] {
				seen[row.IP] = true
				alive = append(alive, row.IP)
			}
		}
		r.mutate(func(t *models.Task) {
			t.AliveHosts = alive
			t.TotalPorts = len(rows)
			if len(alive) > t.TotalHosts {
				t.TotalHosts = len(alive)
			}
			t.ScannedHosts = len(alive)
		})
	} else {
		r.mutate(func(t *models.Task) { t.TotalPorts = 0 })
	}

	r.setPhase(models.PhaseServiceScan, 100, fmt.Sprintf("服务识别完成：%d 个目标", done))
	return nil
}

// runNmapPort Nmap 端口扫描：只做 nmap 端口扫描
func (r *runCtx) runNmapPort() error {
	r.setPhase(models.PhaseNmapScan, 3, "开始 Nmap 端口扫描（仅端口扫描）")
	res, err := RunNmapPortScan(r.ctx, r.task.Target, r.task.PortRange, r.nmapPath, r.nmapPortArgs,
		r.taskID, r.nmapEmitter(models.OutputSourceNmap, models.PhaseNmapScan, 3, 98), r.logCmd)
	if err != nil {
		if errors.Is(err, ErrInterrupted) {
			return err
		}
		return err
	}

	for _, item := range res.Results {
		item.TaskID = r.taskID
	}
	if len(res.Results) > 0 {
		r.db.AddResults(res.Results)
	}
	alive := distinctIPs(res.Results)
	r.mutate(func(t *models.Task) {
		t.PortScanOutput = res.RawXML
		t.TotalPorts = len(res.Results)
		t.TotalHosts = res.HostsUp
		if t.TotalHosts == 0 {
			t.TotalHosts = len(alive)
		}
		t.ScannedHosts = len(alive)
		if len(alive) > 0 {
			t.AliveHosts = alive
		}
		t.CurrentPhase = models.PhaseNmapScan
		t.ProgressPct = 100
	})
	r.setPhase(models.PhaseNmapScan, 100, fmt.Sprintf("Nmap 端口扫描完成：%d 个开放端口", len(res.Results)))
	return nil
}

// ========== 阶段实现 ==========

func (r *runCtx) pingPhase() ([]string, error) {
	res, err := RunPingScan(r.ctx, r.task.Target, r.nmapPath, r.pingArgs, r.taskID,
		r.nmapEmitter(models.OutputSourcePing, models.PhasePingScan, 2, 20), r.logCmd)
	if err != nil {
		return nil, err
	}
	r.mutate(func(t *models.Task) {
		t.AliveHosts = res.AliveIPs
		t.TotalHosts = len(res.AliveIPs)
		t.PingOutput = res.RawXML
		t.CurrentPhase = models.PhasePingScan
	})
	r.appendLog(fmt.Sprintf("[info] 存活主机 %d 台\n", len(res.AliveIPs)))
	return res.AliveIPs, nil
}

// masscanPhase 执行 masscan 端口扫描，并把自带进度换算成整体进度与预估剩余时间
func (r *runCtx) masscanPhase(hosts []string, from, to float64) ([]MasscanHit, error) {
	r.setPhase(models.PhasePortScan, from, "开始端口扫描（masscan）")
	// 记录“端口扫描已开始”：暂停/取消后可据此判断并保留已发现结果
	r.setResume(models.ResumeStagePortRunning)
	phaseStart := time.Now()
	lastPersist := time.Now()

	onProgress := func(p MasscanProgress) {
		eta := p.EtaSeconds
		overall := from
		if p.HasPercent && p.Percent > 0 {
			overall = from + (to-from)*(p.Percent/100.0)
			if eta <= 0 {
				elapsed := time.Since(phaseStart).Seconds()
				if p.Percent < 100 {
					eta = int64(elapsed / p.Percent * (100 - p.Percent))
				}
			}
		} else if eta <= 0 {
			return
		}
		if overall < from {
			overall = from
		}
		if overall > to {
			overall = to
		}

		// 1 秒一次的落库，避免高频写
		if time.Since(lastPersist) >= time.Second || p.Percent >= 100 {
			lastPersist = time.Now()
			r.mutate(func(t *models.Task) {
				t.EtaSeconds = eta
				t.EtaText = formatDuration(eta)
				t.ScanPercent = p.Percent
				t.RateKpps = p.RateKpps
				t.ProgressPct = overall
				t.CurrentPhase = models.PhasePortScan
			})
		}

		msg := fmt.Sprintf("端口扫描中 %s", formatPercent(p.Percent))
		if eta > 0 {
			msg += "，预计剩余 " + formatDuration(eta)
		}
		if p.RateKpps > 0 {
			msg += fmt.Sprintf("（%.1f kpps）", p.RateKpps)
		}
		if p.Found > 0 {
			msg += fmt.Sprintf("，已发现 %d 个端口", p.Found)
		}
		GetEventBus().Publish(ProgressEvent{
			TaskID: r.taskID, Status: models.StatusRunning, CurrentPhase: models.PhasePortScan,
			ProgressPct: overall, EventType: "eta", Message: msg,
			EtaSeconds: eta, EtaText: formatDuration(eta),
			ScanPercent: p.Percent, RateKpps: p.RateKpps,
		})
	}

	res, err := RunMasscan(r.ctx, hosts, r.task.PortRange, r.masscanPath, r.masscanArgs, r.taskID,
		r.emitFor(models.OutputSourcePort), onProgress, r.logCmd)

	interrupted := errors.Is(err, ErrInterrupted)

	// 无论成功还是被中断，先把已经拿到的输出与命中的端口落库，
	// 避免“取消/暂停后结果页与导出全是空的”（历史缺陷 D-02）
	hits := []MasscanHit{}
	rawOutput := ""
	if res != nil {
		hits = res.Hits
		rawOutput = res.RawOutput
	}
	if rawOutput != "" || len(hits) > 0 {
		r.persistPortResults(hits)
		r.mutate(func(t *models.Task) {
			if rawOutput != "" {
				t.PortScanOutput = capText(rawOutput, maxPortScanOutputBytes)
			}
			t.EtaSeconds = 0
			t.EtaText = ""
			t.RateKpps = 0
			if !interrupted {
				t.ScanPercent = 100
				t.ProgressPct = to
			}
			if len(hits) > 0 {
				t.TotalPorts = len(hits)
			}
			t.CurrentPhase = models.PhasePortScan
		})
	}

	if err != nil {
		if interrupted {
			r.appendLog(fmt.Sprintf("[info] 端口扫描被中断，已保留 %d 个已发现端口\n", len(hits)))
			return hits, err
		}
		return hits, err
	}

	r.setResume(models.ResumeStagePort)
	r.appendLog(fmt.Sprintf("[info] 端口扫描命中 %d 个开放端口\n", len(hits)))
	if len(hits) == 0 {
		r.appendLog("[info] masscan 未返回开放端口，请确认 masscan 是否具备 root 权限\n")
	}
	return hits, nil
}

// servicePhase 按主机做服务识别（支持断点续跑）
func (r *runCtx) servicePhase(hits []MasscanHit, from, to float64) error {
	if len(hits) == 0 {
		return nil
	}
	r.setResume(models.ResumeStageService)

	byHost := groupHits(hits)
	ips := make([]string, 0, len(byHost))
	for ip := range byHost {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	total := len(ips)
	for i, ip := range ips {
		if err := r.checkCtx(); err != nil {
			return err
		}
		if r.hasServiceDone(ip) {
			continue
		}
		pct := from
		nextPct := to
		if total > 0 {
			pct = from + (to-from)*float64(i)/float64(total)
			nextPct = from + (to-from)*float64(i+1)/float64(total)
		}
		r.setPhase(models.PhaseServiceScan, pct, fmt.Sprintf("服务识别 %s (%d/%d)", ip, i+1, total))

		portsArg, needUDP := nmapPortsForHost(byHost[ip])
		res, err := RunServiceScan(r.ctx, ip, portsArg, needUDP, r.nmapPath, r.serviceArgs,
			r.taskID, r.nmapEmitter(models.OutputSourceService, models.PhaseServiceScan, pct, nextPct), r.logCmd)
		if err != nil {
			if errors.Is(err, ErrInterrupted) {
				return err
			}
			r.appendLog("[error] 服务识别失败 " + ip + ": " + err.Error() + "\n")
			// 服务识别失败时保留端口扫描结果，避免丢数据
			r.saveHostHits(ip, byHost[ip])
			r.markServiceDone(ip)
			continue
		}

		if len(res.Results) == 0 {
			r.saveHostHits(ip, byHost[ip])
		} else {
			for _, item := range res.Results {
				item.TaskID = r.taskID
			}
			// 按主机替换，保证续扫不会重复写入
			r.db.ReplaceHostResults(r.taskID, ip, res.Results)
		}
		r.mutate(func(t *models.Task) {
			t.ServiceOutput = capText(t.ServiceOutput+res.RawXML+"\n", maxServiceOutputBytes)
			t.ScannedHosts++
		})
		r.markServiceDone(ip)
	}
	return nil
}

// ========== 结果落库 ==========

func (r *runCtx) saveHits(hits []MasscanHit) {
	if len(hits) == 0 {
		return
	}
	results := make([]*models.ScanResult, 0, len(hits))
	for _, h := range hits {
		results = append(results, &models.ScanResult{
			TaskID: r.taskID, IP: h.IP, Port: h.Port, Protocol: h.Proto, State: "open",
		})
	}
	if err := r.db.AddResults(results); err != nil {
		r.appendLog("[error] 写入扫描结果失败: " + err.Error() + "\n")
		log.Printf("task %d AddResults error: %v", r.taskID, err)
	}
}

// persistPortResults 按主机覆盖写入端口命中：重复扫描同一主机不会产生重复行
func (r *runCtx) persistPortResults(hits []MasscanHit) {
	if len(hits) == 0 {
		return
	}
	for ip, hs := range groupHits(hits) {
		results := make([]*models.ScanResult, 0, len(hs))
		for _, h := range hs {
			results = append(results, &models.ScanResult{
				TaskID: r.taskID, IP: h.IP, Port: h.Port, Protocol: h.Proto, State: "open",
			})
		}
		r.db.ReplaceHostResults(r.taskID, ip, results)
	}
}

func (r *runCtx) saveHostHits(ip string, hits []MasscanHit) {
	results := make([]*models.ScanResult, 0, len(hits))
	for _, h := range hits {
		if h.IP != ip {
			continue
		}
		results = append(results, &models.ScanResult{
			TaskID: r.taskID, IP: h.IP, Port: h.Port, Protocol: h.Proto, State: "open",
		})
	}
	if len(results) > 0 {
		r.db.ReplaceHostResults(r.taskID, ip, results)
	}
}

// ========== 工具函数 ==========

// capText 超出上限时保留尾部内容并加上截断标记（避免整段输出把 SQLite 撑爆）
func capText(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	tail := s[len(s)-max:]
	if idx := strings.IndexByte(tail, '\n'); idx >= 0 && idx < 512 {
		tail = tail[idx+1:]
	}
	return "[... 输出过大，前部已截断，仅保留最后 " + strconv.Itoa(max/1024) + " KB ...]\n" + tail
}

func formatDuration(sec int64) string {
	if sec < 0 {
		sec = 0
	}
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func formatPercent(p float64) string {
	if p >= 100 {
		return "100%"
	}
	return strconv.FormatFloat(p, 'f', 1, 64) + "%"
}

func groupHits(hits []MasscanHit) map[string][]MasscanHit {
	out := make(map[string][]MasscanHit)
	for _, h := range hits {
		out[h.IP] = append(out[h.IP], h)
	}
	return out
}

func distinctHosts(hits []MasscanHit) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, h := range hits {
		if !seen[h.IP] {
			seen[h.IP] = true
			out = append(out, h.IP)
		}
	}
	return out
}

// nmapPortsForHost 把某台主机的命中端口组装成 nmap -p 参数（区分 TCP/UDP）
func nmapPortsForHost(hits []MasscanHit) (string, bool) {
	tcp := make([]string, 0, len(hits))
	udp := make([]string, 0, len(hits))
	for _, h := range hits {
		if strings.EqualFold(h.Proto, "udp") {
			udp = append(udp, strconv.Itoa(h.Port))
		} else {
			tcp = append(tcp, strconv.Itoa(h.Port))
		}
	}
	parts := make([]string, 0, 2)
	if len(tcp) > 0 {
		parts = append(parts, "T:"+strings.Join(tcp, ","))
	}
	if len(udp) > 0 {
		parts = append(parts, "U:"+strings.Join(udp, ","))
	}
	spec := strings.Join(parts, ",")
	return spec, len(udp) > 0
}

// rebuildHits 续扫时从已保存的 masscan 输出（或已有结果）重建端口命中
func rebuildHits(portScanOutput string, db *database.DB, taskID int64) []MasscanHit {
	if strings.TrimSpace(portScanOutput) != "" {
		res := parseMasscanOutput(portScanOutput)
		if len(res.Hits) > 0 {
			return res.Hits
		}
	}
	// 退化：从数据库已有结果重建
	rows := db.GetResultsByTask(taskID)
	hits := make([]MasscanHit, 0, len(rows))
	seen := make(map[string]bool)
	for _, row := range rows {
		key := row.IP + "/" + row.Protocol + "/" + strconv.Itoa(row.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		proto := row.Protocol
		if proto == "" {
			proto = "tcp"
		}
		hits = append(hits, MasscanHit{IP: row.IP, Port: row.Port, Proto: proto})
	}
	return hits
}

// svcTarget 服务识别的目标（IP:端口 或 IP + 端口范围）
type svcTarget struct {
	label    string
	portsArg string
	needUDP  bool
}

// parseServiceTargets 解析服务识别目标：
// 1) 每行 IP:port 形式 → 按 IP 聚合端口（服务识别的唯一取端口方式）
// 2) 纯 IP / CIDR 形式 → 记录到 skipped；服务识别不猜端口，交由调用方明确提示
//
// 历史行为是"纯 IP 用任务端口范围，没填就扫常见 100 端口"，
// 这会让一次「服务识别」在后台悄悄扫出用户没写过的端口。现在只认目标里写明的端口。
func parseServiceTargets(target string, portSpec string) (targets []svcTarget, skipped []string) {
	grouped := make(map[string][]int)
	order := make([]string, 0)
	plain := make([]string, 0)

	for _, line := range strings.Split(target, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 仅当形如 host:port（且 port 为数字）时才按 IP:端口 处理，避免误伤 IPv6/CIDR
		if idx := strings.LastIndex(line, ":"); idx > 0 && idx < len(line)-1 && !strings.Contains(line, "/") {
			host := strings.TrimSpace(line[:idx])
			portStr := strings.TrimSpace(line[idx+1:])
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
				if _, ok := grouped[host]; !ok {
					order = append(order, host)
				}
				grouped[host] = append(grouped[host], port)
				continue
			}
		}
		plain = append(plain, line)
	}

	out := make([]svcTarget, 0, len(order))
	for _, host := range order {
		ports := grouped[host]
		sort.Ints(ports)
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = strconv.Itoa(p)
		}
		out = append(out, svcTarget{label: host, portsArg: "T:" + strings.Join(parts, ","), needUDP: false})
	}

	// 兼容历史任务：端口规约里明确写了范围时，仍允许纯 IP 目标沿用；
	// 没写端口范围的一律跳过，绝不再默认扫常见端口。
	skipped = append(skipped, plain...)
	if strings.TrimSpace(portSpec) != "" && len(plain) > 0 {
		specArg, specUDP := models.NmapPortSpec(portSpec)
		for _, host := range plain {
			out = append(out, svcTarget{label: host, portsArg: specArg, needUDP: specUDP})
		}
		skipped = nil
	}
	return out, skipped
}
