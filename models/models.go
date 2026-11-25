package models

import (
	"strings"
)

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
	CreatedAt    string `json:"created_at"`
}

type Task struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Target         string   `json:"target"`
	ScanMode       string   `json:"scan_mode"`
	PortRange      string   `json:"port_range"`
	PortPresets    []string `json:"port_presets,omitempty"`
	PortPresetsStr string   `json:"-"` // 数据库序列化用
	Status         string   `json:"status"`
	CurrentPhase   string   `json:"current_phase"`
	ProgressPct    float64  `json:"progress_pct"`
	TotalHosts     int      `json:"total_hosts"`
	ScannedHosts   int      `json:"scanned_hosts"`
	TotalPorts     int      `json:"total_ports"`
	ScannedPorts   int      `json:"scanned_ports"`
	ElapsedSeconds int64    `json:"elapsed_seconds"`
	CreatedAt      string   `json:"created_at"`
	StartedAt      string   `json:"started_at,omitempty"`
	CompletedAt    string   `json:"completed_at,omitempty"`
	ErrorMessage   string   `json:"error_message,omitempty"`
	AliveHosts     []string `json:"alive_hosts,omitempty"`
	AliveHostsStr  string   `json:"-"` // 数据库序列化用
	PingOutput     string   `json:"ping_output,omitempty"`
	PortScanOutput string   `json:"port_scan_output,omitempty"`
	ServiceOutput  string   `json:"service_output,omitempty"`
	CmdRecords     string   `json:"cmd_records,omitempty"`

	// 暂停 / 续扫支持
	ResumeStage      string   `json:"resume_stage,omitempty"`
	ServiceDoneHosts []string `json:"service_done_hosts,omitempty"`
	ServiceDoneStr   string   `json:"-"` // 数据库序列化用

	// 端口扫描阶段实时预估（masscan 自带进度）
	EtaSeconds  int64   `json:"eta_seconds,omitempty"`
	EtaText     string  `json:"eta_text,omitempty"`
	ScanPercent float64 `json:"scan_percent,omitempty"`
	RateKpps    float64 `json:"rate_kpps,omitempty"`

	// 过程日志（即使取消/暂停也保留，便于导出存档）
	ScanLog string `json:"-"` // 体积大，列表接口不返回

	// 列表接口附加：已入库的结果条数（不持久化）
	ResultCount int `json:"result_count,omitempty"`
}

const (
	ScanModeFull        = "full"
	ScanModeAliveOnly   = "alive_only"
	ScanModePortOnly    = "port_only"
	ScanModeServiceOnly = "service_only"
	ScanModeNmapPort    = "nmap_port_scan"
)

const (
	PhaseIdle        = "idle"
	PhasePingScan    = "ping_scan"
	PhasePortScan    = "port_scan"
	PhaseServiceScan = "service_scan"
	PhaseNmapScan    = "nmap_scan"
	PhaseCompleted   = "completed"
)

const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusPaused    = "paused"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// 续扫断点：表示“该阶段已完成，下次从下一阶段继续”
const (
	ResumeStageNone        = ""
	ResumeStagePing        = "ping_scan"         // 存活探测已完成
	ResumeStagePortRunning = "port_scan_running" // 端口扫描已开始但未完成（masscan 无法精确续扫，续跑会重扫该阶段但保留已发现结果）
	ResumeStagePort        = "port_scan"         // 端口扫描已完成
	ResumeStageService     = "service_scan"      // 服务识别进行中（按主机续跑）
)

const (
	OutputSourcePing    = "ping_scan"
	OutputSourcePort    = "port_scan"
	OutputSourceService = "service_scan"
	OutputSourceNmap    = "nmap_scan"
	OutputSourceInfo    = "info"
)

type ScanResult struct {
	ID        int64  `json:"id"`
	TaskID    int64  `json:"task_id"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Service   string `json:"service"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	ExtraInfo string `json:"extra_info"`
	OSDetails string `json:"os_details"`
	CreatedAt string `json:"created_at"`
}

type Setting struct {
	ID    int64  `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

const (
	SettingNmapPath        = "nmap_path"
	SettingMasscanPath     = "masscan_path"
	SettingNmapPingArgs    = "nmap_ping_args"
	SettingMasscanArgs     = "masscan_args"
	SettingNmapServiceArgs = "nmap_service_args"
	SettingNmapPortArgs    = "nmap_port_args" // 用于增加单独的nmap扫描的参数
	//SettingPingRate        = "ping_rate"
	//SettingPortRate        = "port_rate"
	//SettingMaxConcurrency  = "max_concurrency"
	SettingRefreshInterval = "refresh_interval"
)

func GetDefaultSettings() []Setting {
	return []Setting{
		{Key: SettingNmapPath, Value: "nmap"},
		{Key: SettingMasscanPath, Value: "masscan"},
		{Key: SettingNmapPingArgs, Value: "-sn -n --min-rate=2000 --max-rtt-timeout=1000ms --host-timeout=3s"},
		{Key: SettingMasscanArgs, Value: "--rate=2000"},
		{Key: SettingNmapServiceArgs, Value: "-sV --min-rate=2000 --max-rtt-timeout=2000ms -Pn -n"},
		{Key: SettingNmapPortArgs, Value: "-sS --min-rate=2000 --max-rtt-timeout=2000ms -Pn -n"},
		//{Key: SettingPingRate, Value: "500"},
		//{Key: SettingPortRate, Value: "1000"},
		//{Key: SettingMaxConcurrency, Value: "3"},
		{Key: SettingRefreshInterval, Value: "0"},
	}
}

func (t *Task) SerializeAliveHosts() {
	if t.AliveHostsStr == "" && len(t.AliveHosts) > 0 {
		t.AliveHostsStr = strings.Join(t.AliveHosts, ",")
	}
	if len(t.AliveHosts) == 0 && t.AliveHostsStr != "" {
		t.AliveHosts = strings.Split(t.AliveHostsStr, ",")
	}
}

func (t *Task) ParseAliveHosts() {
	if t.AliveHostsStr != "" && len(t.AliveHosts) == 0 {
		t.AliveHosts = strings.Split(t.AliveHostsStr, ",")
	}
}

func (t *Task) SerializeServiceDone() {
	if t.ServiceDoneStr == "" && len(t.ServiceDoneHosts) > 0 {
		t.ServiceDoneStr = strings.Join(t.ServiceDoneHosts, ",")
	}
	if len(t.ServiceDoneHosts) == 0 && t.ServiceDoneStr != "" {
		t.ServiceDoneHosts = strings.Split(t.ServiceDoneStr, ",")
	}
}

func (t *Task) ParseServiceDone() {
	if t.ServiceDoneStr != "" && len(t.ServiceDoneHosts) == 0 {
		t.ServiceDoneHosts = strings.Split(t.ServiceDoneStr, ",")
	}
}

func (t *Task) SerializePortPresets() {
	if t.PortPresetsStr == "" && len(t.PortPresets) > 0 {
		t.PortPresetsStr = strings.Join(t.PortPresets, ",")
	}
}

func (t *Task) ParsePortPresets() {
	if t.PortPresetsStr != "" && len(t.PortPresets) == 0 {
		t.PortPresets = strings.Split(t.PortPresetsStr, ",")
	}
}

// HasServiceDone 判断某主机是否已完成服务识别（续扫用）
func (t *Task) HasServiceDone(ip string) bool {
	for _, h := range t.ServiceDoneHosts {
		if strings.TrimSpace(h) == ip {
			return true
		}
	}
	return false
}

// ModeLabel 扫描模式的中文名
func ModeLabel(mode string) string {
	switch mode {
	case ScanModeFull:
		return "全套扫描"
	case ScanModeAliveOnly:
		return "存活探测"
	case ScanModePortOnly:
		return "端口扫描"
	case ScanModeServiceOnly:
		return "服务识别"
	case ScanModeNmapPort:
		return "Nmap端口扫描"
	default:
		return "全套扫描"
	}
}

// ModePhases 返回该模式下实际的阶段顺序（用于前端阶段指示器）
func ModePhases(mode string) []string {
	switch mode {
	case ScanModeAliveOnly:
		return []string{PhaseIdle, PhasePingScan, PhaseCompleted}
	case ScanModePortOnly:
		return []string{PhaseIdle, PhasePortScan, PhaseCompleted}
	case ScanModeServiceOnly:
		return []string{PhaseIdle, PhaseServiceScan, PhaseCompleted}
	case ScanModeNmapPort:
		return []string{PhaseIdle, PhaseNmapScan, PhaseCompleted}
	default:
		return []string{PhaseIdle, PhasePingScan, PhasePortScan, PhaseServiceScan, PhaseCompleted}
	}
}

// StatusLabel 任务状态中文名
func StatusLabel(s string) string {
	switch s {
	case StatusPending:
		return "等待"
	case StatusRunning:
		return "运行中"
	case StatusPaused:
		return "已暂停"
	case StatusCompleted:
		return "完成"
	case StatusFailed:
		return "失败"
	case StatusCancelled:
		return "已取消"
	default:
		return s
	}
}
