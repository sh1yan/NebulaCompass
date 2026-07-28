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
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
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
}

func (t *Task) ParseAliveHosts() {
	if t.AliveHostsStr != "" && len(t.AliveHosts) == 0 {
		t.AliveHosts = strings.Split(t.AliveHostsStr, ",")
	}
}
