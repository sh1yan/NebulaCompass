package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"NebulaCompass/models"
)

type NmapPingResult struct {
	AliveIPs []string
	RawXML   string
}

type NmapServiceResult struct {
	Results []*models.ScanResult
	RawXML  string
}

// NmapPortResult 存储 nmap 端口扫描结果
type NmapPortResult struct {
	Results []*models.ScanResult
	RawXML  string
	HostsUp int
}

type NmapXML struct {
	XMLName  xml.Name   `xml:"nmaprun"`
	Hosts    []NmapHost `xml:"host"`
	RunStats NmapStats  `xml:"runstats"`
}

type NmapStats struct {
	Hosts NmapHostsStats `xml:"hosts"`
}

type NmapHostsStats struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

type NmapHost struct {
	Status    NmapStatus    `xml:"status"`
	Addresses []NmapAddress `xml:"address"`
	Ports     []NmapPort    `xml:"ports>port"`
	OS        NmapOS        `xml:"os"`
}

type NmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type NmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    NmapPortState `xml:"state"`
	Service  NmapService   `xml:"service"`
}

type NmapPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	Extrainfo string `xml:"extrainfo,attr"`
	Method    string `xml:"method,attr"`
	// Ostype 由 -sV 的版本探测给出（如 "Linux 5.0 - 5.4"），无需 -O 也能做 OS 汇总
	Ostype string `xml:"ostype,attr"`
}

type NmapOS struct {
	Matches []NmapOSMatch `xml:"osmatch"`
}

type NmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

func (h *NmapHost) GetIPv4() string {
	for _, addr := range h.Addresses {
		if addr.AddrType == "ipv4" {
			return addr.Addr
		}
	}
	for _, addr := range h.Addresses {
		if strings.Contains(addr.Addr, ".") {
			return addr.Addr
		}
	}
	return ""
}

// scanTypeArg 选择 TCP 扫描类型：root 用 SYN，普通用户退化为 connect 扫描
func scanTypeArg() string {
	if isRoot() {
		return "-sS"
	}
	return "-sT"
}

// nmapSupportsStats 判断当前 nmap 是否支持 --stats-every（7.0+ 提供实时进度）
var (
	nmapStatsOnce sync.Once
	nmapStatsOK   bool
)

func nmapSupportsStats(nmapPath string) bool {
	nmapStatsOnce.Do(func() {
		out, err := exec.Command(nmapPath, "--version").CombinedOutput()
		if err != nil {
			return
		}
		m := regexp.MustCompile(`Nmap version (\d+)\.(\d+)`).FindStringSubmatch(string(out))
		if len(m) < 3 {
			return
		}
		major, err1 := strconv.Atoi(m[1])
		minor, err2 := strconv.Atoi(m[2])
		if err1 != nil || err2 != nil {
			return
		}
		nmapStatsOK = major > 7 || (major == 7 && minor >= 0)
	})
	return nmapStatsOK
}

// runNmap 统一执行 nmap 并输出命令行、过程日志
func runNmap(ctx context.Context, nmapPath string, args []string, taskID int64, source string, emit lineEmitter, logCmd func(string)) (*cmdStreamResult, error) {
	// 让 nmap 周期性打印真实进度（stderr），供上层换算为整体进度与预估剩余时间
	if !hasAnyArg(args, "--stats-every") && nmapSupportsStats(nmapPath) {
		args = append(args, "--stats-every", "3s")
	}
	cmd := exec.CommandContext(ctx, nmapPath, args...)
	cmdLine := strings.Join(cmd.Args, " ")
	GetEventBus().Publish(ProgressEvent{
		TaskID:       taskID,
		EventType:    "command",
		OutputSource: source,
		OutputLine:   cmdLine,
	})
	if logCmd != nil {
		logCmd(cmdLine)
	}
	return runStream(ctx, cmd, emit)
}

// RunPingScan 存活探测（仅 nmap -sn，不做端口扫描）
func RunPingScan(ctx context.Context, target, nmapPath, nmapArgs string, taskID int64, emit lineEmitter, logCmd func(string)) (*NmapPingResult, error) {
	args := parseArgs(nmapArgs)
	args = dropArgWithValue(args, "-oX")
	if !hasAnyArg(args, "-sn", "-sP") {
		args = append(args, "-sn")
	}
	if !hasAnyArg(args, "-n") {
		args = append(args, "-n")
	}
	args = append(args, "-oX", "-")
	for _, t := range splitTargets(target) {
		args = append(args, t)
	}

	res, err := runNmap(ctx, nmapPath, args, taskID, models.OutputSourcePing, emit, logCmd)
	rawStdout, rawAll := "", ""
	if res != nil {
		rawStdout = res.Stdout
		rawAll = res.Stdout + res.Stderr
	}
	if err != nil {
		if err == ErrInterrupted {
			return nil, err
		}
		return nil, fmt.Errorf("nmap 存活探测失败: %v", err)
	}

	alive := parsePingXML([]byte(rawStdout))
	if len(alive) == 0 {
		// XML 不完整时退化为文本解析（兼容老版本或被中断的输出）
		alive = parsePingText(rawAll)
	}
	return &NmapPingResult{AliveIPs: alive, RawXML: rawStdout}, nil
}

// RunServiceScan 服务识别（仅 nmap -sV，不做存活探测/端口扫描）
func RunServiceScan(ctx context.Context, ip, portsArg string, needUDP bool, nmapPath, nmapArgs string, taskID int64, emit lineEmitter, logCmd func(string)) (*NmapServiceResult, error) {
	args := parseArgs(nmapArgs)
	args = dropArgWithValue(args, "-oX")
	args = dropArgWithValue(args, "-p")
	if !hasAnyArg(args, "-sV") {
		args = append(args, "-sV")
	}
	if !hasAnyArg(args, "-Pn") {
		args = append(args, "-Pn")
	}
	if !hasAnyArg(args, "-n") {
		args = append(args, "-n")
	}
	if needUDP && !hasAnyArg(args, "-sU") {
		args = append(args, "-sU")
		if !hasAnyArg(args, "-sS", "-sT", "-sA", "-sW") {
			args = append(args, scanTypeArg())
		}
	}
	if !hasAnyArg(args, "-sS", "-sT", "-sA", "-sW", "-sU") {
		args = append(args, scanTypeArg())
	}
	if portsArg != "" {
		args = append(args, "-p", portsArg)
	}
	args = append(args, "-oX", "-", ip)

	res, err := runNmap(ctx, nmapPath, args, taskID, models.OutputSourceService, emit, logCmd)
	raw := ""
	if res != nil {
		raw = res.Stdout
	}
	if err != nil {
		if err == ErrInterrupted {
			return nil, err
		}
		return nil, fmt.Errorf("nmap 服务识别失败 (%s): %v", ip, err)
	}

	results := parseServiceXML([]byte(raw), ip)
	return &NmapServiceResult{Results: results, RawXML: raw}, nil
}

// RunNmapPortScan 使用 nmap 进行纯端口扫描（不带 -sV 服务识别）
func RunNmapPortScan(ctx context.Context, target, portSpec, nmapPath, nmapArgs string, taskID int64, emit lineEmitter, logCmd func(string)) (*NmapPortResult, error) {
	portsArg, needUDP := models.NmapPortSpec(portSpec)

	args := parseArgs(nmapArgs)
	args = dropArgWithValue(args, "-oX")
	args = dropArgWithValue(args, "-p")
	// 纯端口扫描不带 -sV
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if a == "-sV" || strings.HasPrefix(a, "--version") {
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered
	if !hasAnyArg(args, "-Pn") {
		args = append(args, "-Pn")
	}
	if !hasAnyArg(args, "-n") {
		args = append(args, "-n")
	}
	if needUDP && !hasAnyArg(args, "-sU") {
		args = append(args, "-sU")
	}
	if !hasAnyArg(args, "-sS", "-sT", "-sA", "-sW", "-sU") {
		args = append(args, scanTypeArg())
	}
	// 非 root 无法使用 -sS（SYN 扫描需要原始套接字），自动退化为 -sT
	if !isRoot() && hasAnyArg(args, "-sS") {
		converted := make([]string, 0, len(args))
		for _, a := range args {
			if a == "-sS" {
				a = "-sT"
			}
			converted = append(converted, a)
		}
		args = converted
	}
	args = append(args, "-p", portsArg, "-oX", "-")
	for _, t := range splitTargets(target) {
		args = append(args, t)
	}

	res, err := runNmap(ctx, nmapPath, args, taskID, models.OutputSourceNmap, emit, logCmd)
	raw := ""
	if res != nil {
		raw = res.Stdout
	}
	if err != nil {
		if err == ErrInterrupted {
			return nil, err
		}
		return nil, fmt.Errorf("nmap 端口扫描失败: %v", err)
	}

	results := parseServiceXML([]byte(raw), "")
	hostsUp := len(distinctIPs(results))
	var nmapXML NmapXML
	if xml.Unmarshal([]byte(raw), &nmapXML) == nil && nmapXML.RunStats.Hosts.Up > 0 {
		hostsUp = nmapXML.RunStats.Hosts.Up
	}
	if hostsUp == 0 {
		hostsUp = len(splitTargets(target))
	}
	return &NmapPortResult{Results: results, RawXML: raw, HostsUp: hostsUp}, nil
}

func distinctIPs(results []*models.ScanResult) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, r := range results {
		if !seen[r.IP] {
			seen[r.IP] = true
			out = append(out, r.IP)
		}
	}
	return out
}

func parsePingXML(data []byte) []string {
	var nmapXML NmapXML
	if err := xml.Unmarshal(data, &nmapXML); err != nil {
		return nil
	}
	aliveIPs := make([]string, 0)
	for _, host := range nmapXML.Hosts {
		if host.Status.State == "up" {
			ip := host.GetIPv4()
			if ip != "" {
				aliveIPs = append(aliveIPs, ip)
			}
		}
	}
	return aliveIPs
}

var ipRe = regexp.MustCompile(`Nmap scan report for ([\d.]+)`)

func parsePingText(output string) []string {
	aliveIPs := make([]string, 0)
	matches := ipRe.FindAllStringSubmatch(output, -1)
	for _, m := range matches {
		if len(m) > 1 {
			ip := m[1]
			if strings.Count(ip, ".") == 3 {
				aliveIPs = append(aliveIPs, ip)
			}
		}
	}
	return aliveIPs
}

func parseServiceXML(data []byte, targetIP string) []*models.ScanResult {
	var nmapXML NmapXML
	if err := xml.Unmarshal(data, &nmapXML); err != nil {
		return nil
	}
	results := make([]*models.ScanResult, 0)
	for _, host := range nmapXML.Hosts {
		ip := host.GetIPv4()
		if ip == "" {
			ip = targetIP
		}
		osGuess := ""
		if len(host.OS.Matches) > 0 {
			osGuess = host.OS.Matches[0].Name
		}
		for _, port := range host.Ports {
			if port.State.State != "open" && port.State.State != "open|filtered" {
				continue
			}
			state := port.State.State
			if state == "" {
				state = "open"
			}
			result := &models.ScanResult{
				IP:        ip,
				Port:      port.PortID,
				Protocol:  port.Protocol,
				State:     state,
				Service:   port.Service.Name,
				Product:   port.Service.Product,
				Version:   port.Service.Version,
				ExtraInfo: port.Service.Extrainfo,
			}
			if osGuess != "" {
				result.OSDetails = osGuess
			} else if strings.TrimSpace(port.Service.Ostype) != "" {
				result.OSDetails = port.Service.Ostype
			}
			results = append(results, result)
		}
	}
	return results
}

// splitTargets 拆分多行/多列目标，过滤空行与注释
func splitTargets(target string) []string {
	out := make([]string, 0)
	for _, t := range strings.FieldsFunc(target, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ',' || r == ';'
	}) {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// 防止目标被当作 nmap/masscan 的选项（例如 "-oJ/tmp/x"）
		if strings.HasPrefix(t, "-") {
			continue
		}
		out = append(out, t)
	}
	return out
}
