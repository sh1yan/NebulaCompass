package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"NebulaCompass/models"
)

// MasscanHit 一条端口命中
type MasscanHit struct {
	IP    string
	Port  int
	Proto string
}

type MasscanResult struct {
	Hits      []MasscanHit
	OpenPorts map[string][]int
	RawOutput string
}

// MasscanProgress masscan 自带的扫描进度/预估剩余时间
type MasscanProgress struct {
	HasPercent bool
	Percent    float64 // masscan 自身进度 0-100
	EtaSeconds int64   // masscan 预估剩余秒数
	RateKpps   float64 // 扫描速率 kpps
	Found      int     // 已发现开放端口数
}

var (
	msRateRe  = regexp.MustCompile(`rate:\s*([0-9.]+)-kpps`)
	msPctRe   = regexp.MustCompile(`([0-9.]+)%\s*done`)
	msEtaRe   = regexp.MustCompile(`(\d+):(\d{2}):(\d{2})\s*remaining`)
	msFoundRe = regexp.MustCompile(`found=(\d+)`)
	// masscan -oL 列表格式： open tcp 80 1.2.3.4 1699999999
	msListRe = regexp.MustCompile(`^(open|open\|filtered)\s+(tcp|udp|sctp)\s+(\d+)\s+([0-9a-fA-F.:]+)(?:\s+\d+)?\s*$`)
)

// parseMasscanProgress 从 masscan 的进度行中提取百分比 / 预估剩余时间 / 速率
func parseMasscanProgress(line string) (MasscanProgress, bool) {
	l := strings.TrimSpace(line)
	if l == "" {
		return MasscanProgress{}, false
	}
	hasMarker := strings.Contains(l, "rate:") || strings.Contains(l, "% done") || strings.Contains(l, "remaining")
	if !hasMarker {
		return MasscanProgress{}, false
	}
	p := MasscanProgress{}
	if m := msRateRe.FindStringSubmatch(l); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			p.RateKpps = v
		}
	}
	if m := msPctRe.FindStringSubmatch(l); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			p.Percent = v
			p.HasPercent = true
		}
	}
	if m := msEtaRe.FindStringSubmatch(l); m != nil {
		h, _ := strconv.ParseInt(m[1], 10, 64)
		mi, _ := strconv.ParseInt(m[2], 10, 64)
		s, _ := strconv.ParseInt(m[3], 10, 64)
		p.EtaSeconds = h*3600 + mi*60 + s
	}
	if m := msFoundRe.FindStringSubmatch(l); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil {
			p.Found = v
		}
	}
	return p, true
}

// RunMasscan 执行 masscan 端口扫描（只做端口扫描，不做存活探测与服务识别）
func RunMasscan(ctx context.Context, targets []string, portSpec, masscanPath, masscanArgs string, taskID int64,
	emit lineEmitter, onProgress func(MasscanProgress), logCmd func(string)) (*MasscanResult, error) {

	if len(targets) == 0 {
		return nil, fmt.Errorf("没有可扫描的目标")
	}

	args := parseArgs(masscanArgs)
	args = dropArgWithValue(args, "-p")
	args = dropArgWithValue(args, "--ports")
	args = dropArgWithValue(args, "-oL")
	args = dropArgWithValue(args, "-oX")
	args = dropArgWithValue(args, "-oJ")
	args = dropArgWithValue(args, "--output-format")
	args = dropArgWithValue(args, "--output-filename")
	args = append(args, "-oL", "-", "-p", models.MasscanPortSpec(portSpec))
	args = append(args, targets...)

	cmd := exec.CommandContext(ctx, masscanPath, args...)
	cmdLine := strings.Join(cmd.Args, " ")
	GetEventBus().Publish(ProgressEvent{
		TaskID:       taskID,
		EventType:    "command",
		OutputSource: models.OutputSourcePort,
		OutputLine:   cmdLine,
	})
	if logCmd != nil {
		logCmd(cmdLine)
	}

	wrapped := func(line string, isErr bool) {
		if p, ok := parseMasscanProgress(line); ok {
			if onProgress != nil {
				onProgress(p)
			}
			return // 进度行不写入常规输出，改由 eta 事件展示
		}
		if emit != nil {
			emit(line, isErr)
		}
	}

	res, err := runStream(ctx, cmd, wrapped)
	raw := ""
	if res != nil {
		raw = res.Stdout
	}
	// 先解析已收到的输出：即使被暂停/取消，已命中的端口也要保留下来
	parsed := parseMasscanOutput(raw)
	parsed.RawOutput = raw
	if err != nil {
		if err == ErrInterrupted {
			return parsed, err
		}
		return parsed, fmt.Errorf("masscan 端口扫描失败: %v", err)
	}
	return parsed, nil
}

// parseMasscanOutput 解析 masscan -oL 列表输出
// 行格式： open tcp 80 1.2.3.4 1699999999
func parseMasscanOutput(output string) *MasscanResult {
	result := &MasscanResult{
		Hits:      make([]MasscanHit, 0),
		OpenPorts: make(map[string][]int),
	}
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	seen := make(map[string]bool)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := msListRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		proto := m[2]
		port, err := strconv.Atoi(m[3])
		if err != nil {
			continue
		}
		ip := m[4]
		key := ip + "/" + proto + "/" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true
		result.Hits = append(result.Hits, MasscanHit{IP: ip, Port: port, Proto: proto})
		result.OpenPorts[ip] = append(result.OpenPorts[ip], port)
	}
	for ip := range result.OpenPorts {
		sort.Ints(result.OpenPorts[ip])
	}
	return result
}
