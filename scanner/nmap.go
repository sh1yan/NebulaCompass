package scanner

import (
	"NebulaCompass/models"
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type NmapPingResult struct {
	AliveIPs []string
	RawXML   string
}

type NmapServiceResult struct {
	Results []*models.ScanResult
	RawXML  string
}

type NmapXML struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
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

func execCmdStream(cmd *exec.Cmd, taskID int64, source string) (string, error) {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start: %w", err)
	}

	var buf bytes.Buffer
	var mu sync.Mutex
	var wg sync.WaitGroup

	reader := func(r io.Reader, prefix string) {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 1024*64), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			if prefix != "" {
				buf.WriteString("[stderr] " + line + "\n")
			} else {
				buf.WriteString(line + "\n")
			}
			mu.Unlock()
			GetEventBus().Publish(ProgressEvent{
				TaskID:       taskID,
				OutputLine:   prefix + line,
				OutputSource: source,
				EventType:    "output",
			})
		}
	}

	wg.Add(2)
	go reader(stdoutPipe, "")
	go reader(stderrPipe, "[stderr] ")
	wg.Wait()

	err = cmd.Wait()
	if err != nil {
		return buf.String(), fmt.Errorf("command failed: %w\noutput: %s", err, buf.String())
	}
	return buf.String(), nil
}

func RunPingScan(target string, nmapPath string, nmapArgs string, taskID int64) (*NmapPingResult, error) {
	args := parseArgs(nmapArgs)
	hasOX := false
	for _, a := range args {
		if a == "-oX" {
			hasOX = true
			break
		}
	}
	if !hasOX {
		args = append(args, "-oX", "-")
	}
	// Split multi-line targets into separate arguments for nmap
	targets := strings.Fields(target)
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
		OutputSource: "ping_scan",
		OutputLine:   strings.Join(cmd.Args, " "),
	})
	saveCmdRecord(taskID, strings.Join(cmd.Args, " "))
	raw, err := execCmdStream(cmd, taskID, "ping_scan")
	if err != nil {
		return nil, err
	}

	aliveIPs := parsePingXML([]byte(raw))

	return &NmapPingResult{
		AliveIPs: aliveIPs,
		RawXML:   raw,
	}, nil
}

func RunServiceScan(ip string, ports []int, nmapPath string, nmapArgs string, taskID int64) (*NmapServiceResult, error) {
	portStr := joinPorts(ports)
	args := parseArgs(nmapArgs)
	args = append(args, "-oX", "-", "-p", portStr, ip)

	cmd := exec.Command(nmapPath, args...)
	GetEventBus().Publish(ProgressEvent{
		TaskID:       taskID,
		EventType:    "command",
		OutputSource: "service_scan",
		OutputLine:   strings.Join(cmd.Args, " "),
	})
	saveCmdRecord(taskID, strings.Join(cmd.Args, " "))
	raw, err := execCmdStream(cmd, taskID, "service_scan")
	if err != nil {
		return nil, fmt.Errorf("nmap service scan failed for %s: %v\noutput: %s", ip, err, raw)
	}

	results := parseServiceXML([]byte(raw), ip)

	return &NmapServiceResult{
		Results: results,
		RawXML:  raw,
	}, nil
}

func parsePingXML(data []byte) []string {
	var nmapXML NmapXML
	if err := xml.Unmarshal(data, &nmapXML); err != nil {
		return parsePingText(string(data))
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
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			result := &models.ScanResult{
				IP:        ip,
				Port:      port.PortID,
				Protocol:  port.Protocol,
				State:     port.State.State,
				Service:   port.Service.Name,
				Product:   port.Service.Product,
				Version:   port.Service.Version,
				ExtraInfo: port.Service.Extrainfo,
			}
			if len(host.OS.Matches) > 0 {
				result.OSDetails = host.OS.Matches[0].Name
			}
			results = append(results, result)
		}
	}
	return results
}

func parseArgs(raw string) []string {
	args := strings.Fields(raw)
	result := make([]string, 0, len(args))
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg != "" {
			result = append(result, arg)
		}
	}
	return result
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
