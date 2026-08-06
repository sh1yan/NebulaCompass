package scanner

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type MasscanResult struct {
	OpenPorts map[string][]int
	RawOutput string
}

func RunMasscanWithFile(aliveHosts []string, portRange string, masscanPath string, masscanArgs string, taskID int64) (*MasscanResult, error) {
	args := parseArgs(masscanArgs)
	args = append(args, "-oL", "-")
	args = append(args, "-p", portRange)

	for _, ip := range aliveHosts {
		args = append(args, ip)
	}

	cmd := exec.Command(masscanPath, args...)
	GetEventBus().Publish(ProgressEvent{
		TaskID:       taskID,
		EventType:    "command",
		OutputSource: "port_scan",
		OutputLine:   strings.Join(cmd.Args, " "),
	})
	saveCmdRecord(taskID, strings.Join(cmd.Args, " "))
	outPipe, _ := cmd.StdoutPipe()
	errPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("masscan start failed: %v", err)
	}

	var mu sync.Mutex
	var stdoutBuf, stderrBuf strings.Builder

	// 读取stdout
	go func() {
		scanner := bufio.NewScanner(outPipe)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			stdoutBuf.WriteString(line + "\n")
			mu.Unlock()
			GetEventBus().Publish(ProgressEvent{
				TaskID:       taskID,
				OutputLine:   line,
				OutputSource: "port_scan",
				EventType:    "output",
			})
		}
	}()
	// 读取stderr
	go func() {
		scanner := bufio.NewScanner(errPipe)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			stderrBuf.WriteString("[stderr] " + line + "\n")
			mu.Unlock()
			GetEventBus().Publish(ProgressEvent{
				TaskID:       taskID,
				OutputLine:   "[stderr] " + line,
				OutputSource: "port_scan",
				EventType:    "output",
			})
		}
	}()

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("masscan failed: %v\nstderr: %s", err, stderrBuf.String())
	}

	output := stdoutBuf.String()
	result := parseMasscanOutput(output)
	result.RawOutput = output
	return result, nil
}

func parseMasscanOutput(output string) *MasscanResult {
	/***
	该函数用于取值masscan扫描的开放端口条数，并按照ip:port进行去重来获取
	*/
	result := &MasscanResult{
		OpenPorts: make(map[string][]int),
	}
	scanner := bufio.NewScanner(strings.NewReader(output))

	//re := regexp.MustCompile(`^(open|filtered)\s+(tcp|udp)\s+(\d+)\s+([\d.]+)`)
	//for scanner.Scan() {
	//	line := strings.TrimSpace(scanner.Text())
	//	matches := re.FindStringSubmatch(line)
	//	if matches != nil {
	//		ip := matches[4]
	//		port, _ := strconv.Atoi(matches[3])
	//		result.OpenPorts[ip] = append(result.OpenPorts[ip], port)
	//	}
	//}

	re := regexp.MustCompile(`^open\s+(tcp|udp)\s+(\d+)\s+([\d.]+)`)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		matches := re.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		ip := matches[4]
		key := ip + "/" + matches[3]
		if seen[key] {
			continue
		}
		seen[key] = true
		port, _ := strconv.Atoi(matches[3])
		result.OpenPorts[ip] = append(result.OpenPorts[ip], port)
	}

	return result
}
