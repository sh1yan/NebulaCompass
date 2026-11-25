package models

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// SplitTargetsText 拆分多行/多列目标，过滤空行与注释
func SplitTargetsText(target string) []string {
	out := make([]string, 0)
	for _, t := range strings.FieldsFunc(target, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ',' || r == ';'
	}) {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// ValidateTargets 校验扫描目标，返回非法条目（最多 20 条）。
// 目的：① 阻止把 nmap/masscan 的选项当成目标传入（如 "-oJ/tmp/x"）；② 尽早暴露格式错误。
func ValidateTargets(target string) []string {
	bad := make([]string, 0)
	for _, t := range SplitTargetsText(target) {
		if len(t) > 255 {
			bad = append(bad, t[:40]+"...（过长）")
			continue
		}
		if strings.HasPrefix(t, "-") {
			bad = append(bad, t+"（目标不允许以 - 开头）")
			continue
		}
		if !isValidTargetToken(t) {
			bad = append(bad, t)
		}
		if len(bad) >= 20 {
			break
		}
	}
	return bad
}

func isValidTargetToken(t string) bool {
	// CIDR
	if strings.Contains(t, "/") {
		_, _, err := net.ParseCIDR(t)
		return err == nil
	}
	// IPv6 字面量
	if net.ParseIP(t) != nil {
		return true
	}
	// host:port
	if strings.Contains(t, ":") {
		host, portStr, err := net.SplitHostPort(t)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		if net.ParseIP(host) != nil {
			return true
		}
		return hostnameRe.MatchString(host)
	}
	// 域名
	return hostnameRe.MatchString(t)
}

// TargetCount 统计目标条目数（用于服务识别等按条目推进的场景）
func TargetCount(target string) int {
	return len(SplitTargetsText(target))
}

// IsHostPortToken 判断 token 是否为 host:port 形式（IPv4 / 域名 / IPv6 字面量 + 1-65535 端口）
func IsHostPortToken(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" || strings.Contains(t, "/") || strings.HasPrefix(t, "-") {
		return false
	}
	host, portStr, err := net.SplitHostPort(t)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return hostnameRe.MatchString(host)
}

// ServiceTargetIssues 校验「服务识别」模式的目标：必须写成 IP:端口。
// 服务识别只扫描目标里写明的端口，没有端口就无从扫起；
// 与其静默跳过或退化成扫常见端口，不如在创建任务时就明确指出哪几条缺端口。
func ServiceTargetIssues(target string) []string {
	bad := make([]string, 0)
	for _, t := range SplitTargetsText(target) {
		if IsHostPortToken(t) {
			continue
		}
		reason := "（缺少端口，应写成 IP:端口）"
		if strings.Contains(t, "/") {
			reason = "（不支持网段，应写成 IP:端口）"
		}
		label := t
		if len(label) > 60 {
			label = label[:60] + "..."
		}
		bad = append(bad, label+reason)
		if len(bad) >= 20 {
			break
		}
	}
	return bad
}
