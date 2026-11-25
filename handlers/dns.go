package handlers

import (
	"encoding/csv"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

type DNSHandler struct{}

func NewDNSHandler() *DNSHandler { return &DNSHandler{} }

type dnsRequest struct {
	Domains string      `json:"domains"`
	Results []dnsResult `json:"results"` // 可选：导出时直接复用页面已有结果，不再重复解析
}

type dnsResult struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
	Error  string   `json:"error,omitempty"`
}

type dnsResponse struct {
	Success  bool        `json:"success"`
	Results  []dnsResult `json:"results"`
	Total    int         `json:"total"`
	Resolved int         `json:"resolved"`
	Failed   int         `json:"failed"`
}

func resolveDomain(domain string) dnsResult {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return dnsResult{Domain: domain, Error: "空域名"}
	}

	// 移除可能的协议前缀
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "HTTPS://")
	domain = strings.TrimPrefix(domain, "HTTP://")
	// 移除路径 / 查询串
	if idx := strings.IndexAny(domain, "/?#"); idx >= 0 {
		domain = domain[:idx]
	}
	// 移除端口（兼容 IPv6 字面量：[::1]:8080 与 ::1:8080）
	domain = strings.TrimSuffix(domain, "]")
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	} else if strings.HasPrefix(domain, "[") {
		domain = strings.TrimPrefix(domain, "[")
	} else if c := strings.Count(domain, ":"); c == 1 {
		// 仅一个冒号 → 形如 host:port
		domain = domain[:strings.Index(domain, ":")]
	}
	domain = strings.Trim(domain, "[]")

	ips, err := net.LookupHost(domain)
	if err != nil {
		return dnsResult{Domain: domain, Error: err.Error()}
	}
	return dnsResult{Domain: domain, IPs: ips}
}

func (h *DNSHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	var req dnsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求格式"})
		return
	}

	lines := strings.Split(req.Domains, "\n")
	results := make([]dnsResult, 0, len(lines))
	resolved := 0
	failed := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 支持逗号/分号/制表符分隔，取第一个非空部分
		parts := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '\t' || r == '|'
		})
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			result := resolveDomain(part)
			if result.Error != "" {
				failed++
			} else {
				resolved++
			}
			results = append(results, result)
		}
	}

	resp := dnsResponse{
		Success:  true,
		Results:  results,
		Total:    len(results),
		Resolved: resolved,
		Failed:   failed,
	}
	json.NewEncoder(w).Encode(resp)
}

func (h *DNSHandler) Export(w http.ResponseWriter, r *http.Request) {
	var req dnsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求格式"})
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=dns_results.csv; filename*=UTF-8''dns_results.csv")
	// 写入 BOM 以便 Excel 识别 UTF-8
	w.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(w)
	writer.Write([]string{"域名", "IP地址", "状态"})

	// 页面已经解析过：直接复用结果，保证导出内容与页面一致且不重复解析
	if len(req.Results) > 0 {
		for _, r := range req.Results {
			if r.Error != "" {
				writer.Write([]string{r.Domain, "", "失败: " + r.Error})
				continue
			}
			writer.Write([]string{r.Domain, strings.Join(r.IPs, "; "), "成功"})
		}
		writer.Flush()
		return
	}

	lines := strings.Split(req.Domains, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '\t' || r == '|'
		})
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			result := resolveDomain(part)
			if result.Error != "" {
				writer.Write([]string{part, "", "失败: " + result.Error})
			} else {
				writer.Write([]string{part, strings.Join(result.IPs, "; "), "成功"})
			}
		}
	}

	writer.Flush()
}

func (h *DNSHandler) PageDNS(w http.ResponseWriter, r *http.Request) {
	ServePage(w, r, "dns.html")
}
