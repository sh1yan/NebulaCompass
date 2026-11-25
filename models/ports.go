package models

import (
	"strconv"
	"strings"
)

// PortPreset 预置端口列表
// Spec 采用 masscan 风格的端口规约：TCP 端口直接列举，UDP 端口用 U: 前缀。
// 例： "80,443,8000-8100"  或  "161,500,U:53,123,161"
type PortPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Spec        string `json:"spec"`
	Count       int    `json:"count"`
	HasUDP      bool   `json:"has_udp"`
	Group       string `json:"group"`
}

// 常见 WEB 端口
const presetWebPorts = "80,81,82,83,84,85,88,443,591,800,801,888,1000,1080,1888,2000,2082,2083," +
	"3000,4000,4443,4848,5000,5001,5555,5601,7001,7002,7070,7071,7080,7777,8000,8001,8008,8009," +
	"8010,8030,8040,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093," +
	"8094,8095,8096,8097,8098,8099,8100,8180,8181,8188,8280,8333,8400,8443,8444,8500,8686,8787," +
	"8800,8834,8880,8881,8888,8899,8983,9000,9001,9002,9043,9080,9090,9091,9200,9300,9443,9500," +
	"9800,9900,9999,10000,10443,15672,18080,18081,28080,30000"

// 常见 TOP100 端口（nmap-services 常用排名）
const presetTop100Ports = "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143," +
	"144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995," +
	"1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128," +
	"3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001," +
	"6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155," +
	"49156,49157"

// 常见高位端口（配合 1-1024 形成“常见一两千端口”）
const presetHighCommonPorts = "1080,1099,1433,1521,1522,2049,2082,2083,2181,2222,2375,2376,2379," +
	"3000,3128,3268,3269,3306,3389,3690,4000,4040,4369,4440,4444,4567,4848,5000,5001,5005,5007," +
	"5060,5222,5269,5357,5432,5443,5601,5632,5672,5678,5900,5901,5984,5985,5986,5988,6000,6222," +
	"6379,6443,7001,7002,7070,7071,7080,7077,7443,7474,7477,7687,7777,7890,8000,8008,8009,8010," +
	"8020,8042,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093," +
	"8094,8095,8096,8097,8098,8099,8100,8161,8172,8180,8181,8200,8280,8291,8333,8400,8443,8444," +
	"8445,8446,8447,8448,8449,8450,8500,8520,8555,8649,8686,8787,8800,8834,8880,8888,8899,8983," +
	"8990,9000,9001,9002,9003,9004,9005,9010,9042,9043,9060,9080,9090,9091,9092,9093,9094,9095," +
	"9100,9200,9300,9418,9443,9444,9500,9600,9800,9876,9900,9943,9944,9981,9990,9999,10000," +
	"10001,10010,10250,10255,10443,11211,11214,11215,15672,16379,18080,20000,25565,25672,27017," +
	"27018,27019,28017,30000,32400,33060,35357,45678,50000,50070,50075,50090,61616"

// 常见数据库与消息队列端口
const presetDBMQPorts = "1433,1434,1521,1830,3306,3307,5000,5432,5433,5984,6379,6380,7000,7001," +
	"7474,7687,8000,8086,8161,8888,9000,9042,9092,9093,9094,9300,9200,9418,11214,11215,11211," +
	"2181,2196,22181,2888,3888,4369,5671,5672,5673,5674,61613,61614,61616,61617,15672,15674," +
	"16379,27017,27018,27019,28017,26257,50000,50070,50075,50090,10250,10255,2379,2380,9090"

// 常见 UDP 端口
const presetUDPPorts = "53,67,68,69,111,123,137,138,139,161,162,177,389,427,443,500,514,515,518," +
	"520,623,631,636,1900,2049,3478,4500,5060,5061,5353,5355,5683,6343,1723,11211,4789,49152,49153"

func builtinPresets() []PortPreset {
	presets := []PortPreset{
		{
			ID:          "top100",
			Name:        "常见 100 端口",
			Description: "nmap-services 中排名最靠前的 100 个 TCP 端口，快速摸底",
			Spec:        presetTop100Ports,
			Group:       "常用",
		},
		{
			ID:          "web",
			Name:        "常见 WEB 端口",
			Description: "HTTP/HTTPS/各类 Web 中间件与管理后台端口",
			Spec:        presetWebPorts,
			Group:       "常用",
		},
		{
			ID:          "common1200",
			Name:        "常见约 1200 端口",
			Description: "1-1024 全端口 + 常用高位端口，覆盖面与耗时折中",
			Spec:        "1-1024," + presetHighCommonPorts,
			Group:       "常用",
		},
		{
			ID:          "db_mq",
			Name:        "数据库与 MQ 端口",
			Description: "MySQL/Redis/MongoDB/Oracle/MSSQL/ES/Kafka/RabbitMQ 等",
			Spec:        presetDBMQPorts,
			Group:       "专项",
		},
		{
			ID:          "udp_common",
			Name:        "常见 UDP 端口",
			Description: "DNS/SNMP/NTP/TFTP/NetBIOS/Kerberos/mDNS 等（自动加 -sU / U: 前缀）",
			Spec:        "U:" + presetUDPPorts,
			Group:       "专项",
			HasUDP:      true,
		},
	}
	for i := range presets {
		presets[i].Count = CountPortSpec(presets[i].Spec)
		if strings.Contains(presets[i].Spec, "U:") {
			presets[i].HasUDP = true
		}
	}
	return presets
}

// GetPortPresets 返回全部内置预置端口列表
func GetPortPresets() []PortPreset {
	return builtinPresets()
}

// GetPortPreset 按 ID 查找预置
func GetPortPreset(id string) (PortPreset, bool) {
	for _, p := range builtinPresets() {
		if p.ID == id {
			return p, true
		}
	}
	return PortPreset{}, false
}

// PortSpecParse 端口规约解析结果；Invalid 保存无法识别的原始 token（用于向用户报错）
type PortSpecParse struct {
	TCP     []string
	UDP     []string
	Invalid []string
}

// ParsePortSpec 严格解析端口规约，支持 "U:53,123"、"T:80,443"、"80,443,U:53" 等写法。
// 无法识别的 token 不会被静默丢弃，而是收集到 Invalid 中由调用方决定如何处理。
func ParsePortSpec(spec string) PortSpecParse {
	var res PortSpecParse
	cur := "tcp"
	for _, raw := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '|'
	}) {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		up := strings.ToUpper(tok)
		if strings.HasPrefix(up, "U:") {
			cur = "udp"
			tok = tok[2:]
		} else if strings.HasPrefix(up, "T:") {
			cur = "tcp"
			tok = tok[2:]
		}
		tok = strings.TrimSpace(tok)
		if tok == "" {
			// 只有前缀没有内容的 token，例如 "U:" —— 视为无意义输入直接忽略
			continue
		}
		norm := normalizeToken(tok)
		if norm == "" {
			if len(res.Invalid) < 10 {
				res.Invalid = append(res.Invalid, raw)
			}
			continue
		}
		if cur == "udp" {
			res.UDP = append(res.UDP, norm)
		} else {
			res.TCP = append(res.TCP, norm)
		}
	}
	return res
}

// splitSpec 把端口规约拆成 tcp / udp 两组 token（忽略非法 token，供内部归一化使用）
// 支持 "U:53,123"、"T:80,443"、"80,443,U:53" 等写法
func splitSpec(spec string) (tcp []string, udp []string) {
	p := ParsePortSpec(spec)
	return p.TCP, p.UDP
}

// normalizeToken 校验并规范化单个 token（支持 80、8000-8100）
func normalizeToken(tok string) string {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return ""
	}
	if !strings.Contains(tok, "-") {
		p, err := strconv.Atoi(tok)
		if err != nil || p < 1 || p > 65535 {
			return ""
		}
		return strconv.Itoa(p)
	}
	parts := strings.SplitN(tok, "-", 2)
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return ""
	}
	// 越界 / 区间写反都视为非法输入，交由调用方报错（不再静默裁剪成 1-65535）
	if lo < 1 || hi > 65535 || lo > hi {
		return ""
	}
	if lo == hi {
		return strconv.Itoa(lo)
	}
	return strconv.Itoa(lo) + "-" + strconv.Itoa(hi)
}

func dedupe(tokens []string) []string {
	seen := make(map[string]bool, len(tokens))
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// ComposePortSpecResult 端口规约合成结果
type ComposePortSpecResult struct {
	Spec           string
	UsedPresets    []string
	InvalidTokens  []string // 自定义端口里无法识别的 token
	UnknownPresets []string // 不存在的预置 ID
}

// ComposePortSpecChecked 合并勾选的预置端口列表与自定义端口，生成统一端口规约。
// 与旧版不同：不再静默丢弃非法输入，而是把非法 token / 未知预置回传，由调用方报错。
func ComposePortSpecChecked(presetIDs []string, custom string) ComposePortSpecResult {
	var res ComposePortSpecResult
	var tcp, udp []string
	used := make([]string, 0, len(presetIDs))
	for _, id := range presetIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		p, ok := GetPortPreset(id)
		if !ok {
			res.UnknownPresets = append(res.UnknownPresets, id)
			continue
		}
		t, u := splitSpec(p.Spec)
		tcp = append(tcp, t...)
		udp = append(udp, u...)
		used = append(used, p.ID)
	}
	if strings.TrimSpace(custom) != "" {
		parsed := ParsePortSpec(custom)
		tcp = append(tcp, parsed.TCP...)
		udp = append(udp, parsed.UDP...)
		res.InvalidTokens = parsed.Invalid
	}
	tcp = dedupe(tcp)
	udp = dedupe(udp)

	parts := make([]string, 0, len(tcp)+len(udp)+1)
	parts = append(parts, tcp...)
	if len(udp) > 0 {
		parts = append(parts, "U:"+strings.Join(udp, ","))
	}
	res.Spec = strings.Join(parts, ",")
	res.UsedPresets = used
	return res
}

// ComposePortSpec 合并勾选的预置端口列表与自定义端口，生成统一端口规约
// 返回：规约字符串、命中的预置 ID 列表（忽略非法输入，仅供内部/兼容调用）
func ComposePortSpec(presetIDs []string, custom string) (string, []string) {
	r := ComposePortSpecChecked(presetIDs, custom)
	return r.Spec, r.UsedPresets
}

// NormalizePortSpec 规范化一个已有的端口规约；空则返回默认值
func NormalizePortSpec(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "" {
		return "1-65535"
	}
	tcp, udp := splitSpec(s)
	tcp = dedupe(tcp)
	udp = dedupe(udp)
	if len(tcp) == 0 && len(udp) == 0 {
		return "1-65535"
	}
	parts := make([]string, 0, len(tcp)+len(udp)+1)
	parts = append(parts, tcp...)
	if len(udp) > 0 {
		parts = append(parts, "U:"+strings.Join(udp, ","))
	}
	return strings.Join(parts, ",")
}

// NmapPortSpec 把端口规约转换成 nmap -p 可用的写法，并告知是否需要 -sU
func NmapPortSpec(spec string) (string, bool) {
	tcp, udp := splitSpec(spec)
	if len(tcp) == 0 && len(udp) == 0 {
		return "1-65535", false
	}
	parts := make([]string, 0, 2)
	if len(tcp) > 0 {
		parts = append(parts, "T:"+strings.Join(tcp, ","))
	}
	if len(udp) > 0 {
		parts = append(parts, "U:"+strings.Join(udp, ","))
	}
	out := strings.Join(parts, ",")
	if len(tcp) == 0 {
		// 只有 UDP 时 nmap 允许省掉 T:
		out = "U:" + strings.Join(udp, ",")
	}
	return out, len(udp) > 0
}

// MasscanPortSpec 把端口规约转换成 masscan -p 可用的写法
func MasscanPortSpec(spec string) string {
	tcp, udp := splitSpec(spec)
	if len(tcp) == 0 && len(udp) == 0 {
		return "1-65535"
	}
	parts := make([]string, 0, len(tcp)+len(udp)+1)
	parts = append(parts, tcp...)
	if len(udp) > 0 {
		parts = append(parts, "U:"+strings.Join(udp, ","))
	}
	return strings.Join(parts, ",")
}

// CountPortSpec 估算端口规约覆盖的端口数量
func CountPortSpec(spec string) int {
	tcp, udp := splitSpec(spec)
	count := func(tokens []string) int {
		n := 0
		for _, t := range tokens {
			if !strings.Contains(t, "-") {
				n++
				continue
			}
			parts := strings.SplitN(t, "-", 2)
			lo, err1 := strconv.Atoi(parts[0])
			hi, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil {
				continue
			}
			if hi >= lo {
				n += hi - lo + 1
			}
		}
		return n
	}
	return count(tcp) + count(udp)
}
