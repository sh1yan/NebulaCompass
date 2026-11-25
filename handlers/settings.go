package handlers

import (
	"NebulaCompass/database"
	"NebulaCompass/models"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type SettingsHandler struct{}

func NewSettingsHandler() *SettingsHandler { return &SettingsHandler{} }

type settingDef struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Value       string `json:"value"`
	Type        string `json:"type"`
}

func getSettingDefs() []settingDef {
	db := database.GetDB()
	settings := db.GetAllSettings()
	settingMap := make(map[string]string)
	for _, s := range settings {
		settingMap[s.Key] = s.Value
	}

	defs := []settingDef{
		{Key: models.SettingNmapPath, Label: "Nmap 路径", Description: "nmap 可执行文件的路径（默认使用系统 PATH）", Type: "text"},
		{Key: models.SettingMasscanPath, Label: "Masscan 路径", Description: "masscan 可执行文件的路径（默认使用系统 PATH）", Type: "text"},
		{Key: models.SettingNmapPingArgs, Label: "Nmap Ping 扫描参数", Description: "nmap -sn 存活扫描的额外参数", Type: "text"},
		{Key: models.SettingMasscanArgs, Label: "Masscan 扫描参数", Description: "masscan 端口扫描的额外参数（排除 -p 和端口范围）", Type: "text"},
		{Key: models.SettingNmapServiceArgs, Label: "Nmap 服务扫描参数", Description: "nmap -sV 服务版本识别的参数", Type: "text"},
		{Key: models.SettingNmapPortArgs, Label: "Nmap 端口扫描参数", Description: "nmap 端口扫描识别的参数", Type: "text"},
		// {Key: models.SettingPingRate, Label: "Ping 速率", Description: "nmap ping 扫描的发送速率（packets/sec）", Type: "number"},
		// {Key: models.SettingPortRate, Label: "端口扫描速率", Description: "masscan 端口扫描的速率（packets/sec）", Type: "number"},
		// {Key: models.SettingMaxConcurrency, Label: "最大并发任务数", Description: "同时运行的最大扫描任务数", Type: "number"},
		{Key: models.SettingRefreshInterval, Label: "首页自动刷新间隔", Description: "任务列表页自动刷新时间（秒），设为0表示不自动刷新", Type: "number"},
	}

	for i := range defs {
		if v, ok := settingMap[defs[i].Key]; ok {
			defs[i].Value = v
		}
	}
	return defs
}

func (h *SettingsHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	defs := getSettingDefs()
	json.NewEncoder(w).Encode(defs)
}

func (h *SettingsHandler) SaveSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var incoming map[string]string
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Invalid request"})
		return
	}

	// 只接受已知配置项，且做基本校验（历史缺陷 D-21：任意 key 都能写库）
	allowed := map[string]bool{
		models.SettingNmapPath:        true,
		models.SettingMasscanPath:     true,
		models.SettingNmapPingArgs:    true,
		models.SettingMasscanArgs:     true,
		models.SettingNmapServiceArgs: true,
		models.SettingNmapPortArgs:    true,
		models.SettingRefreshInterval: true,
	}

	settings := make(map[string]string, len(incoming))
	ignored := make([]string, 0)
	for k, v := range incoming {
		if !allowed[k] {
			ignored = append(ignored, k)
			continue
		}
		v = strings.TrimSpace(v)
		if strings.ContainsAny(v, "\r\n\x00") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "配置项 " + k + " 含有非法字符（不允许换行）",
			})
			return
		}
		switch k {
		case models.SettingRefreshInterval:
			if v == "" {
				v = "0"
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 86400 {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "首页自动刷新间隔必须为 0-86400 之间的整数（0 表示不刷新）",
				})
				return
			}
			v = strconv.Itoa(n)
		case models.SettingNmapPath, models.SettingMasscanPath:
			if strings.ContainsAny(v, "\t") {
				v = strings.ReplaceAll(v, "\t", " ")
			}
		}
		settings[k] = v
	}

	db := database.GetDB()
	if err := db.UpdateSettings(settings); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "保存失败: " + err.Error()})
		return
	}

	resp := map[string]interface{}{"success": true, "saved": len(settings)}
	if len(ignored) > 0 {
		resp["ignored"] = ignored
		resp["message"] = "已忽略未知配置项：" + strings.Join(ignored, "、")
	}
	json.NewEncoder(w).Encode(resp)
}

func (h *SettingsHandler) VerifyPath(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "message": "请提供路径"})
		return
	}

	// 尝试在系统 PATH 中查找
	_, err := exec.LookPath(path)
	if err == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": true, "message": "✓ 路径正确，工具已在系统 PATH 中"})
		return
	}

	// 检查文件是否存在且可执行
	info, statErr := os.Stat(path)
	if statErr != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "message": "✗ 文件不存在，请检查路径是否正确"})
		return
	}

	mode := info.Mode()
	if mode.IsRegular() && (mode&0111) != 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": true, "message": "✓ 路径正确，文件存在且可执行"})
	} else if mode.IsRegular() {
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "message": "✗ 文件存在但不可执行，请检查权限"})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "message": "✗ 指定的路径不是一个可执行文件"})
	}
}

func (h *SettingsHandler) PageSettings(w http.ResponseWriter, r *http.Request) {
	ServePage(w, r, "settings.html")
}
