package handlers

import (
	"encoding/json"
	"net/http"

	"NebulaCompass/models"
)

// PortHandler 端口预置列表接口
type PortHandler struct{}

func NewPortHandler() *PortHandler { return &PortHandler{} }

// GetPresets 返回内置预置端口列表
func (h *PortHandler) GetPresets(w http.ResponseWriter, r *http.Request) {
	presets := models.GetPortPresets()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"presets": presets,
	})
}
