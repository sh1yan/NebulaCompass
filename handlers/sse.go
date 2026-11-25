package handlers

import (
	"NebulaCompass/database"
	"NebulaCompass/scanner"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type SSEHandler struct{}

func NewSSEHandler() *SSEHandler { return &SSEHandler{} }

func (h *SSEHandler) Subscribe(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("SSE handler panic recovered: %v", rec)
		}
	}()

	idStr := strings.TrimPrefix(r.URL.Path, "/api/sse/")
	// Support both /api/sse/{id} and /api/sse/output/{id}
	if strings.HasPrefix(idStr, "output/") {
		idStr = strings.TrimPrefix(idStr, "output/")
	}
	taskID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid task ID", 400)
		return
	}
	// 任务不存在时立即返回 404，避免前端 EventSource 永久挂着等不到任何事件
	if database.GetDB().GetTask(taskID) == nil {
		http.Error(w, "Task not found", 404)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	bus := scanner.GetEventBus()
	ch := bus.Subscribe(taskID)
	defer bus.Unsubscribe(taskID, ch)

	fmt.Fprintf(w, "event: connected\ndata: {\"task_id\":%d}\n\n", taskID)
	flusher.Flush()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.EventType, data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
