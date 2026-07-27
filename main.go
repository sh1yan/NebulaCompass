package main

import (
	"NebulaCompass/handlers"
	"NebulaCompass/middleware"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
)

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static/*
var staticFiles embed.FS

func main() {
	checkTool("nmap")
	checkTool("masscan")

	middleware.EnsureDefaultAdmin()

	authHandler := handlers.NewAuthHandler()
	taskHandler := handlers.NewTaskHandler()
	resultHandler := handlers.NewResultHandler()
	settingsHandler := handlers.NewSettingsHandler()
	docsHandler := handlers.NewDocsHandler()
	dnsHandler := handlers.NewDNSHandler()
	sseHandler := handlers.NewSSEHandler()

	mux := http.NewServeMux()

	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Auth
	mux.HandleFunc("GET /login", authHandler.Login)
	mux.HandleFunc("POST /api/login", authHandler.Login)
	mux.HandleFunc("POST /api/logout", authHandler.Logout)
	mux.HandleFunc("POST /api/change-password", authHandler.ChangePassword)
	mux.HandleFunc("GET /", rootRedirect)

	// Pages
	mux.HandleFunc("GET /tasks", taskHandler.PageList)
	mux.HandleFunc("GET /tasks/{id}", taskHandler.PageDetail)
	mux.HandleFunc("GET /results/{id}", resultHandler.PageResults)
	mux.HandleFunc("GET /output/{id}", outputPage)
	mux.HandleFunc("GET /settings", settingsHandler.PageSettings)
	mux.HandleFunc("GET /docs", docsHandler.PageDocs)
	mux.HandleFunc("GET /dns", dnsHandler.PageDNS)

	// Task API
	mux.HandleFunc("GET /api/tasks", taskHandler.List)
	mux.HandleFunc("POST /api/tasks", taskHandler.Create)
	mux.HandleFunc("GET /api/tasks/{id}", taskHandler.Get)
	mux.HandleFunc("POST /api/tasks/{id}/start", taskHandler.Start)
	mux.HandleFunc("POST /api/tasks/{id}/cancel", taskHandler.Cancel)
	mux.HandleFunc("POST /api/tasks/{id}/delete", taskHandler.Delete)

	// Results API
	mux.HandleFunc("GET /api/results/{id}", resultHandler.List)
	mux.HandleFunc("GET /api/results/summary/{id}", resultHandler.Summary)
	mux.HandleFunc("GET /api/results/export/{id}", resultHandler.ExportXLSX)
	mux.HandleFunc("GET /api/results/services/{id}", resultHandler.GetServiceSummary)
	mux.HandleFunc("GET /api/results/os/{id}", resultHandler.GetOSSummary)

	// Settings API
	mux.HandleFunc("GET /api/settings", settingsHandler.GetSettings)
	mux.HandleFunc("POST /api/settings", settingsHandler.SaveSettings)
	mux.HandleFunc("GET /api/settings/verify", settingsHandler.VerifyPath)

	// DNS API
	mux.HandleFunc("POST /api/dns/resolve", dnsHandler.Resolve)
	mux.HandleFunc("POST /api/dns/export", dnsHandler.Export)

	// SSE
	mux.HandleFunc("GET /api/sse/{id}", sseHandler.Subscribe)

	wrapped := middleware.AuthMiddleware(mux)

	addr := ":8080"
	// 手动解析 -p 参数
	var port = 8080
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "-p" && i+1 < len(os.Args) {
			if p, err := strconv.Atoi(os.Args[i+1]); err == nil {
				port = p
			}
			break
		}
	}
	addr = fmt.Sprintf(":%d", port)

	log.Printf("=== 星云罗盘 - 资产测绘平台 ===")
	log.Printf("启动服务: http://localhost%s", addr)
	log.Printf("默认账号: admin / admin123")
	log.Printf("数据存放目录: ./Data_folder/")
	log.Printf("按 Ctrl+C 停止服务")

	if err := http.ListenAndServe(addr, wrapped); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

func outputPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/output.html")
}

func rootRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/tasks", http.StatusFound)
}

func checkTool(name string) {
	if _, err := exec.LookPath(name); err != nil {
		log.Printf("警告: %s 未在 PATH 中找到，请在设置中指定路径", name)
	} else {
		log.Printf("检测到 %s", name)
	}
}
