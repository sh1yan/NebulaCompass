package main

import (
	"NebulaCompass/database"
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
	"time"
)

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static/*
var staticFiles embed.FS

func main() {
	checkTool("nmap")
	checkTool("masscan")
	warnIfNotRoot()

	middleware.EnsureDefaultAdmin()

	// 服务重启后，把上次残留的 running 任务置为已暂停，避免出现“永远在跑”的僵尸任务
	if n := database.GetDB().MarkInterruptedTasks(); n > 0 {
		log.Printf("已将 %d 个中断的扫描任务标记为已暂停（可在界面继续扫描）", n)
	}

	// 页面模板也使用内嵌文件系统，确保二进制拷到任意目录都能跑
	handlers.SetPageFS(templateFiles)

	authHandler := handlers.NewAuthHandler()
	taskHandler := handlers.NewTaskHandler()
	resultHandler := handlers.NewResultHandler()
	settingsHandler := handlers.NewSettingsHandler()
	docsHandler := handlers.NewDocsHandler()
	dnsHandler := handlers.NewDNSHandler()
	sseHandler := handlers.NewSSEHandler()

	mux := http.NewServeMux()

	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /static/", noStoreStatic(http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))))

	// Auth
	mux.HandleFunc("GET /login", authHandler.Login)
	mux.HandleFunc("POST /api/login", authHandler.Login)
	mux.HandleFunc("POST /api/logout", authHandler.Logout)
	mux.HandleFunc("POST /api/change-password", authHandler.ChangePassword)
	mux.HandleFunc("GET /{$}", rootRedirect)

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
	mux.HandleFunc("POST /api/tasks/{id}/pause", taskHandler.Pause)
	mux.HandleFunc("POST /api/tasks/{id}/resume", taskHandler.Start)
	mux.HandleFunc("POST /api/tasks/{id}/cancel", taskHandler.Cancel)
	mux.HandleFunc("POST /api/tasks/{id}/delete", taskHandler.Delete)

	// 端口预置列表
	portHandler := handlers.NewPortHandler()
	mux.HandleFunc("GET /api/port-presets", portHandler.GetPresets)

	// Results API
	mux.HandleFunc("GET /api/results/{id}", resultHandler.List)
	mux.HandleFunc("GET /api/results/summary/{id}", resultHandler.Summary)
	mux.HandleFunc("GET /api/results/export/{id}", resultHandler.ExportXLSX)
	mux.HandleFunc("GET /api/results/archive/{id}", resultHandler.ExportArchive)
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

	srv := &http.Server{
		Addr:              addr,
		Handler:           wrapped,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

// warnIfNotRoot masscan 需要原始套接字权限，非 root 下端口扫描必然失败，启动时提前告知
func warnIfNotRoot() {
	if os.Geteuid() == 0 {
		return
	}
	log.Printf("警告: 当前以非 root 运行，masscan 端口扫描（全套扫描 / 端口扫描模式）会失败")
	log.Printf("      如需端口扫描请用 sudo 运行本程序，或改用「Nmap 端口扫描」模式（自动退化为 -sT）")
}

// noStoreStatic 让前端静态资源始终重新校验：
// 内嵌 FS 没有 Last-Modified/ETag，浏览器可能沿用旧缓存，
// 旧 app.js 配新模板就会出现 "Cannot read properties of null (reading 'style')" 这类脚本错误。
func noStoreStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		h.ServeHTTP(w, r)
	})
}

func outputPage(w http.ResponseWriter, r *http.Request) {
	handlers.ServePage(w, r, "output.html")
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
