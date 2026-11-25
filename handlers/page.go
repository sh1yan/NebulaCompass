package handlers

import (
	"io/fs"
	"net/http"
	"path"
	"path/filepath"
)

// pageFS 内嵌的模板文件系统（由 main 在启动时注入）。
// 注入后二进制无需依赖工作目录下的 templates 目录即可提供页面。
var pageFS fs.FS

// SetPageFS 注入内嵌文件系统
func SetPageFS(fsys fs.FS) {
	pageFS = fsys
}

// noStorePage 禁止浏览器缓存 HTML 页面。
// 内嵌 FS 的文件没有 ModTime/ETag，浏览器对“无缓存头”的导航响应可能走
// bfcache / 内存缓存，导致从任务列表点进详情页时拿到的是上一次的旧 DOM
// （表现为进度一直停在“等待开始”），这里显式声明 no-store 让每次导航都取新页面。
func noStorePage(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
}

// ServePage 提供 templates 目录下的页面：
// 优先使用内嵌 FS（二进制可独立运行），仅在未注入或文件缺失时回退到磁盘（便于改模板调试）。
func ServePage(w http.ResponseWriter, r *http.Request, name string) {
	noStorePage(w)
	rel := path.Join("templates", name)
	if pageFS != nil {
		if _, err := fs.Stat(pageFS, rel); err == nil {
			http.ServeFileFS(w, r, pageFS, rel)
			return
		}
	}
	http.ServeFile(w, r, filepath.Join("templates", name))
}
