package database

import (
	"NebulaCompass/models"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	mu sync.RWMutex
	db *sql.DB
}

var globalDB *DB
var globalOnce sync.Once

func GetDB() *DB {
	globalOnce.Do(func() {
		var err error
		globalDB, err = openDB()
		if err != nil {
			panic("Failed to open database: " + err.Error())
		}
	})
	return globalDB
}

func openDB() (*DB, error) {

	//dataDir := os.Getenv("PORTSCAN_DATA_DIR")
	//if dataDir == "" {
	//	dataDir = "./Data_folder"
	//}

	dataDir := "./Data_folder"

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "NebulaCompass.db")

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	d := &DB{db: db}
	if err := d.initSchema(); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return d, nil
}

func (db *DB) initSchema() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			salt TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			target TEXT NOT NULL,
			port_range TEXT DEFAULT '1-65535',
			status TEXT NOT NULL DEFAULT 'pending',
			current_phase TEXT NOT NULL DEFAULT 'idle',
			progress_pct REAL NOT NULL DEFAULT 0,
			total_hosts INTEGER NOT NULL DEFAULT 0,
			scanned_hosts INTEGER NOT NULL DEFAULT 0,
			total_ports INTEGER NOT NULL DEFAULT 0,
			scanned_ports INTEGER NOT NULL DEFAULT 0,
			elapsed_seconds INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT,
			error_message TEXT,
			alive_hosts TEXT,
			ping_output TEXT,
			port_scan_output TEXT,
			service_output TEXT,
			cmd_records TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS scan_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id INTEGER NOT NULL,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tcp',
			state TEXT NOT NULL DEFAULT 'open',
			service TEXT DEFAULT '',
			product TEXT DEFAULT '',
			version TEXT DEFAULT '',
			extra_info TEXT DEFAULT '',
			os_details TEXT DEFAULT '',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT UNIQUE NOT NULL,
			value TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_results_task ON scan_results(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_results_ip ON scan_results(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_results_service ON scan_results(service)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
	}
	for _, ddl := range tables {
		if _, err := db.db.Exec(ddl); err != nil {
			return fmt.Errorf("exec: %s: %w", ddl[:60], err)
		}
	}
	// 迁移：逐列补齐（兼容旧数据库，重复执行报错可忽略）
	migrations := []string{
		"ALTER TABLE tasks ADD COLUMN cmd_records TEXT",
		"ALTER TABLE tasks ADD COLUMN scan_mode TEXT DEFAULT 'full'",
		"ALTER TABLE tasks ADD COLUMN port_presets TEXT DEFAULT ''",
		"ALTER TABLE tasks ADD COLUMN resume_stage TEXT DEFAULT ''",
		"ALTER TABLE tasks ADD COLUMN service_done_hosts TEXT DEFAULT ''",
		"ALTER TABLE tasks ADD COLUMN eta_seconds INTEGER DEFAULT 0",
		"ALTER TABLE tasks ADD COLUMN eta_text TEXT DEFAULT ''",
		"ALTER TABLE tasks ADD COLUMN scan_percent REAL DEFAULT 0",
		"ALTER TABLE tasks ADD COLUMN rate_kpps REAL DEFAULT 0",
		"ALTER TABLE tasks ADD COLUMN scan_log TEXT DEFAULT ''",
	}
	for _, m := range migrations {
		db.db.Exec(m)
	}
	return db.initDefaults()
}

func (db *DB) initDefaults() error {
	var count int
	err := db.db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		for _, s := range models.GetDefaultSettings() {
			_, err := db.db.Exec("INSERT INTO settings (key, value) VALUES (?, ?)", s.Key, s.Value)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *DB) Close() error { return db.db.Close() }

// ========== User operations ==========

func (db *DB) GetUserByUsername(username string) *models.User {
	row := db.db.QueryRow("SELECT id, username, password_hash, salt, created_at FROM users WHERE username = ?", username)
	u := &models.User{}
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.CreatedAt); err != nil {
		return nil
	}
	return u
}

func (db *DB) GetUserByID(id int64) *models.User {
	row := db.db.QueryRow("SELECT id, username, password_hash, salt, created_at FROM users WHERE id = ?", id)
	u := &models.User{}
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.CreatedAt); err != nil {
		return nil
	}
	return u
}

func (db *DB) CreateUser(username, passwordHash, salt string) *models.User {
	result, err := db.db.Exec(
		"INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
		username, passwordHash, salt, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		log.Printf("CreateUser error: %v", err)
		return nil
	}
	id, _ := result.LastInsertId()
	return &models.User{ID: id, Username: username, PasswordHash: passwordHash, Salt: salt, CreatedAt: time.Now().Format(time.RFC3339)}
}

func (db *DB) UpdateUser(user *models.User) {
	db.db.Exec("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", user.PasswordHash, user.Salt, user.ID)
}

// ========== Session operations ==========
// 会话落库，服务重启后登录态仍然有效

func (db *DB) SaveSession(token string, userID int64, expiresAt time.Time) {
	if token == "" {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, err := db.db.Exec(
		"INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?) ON CONFLICT(token) DO UPDATE SET user_id = ?, expires_at = ?",
		token, userID, expiresAt.Unix(), userID, expiresAt.Unix()); err != nil {
		log.Printf("SaveSession error: %v", err)
	}
}

func (db *DB) LoadSession(token string) (int64, time.Time, bool) {
	if token == "" {
		return 0, time.Time{}, false
	}
	var userID, expires int64
	if err := db.db.QueryRow("SELECT user_id, expires_at FROM sessions WHERE token = ?", token).Scan(&userID, &expires); err != nil {
		return 0, time.Time{}, false
	}
	return userID, time.Unix(expires, 0), true
}

func (db *DB) DeleteSession(token string) {
	if token == "" {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, err := db.db.Exec("DELETE FROM sessions WHERE token = ?", token); err != nil {
		log.Printf("DeleteSession error: %v", err)
	}
}

// DeleteSessionsByUser 吊销用户全部会话，keepToken 非空时保留该会话
func (db *DB) DeleteSessionsByUser(userID int64, keepToken string) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	res, err := db.db.Exec("DELETE FROM sessions WHERE user_id = ? AND token <> ?", userID, keepToken)
	if err != nil {
		log.Printf("DeleteSessionsByUser error: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

func (db *DB) PurgeExpiredSessions(now time.Time) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, err := db.db.Exec("DELETE FROM sessions WHERE expires_at < ?", now.Unix()); err != nil {
		log.Printf("PurgeExpiredSessions error: %v", err)
	}
}

// ========== Task operations ==========

const taskCols = "(SELECT COUNT(*) FROM scan_results sr WHERE sr.task_id = tasks.id), id, name, target, COALESCE(scan_mode,'full'), port_range, COALESCE(port_presets,''), status, current_phase, progress_pct, total_hosts, scanned_hosts, total_ports, scanned_ports, elapsed_seconds, created_at, COALESCE(started_at,''), COALESCE(completed_at,''), COALESCE(error_message,''), COALESCE(alive_hosts,''), COALESCE(ping_output,''), COALESCE(port_scan_output,''), COALESCE(service_output,''), COALESCE(cmd_records,''), COALESCE(resume_stage,''), COALESCE(service_done_hosts,''), COALESCE(eta_seconds,0), COALESCE(eta_text,''), COALESCE(scan_percent,0), COALESCE(rate_kpps,0), COALESCE(scan_log,'')"

func scanTask(scanner interface{ Scan(...interface{}) error }) (*models.Task, error) {
	t := &models.Task{}
	err := scanner.Scan(&t.ResultCount, &t.ID, &t.Name, &t.Target, &t.ScanMode, &t.PortRange, &t.PortPresetsStr, &t.Status, &t.CurrentPhase, &t.ProgressPct,
		&t.TotalHosts, &t.ScannedHosts, &t.TotalPorts, &t.ScannedPorts, &t.ElapsedSeconds,
		&t.CreatedAt, &t.StartedAt, &t.CompletedAt, &t.ErrorMessage,
		&t.AliveHostsStr, &t.PingOutput, &t.PortScanOutput, &t.ServiceOutput, &t.CmdRecords,
		&t.ResumeStage, &t.ServiceDoneStr, &t.EtaSeconds, &t.EtaText, &t.ScanPercent, &t.RateKpps, &t.ScanLog)
	if err != nil {
		return nil, err
	}
	t.ParseAliveHosts()
	t.ParseServiceDone()
	t.ParsePortPresets()
	return t, nil
}

func (db *DB) CreateTaskWithMode(name, target, portRange, scanMode, portPresets string) *models.Task {
	now := time.Now().Format(time.RFC3339)
	result, err := db.db.Exec(
		"INSERT INTO tasks (name, target, scan_mode, port_range, port_presets, status, current_phase, progress_pct, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
		name, target, scanMode, portRange, portPresets, models.StatusPending, models.PhaseIdle, now,
	)
	if err != nil {
		log.Printf("CreateTask error: %v", err)
		return nil
	}
	id, _ := result.LastInsertId()
	task := &models.Task{ID: id, Name: name, Target: target, ScanMode: scanMode, PortRange: portRange,
		PortPresetsStr: portPresets, Status: models.StatusPending, CurrentPhase: models.PhaseIdle, ProgressPct: 0, CreatedAt: now}
	task.ParsePortPresets()
	return task
}

func (db *DB) GetTask(id int64) *models.Task {
	row := db.db.QueryRow("SELECT "+taskCols+" FROM tasks WHERE id = ?", id)
	t, err := scanTask(row)
	if err != nil {
		return nil
	}
	return t
}

func (db *DB) GetAllTasks() []*models.Task {
	rows, err := db.db.Query("SELECT " + taskCols + " FROM tasks ORDER BY id DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()
	list := make([]*models.Task, 0)
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			continue
		}
		list = append(list, t)
	}
	return list
}

func (db *DB) UpdateTask(task *models.Task) {
	task.SerializeAliveHosts()
	task.SerializeServiceDone()
	task.SerializePortPresets()
	_, err := db.db.Exec(`UPDATE tasks SET name=?, target=?, scan_mode=?, port_range=?, port_presets=?, status=?, current_phase=?,
		progress_pct=?, total_hosts=?, scanned_hosts=?, total_ports=?, scanned_ports=?,
		elapsed_seconds=?, started_at=?, completed_at=?, error_message=?, alive_hosts=?,
		ping_output=?, port_scan_output=?, service_output=?, cmd_records=?,
		resume_stage=?, service_done_hosts=?, eta_seconds=?, eta_text=?, scan_percent=?, rate_kpps=? WHERE id=?`,
		task.Name, task.Target, task.ScanMode, task.PortRange, task.PortPresetsStr, task.Status, task.CurrentPhase,
		task.ProgressPct, task.TotalHosts, task.ScannedHosts, task.TotalPorts, task.ScannedPorts,
		task.ElapsedSeconds, task.StartedAt, task.CompletedAt, task.ErrorMessage,
		task.AliveHostsStr, task.PingOutput, task.PortScanOutput, task.ServiceOutput, task.CmdRecords,
		task.ResumeStage, task.ServiceDoneStr, task.EtaSeconds, task.EtaText, task.ScanPercent, task.RateKpps, task.ID)
	if err != nil {
		log.Printf("UpdateTask error: %v", err)
	}
}

// UpdateElapsed 仅更新耗时，避免整行重写（scan_log 可能较大）
func (db *DB) UpdateElapsed(taskID int64, seconds int64) {
	db.db.Exec("UPDATE tasks SET elapsed_seconds = ? WHERE id = ?", seconds, taskID)
}

// AppendScanLog 追加上限受控的过程日志（暂停/取消后仍可导出）
func (db *DB) AppendScanLog(taskID int64, chunk string, maxBytes int) {
	if chunk == "" {
		return
	}
	if maxBytes <= 0 {
		maxBytes = 512 * 1024
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	_, err := db.db.Exec(
		`UPDATE tasks SET scan_log = substr(COALESCE(scan_log,'') || ?, -?) WHERE id = ?`,
		chunk, maxBytes, taskID)
	if err != nil {
		log.Printf("AppendScanLog error: %v", err)
	}
}

// CountResults 统计某任务的端口结果条数
func (db *DB) CountResults(taskID int64) int {
	var n int
	db.db.QueryRow("SELECT COUNT(*) FROM scan_results WHERE task_id = ?", taskID).Scan(&n)
	return n
}

// ResetTaskForRerun 清空扫描数据，保留任务基础信息，用于“重新扫描”
func (db *DB) ResetTaskForRerun(taskID int64) {
	db.db.Exec("DELETE FROM scan_results WHERE task_id = ?", taskID)
	db.db.Exec(`UPDATE tasks SET status=?, current_phase=?, progress_pct=0, total_hosts=0, scanned_hosts=0,
		total_ports=0, scanned_ports=0, elapsed_seconds=0, started_at='', completed_at='', error_message='',
		alive_hosts='', ping_output='', port_scan_output='', service_output='', cmd_records='',
		resume_stage='', service_done_hosts='', eta_seconds=0, eta_text='', scan_percent=0, rate_kpps=0,
		scan_log='' WHERE id = ?`,
		models.StatusPending, models.PhaseIdle, taskID)
}

func (db *DB) DeleteTask(id int64) {
	db.db.Exec("DELETE FROM scan_results WHERE task_id = ?", id)
	db.db.Exec("DELETE FROM tasks WHERE id = ?", id)
}

// MarkInterruptedTasks 服务重启后，把仍处于 running 的任务标记为已暂停（可续扫）
func (db *DB) MarkInterruptedTasks() int64 {
	res, err := db.db.Exec("UPDATE tasks SET status = ?, eta_seconds = 0, eta_text = '', rate_kpps = 0 WHERE status = ?",
		models.StatusPaused, models.StatusRunning)
	if err != nil {
		log.Printf("MarkInterruptedTasks error: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// ========== ScanResult operations ==========

// AddResults 批量写入结果；任何一步失败都会回滚并返回错误（不再静默丢数据）
func (db *DB) AddResults(results []*models.ScanResult) error {
	if len(results) == 0 {
		return nil
	}
	now := time.Now().Format(time.RFC3339)
	tx, err := db.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	stmt, err := tx.Prepare("INSERT INTO scan_results (task_id, ip, port, protocol, state, service, product, version, extra_info, os_details, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()
	for _, r := range results {
		r.CreatedAt = now
		if _, err := stmt.Exec(r.TaskID, r.IP, r.Port, r.Protocol, r.State,
			r.Service, r.Product, r.Version, r.ExtraInfo, r.OSDetails, r.CreatedAt); err != nil {
			tx.Rollback()
			return fmt.Errorf("insert result %s:%d: %w", r.IP, r.Port, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ReplaceHostResults 用新结果替换某主机在任务下的全部结果（避免续扫重复写入）
func (db *DB) ReplaceHostResults(taskID int64, ip string, results []*models.ScanResult) {
	tx, err := db.db.Begin()
	if err != nil {
		log.Printf("ReplaceHostResults begin error: %v", err)
		return
	}
	if _, err := tx.Exec("DELETE FROM scan_results WHERE task_id = ? AND ip = ?", taskID, ip); err != nil {
		log.Printf("ReplaceHostResults delete error: %v", err)
		tx.Rollback()
		return
	}
	now := time.Now().Format(time.RFC3339)
	stmt, err := tx.Prepare("INSERT INTO scan_results (task_id, ip, port, protocol, state, service, product, version, extra_info, os_details, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		log.Printf("ReplaceHostResults prepare error: %v", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()
	for _, r := range results {
		r.CreatedAt = now
		stmt.Exec(r.TaskID, r.IP, r.Port, r.Protocol, r.State,
			r.Service, r.Product, r.Version, r.ExtraInfo, r.OSDetails, r.CreatedAt)
	}
	tx.Commit()
}

func (db *DB) GetResultsByTask(taskID int64) []*models.ScanResult {
	rows, err := db.db.Query(
		"SELECT id, task_id, ip, port, protocol, state, COALESCE(service,''), COALESCE(product,''), COALESCE(version,''), COALESCE(extra_info,''), COALESCE(os_details,''), created_at FROM scan_results WHERE task_id = ? ORDER BY ip, port",
		taskID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	list := make([]*models.ScanResult, 0)
	for rows.Next() {
		r := &models.ScanResult{}
		if err := rows.Scan(&r.ID, &r.TaskID, &r.IP, &r.Port, &r.Protocol, &r.State,
			&r.Service, &r.Product, &r.Version, &r.ExtraInfo, &r.OSDetails, &r.CreatedAt); err == nil {
			list = append(list, r)
		}
	}
	return list
}

func (db *DB) GetResultsSummary(taskID int64) map[string]int {
	summary := map[string]int{"total": 0, "open": 0, "filtered": 0, "closed": 0, "services": 0}
	rows, err := db.db.Query("SELECT state, COUNT(*) FROM scan_results WHERE task_id = ? GROUP BY state", taskID)
	if err != nil {
		return summary
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			continue
		}
		summary["total"] += n
		switch state {
		case "open":
			summary["open"] += n
		case "open|filtered":
			summary["filtered"] += n
		case "closed":
			summary["closed"] += n
		default:
			summary["open"] += n // 兼容历史数据里非标准 state
		}
	}
	// 服务识别数：单独的聚合查询，避免把全部行拉到内存
	var services int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM scan_results WHERE task_id = ? AND COALESCE(service,'') <> ''", taskID).Scan(&services); err == nil {
		summary["services"] = services
	}
	return summary
}

// ========== Setting operations ==========

func (db *DB) GetSetting(key string) string {
	var value string
	db.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	return value
}

func (db *DB) GetAllSettings() []*models.Setting {
	rows, err := db.db.Query("SELECT id, key, value FROM settings ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()
	list := make([]*models.Setting, 0)
	for rows.Next() {
		s := &models.Setting{}
		if rows.Scan(&s.ID, &s.Key, &s.Value) == nil {
			list = append(list, s)
		}
	}
	return list
}

// UpdateSettings 批量写设置；失败时回滚并返回错误
func (db *DB) UpdateSettings(settings map[string]string) error {
	if len(settings) == 0 {
		return nil
	}
	tx, err := db.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	stmt, err := tx.Prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare upsert: %w", err)
	}
	defer stmt.Close()
	for k, v := range settings {
		if _, err := stmt.Exec(k, v, v); err != nil {
			tx.Rollback()
			return fmt.Errorf("upsert setting %s: %w", k, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ========== Summary ==========

type HostPortSummary struct {
	IP    string `json:"ip"`
	Ports []int  `json:"ports"`
}

func (db *DB) GetHostPortSummary(taskID int64) []HostPortSummary {
	results := db.GetResultsByTask(taskID)
	hostMap := make(map[string]map[int]bool)
	for _, r := range results {
		// open 与 open|filtered 都算作开放端口（口径与统计卡片一致）
		if r.State != "open" && r.State != "open|filtered" {
			continue
		}
		if hostMap[r.IP] == nil {
			hostMap[r.IP] = make(map[int]bool)
		}
		hostMap[r.IP][r.Port] = true
	}
	hosts := make([]string, 0, len(hostMap))
	for ip := range hostMap {
		hosts = append(hosts, ip)
	}
	sort.Strings(hosts)
	summaries := make([]HostPortSummary, 0, len(hosts))
	for _, ip := range hosts {
		ports := make([]int, 0, len(hostMap[ip]))
		for p := range hostMap[ip] {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		summaries = append(summaries, HostPortSummary{IP: ip, Ports: ports})
	}
	return summaries
}

// escapeLike 转义 LIKE 通配符，避免用户输入的 % / _ 变成通配符
func escapeLike(q string) string {
	q = strings.ReplaceAll(q, "\\", "\\\\")
	q = strings.ReplaceAll(q, "%", "\\%")
	q = strings.ReplaceAll(q, "_", "\\_")
	return q
}

func (db *DB) SearchOpenPorts(taskID int64, query string) []*models.ScanResult {
	if query == "" {
		return db.GetResultsByTask(taskID)
	}
	q := fmt.Sprintf("%%%s%%", escapeLike(strings.TrimSpace(query)))
	// 与列表保持一致：不按 state 过滤（否则搜索结果会漏掉非 open 的行）
	rows, err := db.db.Query(
		`SELECT id, task_id, ip, port, protocol, state, COALESCE(service,''), COALESCE(product,''), COALESCE(version,''), COALESCE(extra_info,''), COALESCE(os_details,''), created_at FROM scan_results 
		WHERE task_id = ? AND (ip LIKE ? ESCAPE '\' OR protocol LIKE ? ESCAPE '\' OR service LIKE ? ESCAPE '\' OR product LIKE ? ESCAPE '\' OR version LIKE ? ESCAPE '\' OR os_details LIKE ? ESCAPE '\')
		ORDER BY ip, port`,
		taskID, q, q, q, q, q, q)
	if err != nil {
		return nil
	}
	defer rows.Close()
	list := make([]*models.ScanResult, 0)
	for rows.Next() {
		r := &models.ScanResult{}
		if err := rows.Scan(&r.ID, &r.TaskID, &r.IP, &r.Port, &r.Protocol, &r.State,
			&r.Service, &r.Product, &r.Version, &r.ExtraInfo, &r.OSDetails, &r.CreatedAt); err == nil {
			list = append(list, r)
		}
	}
	return list
}
