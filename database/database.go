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
		`CREATE INDEX IF NOT EXISTS idx_results_task ON scan_results(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_results_ip ON scan_results(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_results_service ON scan_results(service)`,
	}
	for _, ddl := range tables {
		if _, err := db.db.Exec(ddl); err != nil {
			return fmt.Errorf("exec: %s: %w", ddl[:60], err)
		}
	}
	// 迁移：添加 cmd_records 列（兼容旧数据库）
	db.db.Exec("ALTER TABLE tasks ADD COLUMN cmd_records TEXT")
	db.db.Exec("ALTER TABLE tasks ADD COLUMN scan_mode TEXT DEFAULT 'full'")
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

// ========== Task operations ==========

const taskCols = "id, name, target, COALESCE(scan_mode,'full'), port_range, status, current_phase, progress_pct, total_hosts, scanned_hosts, total_ports, scanned_ports, elapsed_seconds, created_at, COALESCE(started_at,''), COALESCE(completed_at,''), COALESCE(error_message,''), COALESCE(alive_hosts,''), COALESCE(ping_output,''), COALESCE(port_scan_output,''), COALESCE(service_output,''), COALESCE(cmd_records,'')"

func scanTask(scanner interface{ Scan(...interface{}) error }) (*models.Task, error) {
	t := &models.Task{}
	err := scanner.Scan(&t.ID, &t.Name, &t.Target, &t.ScanMode, &t.PortRange, &t.Status, &t.CurrentPhase, &t.ProgressPct,
		&t.TotalHosts, &t.ScannedHosts, &t.TotalPorts, &t.ScannedPorts, &t.ElapsedSeconds,
		&t.CreatedAt, &t.StartedAt, &t.CompletedAt, &t.ErrorMessage,
		&t.AliveHostsStr, &t.PingOutput, &t.PortScanOutput, &t.ServiceOutput, &t.CmdRecords)
	if err != nil {
		return nil, err
	}
	t.ParseAliveHosts()
	return t, nil
}

func (db *DB) CreateTaskWithMode(name, target, portRange, scanMode string) *models.Task {
	now := time.Now().Format(time.RFC3339)
	result, err := db.db.Exec(
		"INSERT INTO tasks (name, target, scan_mode, port_range, status, current_phase, progress_pct, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
		name, target, scanMode, portRange, models.StatusPending, models.PhaseIdle, now,
	)
	if err != nil {
		log.Printf("CreateTask error: %v", err)
		return nil
	}
	id, _ := result.LastInsertId()
	return &models.Task{ID: id, Name: name, Target: target, ScanMode: scanMode, PortRange: portRange, Status: models.StatusPending, CurrentPhase: models.PhaseIdle, ProgressPct: 0, CreatedAt: now}
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
	_, err := db.db.Exec(`UPDATE tasks SET name=?, target=?, scan_mode=?, port_range=?, status=?, current_phase=?,
		progress_pct=?, total_hosts=?, scanned_hosts=?, total_ports=?, scanned_ports=?,
		elapsed_seconds=?, started_at=?, completed_at=?, error_message=?, alive_hosts=?,
		ping_output=?, port_scan_output=?, service_output=?, cmd_records=? WHERE id=?`,
		task.Name, task.Target, task.ScanMode, task.PortRange, task.Status, task.CurrentPhase,
		task.ProgressPct, task.TotalHosts, task.ScannedHosts, task.TotalPorts, task.ScannedPorts,
		task.ElapsedSeconds, task.StartedAt, task.CompletedAt, task.ErrorMessage,
		task.AliveHostsStr, task.PingOutput, task.PortScanOutput, task.ServiceOutput, task.CmdRecords, task.ID)
	if err != nil {
		log.Printf("UpdateTask error: %v", err)
	}
}

func (db *DB) DeleteTask(id int64) {
	db.db.Exec("DELETE FROM scan_results WHERE task_id = ?", id)
	db.db.Exec("DELETE FROM tasks WHERE id = ?", id)
}

// ========== ScanResult operations ==========

func (db *DB) AddResults(results []*models.ScanResult) {
	now := time.Now().Format(time.RFC3339)
	tx, _ := db.db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO scan_results (task_id, ip, port, protocol, state, service, product, version, extra_info, os_details, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
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
	rows, err := db.db.Query("SELECT state, service FROM scan_results WHERE task_id = ?", taskID)
	if err != nil {
		return summary
	}
	defer rows.Close()
	for rows.Next() {
		var state, service string
		rows.Scan(&state, &service)
		summary["total"]++
		switch state {
		case "open":
			summary["open"]++
		case "filtered":
			summary["filtered"]++
		case "closed":
			summary["closed"]++
		}
		if service != "" {
			summary["services"]++
		}
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

func (db *DB) UpdateSettings(settings map[string]string) {
	tx, _ := db.db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?")
	defer stmt.Close()
	for k, v := range settings {
		stmt.Exec(k, v, v)
	}
	tx.Commit()
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
		if r.State != "open" {
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

func (db *DB) SearchOpenPorts(taskID int64, query string) []*models.ScanResult {
	if query == "" {
		return db.GetResultsByTask(taskID)
	}
	q := fmt.Sprintf("%%%s%%", strings.ReplaceAll(query, "'", "''"))
	rows, err := db.db.Query(
		`SELECT id, task_id, ip, port, protocol, state, COALESCE(service,''), COALESCE(product,''), COALESCE(version,''), COALESCE(extra_info,''), COALESCE(os_details,''), created_at FROM scan_results 
		WHERE task_id = ? AND state = 'open' AND (ip LIKE ? OR service LIKE ? OR product LIKE ? OR version LIKE ?)
		ORDER BY ip, port`,
		taskID, q, q, q, q)
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
