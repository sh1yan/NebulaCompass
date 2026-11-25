// ========== Auth ==========
async function handleLogout() {
  await fetch('/api/logout', { method: 'POST' });
  if (detailEventSource) { detailEventSource.close(); detailEventSource = null; }
  if (outputEventSource) { outputEventSource.close(); outputEventSource = null; }
  document.cookie = 'session_token=; path=/; max-age=-1';
  window.location.href = '/login';
}

function showModal(id) {
  var node = document.getElementById(id);
  if (node) node.style.display = 'flex';
}
function closeModal(id) {
  var node = document.getElementById(id);
  if (node) node.style.display = 'none';
}
function showChangePwd() { showModal('changePwdModal'); }

async function handleChangePwd(e) {
  e.preventDefault();
  const oldPwd = document.getElementById('oldPassword').value;
  const newPwd = document.getElementById('newPassword').value;
  const confirmPwd = document.getElementById('confirmPassword').value;
  const errEl = document.getElementById('changePwdError') || document.querySelector('#changePwdModal .form-error');
  if (newPwd !== confirmPwd) {
    errEl.textContent = '两次输入的密码不一致';
    errEl.style.display = 'block';
    return false;
  }
  const resp = await fetch('/api/change-password', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ old_password: oldPwd, new_password: newPwd })
  });
  const data = await resp.json();
  if (data.success) {
    alert('密码修改成功！');
    closeModal('changePwdModal');
  } else {
    errEl.textContent = data.message || '修改失败';
    errEl.style.display = 'block';
  }
  return false;
}

// API请求封装：401时自动跳转登录页
async function apiFetch(url, options) {
  var resp = await fetch(url, options);
  if (resp.status === 401) {
    window.location.href = "/login";
    throw new Error("登录已过期");
  }
  return resp;
}

// ========== Tasks Page ==========
var tasksPollTimer = null;
var allTasks = [];
var taskPage = 1;
var TASK_PAGE_SIZE = 20;

async function loadTasks() {
  const listEl = document.getElementById('taskList');
  if (!listEl) return;
  try {
    const resp = await apiFetch('/api/tasks');
    allTasks = (await resp.json()) || [];
    renderTaskPage();

    // 有运行中的任务时自动刷新（便于实时查看 masscan 预估剩余时间）
    if (tasksPollTimer) { clearTimeout(tasksPollTimer); tasksPollTimer = null; }
    if (allTasks.some(t => t.status === 'running')) {
      tasksPollTimer = setTimeout(function() {
        if (window.location.pathname === '/tasks' || window.location.pathname === '/tasks/') loadTasks();
      }, 3000);
    }
  } catch (err) {
    listEl.innerHTML = `<div class="error-state">加载失败: ${escapeHtml(err.message)}</div>`;
  }
}

function filteredTasks() {
  var input = document.getElementById('taskSearchInput');
  var q = input ? String(input.value || '').trim().toLowerCase() : '';
  if (!q) return allTasks;
  return allTasks.filter(function(t) {
    return (t.name || '').toLowerCase().indexOf(q) >= 0
      || (t.target || '').toLowerCase().indexOf(q) >= 0
      || (t.status || '').toLowerCase().indexOf(q) >= 0
      || statusLabel(t.status).indexOf(q) >= 0;
  });
}

// 任务列表分页渲染（任务多时不再一次性堆满页面）
function renderTaskPage() {
  const listEl = document.getElementById('taskList');
  if (!listEl) return;
  var list = filteredTasks();
  syncTaskSearchUI(list ? list.length : 0);
  if (!list || list.length === 0) {
    listEl.innerHTML = (allTasks.length === 0)
      ? '<div class="empty-state"><p>暂无扫描任务，点击右上角"新建任务"开始</p></div>'
      : '<div class="empty-state"><p>没有匹配的任务</p></div>';
    var pagerEmpty = document.getElementById('taskPager');
    if (pagerEmpty) pagerEmpty.style.display = 'none';
    return;
  }
  var totalPages = Math.max(1, Math.ceil(list.length / TASK_PAGE_SIZE));
  if (taskPage > totalPages) taskPage = totalPages;
  if (taskPage < 1) taskPage = 1;
  var start = (taskPage - 1) * TASK_PAGE_SIZE;
  var pageData = list.slice(start, start + TASK_PAGE_SIZE);
  listEl.innerHTML = pageData.map(t => renderTaskCard(t)).join('');

  var pager = document.getElementById('taskPager');
  if (pager) {
    pager.style.display = 'flex';
    var infoEl = document.getElementById('taskPagerInfo');
    if (infoEl) infoEl.textContent = '共 ' + list.length + ' 个任务，第 ' + (start + 1) + '-' + (start + pageData.length) + ' 个';
    var indEl = document.getElementById('taskPageIndicator');
    if (indEl) indEl.textContent = '第 ' + taskPage + '/' + totalPages + ' 页';
    var prevBtn = document.getElementById('taskPrevBtn');
    var nextBtn = document.getElementById('taskNextBtn');
    if (prevBtn) prevBtn.disabled = taskPage <= 1;
    if (nextBtn) nextBtn.disabled = taskPage >= totalPages;
  }
}

function syncTaskSearchUI(matched) {
  var input = document.getElementById('taskSearchInput');
  var field = document.getElementById('taskSearchField');
  var q = input ? String(input.value || '').trim() : '';
  if (field) field.classList.toggle('has-value', !!q);
  var countEl = document.getElementById('taskSearchCount');
  if (!countEl) return;
  if (!allTasks.length) { countEl.textContent = ''; return; }
  if (q) countEl.innerHTML = '匹配 <b>' + matched + '</b> / ' + allTasks.length + ' 个任务';
  else countEl.innerHTML = '共 <b>' + allTasks.length + '</b> 个任务';
}

function taskSearchChanged() {
  taskPage = 1;
  renderTaskPage();
}

function handleTaskSearchKey(e) {
  if (e.key === 'Escape') { clearTaskSearch(); return; }
  if (e.key === 'Enter') e.preventDefault();
}

function clearTaskSearch() {
  var input = document.getElementById('taskSearchInput');
  if (!input) return;
  input.value = '';
  taskPage = 1;
  renderTaskPage();
  input.focus();
}

function taskPrevPage() { if (taskPage > 1) { taskPage--; renderTaskPage(); } }
function taskNextPage() {
  var totalPages = Math.max(1, Math.ceil(filteredTasks().length / TASK_PAGE_SIZE));
  if (taskPage < totalPages) { taskPage++; renderTaskPage(); }
}

function hasTaskData(t) {
  return (t.result_count || 0) > 0 || (t.total_hosts || 0) > 0 || (t.total_ports || 0) > 0;
}

function renderTaskEta(t) {
  if (t.status !== 'running') return '';
  if (t.current_phase !== 'port_scan' && t.current_phase !== 'nmap_scan') return '';
  if (!t.eta_seconds && !t.scan_percent) return '';
  var parts = [];
  if (t.eta_seconds > 0) parts.push('预计剩余 ' + formatTimer(t.eta_seconds));
  if (t.scan_percent > 0) parts.push(phaseLabel(t.current_phase) + ' ' + Number(t.scan_percent).toFixed(1) + '%');
  if (t.rate_kpps > 0) parts.push(Number(t.rate_kpps).toFixed(1) + ' kpps');
  if (!parts.length) return '';
  return `<span class="meta-item eta-meta">&#9203; ${parts.join(' · ')}</span>`;
}

// 列表卡片上的端口说明：服务识别不吃端口范围，历史任务里残留的 1-65535 也不应展示
function renderTaskPortInfo(t) {
  if (t.scan_mode === 'alive_only') return '';
  if (t.scan_mode === 'service_only') return ' · 端口: 按目标中的 IP:端口';
  if (!t.port_range) return '';
  return ' · 端口: ' + escapeHtml(truncateText(t.port_range, 60));
}

function renderTaskCard(t) {
  var data = hasTaskData(t);
  var actions = [];
  if (t.status === 'pending') {
    actions.push(`<button class="btn btn-xs btn-solid btn-solid-primary" onclick="location.href='/tasks/${t.id}'">开始</button>`);
  }
  if (t.status === 'running') {
    actions.push(`<button class="btn btn-xs btn-solid btn-solid-warning" onclick="pauseTaskById(${t.id})">暂停</button>`);
    actions.push(`<button class="btn btn-xs btn-solid btn-solid-danger" onclick="cancelTaskById(${t.id})">取消</button>`);
  }
  if (t.status === 'paused') {
    actions.push(`<button class="btn btn-xs btn-solid btn-solid-primary" onclick="resumeTaskById(${t.id})">继续</button>`);
    actions.push(`<button class="btn btn-xs btn-solid btn-solid-danger" onclick="cancelTaskById(${t.id})">取消</button>`);
  }
  if (t.status === 'failed' || t.status === 'cancelled' || t.status === 'completed') {
    actions.push(`<button class="btn btn-xs btn-solid btn-solid-primary" title="清空结果并重新扫描（旧结果自动存档）" onclick="rescanTaskById(${t.id})">重新扫描</button>`);
  }
  if (data) {
    actions.push(`<button class="btn btn-xs btn-soft btn-soft-success" onclick="location.href='/results/${t.id}'">结果</button>`);
  }
  if (data) {
    actions.push(`<button class="btn btn-xs btn-soft btn-soft-cyan" title="导出 XLSX" onclick="exportTaskXlsx(${t.id})">导出</button>`);
    actions.push(`<button class="btn btn-xs btn-soft btn-soft-cyan" title="导出完整过程存档 ZIP" onclick="exportTaskArchive(${t.id})">存档</button>`);
  }
  if (t.status === 'running' || t.status === 'completed' || t.status === 'failed' || t.status === 'paused' || t.status === 'cancelled') {
    actions.push(`<button class="btn btn-xs btn-soft btn-soft-violet" onclick="location.href='/output/${t.id}'">输出</button>`);
  }
  actions.push(`<button class="btn btn-xs btn-soft btn-soft-danger" onclick="deleteTask(${t.id})" ${t.status === 'running' ? 'disabled' : ''}>删除</button>`);

  var progressLabel = (t.status === 'running' && Number(t.progress_pct) <= 0)
    ? '<span class="meta-item">进度: 扫描中…</span>'
    : `<span class="meta-item">进度: ${Math.round(t.progress_pct)}%</span>`;

  return `
      <div class="task-card">
        <div class="task-main">
          <div class="task-info">
            <div class="task-name"><a href="/tasks/${t.id}" title="${escapeHtml(t.name)}">${escapeHtml(t.name)}</a></div>
            <div class="${t.target && t.target.includes(String.fromCharCode(10)) ? 'task-target-multi' : 'task-target'}">${escapeHtml(t.target)}</div>
            <div class="task-target" style="font-family:var(--font);font-size:11px;margin-top:4px">模式: ${modeLabel(t.scan_mode)}${renderTaskPortInfo(t)}</div>
          </div>
          <div class="task-meta-row">
            <span class="badge badge-${t.status}">${statusLabel(t.status)}</span>
            <span class="meta-item">阶段: ${escapeHtml(currentPhaseText(t))}</span>
            ${progressLabel}
            <span class="meta-item">耗时: ${formatElapsed(t.elapsed_seconds)}</span>
            ${t.total_hosts > 0 ? `<span class="meta-item">主机: ${t.total_hosts}</span>` : ''}
            ${t.result_count > 0 ? `<span class="meta-item">端口: ${t.result_count}</span>` : (t.total_ports > 0 ? `<span class="meta-item">端口: ${t.total_ports}</span>` : '')}
            ${renderTaskEta(t)}
          </div>
        </div>
        <div class="task-actions">
          ${actions.join('')}
        </div>
      </div>
    `;
}

// ========== Create Task ==========
function refreshTasks() { loadTasks(); showToast('已刷新任务列表', 'success'); }

function showCreateTask() {
  showModal('createTaskModal');
  if (portPresets.length === 0) loadPortPresets();
  // 重新打开弹窗时按当前选中的模式重算一次表单显隐（上一次可能停在「服务识别」）
  var checked = document.querySelector('.scan-mode-option input[name="scan_mode"]:checked');
  var opt = checked ? checked.closest('.scan-mode-option') : document.querySelector('.scan-mode-option[data-mode="full"]');
  if (opt) selectScanMode(opt);
  else updatePortSpecPreview();
  updateServiceTargetWarn();
}

// ===== 服务识别模式：目标必须是 IP:端口 =====
function splitTargetTokens(text) {
  return String(text || '').split(/[\s,;]+/)
    .map(function(s) { return s.trim(); })
    .filter(function(s) { return s && s.charAt(0) !== '#'; });
}

// 返回缺少合法端口的目标条目
function serviceTargetIssues(text) {
  var bad = [];
  splitTargetTokens(text).forEach(function(tok) {
    if (tok.indexOf('/') >= 0) { bad.push(tok); return; }
    var m = tok.match(/:(\d{1,5})$/);
    if (!m) { bad.push(tok); return; }
    var p = parseInt(m[1], 10);
    if (!(p >= 1 && p <= 65535)) bad.push(tok);
  });
  return bad;
}

function onTaskTargetInput() {
  updateServiceTargetWarn();
}

function updateServiceTargetWarn() {
  var warnEl = document.getElementById('serviceTargetWarn');
  if (!warnEl) return;
  var modeEl = document.querySelector('input[name="scan_mode"]:checked');
  var mode = modeEl ? modeEl.value : 'full';
  if (mode !== 'service_only') {
    warnEl.style.display = 'none';
    warnEl.textContent = '';
    return;
  }
  var ta = document.getElementById('taskTarget');
  var val = ta ? ta.value : '';
  if (!String(val).trim()) { warnEl.style.display = 'none'; warnEl.textContent = ''; return; }
  var issues = serviceTargetIssues(val);
  if (!issues.length) { warnEl.style.display = 'none'; warnEl.textContent = ''; return; }
  var head = issues.slice(0, 5).join('、');
  var more = issues.length > 5 ? ' 等 ' + issues.length + ' 条' : '';
  warnEl.textContent = '这些目标缺少端口，无法做服务识别：' + head + more + '（写法：10.0.0.1:80）';
  warnEl.style.display = 'block';
}

async function handleCreateTask(e) {
  e.preventDefault();
  const name = document.getElementById('taskName').value.trim();
  const target = document.getElementById('taskTarget').value.trim();
  const customPortsRaw = document.getElementById('taskPortRange').value.trim();
  const scanModeEl = document.querySelector('input[name="scan_mode"]:checked');
  const scanMode = scanModeEl ? scanModeEl.value : 'full';
  const presets = Object.keys(selectedPresets).filter(function(id) { return selectedPresets[id]; });

  // 服务识别只扫目标里写明的端口：缺端口直接拦下，避免建了任务却什么都没扫
  if (scanMode === 'service_only') {
    const issues = serviceTargetIssues(target);
    if (issues.length) {
      showToast('服务识别只扫描目标里写明的端口，请写成 IP:端口（如 10.0.0.1:80）：' + issues.slice(0, 3).join('、'), 'error');
      document.getElementById('taskTarget').focus();
      return false;
    }
  }
  // 服务识别不使用端口范围 / 预置端口列表
  const serviceMode = scanMode === 'service_only';
  const customPorts = serviceMode ? '' : customPortsRaw;
  const portPresets = serviceMode ? [] : presets;

  // 端口非法时直接拦下（后端同样会校验）
  const preview = serviceMode ? { invalid: [] } : composePortSpecClient();
  if (scanMode !== 'alive_only' && preview.invalid && preview.invalid.length) {
    showToast('端口格式不合法：' + preview.invalid.join('、'), 'error');
    return false;
  }
  const submitBtn = document.querySelector('#createTaskForm button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = '创建中...';
  try {
  const resp = await fetch('/api/tasks', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      name: name, target: target,
      custom_ports: customPorts, port_range: customPorts,
      port_presets: portPresets, scan_mode: scanMode
    })
  });
  const data = await resp.json();
  if (data.success) {
    if (data.warning) {
      // 跳转会清掉 toast，先缓存到详情页再提示
      try { sessionStorage.setItem('nc_start_warning', data.warning); } catch (e2) {}
    }
    closeModal('createTaskModal');
    const taskId = data.task.id;
    const startResp = await fetch(`/api/tasks/${taskId}/start`, { method: 'POST' });
    const startData = await startResp.json();
    if (startData.success) {
      window.location.href = `/tasks/${taskId}`;
    } else {
      showToast('扫描启动失败: ' + (startData.message || '未知错误'), 'error');
      window.location.href = `/tasks/${taskId}`;
    }
  } else {
    showToast(data.message || '创建失败', 'error');
  }
  } catch (err) {
    showToast('创建失败: ' + (err.message || '网络错误'), 'error');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = '创建并开始扫描';
  }
  return false;
}

// ========== Task Operations ==========
async function deleteTask(id) {
  showConfirmModal(
    '删除任务',
    '确定要删除该任务吗？关联的扫描结果也将被删除（删除前会自动在 ExportResults/history 留一份存档）。此操作不可撤销。',
    'danger',
    async function() {
      await fetch('/api/tasks/' + id + '/delete', { method: 'POST' });
      closeConfirmModal();
      if (document.getElementById('taskList')) loadTasks();
      else window.location.href = '/tasks';
    }
  );
}

async function cancelTaskById(id) {
  showConfirmModal(
    '取消任务',
    '确定要取消该扫描任务吗？后台扫描进程将被中断，已扫描的数据会被保留，可随时导出。',
    'warning',
    async function() {
      await fetch('/api/tasks/' + id + '/cancel', { method: 'POST' });
      closeConfirmModal();
      if (document.getElementById('taskList')) loadTasks();
      else refreshTaskSnapshot();
    }
  );
}

async function pauseTaskById(id) {
  const resp = await fetch('/api/tasks/' + id + '/pause', { method: 'POST' });
  const data = await resp.json();
  if (data.success) {
    showToast('已暂停，可在需要时继续扫描', 'success');
  } else {
    showToast(data.message || '暂停失败', 'error');
  }
  if (document.getElementById('taskList')) loadTasks();
  else refreshTaskSnapshot();
}

function notifyStartResult(data) {
  if (!data || !data.success) {
    showToast((data && data.message) || '启动失败', 'error');
    return;
  }
  if (data.resumed) {
    showToast('已从断点继续扫描', 'success');
  } else if (data.was_paused) {
    // 暂停的任务在“端口扫描 / 存活探测 / Nmap 端口扫描”等无法精确断点的阶段，会从头重新扫描
    showToast('该阶段不支持精确断点，已从头重新扫描（旧结果已存档）', 'warning');
  } else {
    showToast('已开始扫描', 'success');
  }
}

async function resumeTaskById(id) {
  const resp = await fetch('/api/tasks/' + id + '/start', { method: 'POST' });
  notifyStartResult(await resp.json());
  if (document.getElementById('taskList')) loadTasks();
  else refreshTaskSnapshot();
}

// 已完成 / 失败 / 取消的任务：清空结果并重新扫描（后端会自动先存档）
function rescanTaskById(id) {
  showConfirmModal(
    '重新扫描',
    '将清空本任务的扫描结果并从头重新扫描；旧结果会先自动存档到 ExportResults/history。',
    'warning',
    async function() {
      closeConfirmModal();
      const resp = await fetch('/api/tasks/' + id + '/start', { method: 'POST' });
      notifyStartResult(await resp.json());
      if (document.getElementById('taskList')) loadTasks();
      else refreshTaskSnapshot();
    }
  );
}

function exportTaskXlsx(id) {
  if (!id) return;
  window.location.href = `/api/results/export/${id}`;
}

function exportTaskArchive(id) {
  if (!id) return;
  window.location.href = `/api/results/archive/${id}`;
}

// ========== Task Detail ==========
let currentTaskId = null;
let currentTaskData = null;
let detailEventSource = null;
let detailSSETaskId = null;
let detailPollTimer = null;      // setTimeout 句柄（自适应的自动刷新）
let detailPollBusy = false;
let detailPollTick = 0;
let detailSnapshotBusy = false;

const DETAIL_POLL_ACTIVE_MS = 2000;   // 扫描进行中：2 秒对齐一次
const DETAIL_POLL_IDLE_MS = 12000;    // 空闲 / 已结束：低频对齐，避免页面彻底“冻住”

const MODE_PHASES = {
  'full': ['idle', 'ping_scan', 'port_scan', 'service_scan', 'completed'],
  'alive_only': ['idle', 'ping_scan', 'completed'],
  'port_only': ['idle', 'port_scan', 'completed'],
  'service_only': ['idle', 'service_scan', 'completed'],
  'nmap_port_scan': ['idle', 'nmap_scan', 'completed']
};

const PHASE_LABELS = {
  'idle': '排队',
  'ping_scan': '存活探测',
  'port_scan': '端口扫描',
  'service_scan': '服务识别',
  'nmap_scan': 'Nmap端口扫描',
  'completed': '完成'
};

function getEl(id) { return document.getElementById(id); }

// 统一的显隐工具：元素不存在时静默跳过。
// 早期版本直接写 document.getElementById(x).style，一旦模板与脚本版本不匹配
// 就会抛 "Cannot read properties of null (reading 'style')"，把整个详情页打成“加载失败”。
function setDisp(id, show, mode) {
  var node = getEl(id);
  if (!node) return null;
  node.style.display = show ? (mode || 'inline-flex') : 'none';
  return node;
}

function isTerminalStatus(s) { return s === 'completed' || s === 'failed' || s === 'cancelled'; }
function isActiveStatus(s) { return s === 'pending' || s === 'running' || s === 'paused'; }

function safeJsonParse(text) {
  try { return JSON.parse(text); } catch (e) { return null; }
}

function renderTaskLoadError(msg) {
  var infoEl = getEl('taskInfo');
  if (infoEl) {
    infoEl.innerHTML = '<div class="error-state">加载失败: ' + escapeHtml(msg || '未知错误') + '</div>';
  }
  setDisp('taskProgress', false, 'block');
  setDisp('taskActions', false, 'block');
  setDisp('taskSummary', false, 'block');
}

// 上一页：优先回浏览器历史（从哪个页面点进来就回哪），没有历史时才回任务列表
function goBack() {
  var ref = '';
  try { ref = document.referrer || ''; } catch (e) {}
  var sameOrigin = false;
  try { sameOrigin = !!ref && new URL(ref).origin === window.location.origin; } catch (e2) { sameOrigin = false; }
  if (sameOrigin && window.history.length > 1) {
    window.history.back();
    return;
  }
  window.location.href = '/tasks';
}

// ===== 详情页自动刷新状态提示 =====
function updateLiveIndicator(kind, note) {
  var ind = getEl('liveIndicator');
  var txt = getEl('liveUpdatedText');
  if (!ind) return;
  var stamp = new Date().toTimeString().slice(0, 8);
  ind.classList.remove('is-live', 'is-idle', 'is-error');
  if (kind === 'live') {
    ind.classList.add('is-live');
    if (txt) txt.textContent = (note || '自动刷新') + ' · ' + stamp;
  } else if (kind === 'error') {
    ind.classList.add('is-error');
    if (txt) txt.textContent = '刷新失败，重试中 · ' + stamp;
  } else {
    ind.classList.add('is-idle');
    if (txt) txt.textContent = (note || '已暂停自动刷新') + ' · ' + stamp;
  }
}

async function manualRefreshDetail() {
  if (/^\/tasks\/\d+$/.test(window.location.pathname)) {
    var task = await refreshTaskSnapshot();
    if (task) showToast('已获取最新状态', 'success');
    else showToast('刷新失败，请检查网络后重试', 'error');
    return;
  }
  if (document.getElementById('taskList')) { loadTasks(); showToast('已刷新任务列表', 'success'); }
}

async function loadTaskDetail(opts) {
  var keepScroll = !!(opts && opts.keepScroll);
  var scrollY = keepScroll ? window.scrollY : 0;
  const pathParts = window.location.pathname.split('/');
  const id = parseInt(pathParts[pathParts.length - 1]);
  if (isNaN(id)) { renderTaskLoadError('无效的任务 ID'); return; }
  currentTaskId = id;
  detailPollTick = 0;

  let task = null;
  try {
    const resp = await apiFetch(`/api/tasks/${id}`, { cache: 'no-store' });
    if (!resp.ok) throw new Error('任务不存在或已被删除');
    task = await resp.json();
    if (!task || typeof task !== 'object' || !task.id) throw new Error('任务数据为空');
  } catch (err) {
    console.error('loadTaskDetail error:', err);
    stopDetailPolling();
    closeDetailSSE();
    renderTaskLoadError(err && err.message ? err.message : '未知错误');
    updateLiveIndicator('error');
    return;
  }

  currentTaskData = task;
  renderTaskInfo(task);
  renderPhaseIndicator(task.scan_mode);
  applyTaskSnapshot(task);
  updateLiveIndicator('live');
  syncDetailSections(task);
  if (keepScroll) window.scrollTo(0, scrollY);

  try {
    var warn = sessionStorage.getItem('nc_start_warning');
    if (warn) { showToast(warn, 'warning'); sessionStorage.removeItem('nc_start_warning'); }
  } catch (e3) {}
}

// 摘要卡片 / SSE 的启动与停止，全部按任务当前状态决定。
// 自动刷新（轮询）由 startDetailPolling 单独负责，详情页始终保活。
function syncDetailSections(task) {
  if (!task) return;
  var showSummary = hasTaskData(task) || task.status !== 'pending';
  setDisp('taskSummary', showSummary, 'block');
  if (showSummary) loadTaskSummary(currentTaskId);

  if (isActiveStatus(task.status)) subscribeDetailSSE(currentTaskId);
  else closeDetailSSE();

  startDetailPolling(currentTaskId);
}

// 刚启动阶段还没落到具体阶段时，不要显示成“等待”
function currentPhaseText(task) {
  var status = (task && task.status) || 'pending';
  var phase = (task && task.current_phase) || 'idle';
  if (status === 'pending') return '未开始';
  if (status === 'running' && phase === 'idle') return '启动中';
  if (status === 'running' && phase === 'completed') return '收尾中';
  return phaseLabel(phase);
}

// “扫描目标”和“端口范围”共用：内容超长时自动回缩为 2 行，点“展开全部”看完整
var detailExpanded = { target: false, ports: false };

function toggleDetailExpand(key) {
  detailExpanded[key] = !detailExpanded[key];
  refreshDetailClampState();
}

function refreshDetailClampState() {
  var items = document.querySelectorAll('.detail-clamp[data-detail]');
  Array.prototype.forEach.call(items, function (item) {
    var key = item.getAttribute('data-detail');
    var val = item.querySelector('.detail-value');
    var toggle = item.querySelector('.detail-toggle');
    if (!val || !toggle) return;
    var expanded = !!detailExpanded[key];
    var wasClampable = item.getAttribute('data-clampable') === '1';

    item.classList.toggle('is-expanded', expanded);
    var clampable = wasClampable;
    if (!expanded) {
      // 折叠态下测量：内容高度超过两行才需要“展开全部”
      clampable = val.scrollHeight - val.clientHeight > 2;
      if (clampable) item.setAttribute('data-clampable', '1');
    }
    toggle.style.display = (expanded || clampable) ? 'inline-flex' : 'none';
    toggle.textContent = expanded ? '收起' : '展开全部';
  });
}

function renderTaskInfo(task) {
  var infoEl = getEl('taskInfo');
  if (!infoEl) return;
  var status = task.status || 'pending';

  var portRangeValue = escapeHtml(task.port_range || '1-65535');
  if (task.scan_mode === 'service_only') portRangeValue = '按目标中的 IP:端口';
  if (task.scan_mode === 'alive_only') portRangeValue = '不适用';
  var portRangeItem = task.scan_mode === 'alive_only'
    ? '<div class="detail-item detail-hidden" style="display:none"><div class="detail-value">' + portRangeValue + '</div><div class="detail-label">端口范围</div></div>'
    : '<div class="detail-item detail-clamp" data-detail="ports">' +
        '<div class="detail-value clampable" title="' + portRangeValue + '">' + portRangeValue + '</div>' +
        '<button type="button" class="detail-toggle" onclick="toggleDetailExpand(\'ports\')">展开全部</button>' +
        '<div class="detail-label">端口范围</div></div>';

  infoEl.innerHTML = `
    <div class="detail-grid">
      <div class="detail-item"><div class="detail-value">${escapeHtml(task.name)}</div><div class="detail-label">任务名称</div></div>
      <div class="detail-item detail-clamp" data-detail="target">
        <div class="detail-value clampable" title="${escapeHtml(task.target)}">${escapeHtml(task.target)}</div>
        <button type="button" class="detail-toggle" onclick="toggleDetailExpand('target')">展开全部</button>
        <div class="detail-label">扫描目标</div>
      </div>
      ${portRangeItem}
      <div class="detail-item"><div class="detail-value"><span id="statusBadge" class="badge badge-${escapeHtml(status)}">${statusLabel(status)}</span></div><div class="detail-label">状态</div></div>
      <div class="detail-item"><div class="detail-value">${modeLabel(task.scan_mode)}</div><div class="detail-label">扫描模式</div></div>
      <div class="detail-item"><div class="detail-value" id="infoPhaseValue">${escapeHtml(currentPhaseText(task))}</div><div class="detail-label">当前阶段</div></div>
    </div>
    ${task.error_message ? `<div class="error-msg">${escapeHtml(task.error_message)}</div>` : ''}
  `;
  refreshDetailClampState();
}

// 轮询只更新“会变的字段”，不整块重绘（避免闪烁、也保留“展开全部”的展开状态）
function refreshInfoLiveFields(task) {
  if (!task) return;
  renderStatusBadge(task.status);
  var phaseEl = getEl('infoPhaseValue');
  if (phaseEl) phaseEl.textContent = currentPhaseText(task);
}

// 状态徽标跟随 SSE / 轮询实时变化（修复“都开始扫端口了还显示等待中”）
function renderStatusBadge(status) {
  var badge = getEl('statusBadge');
  if (!badge) return;
  status = status || 'pending';
  badge.className = 'badge badge-' + status;
  badge.textContent = statusLabel(status);
}

function mergeTaskSnapshot(patch) {
  currentTaskData = Object.assign({}, currentTaskData || {}, patch || {});
  return currentTaskData;
}

// 一次快照同时刷新：状态徽标 + 阶段进度 + 预估信息 + 操作按钮
function applyTaskSnapshot(task) {
  if (!task) return;
  renderStatusBadge(task.status);
  updatePhaseUI(task);
  updateEtaUI(task);
  renderTaskActions(task);
  // 运行中才展示页面内的实时输出块（结束后可用「实时输出」页回看完整日志）
  setDisp('liveOutputSection', task.status === 'running', 'block');
}

function renderTaskActions(task) {
  var status = task.status || 'pending';
  var data = hasTaskData(currentTaskData || task);
  var running = status === 'running';
  var paused = status === 'paused';
  var pending = status === 'pending';

  setDisp('taskActions', true, 'block');

  var startBtn = getEl('startBtn');
  if (startBtn) {
    var showStart = pending || isTerminalStatus(status);
    startBtn.style.display = showStart ? 'inline-flex' : 'none';
    startBtn.textContent = pending ? '开始扫描' : '重新扫描';
    // 已结束的任务先走二次确认（会清空结果，旧结果自动存档）
    startBtn.setAttribute('onclick', pending ? 'startTask()' : 'rescanTaskById(currentTaskId)');
  }

  setDisp('pauseBtn', running);
  setDisp('resumeBtn', paused);
  setDisp('cancelBtn', running || paused);
  setDisp('viewResultsBtn', status === 'completed' || (data && !pending));
  setDisp('viewOutputBtn', status !== 'pending');
  setDisp('exportXlsxBtn', data);
  setDisp('exportArchiveBtn', data);
}

function renderPhaseIndicator(scanMode) {
  var el = getEl('phaseIndicator');
  if (!el) return;
  var steps = MODE_PHASES[scanMode] || MODE_PHASES['full'];
  el.innerHTML = steps.map(function(p) {
    return '<div class="phase-step" data-phase="' + p + '">' + (PHASE_LABELS[p] || p) + '</div>';
  }).join('');
}

function detailAppendOutput(line, source) {
  var container = getEl('detailOutputLines');
  if (!container) return;
  var placeholder = container.querySelector('.output-placeholder');
  if (placeholder) placeholder.remove();
  var div = document.createElement('div');
  div.className = 'output-log-line';
  if (source === 'ping_scan') div.classList.add('output-ping');
  else if (source === 'port_scan') div.classList.add('output-port');
  else if (source === 'service_scan') div.classList.add('output-svc');
  else if (source === 'nmap_scan') div.classList.add('output-svc');
  else if (source === 'info') div.classList.add('output-info');
  else if (line && line.indexOf('[stderr]') === 0) div.classList.add('output-err');
  var now = new Date();
  var ts = now.toTimeString().slice(0, 8);
  div.textContent = '[' + ts + '] ' + line;
  container.appendChild(div);
  var scrollContainer = getEl('detailOutputContainer');
  if (scrollContainer) scrollContainer.scrollTop = scrollContainer.scrollHeight;
}

// 进度文案：始终由“最新快照”推导，扫描一启动就不会再显示成等待
function progressStatusText(task) {
  var status = (task && task.status) || 'pending';
  var phase = (task && task.current_phase) || 'idle';
  if (status === 'pending') return '等待开始 · 点击「开始扫描」启动';
  if (status === 'running') {
    if (phase === 'idle') return '正在启动扫描…';
    if (phase === 'completed') return '正在收尾…';
    return '正在执行：' + phaseLabel(phase);
  }
  if (status === 'paused') return '已暂停 · 可点击「继续扫描」从断点续跑';
  if (status === 'completed') return '扫描完成';
  if (status === 'cancelled') return '任务已取消 · 已有结果可导出';
  if (status === 'failed') return '扫描失败';
  return statusLabel(status);
}

function updatePhaseUI(task) {
  var progressEl = getEl('taskProgress');
  if (!progressEl) return;
  progressEl.style.display = 'block';

  var status = task.status || 'pending';
  var phase = task.current_phase || 'idle';
  var stepEls = Array.prototype.slice.call(document.querySelectorAll('.phase-step'));
  var steps = stepEls.map(function(el) { return el.getAttribute('data-phase'); });
  var current = steps.indexOf(phase);

  if (current < 0) {
    current = isTerminalStatus(status) ? steps.length - 1 : 0;
  }
  // 刚启动时后端可能还在 idle：此时不要把“排队”当成正在进行的阶段
  if (status === 'running' && current === 0 && steps.length > 1) {
    current = 1;
  }

  stepEls.forEach(function(el, i) {
    el.className = 'phase-step';
    if (i < current) {
      el.classList.add('completed');
    } else if (i === current) {
      if (status === 'paused') el.classList.add('paused');
      else if (isTerminalStatus(status)) el.classList.add(status === 'completed' ? 'completed' : 'stopped');
      else el.classList.add('active');
    }
  });
  if (status === 'completed') {
    stepEls.forEach(function(el) { el.className = 'phase-step completed'; });
  }

  var statusEl = getEl('progressStatus');
  if (statusEl) {
    statusEl.textContent = progressStatusText(task);
    statusEl.className = 'progress-status status-' + status;
  }

  var pct = Number(task.progress_pct || 0);
  if (isNaN(pct)) pct = 0;
  if (pct < 0) pct = 0;
  if (pct > 100) pct = 100;

  // nmap / 刚开始的阶段拿不到可信百分比时，用“滚动条”表示仍在推进，而不是假装 0%/等待
  var indeterminate = status === 'running' && (
    pct <= 0 ||
    (phase === 'nmap_scan' && pct < 5) ||
    (phase === 'ping_scan' && pct < 5) ||
    (phase === 'port_scan' && pct < 3)
  );

  var fillEl = getEl('progressFill');
  if (fillEl) {
    if (indeterminate) fillEl.classList.add('progress-indeterminate');
    else fillEl.classList.remove('progress-indeterminate');
    fillEl.style.width = indeterminate ? '100%' : Math.round(pct) + '%';
  }
  var pctEl = getEl('progressText');
  if (pctEl) {
    if (status === 'pending') pctEl.textContent = '等待开始';
    else if (indeterminate) pctEl.textContent = '扫描中…';
    else if (status === 'paused') pctEl.textContent = Math.round(pct) + '% · 已暂停';
    else pctEl.textContent = Math.round(pct) + '%';
  }

  var elpEl = getEl('elapsedText');
  if (elpEl) elpEl.textContent = '耗时: ' + formatElapsed(task.elapsed_seconds);

  updateProgressBarStyle(status);
}

// 端口扫描阶段：实时显示 masscan / nmap 自带的预估剩余时间与阶段进度
function updateEtaUI(task) {
  var line = getEl('etaLine');
  if (!line) return;
  var phase = task.current_phase || '';
  var inScanPhase = (phase === 'port_scan' || phase === 'nmap_scan' || phase === 'service_scan' || phase === 'ping_scan');
  var hasData = (Number(task.eta_seconds) > 0) || (Number(task.scan_percent) > 0) || (Number(task.rate_kpps) > 0);
  if (!(task.status === 'running' && inScanPhase && hasData)) {
    line.style.display = 'none';
    return;
  }
  line.style.display = 'flex';
  var etaEl = getEl('etaText');
  var pctEl = getEl('etaPercent');
  var rateEl = getEl('etaRate');
  if (etaEl) etaEl.textContent = '预计剩余: ' + (Number(task.eta_seconds) > 0 ? formatTimer(Number(task.eta_seconds)) : '计算中...');
  if (pctEl) pctEl.textContent = phaseLabel(phase) + ': ' + (Number(task.scan_percent) > 0 ? Number(task.scan_percent).toFixed(1) + '%' : '--');
  if (rateEl) rateEl.textContent = '速率: ' + (Number(task.rate_kpps) > 0 ? Number(task.rate_kpps).toFixed(1) + ' kpps' : '--');
}

async function loadTaskSummary(taskId) {
  if (!taskId) return;
  var contentEl = getEl('summaryContent');
  if (!contentEl) return;
  try {
    const resp = await apiFetch(`/api/results/summary/${taskId}`, { cache: 'no-store' });
    if (!resp.ok) return;
    const data = await resp.json();
    const s = (data && data.summary) || {};
    contentEl.innerHTML = `
      <div class="stat-box"><div class="stat-num" style="color:var(--primary)">${s.total || 0}</div><div class="stat-lbl">端口总数</div></div>
      <div class="stat-box"><div class="stat-num" style="color:var(--success)">${s.open || 0}</div><div class="stat-lbl">开放</div></div>
      <div class="stat-box"><div class="stat-num" style="color:var(--warning)">${s.filtered || 0}</div><div class="stat-lbl">过滤</div></div>
      <div class="stat-box"><div class="stat-num" style="color:var(--accent)">${s.services || 0}</div><div class="stat-lbl">服务识别</div></div>
    `;
  } catch (err) {
    console.error('loadTaskSummary error:', err);
  }
}

function closeDetailSSE() {
  if (detailEventSource) { detailEventSource.close(); detailEventSource = null; }
  detailSSETaskId = null;
}

function subscribeDetailSSE(taskId) {
  if (!taskId) return;
  // 幂等：已经订阅同一任务时不要重连，避免轮询每次都重建连接
  if (detailEventSource && detailSSETaskId === taskId) return;
  closeDetailSSE();
  try {
    detailEventSource = new EventSource(`/api/sse/${taskId}`);
    detailSSETaskId = taskId;
  } catch (err) {
    detailEventSource = null;
    detailSSETaskId = null;
    return;
  }
  const src = detailEventSource;

  src.addEventListener('progress', (e) => {
    const evt = safeJsonParse(e.data);
    if (!evt) return;
    const snap = mergeTaskSnapshot(evt);
    refreshInfoLiveFields(snap);
    applyTaskSnapshot(snap);
    if (evt.status === 'running') setDisp('liveOutputSection', true, 'block');
    // 结束瞬间结果刚落库：立刻刷新摘要，不必等下一次轮询
    if (isTerminalStatus(evt.status)) loadTaskSummary(currentTaskId);
    updateLiveIndicator('live');
  });

  src.addEventListener('eta', (e) => {
    const evt = safeJsonParse(e.data);
    if (!evt) return;
    // eta 事件只带端口扫描的预估信息，不携带耗时/结果数，
    // 全量合并会把「耗时」冲回 0s，所以这里只合并进度相关字段。
    var base = currentTaskData || {};
    var merged = mergeTaskSnapshot({
      status: evt.status || base.status,
      current_phase: evt.current_phase || base.current_phase,
      progress_pct: (typeof evt.progress_pct === 'number' && !isNaN(evt.progress_pct)) ? evt.progress_pct : base.progress_pct,
      eta_seconds: evt.eta_seconds,
      eta_text: evt.eta_text,
      scan_percent: evt.scan_percent,
      rate_kpps: evt.rate_kpps
    });
    refreshInfoLiveFields(merged);
    applyTaskSnapshot(merged);
  });

  src.addEventListener('output', (e) => {
    const evt = safeJsonParse(e.data);
    if (!evt) return;
    detailAppendOutput(evt.output_line, evt.output_source);
  });

  src.addEventListener('command', (e) => {
    const evt = safeJsonParse(e.data);
    if (!evt) return;
    detailAppendOutput('$ ' + evt.output_line, 'info');
  });

  src.onerror = () => { /* EventSource 会自行重连；轮询兜底保证进度不倒退 */ };
}

// 自适应自动刷新：打开页面先对齐一次，运行中 2s / 空闲 12s，标签页切回来立刻对齐
function startDetailPolling(taskId) {
  if (!taskId) return;
  if (detailPollTimer) return;
  scheduleDetailPoll(400);
}

function scheduleDetailPoll(delay) {
  if (detailPollTimer) { clearTimeout(detailPollTimer); detailPollTimer = null; }
  if (!currentTaskId) return;
  detailPollTimer = setTimeout(function () {
    detailPollTimer = null;
    pollDetailOnce();
  }, Math.max(200, delay || 0));
}

function stopDetailPolling() {
  if (detailPollTimer) { clearTimeout(detailPollTimer); detailPollTimer = null; }
}

async function pollDetailOnce() {
  if (!currentTaskId) { stopDetailPolling(); return; }
  if (document.hidden) { scheduleDetailPoll(DETAIL_POLL_IDLE_MS); return; }
  if (detailPollBusy) { scheduleDetailPoll(1200); return; }

  detailPollBusy = true;
  var next = DETAIL_POLL_ACTIVE_MS;
  try {
    const resp = await apiFetch('/api/tasks/' + currentTaskId, { cache: 'no-store' });
    if (!resp.ok) {
      next = 5000;
      updateLiveIndicator('error');
    } else {
      const fresh = await resp.json();
      if (fresh && fresh.id) {
        var prevStatus = (currentTaskData && currentTaskData.status) || '';
        var prevDataFlag = hasTaskData(currentTaskData || {});
        currentTaskData = fresh;
        detailPollTick++;

        refreshInfoLiveFields(fresh);
        applyTaskSnapshot(fresh);
        updateLiveIndicator('live');

        var statusChanged = prevStatus !== fresh.status;
        var dataArrived = !prevDataFlag && hasTaskData(fresh);
        if (statusChanged || dataArrived || detailPollTick % 2 === 0) {
          setDisp('taskSummary', hasTaskData(fresh) || fresh.status !== 'pending', 'block');
          loadTaskSummary(currentTaskId);
        }
        if (isActiveStatus(fresh.status)) subscribeDetailSSE(currentTaskId);
        else closeDetailSSE();

        next = isActiveStatus(fresh.status) ? DETAIL_POLL_ACTIVE_MS : DETAIL_POLL_IDLE_MS;
      }
    }
  } catch (err) {
    next = 5000;
    updateLiveIndicator('error');
  } finally {
    detailPollBusy = false;
    scheduleDetailPoll(next);
  }
}

// 拉一次最新任务快照并就地刷新（保留展开状态，不整页重载）
async function refreshTaskSnapshot() {
  if (!currentTaskId || detailSnapshotBusy) return currentTaskData;
  detailSnapshotBusy = true;
  try {
    const resp = await apiFetch('/api/tasks/' + currentTaskId, { cache: 'no-store' });
    if (!resp.ok) return null;
    const task = await resp.json();
    if (!task || !task.id) return null;
    currentTaskData = task;
    renderTaskInfo(task);
    renderPhaseIndicator(task.scan_mode);
    applyTaskSnapshot(task);
    syncDetailSections(task);
    updateLiveIndicator('live');
    return task;
  } catch (err) {
    console.error('refreshTaskSnapshot error:', err);
    updateLiveIndicator('error');
    return null;
  } finally {
    detailSnapshotBusy = false;
  }
}

async function startTask() {
  if (!currentTaskId) return;
  var btn = getEl('startBtn');
  if (btn) btn.disabled = true;
  try {
    const resp = await fetch(`/api/tasks/${currentTaskId}/start`, { method: 'POST' });
    const data = await resp.json();
    notifyStartResult(data);
  } catch (err) {
    showToast('启动失败: ' + (err.message || '网络错误'), 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
  await refreshTaskSnapshot();
}

async function resumeTask() {
  if (!currentTaskId) return;
  const resp = await fetch(`/api/tasks/${currentTaskId}/start`, { method: 'POST' });
  notifyStartResult(await resp.json());
  await refreshTaskSnapshot();
}

async function pauseTask() {
  if (!currentTaskId) return;
  showConfirmModal(
    '暂停任务',
    '暂停会中断当前的 nmap/masscan 进程，已完成的阶段会被记录为断点；点击「继续扫描」可从断点续跑。',
    'warning',
    async function() {
      await fetch('/api/tasks/' + currentTaskId + '/pause', { method: 'POST' });
      closeConfirmModal();
      await refreshTaskSnapshot();
    }
  );
}

async function cancelTask() {
  if (!currentTaskId) return;
  showConfirmModal(
    '取消任务',
    '确定要取消该扫描任务吗？后台扫描进程将被中断，已扫描的数据会被保留并可导出。',
    'warning',
    async function() {
      await fetch('/api/tasks/' + currentTaskId + '/cancel', { method: 'POST' });
      closeConfirmModal();
      await refreshTaskSnapshot();
    }
  );
}

function viewResults() { if (currentTaskId) window.location.href = `/results/${currentTaskId}`; }
function viewOutput() { if (currentTaskId) window.location.href = `/output/${currentTaskId}`; }

// ========== Results Page ==========
let resultsTaskId = null;
let resultsScanMode = null;
let allResults = [];
let currentPage = 1;
let pageSize = 50;

async function loadResults() {
  const pathParts = window.location.pathname.split('/');
  const id = parseInt(pathParts[pathParts.length - 1]);
  if (isNaN(id)) {
    document.getElementById('resultsBody').innerHTML = '<tr><td colspan="8" class="error-state">无效的任务 ID</td></tr>';
    return;
  }
  resultsTaskId = id;
  currentPage = 1;

  try {
  var scanMode = '';
  let aliveHosts = [];
  let aliveOnly = [];
  const taskResp = await apiFetch(`/api/tasks/${id}`);
  if (taskResp.ok) {
    const task = await taskResp.json();
    var rn = document.getElementById('resultTaskName'); if (rn) rn.textContent = task.name || '扫描结果';
    var sm = document.getElementById('resultScanMode'); if (sm) sm.textContent = '扫描模式: ' + modeLabel(task.scan_mode);
    aliveHosts = task.alive_hosts || [];
    scanMode = task.scan_mode;
    resultsScanMode = scanMode;
    renderPartialBanner(task);
  }
  const sumResp = await apiFetch(`/api/results/summary/${id}`);
  const sumData = await sumResp.json();
  aliveOnly = sumData.alive_only || [];
  const hosts = sumData.hosts || [];
  const s = sumData.summary || {total:0,open:0,filtered:0,services:0};
  const safeSetText = function(eid, val) { var el = document.getElementById(eid); if (el) el.textContent = val; };
  safeSetText('statTotal', s.total);
  safeSetText('statOpen', s.open);
  safeSetText('statFiltered', s.filtered || 0);
  safeSetText('statServices', s.services || 0);
  safeSetText('statHostsWithPorts', hosts.length);
  safeSetText('statAliveHosts', (aliveHosts.length || 0));

  // 存活扫描模式隐藏端口统计相关卡片并调整布局
  if (scanMode === 'alive_only') {
    var searchInput = document.getElementById('searchInput');
    if (searchInput) { var tb = searchInput.closest('.table-toolbar'); if (tb) tb.style.display = 'none'; }
    var rt = document.getElementById('resultsTable');
    if (rt) rt.style.display = 'none';
    var pg = document.getElementById('pagination');
    if (pg) pg.style.display = 'none';
    var sc = document.getElementById('serviceChart');
    if (sc) { var scCard = sc.closest('.card'); if (scCard) scCard.style.display = 'none'; }
    var oc = document.getElementById('osChart');
    if (oc) { var ocCard = oc.closest('.card'); if (ocCard) ocCard.style.display = 'none'; }
    if (rt) { var tc = rt.closest('.card'); if (tc) tc.style.display = 'none'; }
    ['statTotal','statOpen','statFiltered','statServices','statHostsWithPorts'].forEach(function(sid) {
      var el = document.getElementById(sid);
      if (el) { var card = el.closest('.stat-card'); if (card) card.style.display = 'none'; }
    });
    var statsRow = document.getElementById('statsRow');
    if (statsRow) statsRow.classList.add('stats-row-alive');
  }
  try { await loadResultsTable(id); } catch (e) { console.error('loadResultsTable error:', e); }
  if (scanMode !== 'alive_only') {
    try { await loadServiceDist(id); } catch (e) { console.error('loadServiceDist error:', e); }
    try { await loadOSDist(id); } catch (e) { console.error('loadOSDist error:', e); }
  }
  try { loadHostSummary(id, aliveHosts, aliveOnly, scanMode, hosts); } catch (e) { console.error('loadHostSummary error:', e); }
  } catch (err) {
    console.error('loadResults error:', err);
    document.getElementById('resultsBody').innerHTML = '<tr><td colspan="8" class="error-state">加载失败: ' + escapeHtml(err.message || '未知错误') + '</td></tr>';
  }
}

function renderPartialBanner(task) {
  var el = document.getElementById('partialBanner');
  if (!el) return;
  if (task.status === 'completed') { el.style.display = 'none'; return; }
  var text = '';
  if (task.status === 'paused') text = '任务已暂停：以下为已扫描到的部分结果，可继续扫描或直接导出存档。';
  else if (task.status === 'cancelled') text = '任务已取消：以下为已扫描到的部分结果，可直接导出成存档。';
  else if (task.status === 'failed') text = '任务失败：以下为已扫描到的部分结果，可导出用于排查。';
  else if (task.status === 'running') text = '任务正在运行：结果为实时增量，导出即当前快照。';
  if (!text) { el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.className = 'partial-banner partial-' + task.status;
  el.textContent = text;
}

async function loadResultsTable(taskId) {
  const resp = await apiFetch(`/api/results/${taskId}`);
  allResults = await resp.json();
  currentPage = 1;
  renderResultsPage();
}

function renderResultsPage() {
  const tbody = document.getElementById('resultsBody');
  if (!tbody) return;
  if (!allResults || allResults.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="loading">暂无扫描结果</td></tr>';
    setDisp('pagination', false, 'flex');
    return;
  }
  const total = allResults.length;
  const totalPages = Math.ceil(total / pageSize);
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  const start = (currentPage - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  const pageData = allResults.slice(start, end);

  var stateBadge = function(st) {
    if (st === 'open') return 'completed';
    if (st === 'open|filtered') return 'filtered';
    return 'pending';
  };
  tbody.innerHTML = pageData.map(r => `<tr>
    <td>${escapeHtml(r.ip)}</td><td>${r.port}</td><td>${escapeHtml(r.protocol)}</td>
    <td><span class="badge badge-${stateBadge(r.state)}">${escapeHtml(r.state)}</span></td>
    <td>${escapeHtml(r.service)}</td><td>${escapeHtml(r.product)}</td><td>${escapeHtml(r.version)}</td><td>${escapeHtml(r.os_details)}</td>
  </tr>`).join('');

  setDisp('pagination', true, 'flex');
  document.getElementById('paginationInfo').textContent = `共 ${total} 条记录，第 ${start+1}-${end} 条`;
  document.getElementById('pageIndicator').textContent = `第 ${currentPage}/${totalPages} 页`;
  document.getElementById('prevPageBtn').disabled = currentPage <= 1;
  document.getElementById('nextPageBtn').disabled = currentPage >= totalPages;
}

function prevPage() {
  if (currentPage > 1) { currentPage--; renderResultsPage(); }
}

function nextPage() {
  const totalPages = Math.ceil(allResults.length / pageSize);
  if (currentPage < totalPages) { currentPage++; renderResultsPage(); }
}

function changePageSize(newSize) {
  pageSize = parseInt(newSize);
  currentPage = 1;
  renderResultsPage();
}

var searchTimer = null;

// 输入防抖：避免每敲一个字符就打一次接口
function searchResults() {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(doSearchResults, 250);
}

async function doSearchResults() {
  if (!resultsTaskId) return;
  const input = document.getElementById('searchInput');
  const query = input ? input.value.trim() : '';
  const resp = await apiFetch(`/api/results/${resultsTaskId}${query ? '?search=' + encodeURIComponent(query) : ''}`);
  allResults = await resp.json();
  currentPage = 1;
  renderResultsPage();
}

async function loadServiceDist(taskId) {
  const resp = await apiFetch(`/api/results/services/${taskId}`);
  const services = await resp.json();
  const entries = Object.entries(services).sort((a,b) => b[1]-a[1]).slice(0,20);
  const el = document.getElementById('serviceChart');
  if (!el) return;
  el.innerHTML = entries.map(([svc, n]) =>
    `<span class="service-tag">${escapeHtml(svc)} (${n})</span>`
  ).join('') || '<p style="color:var(--muted)">暂无服务数据</p>';
}

async function loadOSDist(taskId) {
  const resp = await apiFetch(`/api/results/os/${taskId}`);
  const osMap = await resp.json();
  const entries = Object.entries(osMap || {}).sort((a, b) => b[1] - a[1]).slice(0, 20);
  const el = document.getElementById('osChart');
  if (!el) return;
  el.innerHTML = entries.length
    ? entries.map(([os, n]) => `<span class="service-tag">${escapeHtml(os)} (${n})</span>`).join('')
    : '<p style="color:var(--muted)">暂无操作系统指纹（nmap -sV 未返回 ostype 时，可在服务识别参数中追加 -O）</p>';
}

async function loadHostSummary(taskId, aliveHosts, aliveOnly, scanMode, hosts) {
  if (!hosts) { hosts = []; }
  let html = '';
  var isAliveOnlyMode = (scanMode === 'alive_only');
  if (hosts.length > 0) {
    html += '<div style="margin-bottom:12px"><strong>有开放端口的主机</strong></div>';
    html += hosts.map(h =>
      '<div class="host-item"><span class="host-ip">' + escapeHtml(h.ip) + '</span><span class="host-ports">' + ((h.ports||[]).join(', ')) + '</span></div>'
    ).join('');
  }
  if (aliveOnly && aliveOnly.length > 0) {
    if (html) html += '<hr style="margin:12px 0;border-color:var(--border)">';
    var sectionTitle = isAliveOnlyMode ? '存活主机' : '仅存活（无开放端口）的主机';
    var portLabel = isAliveOnlyMode ? '' : '无开放端口';
    html += '<div style="margin-bottom:12px"><strong>' + sectionTitle + '</strong></div>';
    html += aliveOnly.map(ip => {
      var portStr = portLabel ? '<span class="host-ports" style="color:var(--text-muted)">' + portLabel + '</span>' : '<span class="host-card-alive-badge alive-only">&#10003;存活</span>';
      return '<div class="host-card-item"><span class="host-card-ip">' + escapeHtml(ip) + '</span>' + portStr + '</div>';
    }).join('');
  }
  if (!html) {
    html = '<p style="color:var(--text-muted);text-align:center;padding:20px 0">' + (isAliveOnlyMode ? '暂无存活主机' : '暂无主机数据') + '</p>';
  }
  const el = document.getElementById('hostSummary');
  if (el) el.innerHTML = html;
}

function exportResults() { if (resultsTaskId) window.location.href = `/api/results/export/${resultsTaskId}`; }
function exportResultsCsv() { if (resultsTaskId) window.location.href = `/api/results/export/${resultsTaskId}?format=csv`; }
function exportResultsJson() { if (resultsTaskId) window.location.href = `/api/results/export/${resultsTaskId}?format=json`; }

// ========== Output Page ==========
let outputTaskId = null;
let outputEventSource = null;
let outputAutoScroll = true;

async function loadOutput() {
  const pathParts = window.location.pathname.split('/');
  const id = parseInt(pathParts[pathParts.length - 1]);
  if (isNaN(id)) return;
  outputTaskId = id;

  const resp = await apiFetch(`/api/tasks/${id}`);
  if (!resp.ok) {
    // 任务不存在 / 已删除：明确提示，不再假装“已连接、等待输出”永久挂起
    document.getElementById('outputTaskName').textContent = '任务不存在';
    document.getElementById('outputLines').innerHTML =
      '<div class="output-log-line output-err">任务 ' + id + ' 不存在或已被删除</div>';
    var badge = document.getElementById('outputStatusBadge');
    if (badge) { badge.className = 'badge badge-failed'; badge.textContent = '不存在'; }
    return;
  }
  {
    const task = await resp.json();
    document.getElementById('outputTaskName').textContent = task.name || '实时输出';
    updateOutputBadge(task.status);
    document.getElementById('outputStatusBadge').setAttribute('data-task-status', task.status);
    updateOutputEta(task);
    var elapsedEl = document.getElementById('outputElapsed');
    if (elapsedEl) elapsedEl.textContent = formatTimer(task.elapsed_seconds || 0);

    // 如果任务失败，显示错误信息
    if (task.status === 'failed' && task.error_message) {
      setDisp('errorOutputSection', true, 'block');
      document.getElementById('errorOutputContent').textContent = task.error_message;
      updateProgressBarStyle('failed');
    }

    // 显示已保存的输出（即使部分输出也能查看）
    renderSavedOutput(task.ping_output, 'ping_scan', '存活探测');
    renderSavedOutput(task.port_scan_output, 'port_scan', '端口扫描');
    renderSavedOutput(task.service_output, 'service_scan', '服务识别');
    renderCmdRecords(task.cmd_records);

    var outFill = document.getElementById('outputProgressFill');
    if (outFill) outFill.style.width = Math.round(task.progress_pct) + '%';
    if (task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled' || task.status === 'paused') {
      updateProgressBarStyle(task.status);
    }
    // 终态任务不会再有新输出：不建立 SSE 连接（避免长期挂着的空连接）
    if (task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled') {
      appendOutputLine('--- 任务已结束，以上为完整历史输出 ---', 'info');
      return;
    }
  }
  subscribeOutputSSE(id);
}

function updateOutputEta(task) {
  var el = document.getElementById('outputEta');
  if (!el) return;
  if (!task) { el.style.display = 'none'; return; }
  var inPortPhase = (task.current_phase === 'port_scan' || task.current_phase === 'nmap_scan');
  var show = inPortPhase && (task.eta_seconds > 0 || task.scan_percent > 0);
  if (!show) { el.style.display = 'none'; return; }
  var parts = [];
  if (task.eta_seconds > 0) parts.push('预计剩余 ' + formatTimer(task.eta_seconds));
  if (task.scan_percent > 0) parts.push('端口扫描 ' + Number(task.scan_percent).toFixed(1) + '%');
  if (task.rate_kpps > 0) parts.push(Number(task.rate_kpps).toFixed(1) + ' kpps');
  el.style.display = 'block';
  el.textContent = parts.join(' · ');
}

function renderSavedOutput(rawText, source, phaseLabelText) {
  if (!rawText || !rawText.trim()) return;
  const container = document.getElementById('outputLines');
  const placeholder = container.querySelector('.output-placeholder');
  if (placeholder) placeholder.remove();
  const headerDiv = document.createElement('div');
  headerDiv.className = 'output-log-line output-info';
  headerDiv.textContent = '--- ' + phaseLabelText + ' 输出 ---';
  container.appendChild(headerDiv);
  const lines = rawText.split('\n');
  for (const line of lines) {
    if (!line.trim()) continue;
    const div = document.createElement('div');
    div.className = 'output-log-line';
    if (source === 'ping_scan') div.classList.add('output-ping');
    else if (source === 'port_scan') div.classList.add('output-port');
    else if (source === 'service_scan') div.classList.add('output-svc');
    if (line.startsWith('[stderr]')) div.classList.add('output-err');
    div.textContent = line;
    container.appendChild(div);
  }
  if (outputAutoScroll) {
    const scrollContainer = document.getElementById('outputContainer');
    scrollContainer.scrollTop = scrollContainer.scrollHeight;
  }
}

function updateOutputBadge(status) {
  const badge = document.getElementById('outputStatusBadge');
  if (!badge) return;
  badge.className = 'badge badge-' + status;
  badge.textContent = statusLabel(status);
}

function subscribeOutputSSE(taskId) {
  if (outputEventSource) { outputEventSource.close(); }
  const container = document.getElementById('outputLines');
  const existingContent = container.querySelector('.output-log-line');
  if (!existingContent) {
    container.innerHTML = '<div class="output-log-line output-info">等待连接...</div>';
  }

  outputEventSource = new EventSource(`/api/sse/${taskId}`);

  outputEventSource.addEventListener('output', (e) => {
    const evt = JSON.parse(e.data);
    appendOutputLine(evt.output_line, evt.output_source);
  });

  outputEventSource.addEventListener('command', (e) => {
    const evt = JSON.parse(e.data);
    appendCommandLine(evt.output_line, evt.output_source);
  });

  outputEventSource.addEventListener('eta', (e) => {
    const evt = JSON.parse(e.data);
    updateOutputEta(evt);
    var outFillEta = document.getElementById('outputProgressFill');
    if (outFillEta) outFillEta.style.width = Math.round(evt.progress_pct) + '%';
    if (evt.eta_text || evt.eta_seconds) {
      appendOutputLine('[ETA] ' + (evt.message || ''), 'info');
    }
  });

  outputEventSource.addEventListener('progress', (e) => {
    const evt = JSON.parse(e.data);
    var outFill2 = document.getElementById('outputProgressFill');
    if (outFill2) outFill2.style.width = Math.round(evt.progress_pct) + '%';
    var outElapsed = document.getElementById('outputElapsed');
    if (outElapsed) outElapsed.textContent = formatTimer(evt.elapsed_seconds);
    updateOutputBadge(evt.status);
    updateProgressBarStyle(evt.status);
    updateOutputEta(evt);
    if (evt.status === 'failed') {
      showFailedTaskOutput();
    }
    if (evt.status === 'completed') {
      appendOutputLine('--- 扫描完成 ---', 'info');
    }
    if (evt.status === 'cancelled') {
      appendOutputLine('--- 扫描已取消（结果已保留，可导出存档） ---', 'info');
    }
    if (evt.status === 'completed' || evt.status === 'cancelled') {
      if (outputEventSource) { outputEventSource.close(); outputEventSource = null; }
    }
    if (evt.status === 'paused') {
      appendOutputLine('--- 扫描已暂停（可继续扫描） ---', 'info');
    }
  });

  outputEventSource.addEventListener('connected', () => {
    var badgeText = document.getElementById('outputStatusBadge').textContent;
    if (badgeText === '完成' || badgeText === '失败' || badgeText === '已取消' || badgeText === '已暂停') {
      appendOutputLine('--- 已连接，以上为历史扫描输出结果 ---', 'info');
    } else {
      appendOutputLine('--- 已连接，等待扫描输出 ---', 'info');
    }
  });

  outputEventSource.onerror = () => {
    appendOutputLine('--- 连接断开，正在重试... ---', 'info');
  };
}

function appendOutputLine(line, source) {
  const container = document.getElementById('outputLines');
  const placeholder = container.querySelector('.output-placeholder');
  if (placeholder) placeholder.remove();

  const div = document.createElement('div');
  div.className = 'output-log-line';

  if (source === 'ping_scan') div.classList.add('output-ping');
  else if (source === 'port_scan') div.classList.add('output-port');
  else if (source === 'service_scan') div.classList.add('output-svc');
  else if (source === 'nmap_scan') div.classList.add('output-svc');
  else if (source === 'info') div.classList.add('output-info');
  else if (line && line.indexOf('[stderr]') === 0) div.classList.add('output-err');

  const now = new Date();
  const ts = now.toTimeString().slice(0, 8);
  div.textContent = `[${ts}] ${line}`;

  container.appendChild(div);

  if (outputAutoScroll) {
    const scrollContainer = document.getElementById('outputContainer');
    scrollContainer.scrollTop = scrollContainer.scrollHeight;
  }
}

function renderCmdRecords(rawText) {
  if (!rawText || !rawText.trim()) return;
  var container = document.getElementById('outputLines');
  var placeholder = container.querySelector('.output-placeholder');
  if (placeholder) placeholder.remove();
  var commands = rawText.split('\n');
  for (var i = 0; i < commands.length; i++) {
    var line = commands[i].trim();
    if (!line) continue;
    var sourceHint = '';
    if (line.indexOf('-sn') > -1) sourceHint = '存活探测';
    else if (line.indexOf('-sV') > -1) sourceHint = '服务识别';
    else if (line.indexOf('masscan') > -1) sourceHint = '端口扫描';
    else if (line.indexOf('nmap') > -1) sourceHint = '端口扫描';
    var div = document.createElement('div');
    div.className = 'output-log-line output-cmd';
    var now = new Date();
    var ts = now.toTimeString().slice(0, 8);
    div.textContent = '[' + ts + '] [' + sourceHint + '] $ ' + line;
    container.appendChild(div);
  }
  if (outputAutoScroll) {
    var scrollContainer = document.getElementById('outputContainer');
    scrollContainer.scrollTop = scrollContainer.scrollHeight;
  }
}

function appendCommandLine(cmdLine, source) {
  const container = document.getElementById('outputLines');
  const placeholder = container.querySelector('.output-placeholder');
  if (placeholder) placeholder.remove();

  const div = document.createElement('div');
  div.className = 'output-log-line output-cmd';
  const sourceMap = {'ping_scan': '存活探测', 'port_scan': '端口扫描', 'service_scan': '服务识别', 'nmap_scan': 'Nmap端口扫描'};
  const prefix = sourceMap[source] || '命令';

  const now = new Date();
  const ts = now.toTimeString().slice(0, 8);
  div.textContent = '[' + ts + '] [' + prefix + '] $ ' + cmdLine;

  container.appendChild(div);

  if (outputAutoScroll) {
    const scrollContainer = document.getElementById('outputContainer');
    scrollContainer.scrollTop = scrollContainer.scrollHeight;
  }
}

function clearOutput() {
  document.getElementById('outputLines').innerHTML = '';
}

function toggleScroll() {
  outputAutoScroll = !outputAutoScroll;
  document.getElementById('scrollLockBtn').textContent = outputAutoScroll ? '锁定滚动' : '解锁滚动';
  if (outputAutoScroll) {
    const container = document.getElementById('outputContainer');
    container.scrollTop = container.scrollHeight;
  }
}

function formatTimer(seconds) {
  if (!seconds || seconds < 0) return '00:00:00';
  const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
  const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
  const s = String(seconds % 60).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

// ========== Toast Notifications ==========
function showToast(message, type) {
  type = type || 'success';
  var existing = document.querySelector('.toast');
  if (existing) existing.remove();
  var toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(function() { toast.remove(); }, 2500);
}

// ========== Progress Bar Color Update ==========
function updateProgressBarStyle(status) {
  var fill = document.getElementById('outputProgressFill');
  if (fill) {
    fill.classList.remove('progress-completed', 'progress-failed', 'progress-cancelled', 'progress-paused');
    if (status === 'completed') fill.classList.add('progress-completed');
    else if (status === 'failed') fill.classList.add('progress-failed');
    else if (status === 'cancelled') fill.classList.add('progress-cancelled');
    else if (status === 'paused') fill.classList.add('progress-paused');
  }
  var detailFill = document.getElementById('progressFill');
  if (detailFill) {
    detailFill.classList.remove('progress-completed', 'progress-failed', 'progress-cancelled', 'progress-paused');
    if (status === 'completed') detailFill.classList.add('progress-completed');
    else if (status === 'failed') detailFill.classList.add('progress-failed');
    else if (status === 'cancelled') detailFill.classList.add('progress-cancelled');
    else if (status === 'paused') detailFill.classList.add('progress-paused');
  }
}

// ========== Confirmation Modal ==========
var confirmActionCallback = null;

function showConfirmModal(title, message, iconClass, actionCallback) {
  document.getElementById('confirmTitle').textContent = title;
  document.getElementById('confirmMessage').textContent = message;
  var icon = document.getElementById('confirmIcon');
  icon.className = 'confirm-icon ' + (iconClass || 'warning');
  if (iconClass === 'danger') {
    icon.innerHTML = '&#10060;';
  } else {
    icon.innerHTML = '&#9888;';
  }
  var btn = document.getElementById('confirmActionBtn');
  btn.className = 'btn ' + (iconClass === 'danger' ? 'btn-danger' : 'btn-warning');
  if (iconClass === 'danger') { btn.style.background = 'var(--danger)'; btn.style.color = '#fff'; }
  else if (iconClass === 'warning') { btn.style.background = 'var(--warning)'; btn.style.color = '#fff'; }
  confirmActionCallback = actionCallback;
  showModal('confirmModal');
}

function closeConfirmModal() {
  confirmActionCallback = null;
  closeModal('confirmModal');
}

function executeConfirmedAction() {
  if (typeof confirmActionCallback === 'function') {
    confirmActionCallback();
  }
}

// ========== Port Presets ==========
var portPresets = [];
var selectedPresets = {};

async function loadPortPresets() {
  try {
    const resp = await apiFetch('/api/port-presets');
    const data = await resp.json();
    portPresets = (data && data.presets) || [];
    renderPortPresets();
    updatePortSpecPreview();
  } catch (err) {
    const el = document.getElementById('portPresetList');
    if (el) el.innerHTML = '<span class="form-hint">预置端口列表加载失败</span>';
  }
}

// 预置分组展示顺序（后端 Group 字段：常用 / 专项 / 其他）
var PRESET_GROUP_ORDER = ['常用', '专项'];

function renderPortPresets() {
  const el = document.getElementById('portPresetList');
  if (!el) return;
  if (!portPresets.length) {
    el.innerHTML = '<span class="form-hint">暂无预置端口列表</span>';
    updatePortPresetSummary();
    return;
  }
  var groups = [];
  var grouped = {};
  portPresets.forEach(function(p) {
    var g = p.group || '其他';
    if (!grouped[g]) { grouped[g] = []; groups.push(g); }
    grouped[g].push(p);
  });
  groups.sort(function(a, b) {
    var ia = PRESET_GROUP_ORDER.indexOf(a);
    var ib = PRESET_GROUP_ORDER.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
  el.innerHTML = groups.map(function(g) {
    return '<div class="port-preset-group">' +
      '<div class="port-preset-group-title">' + escapeHtml(g) + '</div>' +
      '<div class="port-preset-group-grid">' + grouped[g].map(renderPortPresetItem).join('') + '</div>' +
      '</div>';
  }).join('');
  updatePortPresetSummary();
}

function renderPortPresetItem(p) {
  var checked = !!selectedPresets[p.id];
  return '<label class="port-preset-item' + (checked ? ' selected' : '') + '" data-preset-id="' + escapeHtml(p.id) + '">' +
    '<input type="checkbox" value="' + escapeHtml(p.id) + '"' + (checked ? ' checked' : '') +
    ' onchange="togglePortPreset(this.value, this.checked)">' +
    '<span class="port-preset-check" aria-hidden="true">' +
      '<svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="currentColor" ' +
      'stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>' +
    '</span>' +
    '<span class="port-preset-body">' +
      '<span class="port-preset-row">' +
        '<span class="port-preset-name">' + escapeHtml(p.name) + '</span>' +
        (p.has_udp ? '<span class="port-preset-udp">UDP</span>' : '') +
        '<span class="port-preset-count">' + p.count + ' 个</span>' +
      '</span>' +
      '<span class="port-preset-desc">' + escapeHtml(p.description || '') + '</span>' +
    '</span>' +
    '</label>';
}

function togglePortPreset(id, checked) {
  selectedPresets[id] = !!checked;
  var items = document.querySelectorAll('.port-preset-item');
  for (var i = 0; i < items.length; i++) {
    if (items[i].getAttribute('data-preset-id') === id) {
      items[i].classList.toggle('selected', !!checked);
      break;
    }
  }
  updatePortPresetSummary();
  updatePortSpecPreview();
}

function updatePortPresetSummary() {
  var info = document.getElementById('portPresetSelectedInfo');
  if (!info) return;
  var chosen = (portPresets || []).filter(function(p) { return selectedPresets[p.id]; });
  if (!chosen.length) {
    info.textContent = '已选 0 项';
    info.classList.remove('has-selection');
    return;
  }
  var total = 0;
  chosen.forEach(function(p) { total += Number(p.count) || 0; });
  info.textContent = '已选 ' + chosen.length + ' 项 · 约 ' + total + ' 个端口';
  info.classList.add('has-selection');
}

function selectAllPortPresets(on) {
  (portPresets || []).forEach(function(p) { selectedPresets[p.id] = !!on; });
  renderPortPresets();
  updatePortSpecPreview();
}

// 拆解端口规约（与后端一致：U: 前缀切换到 UDP）；非法 token 收集到 invalid
function splitPortTokens(spec, tcp, udp, invalid) {
  if (!spec) return;
  var cur = 'tcp';
  var tokens = String(spec).split(/[,\s;|]+/);
  for (var i = 0; i < tokens.length; i++) {
    var raw = tokens[i].trim();
    if (!raw) continue;
    var tok = raw;
    var up = tok.toUpperCase();
    if (up.indexOf('U:') === 0) { cur = 'udp'; tok = tok.substring(2); }
    else if (up.indexOf('T:') === 0) { cur = 'tcp'; tok = tok.substring(2); }
    if (!tok.trim()) continue;
    var norm = normalizePortToken(tok);
    if (!norm) {
      if (invalid && invalid.indexOf(raw) < 0 && invalid.length < 10) invalid.push(raw);
      continue;
    }
    if (cur === 'udp') { if (udp.indexOf(norm) < 0) udp.push(norm); }
    else { if (tcp.indexOf(norm) < 0) tcp.push(norm); }
  }
}

function normalizePortToken(tok) {
  tok = String(tok).trim();
  if (!tok) return '';
  if (tok.indexOf('-') < 0) {
    var p = parseInt(tok, 10);
    if (isNaN(p) || p < 1 || p > 65535) return '';
    return String(p);
  }
  var parts = tok.split('-');
  var lo = parseInt(parts[0], 10), hi = parseInt(parts[1], 10);
  if (isNaN(lo) || isNaN(hi)) return '';
  if (lo < 1) lo = 1;
  if (hi > 65535) hi = 65535;
  if (lo > hi) { var t = lo; lo = hi; hi = t; }
  return lo === hi ? String(lo) : (lo + '-' + hi);
}

function countPortTokens(tokens) {
  var n = 0;
  for (var i = 0; i < tokens.length; i++) {
    var t = tokens[i];
    if (t.indexOf('-') < 0) { n += 1; continue; }
    var parts = t.split('-');
    var lo = parseInt(parts[0], 10), hi = parseInt(parts[1], 10);
    if (!isNaN(lo) && !isNaN(hi) && hi >= lo) n += (hi - lo + 1);
  }
  return n;
}

function composePortSpecClient() {
  var tcp = [], udp = [], invalid = [];
  Object.keys(selectedPresets).forEach(function(id) {
    if (!selectedPresets[id]) return;
    var p = null;
    for (var i = 0; i < portPresets.length; i++) { if (portPresets[i].id === id) { p = portPresets[i]; break; } }
    if (p) splitPortTokens(p.spec, tcp, udp, invalid);
  });
  var input = document.getElementById('taskPortRange');
  if (input) splitPortTokens(input.value, tcp, udp, invalid);
  var spec = tcp.join(',');
  if (udp.length) spec += (spec ? ',' : '') + 'U:' + udp.join(',');
  return { spec: spec, count: countPortTokens(tcp) + countPortTokens(udp), invalid: invalid };
}

function updatePortSpecPreview() {
  var el = document.getElementById('portSpecPreview');
  if (!el) return;
  var modeEl = document.querySelector('input[name="scan_mode"]:checked');
  var mode = modeEl ? modeEl.value : 'full';
  if (mode === 'alive_only') {
    el.textContent = '存活探测模式不需要端口范围';
    return;
  }
  if (mode === 'service_only') {
    el.textContent = '服务识别不使用端口范围：端口取自目标中的 IP:端口';
    return;
  }
  var res = composePortSpecClient();
  el.classList.remove('port-spec-invalid');
  if (res.invalid && res.invalid.length) {
    // 非法端口不再被静默丢弃：直接提示，避免误变成 1-65535 全端口扫描
    el.textContent = '端口格式不合法：' + res.invalid.join('、') + '（支持 80 / 8000-8100 / U:53）';
    el.classList.add('port-spec-invalid');
    el.title = res.invalid.join(', ');
    return;
  }
  if (!res.spec) {
    el.textContent = mode === 'service_only'
      ? '未指定端口：纯 IP 目标将使用「常见 100 端口」'
      : '未指定端口：默认扫描 1-65535';
    return;
  }
  var preview = res.spec.length > 140 ? res.spec.slice(0, 140) + ' ...' : res.spec;
  el.textContent = '最终端口规约：' + preview + '（约 ' + res.count + ' 个端口）';
  el.title = res.spec;
}

// ========== Scan Mode Selection ==========
function selectScanMode(el) {
  document.querySelectorAll('.scan-mode-option').forEach(function(opt) {
    opt.classList.remove('selected');
  });
  el.classList.add('selected');
  el.querySelector('input[type="radio"]').checked = true;

  var hint = document.getElementById('scanModeHint');
  var mode = el.getAttribute('data-mode');
  var targetEl = document.getElementById('taskTarget');
  var targetHint = document.getElementById('targetHint');
  var csvArea = document.querySelector('.csv-upload-area');
  var portRangeGroup = document.getElementById('portRangeGroup');
  var portPresetGroup = document.getElementById('portPresetGroup');
  var portSpecPreview = document.getElementById('portSpecPreview');

  // 各模式严格只做自己的事
  var hints = {
    'full': '仅执行：存活探测（nmap -sn）&rarr; 端口扫描（masscan）&rarr; 服务识别（nmap -sV）',
    'alive_only': '仅执行存活探测（nmap -sn），不端口扫描、不服务识别，端口范围不生效',
    'port_only': '仅执行端口扫描（masscan），不做存活探测、不做服务识别',
    'service_only': '仅执行服务识别（nmap -sV），<b>只扫目标里写明的端口</b>，不需要端口范围与预置端口列表',
    'nmap_port_scan': '仅执行 Nmap 端口扫描（-sS/-sT + -p），用 nmap 代替 masscan，不做服务识别'
  };

  hint.innerHTML = hints[mode] || '';
  hint.style.display = 'block';
  hint.className = 'scan-mode-hint';
  if (mode === 'service_only' || mode === 'alive_only') hint.classList.add('warning');

  // 存活探测与服务识别都不吃端口规约：这两种模式整块隐藏端口输入
  var showPorts = (mode !== 'alive_only' && mode !== 'service_only');
  if (portRangeGroup) portRangeGroup.style.display = showPorts ? 'block' : 'none';
  if (portPresetGroup) portPresetGroup.style.display = showPorts ? 'block' : 'none';
  if (portSpecPreview) portSpecPreview.style.display = showPorts ? 'block' : 'none';

  if (mode === 'service_only') {
    targetEl.placeholder = '10.0.0.5:22\n10.0.0.6:80\n192.168.1.10:3306\nexample.com:443';
    targetHint.innerHTML = '每行一个 <b>IP:端口</b>（也支持域名:端口），<b>只扫描这里写明的端口</b>；不支持网段/纯 IP';
    if (csvArea) csvArea.style.display = 'flex';
  } else if (mode === 'alive_only') {
    targetEl.placeholder = '192.168.1.0/24\n10.0.0.1\n172.16.0.0/16';
    targetHint.textContent = '支持多个目标，每行一个。支持 CIDR、IP 范围、单个 IP';
    if (csvArea) csvArea.style.display = 'flex';
  } else {
    targetEl.placeholder = '192.168.1.0/24\n10.0.0.1\n172.16.0.0/16';
    targetHint.textContent = '支持多个目标，每行一个。支持 CIDR、IP 范围、单个 IP';
    if (csvArea) csvArea.style.display = 'flex';
  }
  updateServiceTargetWarn();
  updatePortSpecPreview();
}

// ========== CSV Import ==========
function handleCSVImport(event) {
  var file = event.target.files[0];
  if (!file) return;

  var fileInfo = document.getElementById('csvFileInfo');
  fileInfo.textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';

  var reader = new FileReader();
  reader.onload = function(e) {
    var text = e.target.result;
    var lines = text.split('\n').filter(function(l) { return l.trim(); });
    var ips = [];
    // 支持 CIDR / IPv4 / 域名 / IP:端口（服务识别模式常用）
    var targetRe = /(?:\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/\d{1,2})?|\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?::\d{1,5})?/g;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.charAt(0) === '#') continue;
      var matches = line.match(targetRe);
      if (!matches) continue;
      for (var j = 0; j < matches.length; j++) {
        var t = matches[j].trim();
        if (!t) continue;
        // 过滤掉纯数字的端口片段（例如 "10.0.0.1:8080" 里被单独匹配出来的情况不会进入这里）
        ips.push(t);
      }
    }

    ips = ips.filter(function(ip, idx) { return ips.indexOf(ip) === idx; });
    if (ips.length > 5000) {
      ips = ips.slice(0, 5000);
      showToast('目标超过 5000 条，已截断为前 5000 条', 'error');
    }

    if (ips.length > 0) {
      var targetEl = document.getElementById('taskTarget');
      var existing = targetEl.value.trim();
      if (existing) existing += '\n';
      targetEl.value = existing + ips.join('\n');
      fileInfo.textContent += ' - 已提取 ' + ips.length + ' 个目标';
      showToast('已从 CSV 提取 ' + ips.length + ' 个目标', 'success');
    } else {
      fileInfo.textContent = file.name + ' - 未找到有效目标';
      showToast('文件中未找到有效目标（支持 IP、CIDR、域名、IP:端口）', 'error');
    }
  };
  reader.readAsText(file);
}

function showFailedTaskOutput() {
  var sec = document.getElementById('errorOutputSection');
  if (sec) sec.style.display = 'block';
  if (outputTaskId) {
    fetch('/api/tasks/' + outputTaskId).then(function(r) { return r.json(); }).then(function(task) {
      if (task.error_message) {
        document.getElementById('errorOutputContent').textContent = task.error_message;
      }
    }).catch(function() {});
  }
}

// ========== DNS Tools ==========
let lastDNSResults = [];

async function querySingleDomain() {
  const input = document.getElementById('singleDomainInput');
  const domain = input.value.trim();
  const resultEl = document.getElementById('singleResult');
  if (!domain) {
    resultEl.className = 'dns-single-result error';
    resultEl.textContent = '请输入域名';
    resultEl.style.display = 'block';
    return;
  }
  resultEl.style.display = 'block';
  resultEl.className = 'dns-single-result';
  resultEl.textContent = '查询中...';
  try {
    const resp = await fetch('/api/dns/resolve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({domains: domain})
    });
    const data = await resp.json();
    if (data.success && data.results.length > 0) {
      const r = data.results[0];
      if (r.error) {
        resultEl.className = 'dns-single-result error';
        resultEl.innerHTML = '<strong>' + escapeHtml(domain) + '</strong> 解析失败：' + escapeHtml(r.error);
      } else {
        resultEl.className = 'dns-single-result success';
        resultEl.innerHTML = '<strong>' + escapeHtml(r.domain) + '</strong> 解析结果：' +
          r.ips.map(function(ip) { return '<span class="dns-ip-tag">' + escapeHtml(ip) + '</span>'; }).join('') +
          '<div style="margin-top:6px;font-size:12px;color:var(--text-muted)">共 ' + r.ips.length + ' 个 IP 地址</div>';
      }
    } else {
      resultEl.className = 'dns-single-result error';
      resultEl.textContent = '解析失败：未获取到结果';
    }
  } catch (err) {
    resultEl.className = 'dns-single-result error';
    resultEl.textContent = '请求失败：' + (err.message || '网络错误');
  }
}

async function startBatchResolve() {
  const textarea = document.getElementById('domainList');
  const domains = textarea.value.trim();
  const resultsArea = document.getElementById('dnsResultsArea');
  const tbody = document.getElementById('dnsResultsBody');
  const statsEl = document.getElementById('dnsStats');
  const exportBtn = document.getElementById('exportBtn');
  if (!domains) {
    showToast('请先在输入框中粘贴域名列表', 'error');
    return;
  }

  resultsArea.style.display = 'block';
  tbody.innerHTML = '<tr><td colspan="4" class="dns-loading">正在解析域名，请稍候...</td></tr>';
  statsEl.innerHTML = '';
  exportBtn.style.display = 'none';

  try {
    const resp = await fetch('/api/dns/resolve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({domains: domains})
    });
    const data = await resp.json();
    if (!data.success) {
      tbody.innerHTML = '<tr><td colspan="4" class="error-state">解析失败</td></tr>';
      return;
    }

    lastDNSResults = data.results || [];

    statsEl.innerHTML = '<span class="dns-stat">总计：<strong>' + data.total + '</strong> 条</span>' +
      '<span class="dns-stat">成功：<strong style="color:var(--success)">' + data.resolved + '</strong> 条</span>' +
      '<span class="dns-stat">失败：<strong style="color:var(--danger)">' + data.failed + '</strong> 条</span>';

    if (lastDNSResults.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">未解析到任何结果</td></tr>';
      return;
    }

    tbody.innerHTML = lastDNSResults.map(function(r, idx) {
      if (r.error) {
        return '<tr class="dns-error-row"><td>' + (idx + 1) + '</td><td>' + escapeHtml(r.domain) + '</td><td colspan="2">' + escapeHtml(r.error) + '</td></tr>';
      }
      var ips = (r.ips || []).map(function(ip) { return '<span class="dns-ip-tag">' + escapeHtml(ip) + '</span>'; }).join('');
      return '<tr><td>' + (idx + 1) + '</td><td>' + escapeHtml(r.domain) + '</td><td>' + ips + '</td><td><span class="badge badge-completed">成功</span></td></tr>';
    }).join('');

    exportBtn.style.display = 'inline-flex';
    showToast('解析完成：成功 ' + data.resolved + ' 条，失败 ' + data.failed + ' 条', data.failed > 0 ? 'running' : 'success');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="4" class="error-state">请求失败：' + escapeHtml(err.message || '网络错误') + '</td></tr>';
    showToast('请求失败：' + (err.message || '网络错误'), 'error');
  }
}

async function exportDNSResults() {
  const textarea = document.getElementById('domainList');
  const domains = textarea.value.trim();
  if (!domains) {
    showToast('无数据可导出', 'error');
    return;
  }
  try {
    const resp = await fetch('/api/dns/export', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      // 带上页面已解析的结果，导出内容与页面一致，且不会重复解析
      body: JSON.stringify({domains: domains, results: lastDNSResults})
    });
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'dns_results.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('CSV 文件已导出', 'success');
  } catch (err) {
    showToast('导出失败：' + (err.message || '网络错误'), 'error');
  }
}

function clearDNSResults() {
  document.getElementById('domainList').value = '';
  setDisp('dnsResultsArea', false, 'block');
  setDisp('singleResult', false, 'block');
  document.getElementById('singleDomainInput').value = '';
  lastDNSResults = [];
}

// ========== Settings ==========
async function loadSettings() {
  try {
    const resp = await apiFetch('/api/settings');
    const settings = await resp.json();
    document.getElementById('settingsList').innerHTML = settings.map(s => {
      var isPathField = s.key === 'nmap_path' || s.key === 'masscan_path';
      return isPathField ? `
      <div class="form-group">
        <label for="setting_${s.key}">${escapeHtml(s.label)}</label>
        <div class="input-with-verify">
          <input type="text" id="setting_${s.key}" value="${escapeHtml(s.value)}">
          <button type="button" class="btn btn-sm btn-outline verify-btn" onclick="verifyToolPath('${s.key}')">验证</button>
        </div>
        <div id="verify_${s.key}" class="verify-result" style="display:none"></div>
        <small class="form-hint">${escapeHtml(s.description)}</small>
      </div>` : `
      <div class="form-group">
        <label for="setting_${s.key}">${escapeHtml(s.label)}</label>
        <input type="${s.type === 'number' ? 'number' : 'text'}" id="setting_${s.key}" value="${escapeHtml(s.value)}">
        <small class="form-hint">${escapeHtml(s.description)}</small>
     </div>`;
   }).join('');
  } catch(err) {
    document.getElementById('settingsList').innerHTML = `<div class="error-state">加载失败: ${escapeHtml(err.message)}</div>`;
  }
}

async function verifyToolPath(key) {
  const input = document.getElementById('setting_' + key);
  const resultEl = document.getElementById('verify_' + key);
  const path = input.value.trim();
  if (!path) {
    resultEl.className = 'verify-result verify-error';
    resultEl.textContent = '请输入路径';
    resultEl.style.display = 'block';
    return;
  }
  resultEl.className = 'verify-result verify-checking';
  resultEl.textContent = '验证中...';
  resultEl.style.display = 'block';
  try {
    const resp = await fetch('/api/settings/verify?path=' + encodeURIComponent(path));
    const data = await resp.json();
    resultEl.className = 'verify-result ' + (data.valid ? 'verify-success' : 'verify-error');
    resultEl.textContent = data.message;
    resultEl.style.display = 'block';
  } catch (err) {
    resultEl.className = 'verify-result verify-error';
    resultEl.textContent = '✗ 验证请求失败: ' + (err.message || '网络错误');
    resultEl.style.display = 'block';
  }
}

async function saveSettings() {
  const settings = {};
  document.querySelectorAll('#settingsList input, #settingsList select').forEach(input => {
    settings[input.id.replace('setting_', '')] = input.value;
  });
  const msgEl = document.getElementById('settingsSaveMsg');
  msgEl.style.display = 'none';
  try {
    const resp = await fetch('/api/settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(settings)
    });
    const data = await resp.json();
    if (data.success) {
      msgEl.textContent = '✓ 设置已保存成功';
      msgEl.className = 'form-msg form-success';
      msgEl.style.display = 'block';
      showToast('✓ 设置已保存成功', 'success');
    } else {
      msgEl.textContent = '✗ 保存失败: ' + (data.message || '请重试');
      msgEl.className = 'form-msg form-error';
      msgEl.style.display = 'block';
      showToast('✗ ' + (data.message || '保存失败'), 'error');
    }
  } catch (err) {
    msgEl.textContent = '✗ 保存失败: 网络错误，请重试';
    msgEl.className = 'form-msg form-error';
    msgEl.style.display = 'block';
    showToast('✗ 保存失败: 网络错误', 'error');
  }
  setTimeout(function() {
    var el = document.getElementById('settingsSaveMsg');
    if (el) el.style.display = 'none';
  }, 4000);
}

// ========== Utilities ==========
function escapeHtml(str) { return !str ? '' : String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function statusLabel(s) { return {pending:'等待',running:'运行中',paused:'已暂停',completed:'完成',failed:'失败',cancelled:'已取消'}[s]||s; }
function modeLabel(s) { return {full:'全套扫描',alive_only:'存活探测',port_only:'端口扫描',service_only:'服务识别',nmap_port_scan:'Nmap端口扫描'}[s]||'全套扫描'; }
function phaseLabel(p) { return {idle:'等待',ping_scan:'存活探测',port_scan:'端口扫描',service_scan:'服务识别',nmap_scan:'Nmap端口扫描',completed:'完成'}[p]||p; }
function formatElapsed(s) {
  if (!s) return '0s';
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  return h>0 ? `${h}h ${m}m ${sec}s` : m>0 ? `${m}m ${sec}s` : `${sec}s`;
}
function truncateText(s, n) {
  if (!s) return '';
  s = String(s);
  return s.length > n ? s.slice(0, n) + '...' : s;
}

// ========== Auto Refresh ==========
var autoRefreshTimer = null;

async function loadTasksWithRefresh() {
  await loadTasks();
  setupAutoRefresh();
}

function setupAutoRefresh() {
  if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
  fetch('/api/settings').then(function(r) { return r.json(); }).then(function(settings) {
    var intervalSetting = 0;
    for (var i = 0; i < settings.length; i++) {
      if (settings[i].key === 'refresh_interval') {
        intervalSetting = parseInt(settings[i].value) || 0;
        break;
      }
    }
    if (intervalSetting > 0) {
      autoRefreshTimer = setInterval(function() {
        var path = window.location.pathname;
        if (path === '/tasks' || path === '/tasks/') loadTasks();
      }, intervalSetting * 1000);
    }
  }).catch(function() {});
}

// ========== Init ==========
document.addEventListener('DOMContentLoaded', function() {
  const path = window.location.pathname;
  if (path === '/tasks' || path === '/tasks/') { loadTasksWithRefresh(); loadPortPresets(); }
  else if (path.match(/^\/tasks\/\d+$/)) loadTaskDetail();
  else if (path.match(/^\/results\/\d+$/)) loadResults();
  else if (path.match(/^\/output\/\d+$/)) loadOutput();
  else if (path === '/settings' || path === '/settings/') loadSettings();
  else if (path === '/dns' || path === '/dns/') { /* DNS page ready, no init needed */ }
  else if (path === '/docs' || path === '/docs/') { /* Docs page ready, no init needed */ }

  document.querySelectorAll('.modal').forEach(el => {
    el.addEventListener('click', function(e) { if (e.target === this) this.style.display = 'none'; });
  });
});

// 从 bfcache / 内存缓存恢复页面时，DOM 还是上一次的快照（进度停在“等待开始”），
// 这里强制按最新数据重载一次详情页；标签页重新可见 / 窗口重新获得焦点时也立即对齐。
window.addEventListener('pageshow', function(e) {
  if (!/^\/tasks\/\d+$/.test(window.location.pathname)) return;
  if (e.persisted) { loadTaskDetail(); return; }
  if (currentTaskId) refreshTaskSnapshot();
});

document.addEventListener('visibilitychange', function() {
  if (document.hidden) return;
  if (/^\/tasks\/\d+$/.test(window.location.pathname) && currentTaskId) refreshTaskSnapshot();
});

window.addEventListener('focus', function() {
  if (/^\/tasks\/\d+$/.test(window.location.pathname) && currentTaskId) refreshTaskSnapshot();
});