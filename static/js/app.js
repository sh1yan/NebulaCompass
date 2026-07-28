// ========== Auth ==========
async function handleLogout() {
  await fetch('/api/logout', { method: 'POST' });
  if (detailEventSource) { detailEventSource.close(); detailEventSource = null; }
  if (outputEventSource) { outputEventSource.close(); outputEventSource = null; }
  document.cookie = 'session_token=; path=/; max-age=-1';
  window.location.href = '/login';
}

function showModal(id) { document.getElementById(id).style.display = 'flex'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; }
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
async function loadTasks() {
  const listEl = document.getElementById('taskList');
  if (!listEl) return;
  try {
    const resp = await apiFetch('/api/tasks');
    const tasks = await resp.json();
    if (!tasks || tasks.length === 0) {
      listEl.innerHTML = '<div class="empty-state"><p>暂无扫描任务，点击右上角"新建任务"开始</p></div>';
      return;
    }
    listEl.innerHTML = tasks.map(t => `
      <div class="task-card">
        <div class="task-main">
          <div class="task-info">
            <div class="task-name"><a href="/tasks/${t.id}">${escapeHtml(t.name)}</a></div>
            <div class="${t.target && t.target.includes(String.fromCharCode(10)) ? 'task-target-multi' : 'task-target'}">${escapeHtml(t.target)}</div>
            <div class="task-target" style="font-family:var(--font);font-size:11px;margin-top:4px">模式: ${modeLabel(t.scan_mode)}</div>
          </div>
          <div class="task-meta-row">
            <span class="badge badge-${t.status}">${statusLabel(t.status)}</span>
            <span class="meta-item">阶段: ${phaseLabel(t.current_phase)}</span>
            <span class="meta-item">进度: ${Math.round(t.progress_pct)}%</span>
            <span class="meta-item">耗时: ${formatElapsed(t.elapsed_seconds)}</span>
            ${t.total_hosts > 0 ? `<span class="meta-item">主机: ${t.total_hosts}</span>` : ''}
            ${t.total_ports > 0 ? `<span class="meta-item">端口: ${t.total_ports}</span>` : ''}
          </div>
        </div>
        <div class="task-actions">
          ${t.status === 'pending' ? `<button class="btn btn-primary btn-sm" onclick="location.href='/tasks/${t.id}'">开始</button>` : ''}
          ${t.status === 'running' ? `<button class="btn btn-danger btn-sm" onclick="cancelTaskById(${t.id})">取消</button>` : ''}
          ${t.status === 'completed' ? `<button class="btn btn-success btn-sm" onclick="location.href='/results/${t.id}'">结果</button>` : ''}
          ${t.status === 'running' || t.status === 'completed' || t.status === 'failed' ? `<button class="btn btn-sm" onclick="location.href='/output/${t.id}'">输出</button>` : ''}
          <button class="btn btn-sm btn-outline" onclick="deleteTask(${t.id})" ${t.status === 'running' ? 'disabled' : ''}>删除</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    listEl.innerHTML = `<div class="error-state">加载失败: ${err.message}</div>`;
  }
}

// ========== Create Task ==========
function refreshTasks() { loadTasks(); showToast('已刷新任务列表', 'success'); }

function showCreateTask() { showModal('createTaskModal'); }

async function handleCreateTask(e) {
  e.preventDefault();
  const name = document.getElementById('taskName').value.trim();
  const target = document.getElementById('taskTarget').value.trim();
  const portRange = document.getElementById('taskPortRange').value.trim() || '1-65535';
  const scanModeEl = document.querySelector('input[name="scan_mode"]:checked');
  const scanMode = scanModeEl ? scanModeEl.value : 'full';
  const submitBtn = document.querySelector('#createTaskForm button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = '创建中...';
  try {
  const resp = await fetch('/api/tasks', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ name, target, port_range: portRange, scan_mode: scanMode })
  });
  const data = await resp.json();
  if (data.success) {
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
    if (window.showToast) {
      showToast(data.message || '创建失败', 'error');
    } else {
      alert(data.message || '创建失败');
    }
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
    '确定要删除该任务吗？关联的扫描结果也将被删除。此操作不可撤销。',
    'danger',
    async function() {
      await fetch('/api/tasks/' + id + '/delete', { method: 'POST' });
      closeConfirmModal();
      loadTasks();
    }
  );
}

async function cancelTaskById(id) {
  showConfirmModal(
    '取消任务',
    '确定要取消该扫描任务吗？后台扫描进程将被中断，已扫描的数据将被保留。',
    'warning',
    async function() {
      await fetch('/api/tasks/' + id + '/cancel', { method: 'POST' });
      closeConfirmModal();
      loadTasks();
    }
  );
}

// ========== Task Detail ==========
let currentTaskId = null;
let detailEventSource = null;

async function loadTaskDetail() {
  const pathParts = window.location.pathname.split('/');
  const id = parseInt(pathParts[pathParts.length - 1]);
  if (isNaN(id)) return;
  currentTaskId = id;

  try {
  const resp = await apiFetch(`/api/tasks/${id}`);
  const task = await resp.json();

  var portRangeValue = escapeHtml(task.port_range||'1-65535');
  if (task.scan_mode === 'service_only') portRangeValue = '按目标指定';
  if (task.scan_mode === 'alive_only') portRangeValue = '不适用';
  var portRangeItem = task.scan_mode === 'alive_only'
    ? '<div class="detail-item detail-hidden" style="display:none"><div class="detail-value">'+portRangeValue+'</div><div class="detail-label">端口范围</div></div>'
    : '<div class="detail-item"><div class="detail-value">'+portRangeValue+'</div><div class="detail-label">端口范围</div></div>';
  document.getElementById('taskInfo').innerHTML = `
    <div class="detail-grid">
      <div class="detail-item"><div class="detail-value">${escapeHtml(task.name)}</div><div class="detail-label">任务名称</div></div>
      <div class="detail-item detail-target"><div class="detail-value">${escapeHtml(task.target)}</div><div class="detail-label">扫描目标</div></div>
      ${portRangeItem}
      <div class="detail-item"><div class="detail-value"><span class="badge badge-${task.status}">${statusLabel(task.status)}</span></div><div class="detail-label">状态</div></div>
      <div class="detail-item"><div class="detail-value">${modeLabel(task.scan_mode)}</div><div class="detail-label">扫描模式</div></div>
    </div>
    ${task.error_message ? `<div class="error-msg">${escapeHtml(task.error_message)}</div>` : ''}
  `;

  updatePhaseUI(task);

  document.getElementById('taskActions').style.display = 'block';
  document.getElementById('startBtn').style.display = (task.status === 'pending') ? 'inline-flex' : 'none';
  document.getElementById('cancelBtn').style.display = (task.status === 'running') ? 'inline-flex' : 'none';
  document.getElementById('viewResultsBtn').style.display = (task.status === 'completed') ? 'inline-flex' : 'none';
  document.getElementById('viewOutputBtn').style.display = (task.status === 'running' || task.status === 'failed') ? 'inline-flex' : 'none';

  if (task.status === 'completed' || task.status === 'running') {
    document.getElementById('taskSummary').style.display = 'block';
    loadTaskSummary(id);
  }
  if (task.status === 'running' || task.status === 'pending') {
    subscribeDetailSSE(id);
  }
  } catch (err) {
    console.error('loadTaskDetail error:', err);
    document.getElementById('taskInfo').innerHTML = '<div class="error-state">加载失败: ' + escapeHtml(err.message || '未知错误') + '</div>';
  }
}


function detailAppendOutput(line, source) {
  var container = document.getElementById("detailOutputLines");
  var placeholder = container.querySelector(".output-placeholder");
  if (placeholder) placeholder.remove();
  var div = document.createElement("div");
  div.className = "output-log-line";
  if (source === "ping_scan") div.classList.add("output-ping");
  else if (source === "port_scan") div.classList.add("output-port");
  else if (source === "service_scan") div.classList.add("output-svc");
  else if (source === "info") div.classList.add("output-info");
  else if (line.startsWith("[stderr]")) div.classList.add("output-err");
  var now = new Date();
  var ts = now.toTimeString().slice(0, 8);
  div.textContent = "[" + ts + "] " + line;
  container.appendChild(div);
  var scrollContainer = document.getElementById("detailOutputContainer");
  scrollContainer.scrollTop = scrollContainer.scrollHeight;
}

function updatePhaseUI(task) {
  var progressEl = document.getElementById('taskProgress');
  if (!progressEl) return;
  progressEl.style.display = 'block';
  const phases = ['idle', 'ping_scan', 'port_scan', 'service_scan', 'completed'];
  const phaseOrder = { 'idle': 0, 'ping_scan': 1, 'port_scan': 2, 'service_scan': 3, 'completed': 4 };
  const current = phaseOrder[task.current_phase] || 0;
  document.querySelectorAll('.phase-step').forEach(function(el, i) {
    el.className = 'phase-step';
    if (i < current) el.classList.add('completed');
    else if (i === current) el.classList.add('active');
  });
  var fillEl = document.getElementById('progressFill');
  if (fillEl) fillEl.style.width = Math.round(task.progress_pct) + '%';
  var pctEl = document.getElementById('progressText');
  if (pctEl) pctEl.textContent = Math.round(task.progress_pct) + '%';
  var elpEl = document.getElementById('elapsedText');
  if (elpEl) elpEl.textContent = '耗时: ' + formatElapsed(task.elapsed_seconds);
}

async function loadTaskSummary(taskId) {
  const resp = await apiFetch(`/api/results/summary/${taskId}`);
  const data = await resp.json();
  const s = data.summary;
  document.getElementById('summaryContent').innerHTML = `
    <div class="stat-box"><div class="stat-num" style="color:var(--primary)">${s.total}</div><div class="stat-lbl">端口总数</div></div>
    <div class="stat-box"><div class="stat-num" style="color:var(--success)">${s.open}</div><div class="stat-lbl">开放</div></div>
    <div class="stat-box"><div class="stat-num" style="color:var(--warning)">${s.filtered||0}</div><div class="stat-lbl">过滤</div></div>
    <div class="stat-box"><div class="stat-num" style="color:var(--accent)">${s.services||0}</div><div class="stat-lbl">服务识别</div></div>
  `;
}

function subscribeDetailSSE(taskId) {
  if (detailEventSource) { detailEventSource.close(); }
  detailEventSource = new EventSource(`/api/sse/${taskId}`);
  detailEventSource.addEventListener('progress', (e) => {
    const evt = JSON.parse(e.data);
    updatePhaseUI({ status: evt.status, current_phase: evt.current_phase, progress_pct: evt.progress_pct, elapsed_seconds: evt.elapsed_seconds });
    updateProgressBarStyle(evt.status);
    if (evt.status === 'running') {
      document.getElementById('liveOutputSection').style.display = 'block';
    }
    if (evt.status === 'completed' || evt.status === 'failed' || evt.status === 'cancelled') {
      detailEventSource.close();
      detailEventSource = null;
      loadTaskDetail();
    }
  });
  detailEventSource.addEventListener('output', (e) => {
    const evt = JSON.parse(e.data);
    detailAppendOutput(evt.output_line, evt.output_source);
  });
  detailEventSource.onerror = () => {};
}

async function startTask() {
  if (!currentTaskId) return;
  document.getElementById('startBtn').disabled = true;
  await fetch(`/api/tasks/${currentTaskId}/start`, { method: 'POST' });
  loadTaskDetail();
}

async function cancelTask() {
  if (!currentTaskId) return;
  showConfirmModal(
    '取消任务',
    '确定要取消该扫描任务吗？后台扫描进程将被中断，已扫描的数据将被保留。',
    'warning',
    async function() {
      await fetch('/api/tasks/' + currentTaskId + '/cancel', { method: 'POST' });
      closeConfirmModal();
      loadTaskDetail();
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
    var modeLabel = {'full':'全套扫描','alive_only':'存活探测','port_only':'端口扫描','service_only':'服务识别','nmap_port_scan':'Nmap端口扫描'};
    var sm = document.getElementById('resultScanMode'); if (sm) sm.textContent = '扫描模式: ' + (modeLabel[task.scan_mode] || task.scan_mode || '全套扫描');
    aliveHosts = task.alive_hosts || [];
    scanMode = task.scan_mode;
    resultsScanMode = scanMode;
  }
  const sumResp = await apiFetch(`/api/results/summary/${id}`);
  const sumData = await sumResp.json();
  aliveOnly = sumData.alive_only || [];
  const hosts = sumData.hosts || [];
  const s = sumData.summary || {total:0,open:0,filtered:0,services:0};
  const safeSetText = function(id, val) { var el = document.getElementById(id); if (el) el.textContent = val; };
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
    // Hide the table card container to prevent white bar
    if (rt) { var tc = rt.closest('.card'); if (tc) tc.style.display = 'none'; }
    ['statTotal','statOpen','statFiltered','statServices','statHostsWithPorts'].forEach(function(sid) {
      var el = document.getElementById(sid);
      if (el) { var card = el.closest('.stat-card'); if (card) card.style.display = 'none'; }
    });
    // Fix the row layout - collapse gap
    var statsRow = document.getElementById('statsRow');
    if (statsRow) statsRow.classList.add('stats-row-alive');
  }
  try { await loadResultsTable(id); } catch (e) { console.error('loadResultsTable error:', e); }
  if (scanMode !== 'alive_only') { try { await loadServiceDist(id); } catch (e) { console.error('loadServiceDist error:', e); } }
  try { loadHostSummary(id, aliveHosts, aliveOnly, scanMode, hosts); } catch (e) { console.error('loadHostSummary error:', e); }
  } catch (err) {
    console.error('loadResults error:', err);
    document.getElementById('resultsBody').innerHTML = '<tr><td colspan="8" class="error-state">加载失败: ' + escapeHtml(err.message || '未知错误') + '</td></tr>';
  }
}
async function loadResultsTable(taskId) {
  const resp = await apiFetch(`/api/results/${taskId}`);
  allResults = await resp.json();
  currentPage = 1;
  renderResultsPage();
}

function renderResultsPage() {
  const tbody = document.getElementById('resultsBody');
  if (!allResults || allResults.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="loading">暂无扫描结果</td></tr>';
    document.getElementById('pagination').style.display = 'none';
    return;
  }
  const total = allResults.length;
  const totalPages = Math.ceil(total / pageSize);
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  const start = (currentPage - 1) * pageSize;
  const end = Math.min(start + pageSize, total);
  const pageData = allResults.slice(start, end);

  tbody.innerHTML = pageData.map(r => `<tr>
    <td>${r.ip}</td><td>${r.port}</td><td>${r.protocol}</td>
    <td><span class="badge badge-${r.state === 'open' ? 'completed' : 'pending'}">${r.state}</span></td>
    <td>${escapeHtml(r.service)}</td><td>${escapeHtml(r.product)}</td><td>${escapeHtml(r.version)}</td><td>${escapeHtml(r.os_details)}</td>
  </tr>`).join('');

  document.getElementById('pagination').style.display = 'flex';
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

async function searchResults() {
  if (!resultsTaskId) return;
  const query = document.getElementById('searchInput').value.trim();
  const resp = await apiFetch(`/api/results/${resultsTaskId}${query ? '?search=' + encodeURIComponent(query) : ''}`);
  allResults = await resp.json();
  currentPage = 1;
  renderResultsPage();
}

async function loadServiceDist(taskId) {
  const resp = await apiFetch(`/api/results/services/${taskId}`);
  const services = await resp.json();
  const entries = Object.entries(services).sort((a,b) => b[1]-a[1]).slice(0,20);
  document.getElementById('serviceChart').innerHTML = entries.map(([svc, n]) =>
    `<span class="service-tag">${escapeHtml(svc)} (${n})</span>`
  ).join('') || '<p style="color:var(--muted)">暂无服务数据</p>';
}

async function loadHostSummary(taskId, aliveHosts, aliveOnly, scanMode, hosts) {
  if (!hosts) { hosts = []; }
  let html = '';
  var isAliveOnlyMode = (scanMode === 'alive_only');
  if (hosts.length > 0) {
    html += '<div style="margin-bottom:12px"><strong>有开放端口的主机</strong></div>';
    html += hosts.map(h =>
      '<div class="host-item"><span class="host-ip">' + h.ip + '</span><span class="host-ports">' + ((h.ports||[]).join(', ')) + '</span></div>'
    ).join('');
  }
  if (aliveOnly && aliveOnly.length > 0) {
    if (html) html += '<hr style="margin:12px 0;border-color:var(--border)">';
    var sectionTitle = isAliveOnlyMode ? '存活主机' : '仅存活（无开放端口）的主机';
    var portLabel = isAliveOnlyMode ? '' : '无开放端口';
    html += '<div style="margin-bottom:12px"><strong>' + sectionTitle + '</strong></div>';
    html += aliveOnly.map(ip => {
      var portStr = portLabel ? '<span class="host-ports" style="color:var(--text-muted)">' + portLabel + '</span>' : '<span class="host-card-alive-badge alive-only">&#10003;存活</span>';
      return '<div class="host-card-item"><span class="host-card-ip">' + ip + '</span>' + portStr + '</div>';
    }).join('');
  }
  if (!html) {
    html = '<p style="color:var(--text-muted);text-align:center;padding:20px 0">' + (isAliveOnlyMode ? '暂无存活主机' : '暂无主机数据') + '</p>';
  }
  document.getElementById('hostSummary').innerHTML = html;
}

function exportResults() { if (resultsTaskId) window.location.href = `/api/results/export/${resultsTaskId}`; }

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
  if (resp.ok) {
    const task = await resp.json();
    document.getElementById('outputTaskName').textContent = task.name || '实时输出';
    updateOutputBadge(task.status);
    document.getElementById('outputStatusBadge').setAttribute('data-task-status', task.status);
    
    // 如果任务失败，显示错误信息
    if (task.status === 'failed' && task.error_message) {
      document.getElementById('errorOutputSection').style.display = 'block';
      document.getElementById('errorOutputContent').textContent = task.error_message;
      updateProgressBarStyle('failed');
    }
    
    // 显示已保存的输出（即使部分输出也能查看）
    renderSavedOutput(task.ping_output, 'ping_scan', '存活探测');
    renderSavedOutput(task.port_scan_output, 'port_scan', '端口扫描');
    renderSavedOutput(task.service_output, 'service_scan', '服务识别');
    renderCmdRecords(task.cmd_records);
    
    // 如果已完成或失败，更新进度条到最终状态
    document.getElementById('outputProgressFill').style.width = Math.round(task.progress_pct) + '%';
    if (task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled') {
      updateProgressBarStyle(task.status);
    }
  }
  subscribeOutputSSE(id);
}

function renderSavedOutput(rawText, source, phaseLabel) {
  if (!rawText || !rawText.trim()) return;
  const container = document.getElementById('outputLines');
  const placeholder = container.querySelector('.output-placeholder');
  if (placeholder) placeholder.remove();
  const headerDiv = document.createElement('div');
  headerDiv.className = 'output-log-line output-info';
  headerDiv.textContent = '--- ' + phaseLabel + ' 输出 ---';
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
  badge.className = 'badge badge-' + status;
  badge.textContent = statusLabel(status);
}

function subscribeOutputSSE(taskId) {
  if (outputEventSource) { outputEventSource.close(); }
  // 如果还没有历史内容，显示等待连接
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

  outputEventSource.addEventListener('progress', (e) => {
    const evt = JSON.parse(e.data);
    document.getElementById('outputProgressFill').style.width = Math.round(evt.progress_pct) + '%';
    document.getElementById('outputElapsed').textContent = formatTimer(evt.elapsed_seconds);
    updateOutputBadge(evt.status);
    updateProgressBarStyle(evt.status);
    if (evt.status === 'failed') {
      showFailedTaskOutput();
    }
    if (evt.status === 'completed') {
      appendOutputLine('--- 扫描完成 ---', 'info');
    }
    if (evt.status === 'cancelled') {
      appendOutputLine('--- 扫描已取消 ---', 'info');
    }
  });

  outputEventSource.addEventListener('connected', () => {
    var badgeText = document.getElementById('outputStatusBadge').textContent;
    if (badgeText === '完成' || badgeText === '失败' || badgeText === '已取消') {
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

  // Color by source
  if (source === 'ping_scan') div.classList.add('output-ping');
  else if (source === 'port_scan') div.classList.add('output-port');
  else if (source === 'service_scan') div.classList.add('output-svc');
  else if (source === 'info') div.classList.add('output-info');
  else if (line.startsWith('[stderr]')) div.classList.add('output-err');

  // Timestamp
  const now = new Date();
  const ts = now.toTimeString().slice(0, 8);
  div.textContent = `[${ts}] ${line}`;

  container.appendChild(div);

  // Auto scroll
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
    var sep = line.indexOf(' ');
    var sourceHint = '';
    if (line.indexOf('-sn') > -1 || line.indexOf('-sV') > -1) {
      sourceHint = (line.indexOf('-sn') > -1) ? '存活探测' : '服务识别';
    } else if (line.indexOf('nmap') > -1) {
      sourceHint = '端口扫描';
    }
    if (line.indexOf('masscan') > -1) sourceHint = '端口扫描';
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
  const sourceMap = {'ping_scan': '存活探测', 'port_scan': '端口扫描', 'service_scan': '服务识别'};
  const prefix = sourceMap[source] || '命令';

  const now = new Date();
  const ts = now.toTimeString().slice(0, 8);
  div.textContent = '[' + ts + '] [' + prefix + '] $ ' + cmdLine;

  container.appendChild(div);

  // Auto scroll
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
  if (!seconds) return '00:00:00';
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
  setTimeout(function() { toast.remove(); }, 2000);
}

// ========== Progress Bar Color Update ==========
function updateProgressBarStyle(status) {
  // Update output progress fill
  var fill = document.getElementById('outputProgressFill');
  if (fill) {
    fill.classList.remove('progress-completed', 'progress-failed', 'progress-cancelled');
    if (status === 'completed') fill.classList.add('progress-completed');
    else if (status === 'failed') fill.classList.add('progress-failed');
    else if (status === 'cancelled') fill.classList.add('progress-cancelled');
  }
  // Update detail progress fill
  var detailFill = document.getElementById('progressFill');
  if (detailFill) {
    detailFill.classList.remove('progress-completed', 'progress-failed', 'progress-cancelled');
    if (status === 'completed') detailFill.classList.add('progress-completed');
    else if (status === 'failed') detailFill.classList.add('progress-failed');
    else if (status === 'cancelled') detailFill.classList.add('progress-cancelled');
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
  if (iconClass === 'danger') btn.style.background = 'var(--danger)';
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
  
  var hints = {
    'full': '默认全套扫描流程：存活探测 &rarr; Masscan端口扫描 &rarr; 服务版本识别。请输入目标网段或 IP',
    'alive_only': '仅进行主机存活探测（Ping扫描），无需端口范围。请输入目标网段或 IP，每行一个',
    'port_only': '存活探测 + 端口扫描，不进行服务识别。请输入目标网段或 IP',
    'service_only': '仅对指定 IP:端口 进行服务版本识别。请输入 IP:端口 格式，每行一个（如 192.168.1.1:80）',
    'nmap_port_scan': '使用 Nmap 进行端口扫描（代替 Masscan）。请输入目标网段或 IP，每行一个'
  };
  
  hint.innerHTML = hints[mode] || '';
  hint.style.display = 'block';
  hint.className = 'scan-mode-hint';
  if (mode === 'service_only') hint.classList.add('warning');
  
  // Update target help text and placeholder
  var portRangeGroup = document.getElementById('portRangeGroup');
  if (mode === 'service_only' || mode === 'alive_only') {
    targetEl.placeholder = mode === 'service_only' ? '192.168.1.1:80\n10.0.0.5:443\n172.16.1.100:3306' : '192.168.1.0/24\n10.0.0.1\n172.16.0.0/16';
    targetHint.textContent = mode === 'service_only' ? '服务扫描模式需要输入 IP:端口 格式，每行一个' : '支持多个目标，每行一个。支持 CIDR、IP 范围、单个 IP';
    if (csvArea) csvArea.style.display = mode === 'service_only' ? 'none' : 'flex';
    if (portRangeGroup) portRangeGroup.style.display = 'none';
  } else {
    targetEl.placeholder = '192.168.1.0/24\n10.0.0.1\n172.16.0.0/16';
    targetHint.textContent = '支持多个目标，每行一个。支持 CIDR、IP 范围、单个 IP';
    if (csvArea) csvArea.style.display = 'flex';
    if (portRangeGroup) portRangeGroup.style.display = 'block';
  }
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
    var ipRe = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
    var cidrRe = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/\d{1,2}\b/;
    
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      // Try to extract CIDR or IP from each line (handle CSV columns)
      var parts = line.split(/[,\t;|]/);
      for (var j = 0; j < parts.length; j++) {
        var part = parts[j].trim();
        // Check for CIDR first
        var cidrMatch = part.match(cidrRe);
        if (cidrMatch) {
          ips.push(cidrMatch[0]);
          continue;
        }
        // Check for IP
        var ipMatch = part.match(ipRe);
        if (ipMatch) {
          ips.push(ipMatch[0]);
        }
      }
    }
    
    // Remove duplicates
    ips = ips.filter(function(ip, idx) { return ips.indexOf(ip) === idx; });
    
    if (ips.length > 0) {
      var targetEl = document.getElementById('taskTarget');
      var existing = targetEl.value.trim();
      if (existing) existing += '\n';
      targetEl.value = existing + ips.join('\n');
      fileInfo.textContent += ' - 已提取 ' + ips.length + ' 个 IP/网段';
      showToast('已从 CSV 提取 ' + ips.length + ' 个目标', 'success');
    } else {
      fileInfo.textContent = file.name + ' - 未找到有效 IP';
      showToast('CSV 文件中未找到有效的 IP 地址', 'error');
    }
  };
  reader.readAsText(file);
}

function showFailedTaskOutput() {
  var sec = document.getElementById('errorOutputSection');
  if (sec) sec.style.display = 'block';
  // Try to load error message from API
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
      body: JSON.stringify({domains: domains})
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
  document.getElementById('dnsResultsArea').style.display = 'none';
  document.getElementById('singleResult').style.display = 'none';
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
    document.getElementById('settingsList').innerHTML = `<div class="error-state">加载失败: ${err.message}</div>`;
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
function statusLabel(s) { return {pending:'等待',running:'运行中',completed:'完成',failed:'失败',cancelled:'已取消'}[s]||s; }
function modeLabel(s) { return {full:'全套扫描',alive_only:'存活探测',port_only:'端口扫描',service_only:'服务识别',nmap_port_scan:'Nmap端口扫描'}[s]||'全套扫描'; }
function phaseLabel(p) { return {idle:'等待',ping_scan:'存活探测',port_scan:'端口扫描',service_scan:'服务识别',completed:'完成'}[p]||p; }
function formatElapsed(s) {
  if (!s) return '0s';
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  return h>0 ? `${h}h ${m}m ${sec}s` : m>0 ? `${m}m ${sec}s` : `${sec}s`;
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
  if (path === '/tasks' || path === '/tasks/') loadTasksWithRefresh();
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
