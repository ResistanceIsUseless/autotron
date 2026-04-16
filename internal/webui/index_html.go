package webui

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Autotron ASM</title>
  <style>
    :root {
      --bg: #1a1b26;
      --bg2: #16161e;
      --card: #1f2335;
      --card-hover: #24283b;
      --ink: #c0caf5;
      --ink2: #a9b1d6;
      --muted: #565f89;
      --accent: #7aa2f7;
      --accent2: #7dcfff;
      --green: #9ece6a;
      --yellow: #e0af68;
      --orange: #ff9e64;
      --red: #f7768e;
      --purple: #bb9af7;
      --line: #292e42;
      --line2: #3b4261;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, monospace; background: var(--bg); color: var(--ink); font-size: 13px; }
    .wrap { max-width: 1400px; margin: 0 auto; padding: 16px; }
    .header { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--line); }
    .header h1 { margin: 0; font-size: 20px; color: var(--accent); font-weight: 700; letter-spacing: -0.5px; }
    .header .scan-badge { font-size: 11px; padding: 3px 10px; border-radius: 999px; font-weight: 600; }
    .scan-running { background: rgba(158,206,106,0.15); color: var(--green); border: 1px solid rgba(158,206,106,0.3); }
    .scan-idle { background: rgba(86,95,137,0.2); color: var(--muted); border: 1px solid var(--line); }
    .poll-indicator { font-size: 10px; color: var(--muted); margin-left: auto; }

    .grid { display: grid; gap: 12px; }
    .grid-stats { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }
    .grid-2 { grid-template-columns: 1fr 1fr; }
    .grid-3 { grid-template-columns: 2fr 1fr 1fr; }
    @media (max-width: 900px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } }

    .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px; }
    .card:hover { border-color: var(--line2); }
    .card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
    .card-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); }

    .stat { text-align: center; padding: 12px 8px; }
    .stat .val { font-size: 28px; font-weight: 800; color: var(--ink); }
    .stat .lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }

    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 6px 8px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); border-bottom: 1px solid var(--line); }
    td { padding: 6px 8px; border-bottom: 1px solid var(--line); font-size: 12px; color: var(--ink2); vertical-align: top; }
    tr:hover td { background: rgba(122,162,247,0.04); }

    a { color: var(--accent2); text-decoration: none; }
    a:hover { text-decoration: underline; }

    .pill { display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: 10px; font-weight: 600; }
    .sev-critical { background: rgba(247,118,142,0.2); color: var(--red); }
    .sev-high { background: rgba(255,158,100,0.2); color: var(--orange); }
    .sev-medium { background: rgba(224,175,104,0.2); color: var(--yellow); }
    .sev-low { background: rgba(122,162,247,0.15); color: var(--accent); }
    .sev-info { background: rgba(86,95,137,0.2); color: var(--muted); }
    .status-running { color: var(--green); }
    .status-completed { color: var(--accent); }
    .status-cancelled { color: var(--yellow); }
    .status-failed { color: var(--red); }

    button { font: inherit; font-size: 11px; background: var(--card); color: var(--ink2); border: 1px solid var(--line); border-radius: 6px; padding: 4px 10px; cursor: pointer; }
    button:hover { background: var(--card-hover); border-color: var(--line2); }
    button.primary { background: rgba(122,162,247,0.15); color: var(--accent); border-color: rgba(122,162,247,0.3); }

    input, select { font: inherit; font-size: 11px; background: var(--bg2); color: var(--ink); border: 1px solid var(--line); border-radius: 6px; padding: 4px 8px; }
    input:focus, select:focus { outline: none; border-color: var(--accent); }

    .progress-bar { height: 6px; background: var(--line); border-radius: 3px; overflow: hidden; }
    .progress-fill { height: 100%; border-radius: 3px; transition: width 0.4s ease; }
    .progress-fill.low { background: var(--red); }
    .progress-fill.mid { background: var(--yellow); }
    .progress-fill.high { background: var(--green); }

    .activity-item { display: flex; align-items: center; gap: 8px; padding: 5px 0; border-bottom: 1px solid var(--line); font-size: 11px; }
    .activity-badge { font-size: 9px; padding: 1px 6px; border-radius: 4px; font-weight: 600; text-transform: uppercase; }
    .badge-Finding { background: rgba(247,118,142,0.2); color: var(--red); }
    .badge-Subdomain { background: rgba(122,162,247,0.15); color: var(--accent); }
    .badge-IP { background: rgba(187,154,247,0.15); color: var(--purple); }
    .badge-Service { background: rgba(125,207,255,0.15); color: var(--accent2); }
    .badge-URL { background: rgba(158,206,106,0.15); color: var(--green); }
    .badge-Domain { background: rgba(224,175,104,0.15); color: var(--yellow); }
    .activity-label { color: var(--ink2); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .activity-time { color: var(--muted); font-size: 10px; white-space: nowrap; }

    .dns-toggle { background: none; border: none; color: var(--ink); padding: 0; cursor: pointer; font-weight: 600; font-family: inherit; font-size: 12px; }
    .dns-toggle:hover { color: var(--accent); }
    .dns-caret { display: inline-block; width: 14px; color: var(--muted); }

    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .tiny { font-size: 11px; }

    .section { margin-top: 12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <h1>AUTOTRON</h1>
      <span id="scanBadge" class="scan-badge scan-idle">IDLE</span>
      <span class="poll-indicator" id="pollStatus">auto-poll off</span>
      <button onclick="refreshAll()">Refresh</button>
    </div>

    <!-- Stats row -->
    <div class="grid grid-stats" id="summary"></div>

    <!-- Main 3-col layout: activity | enricher progress | scan runs -->
    <div class="grid grid-3 section">
      <div class="card">
        <div class="card-header">
          <span class="card-title">Activity Feed</span>
          <span class="tiny" style="color:var(--muted)" id="activityCount">-</span>
        </div>
        <div id="activityFeed" style="max-height: 400px; overflow-y: auto;"></div>
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">Enricher Progress</span>
        </div>
        <div id="enricherProgress" style="max-height: 400px; overflow-y: auto;"></div>
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">Scan Runs</span>
        </div>
        <div id="scanRuns" style="max-height: 400px; overflow-y: auto;">
          <table><thead><tr><th>Target</th><th>Status</th><th>Started</th></tr></thead><tbody id="scanRows"></tbody></table>
        </div>
      </div>
    </div>

    <!-- Findings -->
    <div class="card section">
      <div class="card-header">
        <span class="card-title">Top Findings</span>
      </div>
      <table>
        <thead><tr><th>Severity</th><th>Title</th><th>Tools</th><th>Assets</th></tr></thead>
        <tbody id="findingRows"></tbody>
      </table>
    </div>

    <!-- Services grouped by DNS -->
    <div class="card section">
      <div class="card-header">
        <span class="card-title">Services by DNS</span>
        <span class="tiny" style="color:var(--muted)">click to expand</span>
      </div>
      <table>
        <thead><tr><th>DNS Name</th><th>Count</th><th>Last Seen</th></tr></thead>
        <tbody id="serviceRows"></tbody>
      </table>
    </div>

    <!-- URLs -->
    <div class="card section">
      <div class="card-header">
        <span class="card-title">Recent URLs</span>
      </div>
      <table>
        <thead><tr><th>URL</th><th>Host</th><th>Status</th><th>Title</th><th>Last Seen</th></tr></thead>
        <tbody id="urlRows"></tbody>
      </table>
    </div>

    <!-- jsRecon section -->
    <div class="grid grid-2 section">
      <div class="card">
        <div class="card-header">
          <span class="card-title">JS Assets</span>
          <div class="toolbar">
            <span class="tiny" style="color:var(--muted)" id="jsCount">0</span>
            <label class="tiny">Min score <input id="minScore" type="number" value="0" min="0" style="width:60px;" /></label>
            <label class="tiny"><input id="onlyUnmonitored" type="checkbox" /> unmon</label>
            <select id="bulkInterval"><option value="15">15m</option><option value="60" selected>1h</option><option value="360">6h</option><option value="1440">24h</option></select>
            <button onclick="applyFilters()">Filter</button>
            <button class="primary" onclick="bulkMonitor()">Add Sel</button>
          </div>
        </div>
        <table>
          <thead><tr><th></th><th>JS URL</th><th>Score</th><th></th></tr></thead>
          <tbody id="jsRows"></tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">Monitored URLs</span>
          <span id="health" class="pill" style="font-size:10px;">...</span>
        </div>
        <table>
          <thead><tr><th>Label</th><th>URL</th><th>Status</th><th></th></tr></thead>
          <tbody id="monitorRows"></tbody>
        </table>
      </div>
    </div>

    <!-- Change Events -->
    <div class="card section">
      <div class="card-header">
        <span class="card-title">Change Events</span>
        <div class="toolbar">
          <input id="changeSearch" placeholder="search..." style="width:160px;" />
          <input id="changeSince" placeholder="since..." style="width:140px;" />
          <select id="changeLimit"><option value="20">20</option><option value="50" selected>50</option><option value="100">100</option></select>
          <button onclick="applyChangeFilters()">Go</button>
          <button onclick="prevChanges()">Prev</button>
          <button onclick="nextChanges()">Next</button>
          <span class="tiny" style="color:var(--muted)" id="changeMeta">-</span>
        </div>
      </div>
      <table>
        <thead><tr><th>ID</th><th>URL</th><th>Summary</th><th>When</th></tr></thead>
        <tbody id="changeRows"></tbody>
      </table>
    </div>
  </div>

  <script>
    // --- Helpers ---
    async function j(url, opts) {
      try { const r = await fetch(url, opts || {}); return r.json(); }
      catch(e) { return {}; }
    }
    function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    function sevClass(s) { return 'sev-' + (s||'info').toLowerCase(); }
    function statusClass(s) { return 'status-' + (s||'').toLowerCase(); }
    function relTime(ts) {
      if (!ts) return '';
      const d = new Date(ts);
      if (isNaN(d)) return String(ts);
      const sec = Math.floor((Date.now() - d) / 1000);
      if (sec < 60) return sec + 's ago';
      if (sec < 3600) return Math.floor(sec/60) + 'm ago';
      if (sec < 86400) return Math.floor(sec/3600) + 'h ago';
      return Math.floor(sec/86400) + 'd ago';
    }

    // --- State ---
    let jsItems = [], monitoredSet = new Set(), scanIsRunning = false;
    let changePage = { limit: 50, offset: 0, has_more: false };
    let expandedServiceGroups = new Set(), serviceGroupMap = {};
    let pollTimer = null;
    const POLL_INTERVAL = 8000;

    // --- Loaders ---
    async function loadSummary() {
      const data = await j('/api/summary');
      const el = document.getElementById('summary');
      el.innerHTML = (data.node_counts || []).map(x =>
        '<div class="card stat"><div class="val">' + esc(x.count) + '</div><div class="lbl">' + esc(x.label) + '</div></div>'
      ).join('');
    }

    async function loadActivity() {
      const data = await j('/api/activity?limit=40');
      const el = document.getElementById('activityFeed');
      const items = data.items || [];
      document.getElementById('activityCount').textContent = items.length + ' recent';
      el.innerHTML = items.map(a =>
        '<div class="activity-item">' +
          '<span class="activity-badge badge-' + esc(a.type) + '">' + esc(a.type) + '</span>' +
          '<span class="activity-label" title="' + esc(a.label) + '">' + esc(a.label) + '</span>' +
          (a.detail ? '<span class="tiny" style="color:var(--muted)">' + esc(a.detail) + '</span>' : '') +
          '<span class="activity-time">' + relTime(a.timestamp) + '</span>' +
        '</div>'
      ).join('');
    }

    async function loadEnricherProgress() {
      const data = await j('/api/enricher-progress');
      const el = document.getElementById('enricherProgress');
      const items = (data.items || []).sort((a,b) => b.pct - a.pct);
      if (!items.length) { el.innerHTML = '<div class="tiny" style="color:var(--muted);padding:8px;">No enricher data yet</div>'; return; }
      el.innerHTML = items.map(e => {
        const pct = Math.min(100, e.pct || 0).toFixed(0);
        const cls = pct < 33 ? 'low' : pct < 75 ? 'mid' : 'high';
        return '<div style="margin-bottom:8px;">' +
          '<div style="display:flex;justify-content:space-between;margin-bottom:2px;">' +
            '<span class="tiny">' + esc(e.enricher) + '</span>' +
            '<span class="tiny" style="color:var(--muted)">' + esc(e.done) + '/' + esc(e.total) + ' (' + pct + '%)</span>' +
          '</div>' +
          '<div class="progress-bar"><div class="progress-fill ' + cls + '" style="width:' + pct + '%"></div></div>' +
        '</div>';
      }).join('');
    }

    async function loadScanRuns() {
      const data = await j('/api/scan-runs?limit=15');
      const items = data.items || [];
      scanIsRunning = items.some(r => r.status === 'running');
      const badge = document.getElementById('scanBadge');
      badge.textContent = scanIsRunning ? 'SCANNING' : 'IDLE';
      badge.className = 'scan-badge ' + (scanIsRunning ? 'scan-running' : 'scan-idle');
      updatePoll();

      document.getElementById('scanRows').innerHTML = items.map(r =>
        '<tr>' +
          '<td class="tiny">' + esc(r.target || '') + '</td>' +
          '<td><span class="' + statusClass(r.status) + '">' + esc(r.status) + '</span></td>' +
          '<td class="tiny">' + relTime(r.started_at) + '</td>' +
        '</tr>'
      ).join('');
    }

    async function loadFindings() {
      const data = await j('/api/top-findings');
      document.getElementById('findingRows').innerHTML = (data.items || []).map(f =>
        '<tr>' +
          '<td><span class="pill ' + sevClass(f.severity) + '">' + esc(f.severity) + '</span></td>' +
          '<td>' + esc(f.title) + '<div class="tiny" style="color:var(--muted)">' + esc((f.assets||[]).slice(0,3).join(' | ')) + '</div></td>' +
          '<td class="tiny">' + esc((f.tools||[]).join(', ')) + '</td>' +
          '<td>' + esc(f.asset_count) + '</td>' +
        '</tr>'
      ).join('');
    }

    async function loadServices() {
      const data = await j('/api/data/services?limit=200');
      const items = data.items || [];
      const groups = new Map();
      for (const s of items) {
        const key = String(s.dns_name||'').trim() || '(no dns)';
        (groups.get(key) || (groups.set(key, []), groups.get(key))).push(s);
      }
      const ordered = Array.from(groups.entries()).sort((a,b) => {
        const at = Math.max(...a[1].map(x => Date.parse(x.last_seen||'')||0));
        const bt = Math.max(...b[1].map(x => Date.parse(x.last_seen||'')||0));
        return bt - at;
      });
      const html = [];
      serviceGroupMap = {};
      for (let i = 0; i < ordered.length; i++) {
        const [dns, services] = ordered[i];
        const gid = 'g' + i;
        serviceGroupMap[gid] = dns;
        const exp = expandedServiceGroups.has(gid);
        const last = services.map(s=>s.last_seen||'').filter(Boolean).sort().reverse()[0]||'';
        html.push('<tr><td><button class="dns-toggle" onclick="toggleSG(\'' + gid + '\')"><span class="dns-caret">' + (exp?'&#9662;':'&#9656;') + '</span>' + esc(dns) + '</button></td><td>' + services.length + '</td><td class="tiny">' + relTime(last) + '</td></tr>');
        if (exp) {
          for (const s of services) {
            html.push('<tr><td class="tiny" style="color:var(--muted);padding-left:24px;">&#8627;</td><td colspan="2" class="tiny">' +
              esc(s.ip||'') + ':' + esc(s.port||0) + ' | ' + esc(s.product||'-') + ' | tls=' + (s.tls?'yes':'no') + ' | ' + esc(s.server||s.banner||'-') +
            '</td></tr>');
          }
        }
      }
      document.getElementById('serviceRows').innerHTML = html.join('');
    }
    function toggleSG(gid) {
      if (expandedServiceGroups.has(gid)) expandedServiceGroups.delete(gid);
      else expandedServiceGroups.add(gid);
      loadServices();
    }

    async function loadURLs() {
      const data = await j('/api/data/urls?limit=25');
      document.getElementById('urlRows').innerHTML = (data.items||[]).map(u =>
        '<tr><td class="tiny"><a href="' + esc(u.url) + '" target="_blank" rel="noreferrer">' + esc(u.url) + '</a></td><td class="tiny">' + esc(u.host||'') + '</td><td>' + esc(u.status_code||0) + '</td><td class="tiny">' + esc(u.title||'') + '</td><td class="tiny">' + relTime(u.last_seen) + '</td></tr>'
      ).join('');
    }

    async function loadHealth() {
      const data = await j('/api/jsrecon/health');
      const h = document.getElementById('health');
      h.style.background = data.ok ? 'rgba(158,206,106,0.15)' : 'rgba(247,118,142,0.15)';
      h.style.color = data.ok ? 'var(--green)' : 'var(--red)';
      h.textContent = data.ok ? 'connected' : 'offline';
    }

    // --- JS Assets ---
    function score(item) { return Number(item.finding_count||0)*3 + Number(item.endpoint_hint||0); }

    async function loadJSFiles() {
      const data = await j('/api/jsfiles?limit=200');
      jsItems = data.items || [];
      renderJSFiles();
    }

    function renderJSFiles() {
      const min = Number(document.getElementById('minScore').value||0);
      const unmon = document.getElementById('onlyUnmonitored').checked;
      let items = jsItems.slice().sort((a,b) => score(b)-score(a)).filter(x => score(x) >= min);
      if (unmon) items = items.filter(x => !monitoredSet.has(String(x.url||'')));
      document.getElementById('jsCount').textContent = items.length + ' shown';
      document.getElementById('jsRows').innerHTML = items.map(x => {
        const sc = score(x);
        const mon = monitoredSet.has(String(x.url||''));
        return '<tr><td><input type="checkbox" data-jsurl="' + esc(x.url) + '" /></td>' +
          '<td class="tiny"><a href="' + esc(x.url) + '" target="_blank" rel="noreferrer">' + esc(x.url) + '</a>' + (mon ? ' <span class="pill sev-info">mon</span>' : '') + '</td>' +
          '<td>' + sc + '</td>' +
          '<td><button onclick="addMonitor(\'' + String(x.url).replace(/'/g,"\\'") + '\')">Add</button></td></tr>';
      }).join('');
    }
    function applyFilters() { renderJSFiles(); }

    async function addMonitor(url) {
      const label = prompt('Label:', 'asm-js');
      const interval = Number(document.getElementById('bulkInterval').value||60);
      const data = await j('/api/jsrecon/monitor', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url, label:label||'asm-js', check_interval_minutes:interval}) });
      if (data.ok) { alert('Added'); await loadMonitorList(); renderJSFiles(); }
      else alert('Failed: ' + JSON.stringify(data));
    }

    async function bulkMonitor() {
      const checks = Array.from(document.querySelectorAll('input[data-jsurl]:checked'));
      if (!checks.length) { alert('None selected'); return; }
      const label = prompt('Label prefix:', 'asm-bulk');
      let ok=0, fail=0;
      for (const c of checks) {
        try {
          const interval = Number(document.getElementById('bulkInterval').value||60);
          const d = await j('/api/jsrecon/monitor', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url:c.getAttribute('data-jsurl'), label:label||'asm-bulk', check_interval_minutes:interval}) });
          if (d.ok) ok++; else fail++;
        } catch { fail++; }
      }
      alert(ok + ' added, ' + fail + ' failed');
      await loadMonitorList(); renderJSFiles();
    }

    async function loadMonitorList() {
      const data = await j('/api/jsrecon/monitor/list?limit=200');
      const items = data.monitored_urls || [];
      monitoredSet = new Set(items.map(m => String(m.url||'')));
      document.getElementById('monitorRows').innerHTML = items.map(m =>
        '<tr><td class="tiny">' + esc(m.label||'') + '</td><td class="tiny">' + esc(m.url) + '</td><td>' + esc(m.status||'') + '</td>' +
        '<td><button onclick="runCheck(' + Number(m.id||0) + ')">Check</button></td></tr>'
      ).join('');
    }

    async function runCheck(id) {
      const d = await j('/api/jsrecon/monitor/check', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id}) });
      if (d.ok) { alert('Check: ' + (d.jsrecon?.status||'ok')); await Promise.all([loadMonitorList(),loadChanges()]); }
      else alert('Failed');
    }

    // --- Changes ---
    async function loadChanges() {
      const search = encodeURIComponent((document.getElementById('changeSearch').value||'').trim());
      const since = encodeURIComponent((document.getElementById('changeSince').value||'').trim());
      const limit = Number(document.getElementById('changeLimit').value||50);
      changePage.limit = limit;
      const q = '?limit=' + limit + '&offset=' + changePage.offset + (search?'&search='+search:'') + (since?'&since='+since:'');
      const data = await j('/api/jsrecon/monitor/changes' + q);
      const items = data.change_events || data.items || [];
      document.getElementById('changeRows').innerHTML = items.slice(0,20).map(e =>
        '<tr><td>' + esc(e.id) + '</td><td class="tiny">' + esc(e.url||'') + '</td><td class="tiny">' + esc(e.summary||'') + '</td><td class="tiny">' + relTime(e.created_at) + '</td></tr>'
      ).join('');
      if (data.pagination) { changePage.has_more = !!data.pagination.has_more; changePage.offset = Number(data.pagination.offset||0); }
      else changePage.has_more = items.length === limit;
      document.getElementById('changeMeta').textContent = 'offset=' + changePage.offset + ' n=' + items.length;
    }
    function applyChangeFilters() { changePage.offset=0; loadChanges(); }
    function prevChanges() { changePage.offset = Math.max(0, changePage.offset - changePage.limit); loadChanges(); }
    function nextChanges() { if (changePage.has_more) { changePage.offset += changePage.limit; loadChanges(); } }

    // --- Auto-poll ---
    function updatePoll() {
      const el = document.getElementById('pollStatus');
      if (scanIsRunning && !pollTimer) {
        pollTimer = setInterval(pollRefresh, POLL_INTERVAL);
        el.textContent = 'auto-poll ' + (POLL_INTERVAL/1000) + 's';
        el.style.color = 'var(--green)';
      } else if (!scanIsRunning && pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
        el.textContent = 'auto-poll off';
        el.style.color = 'var(--muted)';
      }
    }

    async function pollRefresh() {
      await Promise.all([loadSummary(), loadScanRuns(), loadEnricherProgress(), loadActivity()]);
    }

    async function refreshAll() {
      await Promise.all([
        loadSummary(), loadScanRuns(), loadEnricherProgress(), loadActivity(),
        loadFindings(), loadServices(), loadURLs(),
        loadHealth(), loadJSFiles(), loadMonitorList(), loadChanges()
      ]);
    }

    refreshAll();
  </script>
</body>
</html>` + ""
