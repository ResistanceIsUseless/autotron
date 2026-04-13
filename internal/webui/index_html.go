package webui

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Autotron ASM UI</title>
  <style>
    :root {
      --bg: #f3efe8;
      --card: #fffdf9;
      --ink: #21312a;
      --muted: #5e6f67;
      --accent: #0d7a5f;
      --warn: #c66b00;
      --line: #d9d2c8;
      --ok: #1c8f6a;
      --err: #b43e3e;
    }
    body { margin: 0; font-family: ui-sans-serif, -apple-system, Segoe UI, sans-serif; background: radial-gradient(1000px 600px at 100% -10%, #dceadf 0%, var(--bg) 55%); color: var(--ink); }
    .wrap { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .row { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }
    .card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px; box-shadow: 0 4px 20px rgba(20, 40, 30, 0.04); }
    h1 { margin: 0 0 6px; font-size: 24px; }
    .muted { color: var(--muted); }
    .pill { display: inline-block; border-radius: 999px; padding: 3px 10px; font-size: 12px; border: 1px solid var(--line); }
    .ok { color: var(--ok); border-color: #bce2d4; background: #eef9f4; }
    .err { color: var(--err); border-color: #efc8c8; background: #fff3f3; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: top; }
    input, button { font: inherit; }
    button { background: var(--accent); color: #fff; border: 0; border-radius: 10px; padding: 7px 12px; cursor: pointer; }
    button.secondary { background: transparent; color: var(--ink); border: 1px solid var(--line); }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .toolbar input { border: 1px solid var(--line); background: #fff; border-radius: 10px; padding: 7px 10px; min-width: 280px; }
    .toolbar select { border: 1px solid var(--line); background: #fff; border-radius: 10px; padding: 7px 10px; }
    .tiny { font-size: 12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Autotron ASM Web UI</h1>
    <div class="muted">Review discovered JS assets and push selected URLs to jsRecon monitor.</div>

    <div class="row" id="summary"></div>

    <div class="card" style="margin-top: 14px;">
      <div class="toolbar" style="justify-content: space-between; margin-bottom: 10px;">
        <div>
          <strong>jsRecon Connectivity</strong>
          <span id="health" class="pill">checking...</span>
        </div>
        <button class="secondary" onclick="refreshAll()">Refresh</button>
      </div>
      <div class="tiny muted" id="healthDetail"></div>
    </div>

    <div class="card" style="margin-top: 14px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; gap:10px; flex-wrap: wrap;">
        <strong>JS Assets</strong>
        <div class="toolbar">
          <span class="tiny muted" id="jsCount">0</span>
          <label class="tiny">Min score <input id="minScore" type="number" value="0" min="0" style="width:70px; min-width:70px;" /></label>
          <label class="tiny"><input id="onlyUnmonitored" type="checkbox" /> only unmonitored</label>
          <label class="tiny">Interval
            <select id="bulkInterval">
              <option value="15">15m</option>
              <option value="60" selected>60m</option>
              <option value="360">6h</option>
              <option value="1440">24h</option>
            </select>
          </label>
          <button class="secondary" onclick="applyFilters()">Apply</button>
          <button class="secondary" onclick="bulkMonitor()">Add Selected</button>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th></th>
            <th>JS URL</th>
            <th>Parent URL</th>
            <th>Score</th>
            <th>Monitor</th>
          </tr>
        </thead>
        <tbody id="jsRows"></tbody>
      </table>
    </div>

    <div class="card" style="margin-top: 14px;">
      <strong>Monitored URLs</strong>
      <table style="margin-top:8px;">
        <thead><tr><th>Label</th><th>URL</th><th>Status</th><th>Errors</th><th>Last Checked</th></tr></thead>
        <tbody id="monitorRows"></tbody>
      </table>
    </div>

    <div class="card" style="margin-top: 14px;">
      <strong>Recent Change Events</strong>
      <div class="toolbar" style="margin-top: 8px; margin-bottom: 8px;">
        <label class="tiny">Search <input id="changeSearch" placeholder="url,label,summary" style="min-width: 220px;" /></label>
        <label class="tiny">Since <input id="changeSince" placeholder="2026-04-12 00:00:00" style="min-width: 180px;" /></label>
        <label class="tiny">Limit
          <select id="changeLimit">
            <option value="20">20</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
          </select>
        </label>
        <button class="secondary" onclick="applyChangeFilters()">Apply</button>
      </div>
      <table style="margin-top:8px;">
        <thead><tr><th>ID</th><th>URL</th><th>Summary</th><th>When</th></tr></thead>
        <tbody id="changeRows"></tbody>
      </table>
      <div class="toolbar" style="margin-top: 8px; justify-content: space-between;">
        <span class="tiny muted" id="changeMeta">-</span>
        <div>
          <button class="secondary" onclick="prevChanges()">Prev</button>
          <button class="secondary" onclick="nextChanges()">Next</button>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top: 14px;">
      <strong>Top Findings</strong>
      <table style="margin-top:8px;">
        <thead>
          <tr><th>Severity</th><th>Title</th><th>Tools</th><th>Assets</th></tr>
        </thead>
        <tbody id="findingRows"></tbody>
      </table>
    </div>
  </div>

  <script>
    async function j(url, opts) {
      const r = await fetch(url, opts || {});
      return r.json();
    }

    function esc(s) {
      return String(s || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
    }

    async function loadSummary() {
      const data = await j('/api/summary');
      const root = document.getElementById('summary');
      root.innerHTML = (data.node_counts || []).map(x =>
        '<div class="card"><div class="muted tiny">' + esc(x.label) + '</div><div style="font-size:24px;font-weight:700;">' + esc(x.count) + '</div></div>'
      ).join('');
    }

    async function loadHealth() {
      const data = await j('/api/jsrecon/health');
      const h = document.getElementById('health');
      h.className = 'pill ' + (data.ok ? 'ok' : 'err');
      h.textContent = data.ok ? 'connected' : 'offline';
      document.getElementById('healthDetail').textContent = JSON.stringify(data.detail || data.error || {}, null, 0);
    }

    let jsItems = [];
    let monitoredSet = new Set();
    let monitorItems = [];
    let changePage = { limit: 50, offset: 0, has_more: false };

    async function addMonitor(url) {
      const label = prompt('Monitor label (optional):', 'asm-js');
      const interval = Number(document.getElementById('bulkInterval').value || 60);
      const body = { url, label: label || 'asm-js', check_interval_minutes: interval };
      const data = await j('/api/jsrecon/monitor', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (data.ok) {
        alert('Added monitor for ' + url);
        await loadMonitorList();
        renderJSFiles();
      } else {
        alert('Failed: ' + JSON.stringify(data));
      }
    }

    async function analyzeNow(url) {
      const data = await j('/api/jsrecon/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (data.ok) {
        alert('Analysis queued/completed for ' + url);
      } else {
        alert('Analyze failed: ' + JSON.stringify(data));
      }
    }

    function score(item) {
      return Number(item.finding_count || 0) * 3 + Number(item.endpoint_hint || 0);
    }

    async function bulkMonitor() {
      const checks = Array.from(document.querySelectorAll('input[data-jsurl]:checked'));
      if (!checks.length) {
        alert('No JS URLs selected');
        return;
      }
      const label = prompt('Bulk label prefix:', 'asm-bulk');
      let ok = 0;
      let fail = 0;
      for (const c of checks) {
        const url = c.getAttribute('data-jsurl');
        try {
          const interval = Number(document.getElementById('bulkInterval').value || 60);
          const data = await j('/api/jsrecon/monitor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, label: (label || 'asm-bulk'), check_interval_minutes: interval })
          });
          if (data.ok) ok++; else fail++;
        } catch {
          fail++;
        }
      }
      alert('Bulk add complete: ' + ok + ' success, ' + fail + ' failed');
      await loadMonitorList();
      renderJSFiles();
    }

    async function runMonitorCheck(id) {
      const data = await j('/api/jsrecon/monitor/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      if (data.ok) {
        const s = data.jsrecon && data.jsrecon.status ? data.jsrecon.status : 'unknown';
        alert('Monitor check status: ' + s);
        await Promise.all([loadMonitorList(), loadChanges()]);
      } else {
        alert('Monitor check failed: ' + JSON.stringify(data));
      }
    }

    async function loadJSFiles() {
      const data = await j('/api/jsfiles?limit=200');
      jsItems = data.items || [];
      renderJSFiles();
    }

    function renderJSFiles() {
      const rows = document.getElementById('jsRows');
      const minScore = Number(document.getElementById('minScore').value || 0);
      const onlyUnmonitored = document.getElementById('onlyUnmonitored').checked;

      let items = jsItems.slice().sort((a, b) => score(b) - score(a));
      items = items.filter(x => score(x) >= minScore);
      if (onlyUnmonitored) {
        items = items.filter(x => !monitoredSet.has(String(x.url || '')));
      }

      document.getElementById('jsCount').textContent = items.length + ' shown';
      rows.innerHTML = items.map(x => {
        const sc = score(x);
        const monitored = monitoredSet.has(String(x.url || ''));
        return '<tr>' +
          '<td><input type="checkbox" data-jsurl="' + esc(x.url) + '" /></td>' +
          '<td><a href="' + esc(x.url) + '" target="_blank" rel="noreferrer">' + esc(x.url) + '</a><div class="tiny muted">' + esc(x.sha256) + '</div><div class="tiny">' + (monitored ? 'monitored' : 'not monitored') + '</div></td>' +
          '<td class="tiny">' + esc(x.parent_url || '') + '</td>' +
          '<td class="tiny"><strong>' + esc(sc) + '</strong><br/>f:' + esc(x.finding_count) + ' e:' + esc(x.endpoint_hint) + '</td>' +
          '<td><button onclick="addMonitor(\'' + String(x.url).replaceAll("'", "\\'") + '\')">Add</button> <button class="secondary" onclick="analyzeNow(\'' + String(x.url).replaceAll("'", "\\'") + '\')">Analyze</button></td>' +
        '</tr>';
      }).join('');
    }

    function applyFilters() {
      renderJSFiles();
    }

    async function loadMonitorList() {
      const data = await j('/api/jsrecon/monitor/list?limit=200');
      const rows = document.getElementById('monitorRows');
      const items = data.monitored_urls || [];
      monitorItems = items;
      monitoredSet = new Set(items.map(m => String(m.url || '')));
      rows.innerHTML = items.map(m =>
        '<tr><td>' + esc(m.label || '') + '</td><td class="tiny">' + esc(m.url) + '</td><td>' + esc(m.status || '') + '</td><td>' + esc(m.consecutive_errors || 0) + '</td><td class="tiny">' + esc(m.last_checked_at || '') + '<br/><button class="secondary" onclick="runMonitorCheck(' + Number(m.id || 0) + ')">Check now</button></td></tr>'
      ).join('');
    }

    async function loadChanges() {
      const search = encodeURIComponent((document.getElementById('changeSearch').value || '').trim());
      const since = encodeURIComponent((document.getElementById('changeSince').value || '').trim());
      const limit = Number(document.getElementById('changeLimit').value || 50);
      changePage.limit = limit;
      const q = '?limit=' + limit + '&offset=' + changePage.offset + (search ? '&search=' + search : '') + (since ? '&since=' + since : '');
      const data = await j('/api/jsrecon/monitor/changes' + q);
      const rows = document.getElementById('changeRows');
      const items = data.change_events || data.items || [];
      rows.innerHTML = items.slice(0, 20).map(e =>
        '<tr><td>' + esc(e.id) + '</td><td class="tiny">' + esc(e.url || '') + '</td><td class="tiny">' + esc(e.summary || '') + '</td><td class="tiny">' + esc(e.created_at || '') + '</td></tr>'
      ).join('');

      if (data.pagination) {
        changePage.has_more = !!data.pagination.has_more;
        changePage.offset = Number(data.pagination.offset || 0);
      } else {
        changePage.has_more = items.length === limit;
      }
      document.getElementById('changeMeta').textContent = 'offset=' + changePage.offset + ' limit=' + limit + ' count=' + items.length + ' has_more=' + changePage.has_more;
    }

    function applyChangeFilters() {
      changePage.offset = 0;
      loadChanges();
    }

    function prevChanges() {
      changePage.offset = Math.max(0, changePage.offset - changePage.limit);
      loadChanges();
    }

    function nextChanges() {
      if (!changePage.has_more) return;
      changePage.offset = changePage.offset + changePage.limit;
      loadChanges();
    }

    async function loadFindings() {
      const data = await j('/api/top-findings');
      const rows = document.getElementById('findingRows');
      rows.innerHTML = (data.items || []).map(f =>
        '<tr><td>' + esc(f.severity) + '</td><td>' + esc(f.title) + '</td><td class="tiny">' + esc((f.tools || []).join(',')) + '</td><td>' + esc(f.asset_count) + '</td></tr>'
      ).join('');
    }

    async function refreshAll() {
      await Promise.all([loadSummary(), loadHealth(), loadMonitorList(), loadJSFiles(), loadFindings(), loadChanges()]);
    }

    refreshAll();
  </script>
</body>
</html>`
