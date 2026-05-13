let currentPage = 'query';
let historyData = [];
let healthPollTimer = null;
const knownPages = new Set(['query', 'cache', 'metrics', 'history', 'compare', 'settings', 'trace']);

function $(id) {
    return document.getElementById(id);
}

function setConnectionStatus(connected, text) {
    const indicator = $('connection-status');
    if (!indicator) return;
    const dot = indicator.querySelector('.status-dot');
    const label = indicator.querySelector('.status-text');
    if (dot) {
        dot.classList.toggle('connected', connected);
    }
    if (label) {
        label.textContent = text;
    }
}

function showLoading() {
    $('loading-overlay').classList.remove('hidden');
}

function hideLoading() {
    $('loading-overlay').classList.add('hidden');
}

function showError(container, message) {
    container.innerHTML = `<div class="error-message">${escapeHtml(message)}</div>`;
}

function showSuccess(container, message) {
    container.innerHTML = `<div class="success-message">${escapeHtml(message)}</div>`;
}

function showTransientStatus(container, type, message) {
    if (!container) return;
    container.innerHTML = `<div class="${type === 'error' ? 'error-message' : 'success-message'}">${escapeHtml(message)}</div>`;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

function formatTime(isoString) {
    if (!isoString) return '-';
    const d = new Date(isoString);
    return d.toLocaleTimeString() + ' ' + d.toLocaleDateString();
}

function formatDuration(ms) {
    if (!ms && ms !== 0) return '-';
    if (ms < 1) return ms.toFixed(2) + 'ms';
    if (ms < 1000) return ms.toFixed(1) + 'ms';
    return (ms / 1000).toFixed(2) + 's';
}

function formatTTL(ttl) {
    if (ttl === undefined || ttl === null) return '-';
    if (ttl < 60) return ttl + 's';
    if (ttl < 3600) return Math.floor(ttl / 60) + 'm ' + (ttl % 60) + 's';
    return Math.floor(ttl / 3600) + 'h ' + Math.floor((ttl % 3600) / 60) + 'm';
}

function rcodeName(value) {
    if (typeof value === 'string') return value;
    switch (value) {
        case 0: return 'NOERROR';
        case 1: return 'FORMERR';
        case 2: return 'SERVFAIL';
        case 3: return 'NXDOMAIN';
        case 4: return 'NOTIMP';
        case 5: return 'REFUSED';
        default: return String(value ?? 'UNKNOWN');
    }
}

function rrTypeName(value) {
    if (typeof value === 'string') return value;
    switch (value) {
        case 1: return 'A';
        case 2: return 'NS';
        case 5: return 'CNAME';
        case 6: return 'SOA';
        case 12: return 'PTR';
        case 15: return 'MX';
        case 16: return 'TXT';
        case 28: return 'AAAA';
        case 33: return 'SRV';
        case 41: return 'OPT';
        case 43: return 'DS';
        case 46: return 'RRSIG';
        case 47: return 'NSEC';
        case 48: return 'DNSKEY';
        case 50: return 'NSEC3';
        case 255: return 'ANY';
        case 257: return 'CAA';
        default: return `TYPE${value ?? ''}`;
    }
}

function navigateTo(page, options = {}) {
    const { updateHash = true } = options;
    if (!knownPages.has(page)) {
        page = 'query';
    }
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => {
        l.classList.remove('active');
        l.removeAttribute('aria-current');
    });
    
    $('page-' + page).classList.add('active');
    const navLink = document.querySelector(`.nav-link[data-page="${page}"]`);
    navLink?.classList.add('active');
    navLink?.setAttribute('aria-current', 'page');
    currentPage = page;
    if (updateHash && window.location.hash !== `#${page}`) {
        window.location.hash = page;
    }
    
    switch (page) {
        case 'cache': loadCache(); break;
        case 'metrics': loadMetrics(); break;
        case 'history': loadHistory(); break;
        case 'settings': loadSettings(); break;
        case 'trace': break;
    }
}

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const page = link.dataset.page;
        if (page) navigateTo(page);
    });
});

async function resolveQuery() {
    const domain = $('query-domain').value.trim();
    const type = $('query-type').value;
    const showTrace = $('query-trace').checked;
    
    if (!domain) {
        showError($('query-result'), 'Please enter a domain name');
        return;
    }
    
    showLoading();
    
    try {
        const result = await api.resolve(domain, type, showTrace);
        hideLoading();
        renderQueryResult(result);
        
        if (showTrace && result.trace) {
            $('query-trace-panel').classList.remove('hidden');
            renderTrace(result.trace);
        } else {
            $('query-trace-panel').classList.add('hidden');
        }
    } catch (err) {
        hideLoading();
        showError($('query-result'), err.message);
    }
}

async function reverseLookup() {
    const ip = $('reverse-ip').value.trim();
    if (!ip) {
        showError($('reverse-result'), 'Please enter an IP address');
        return;
    }

    showLoading();
    try {
        const result = await api.reverse(ip);
        hideLoading();
        $('reverse-result').innerHTML = `
            <div class="result-header">
                <span class="result-domain">${escapeHtml(result.ip)}</span>
                <span class="result-rcode rcode-noerror">PTR</span>
            </div>
            <div style="margin-top: 12px;">Reverse Name: <code class="code">${escapeHtml(result.reverse_name || '-')}</code></div>
            <div style="margin-top: 12px;">Answers: ${(result.message?.answers || []).map(formatAnswerValue).map(escapeHtml).join(', ') || '-'}</div>
            <div style="margin-top: 16px; color: var(--text-muted); font-size: 12px;">
                Duration: ${formatDuration(result.duration_ms)}
            </div>
        `;
    } catch (err) {
        hideLoading();
        showError($('reverse-result'), err.message);
    }
}

async function runBulkResolve(format = 'json') {
    const queries = $('bulk-queries').value.split('\n').map(q => q.trim()).filter(Boolean);
    const type = $('bulk-type').value;
    if (queries.length === 0) {
        showError($('bulk-result'), 'Please enter at least one domain');
        return;
    }

    showLoading();
    try {
        const result = await api.bulkResolve(queries, type, format);
        hideLoading();
        if (format === 'csv') {
            $('bulk-result').innerHTML = `
                <div class="success-message">CSV export generated</div>
                <pre class="code" style="margin-top: 12px; white-space: pre-wrap;">${escapeHtml(result)}</pre>
            `;
            return;
        }
        const rows = result.results || [];
        if (rows.length === 0) {
            $('bulk-result').innerHTML = '<div class="result-empty">No bulk results</div>';
            return;
        }
        $('bulk-result').innerHTML = `
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr><th scope="col">Query</th><th scope="col">RCode</th><th scope="col">Duration</th><th scope="col">Error</th></tr>
                    </thead>
                    <tbody>
                        ${rows.map(row => `
                            <tr>
                                <td><code class="code">${escapeHtml(row.query)}</code></td>
                                <td>${escapeHtml(row.rcode || '-')}</td>
                                <td>${formatDuration(row.duration_ms)}</td>
                                <td>${escapeHtml(row.error || '-')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (err) {
        hideLoading();
        showError($('bulk-result'), err.message);
    }
}

function renderQueryResult(result) {
    const container = $('query-result');
    
    if (!result.message) {
        container.innerHTML = '<div class="result-empty">No response</div>';
        return;
    }
    
    const msg = result.message;
    const rcode = rcodeName(result.rcode ?? msg.header?.rcode);
    const rcodeClass = rcode.toLowerCase() === 'noerror' ? 'rcode-noerror' : 
                       rcode.toLowerCase() === 'nxdomain' ? 'rcode-nxdomain' : 'rcode-servfail';
    
    let html = `
        <div class="result-header">
            <span class="result-domain">${escapeHtml(result.query || msg.questions?.[0]?.name || '-')}</span>
            <span class="result-rcode ${rcodeClass}">${rcode}</span>
        </div>
    `;
    
    if (result.blocked) {
        html += '<div class="error-message">Domain blocked by blocklist</div>';
    }
    
    if (result.cached) {
        html += '<div class="success-message">Served from cache</div>';
    }
    
    if (result.stale) {
        html += '<div style="color: var(--accent-orange); margin-bottom: 12px;">Stale response</div>';
    }
    
    if (msg.answers && msg.answers.length > 0) {
        html += '<ul class="answer-list">';
        for (const answer of msg.answers) {
            html += `
                <li class="answer-item">
                    <div>
                        <span class="answer-name">${escapeHtml(answer.name)}</span>
                        <span style="color: var(--text-muted); margin: 0 8px;">${rrTypeName(answer.type)}</span>
                        <span class="answer-value">${formatAnswerValue(answer)}</span>
                    </div>
                    <span class="answer-ttl">TTL: ${formatTTL(answer.ttl)}</span>
                </li>
            `;
        }
        html += '</ul>';
    } else if (rcode.toLowerCase() === 'noerror') {
        html += '<div class="result-empty">No answers (NODATA)</div>';
    }
    
    html += `<div style="margin-top: 16px; color: var(--text-muted); font-size: 12px;">
        Duration: ${formatDuration(result.duration_ms)} | Steps: ${result.steps || 1}
    </div>`;
    
    container.innerHTML = html;
}

function formatAnswerValue(answer) {
    if (!answer.data) return '-';
    if (typeof answer.data === 'string') return escapeHtml(answer.data);
    if (answer.data.address) {
        if (!Array.isArray(answer.data.address)) return answer.data.address;
        if (answer.data.address.length === 4) return answer.data.address.join('.');
        if (answer.data.address.length === 16) {
            const groups = [];
            for (let i = 0; i < answer.data.address.length; i += 2) {
                groups.push(((answer.data.address[i] << 8) | answer.data.address[i + 1]).toString(16));
            }
            return groups.join(':');
        }
        return answer.data.address.join('.');
    }
    if (answer.data.name) return escapeHtml(answer.data.name);
    if (answer.data.exchange) return escapeHtml(answer.data.exchange);
    if (answer.data.target) return escapeHtml(answer.data.target);
    if (answer.data.texts) return answer.data.texts.map(t => `"${escapeHtml(t)}"`).join(' ');
    return escapeHtml(JSON.stringify(answer.data));
}

function renderTrace(trace) {
    const container = $('query-trace-panel');
    
    if (!trace || trace.length === 0) {
        container.innerHTML = '<div class="result-empty">No trace data</div>';
        return;
    }
    
    let html = '<h3>Resolution Trace</h3><div class="trace-timeline">';
    
    for (const step of trace) {
        const stepClass = (step.step_type || '').replace('_', '-');
        html += `
            <div class="trace-step ${stepClass}">
                <div class="trace-step-header">
                    <span class="trace-step-type">${escapeHtml(step.step_type || 'query')}</span>
                    <span class="trace-step-latency">${formatDuration(step.latency_ms)}</span>
                </div>
                <div class="trace-step-server">${escapeHtml(step.server || '-')}</div>
                <div style="color: var(--text-secondary); margin-top: 4px;">
                    ${escapeHtml(step.query || '')} (${step.query_type || ''})
                </div>
                ${step.error ? `<div style="color: var(--accent-red); margin-top: 4px;">${escapeHtml(step.error)}</div>` : ''}
            </div>
        `;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

async function loadCache() {
    showLoading();
    try {
        const [entries, stats] = await Promise.all([
            api.getCache(1, 50),
            api.getCacheStats()
        ]);
        hideLoading();
        
        renderCacheStats(stats);
        renderCacheTable(entries.entries || []);
    } catch (err) {
        hideLoading();
        showError($('cache-stats'), err.message);
    }
}

function renderCacheStats(stats) {
    $('cache-stats').innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${stats.entries || 0}</div>
            <div class="stat-label">Entries</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${((stats.hit_rate || 0) * 100).toFixed(1)}%</div>
            <div class="stat-label">Hit Rate</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.hits || 0}</div>
            <div class="stat-label">Hits</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.misses || 0}</div>
            <div class="stat-label">Misses</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${stats.stale || 0}</div>
            <div class="stat-label">Stale</div>
        </div>
    `;
}

function renderCacheTable(entries) {
    const tbody = $('cache-tbody');
    
    if (!entries || entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Cache is empty</td></tr>';
        return;
    }
    
    tbody.innerHTML = entries.map(e => `
        <tr>
            <td><code class="code">${escapeHtml(e.key || e.name)}</code></td>
            <td>${e.type || '-'}</td>
            <td><span class="ttl-badge ${e.stale ? 'stale' : ''}">${formatTTL(e.ttl_remaining || e.ttl)}</span></td>
            <td>${e.stale ? 'Yes' : 'No'}</td>
            <td><button class="btn btn-small btn-danger" data-action="evict-cache" data-key="${escapeHtml(e.key || e.name)}">Evict</button></td>
        </tr>
    `).join('');
}

async function evictEntry(key) {
    try {
        await api.evictCacheEntry(key);
        loadCache();
    } catch (err) {
        alert('Failed to evict: ' + err.message);
    }
}

async function flushCache() {
    if (!confirm('Are you sure you want to flush the entire cache?')) return;
    
    try {
        await api.flushCache();
        loadCache();
    } catch (err) {
        alert('Failed to flush: ' + err.message);
    }
}

async function loadMetrics() {
    showLoading();
    try {
        const metrics = await api.getMetrics();
        hideLoading();
        renderMetrics(metrics);
    } catch (err) {
        hideLoading();
        showError($('metrics-grid'), err.message);
    }
}

function renderMetrics(m) {
    $('metrics-grid').innerHTML = `
        <div class="metric-card">
            <div class="metric-title">Total Queries</div>
            <div class="metric-value blue">${m.total_queries?.toLocaleString() || 0}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">QPS (1m)</div>
            <div class="metric-value green">${(m.qps_1m || 0).toFixed(2)}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Cache Hit Rate</div>
            <div class="metric-value">${((m.cache_hit_rate || 0) * 100).toFixed(1)}%</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Latency P50</div>
            <div class="metric-value">${formatDuration(m.latency_p50_ms || m.latency_p50)}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Latency P95</div>
            <div class="metric-value orange">${formatDuration(m.latency_p95_ms || m.latency_p95)}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Latency P99</div>
            <div class="metric-value red">${formatDuration(m.latency_p99_ms || m.latency_p99)}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Goroutines</div>
            <div class="metric-value">${m.goroutines || m.runtime_goroutines || 0}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Heap (MB)</div>
            <div class="metric-value">${((m.runtime_heap_bytes || 0) / 1024 / 1024).toFixed(1)}</div>
        </div>
    `;
    
    renderTypeChart(m.by_type || m.type_distribution || {});
    renderRcodeChart(m.by_rcode || m.rcode_distribution || {});
}

function renderTypeChart(data) {
    const container = $('type-chart');
    const entries = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const max = Math.max(...entries.map(e => e[1]), 1);
    
    container.innerHTML = entries.map(([type, count]) => `
        <div class="chart-bar">
            <div class="chart-bar-fill" style="height: ${(count / max) * 150}px"></div>
            <div class="chart-bar-value">${count}</div>
            <div class="chart-bar-label">${type}</div>
        </div>
    `).join('');
}

function renderRcodeChart(data) {
    const container = $('rcode-chart');
    const entries = Object.entries(data).slice(0, 8);
    const max = Math.max(...entries.map(e => e[1]), 1);
    
    container.innerHTML = entries.map(([rcode, count]) => `
        <div class="chart-bar">
            <div class="chart-bar-fill" style="height: ${(count / max) * 150}px"></div>
            <div class="chart-bar-value">${count}</div>
            <div class="chart-bar-label">${rcode}</div>
        </div>
    `).join('');
}

async function loadHistory() {
    showLoading();
    try {
        const data = await api.getHistory(1, 100);
        hideLoading();
        historyData = data.items || data.queries || data || [];
        renderHistoryTable(historyData);
    } catch (err) {
        hideLoading();
        showError($('history-tbody').parentElement, err.message);
    }
}

function renderHistoryTable(queries) {
    const tbody = $('history-tbody');
    
    if (!queries || queries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No queries yet</td></tr>';
        return;
    }
    
    tbody.innerHTML = queries.map(q => `
        <tr>
            <td>${formatTime(q.timestamp)}</td>
            <td><code class="code">${escapeHtml(q.domain || q.query)}</code></td>
            <td>${q.type || q.qtype || '-'}</td>
            <td><span class="result-rcode rcode-${(q.rcode || '').toLowerCase()}">${q.rcode || '-'}</span></td>
            <td>${formatDuration(q.duration_ms)}</td>
            <td>${q.cached ? 'Yes' : 'No'}</td>
            <td>
                <button class="btn btn-small btn-secondary" data-action="view-trace" data-query-id="${q.query_id || q.id}">Trace</button>
                <button class="btn btn-small btn-secondary" data-action="replay-query" data-query-id="${q.query_id || q.id}">Replay</button>
            </td>
        </tr>
    `).join('');
}

async function viewTrace(id) {
    showLoading();
    try {
        const data = await api.getTrace(id);
        hideLoading();
        navigateTo('trace');
        renderTraceDetail(data);
    } catch (err) {
        hideLoading();
        alert('Failed to load trace: ' + err.message);
    }
}

function renderTraceDetail(data) {
    const container = $('trace-detail');
    const trace = data.trace || data.events || [];
    
    let html = `
        <div class="result-header">
            <span>${escapeHtml(data.query || data.domain)}</span>
            <span class="result-rcode rcode-${(data.rcode || '').toLowerCase()}">${data.rcode || '-'}</span>
        </div>
    `;
    
    if (trace.length > 0) {
        html += '<h3>Resolution Steps</h3><div class="trace-timeline">';
        for (const step of trace) {
            const stepClass = (step.step_type || '').replace('_', '-');
            html += `
                <div class="trace-step ${stepClass}">
                    <div class="trace-step-header">
                        <span class="trace-step-type">${escapeHtml(step.step_type || 'query')}</span>
                        <span class="trace-step-latency">${formatDuration(step.latency_ms)}</span>
                    </div>
                    <div class="trace-step-server">${escapeHtml(step.server || '-')}</div>
                    <div style="color: var(--text-secondary);">${escapeHtml(step.query || '')} (${step.query_type || ''})</div>
                </div>
            `;
        }
        html += '</div>';
    }
    
    container.innerHTML = html;
}

async function replayQuery(id) {
    showLoading();
    try {
        const result = await api.replayQuery(id);
        hideLoading();
        navigateTo('query');
        $('query-domain').value = result.original?.query || result.query || '';
        $('query-type').value = result.original?.type || result.query_type || 'A';
        renderQueryResult(result.replay || result);
    } catch (err) {
        hideLoading();
        alert('Failed to replay: ' + err.message);
    }
}

async function compareServers() {
    const domain = $('compare-domain').value.trim();
    const type = $('compare-type').value;
    const serversStr = $('compare-servers').value.trim();
    
    if (!domain) {
        showError($('compare-result'), 'Please enter a domain name');
        return;
    }
    
    const servers = serversStr ? serversStr.split(',').map(s => s.trim()).filter(s => s) : ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
    
    showLoading();
    try {
        const result = await api.compare(domain, type, servers);
        hideLoading();
        renderCompareResult(result);
    } catch (err) {
        hideLoading();
        showError($('compare-result'), err.message);
    }
}

function renderCompareResult(result) {
    const container = $('compare-result');
    const results = result.results || result;
    
    if (!results || results.length === 0) {
        container.innerHTML = '<div class="result-empty">No results</div>';
        return;
    }
    
    container.innerHTML = results.map(r => {
        const message = r.message || r.answer;
        const rcode = rcodeName(r.rcode ?? message?.header?.rcode);
        const rcodeClass = rcode.toLowerCase() === 'noerror' ? 'rcode-noerror' : 'rcode-servfail';
        const answers = message?.answers || r.answers || [];
        
        return `
            <div class="compare-card">
                <div class="compare-card-header">
                    <span class="compare-server">${escapeHtml(r.server)}</span>
                    <span class="result-rcode ${rcodeClass}">${rcode}</span>
                </div>
                <div class="compare-latency">${formatDuration(r.duration_ms || r.latency_ms)}</div>
                ${r.error ? `<div class="error-message" style="margin-top: 12px;">${escapeHtml(r.error)}</div>` : ''}
                ${answers.length > 0 ? `
                    <ul class="answer-list" style="margin-top: 12px;">
                        ${answers.slice(0, 5).map(a => `
                            <li class="answer-item" style="padding: 8px;">
                                <span class="answer-value">${escapeHtml(formatAnswerValue(a))}</span>
                            </li>
                        `).join('')}
                        ${answers.length > 5 ? `<li style="color: var(--text-muted);">+${answers.length - 5} more</li>` : ''}
                    </ul>
                ` : '<div style="color: var(--text-muted); margin-top: 12px;">No answers</div>'}
            </div>
        `;
    }).join('');
}

async function loadSettings() {
    showLoading();
    try {
        const settings = await api.getSettings();
        hideLoading();
        renderSettings(settings);
    } catch (err) {
        hideLoading();
        showError($('settings-grid'), err.message);
    }
}

function renderSettings(settings) {
    $('settings-grid').innerHTML = Object.entries(settings).map(([key, value]) => `
        <div class="setting-card">
            <div class="setting-label">${escapeHtml(key)}</div>
            <div class="setting-value">${escapeHtml(String(value))}</div>
        </div>
    `).join('');
    
    if (Array.isArray(settings.blocklist)) {
        $('blocklist-text').value = settings.blocklist.join('\n');
    }
}

async function saveBlocklist() {
    const text = $('blocklist-text').value;
    const domains = text.split('\n').map(d => d.trim()).filter(d => d && !d.startsWith('#'));
    const status = $('settings-status');
    
    try {
        await api.updateSettings({ blocklist: domains });
        showTransientStatus(status, 'success', 'Blocklist updated');
    } catch (err) {
        showTransientStatus(status, 'error', err.message);
    }
}

$('query-btn').addEventListener('click', resolveQuery);
$('query-domain').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') resolveQuery();
});
$('reverse-btn').addEventListener('click', reverseLookup);
$('reverse-ip').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') reverseLookup();
});
$('bulk-run-btn').addEventListener('click', () => runBulkResolve('json'));
$('bulk-export-btn').addEventListener('click', () => runBulkResolve('csv'));
$('cache-refresh').addEventListener('click', loadCache);
$('cache-flush').addEventListener('click', flushCache);
$('history-refresh').addEventListener('click', loadHistory);
$('compare-btn').addEventListener('click', compareServers);
$('blocklist-save').addEventListener('click', saveBlocklist);
document.querySelector('.back-link')?.addEventListener('click', (e) => {
    e.preventDefault();
    navigateTo('history');
});
$('cache-tbody').addEventListener('click', (e) => {
    const button = e.target.closest('button[data-action="evict-cache"]');
    if (!button) return;
    evictEntry(button.dataset.key || '');
});
$('history-tbody').addEventListener('click', (e) => {
    const button = e.target.closest('button[data-query-id]');
    if (!button) return;
    const id = button.dataset.queryId || '';
    if (button.dataset.action === 'view-trace') {
        viewTrace(id);
    } else if (button.dataset.action === 'replay-query') {
        replayQuery(id);
    }
});

$('history-search').addEventListener('input', (e) => {
    const search = e.target.value.toLowerCase();
    const filtered = historyData.filter(q => 
        (q.domain || q.query || '').toLowerCase().includes(search) ||
        (q.type || q.qtype || '').toLowerCase().includes(search)
    );
    renderHistoryTable(filtered);
});

async function refreshConnectionStatus() {
    try {
        await api.health();
        setConnectionStatus(true, 'Connected');
    } catch (_) {
        setConnectionStatus(false, 'Disconnected');
    }
}

function startHealthPolling() {
    if (healthPollTimer !== null) {
        clearInterval(healthPollTimer);
    }
    refreshConnectionStatus();
    healthPollTimer = setInterval(refreshConnectionStatus, 15000);
}

const initialHashPage = window.location.hash ? window.location.hash.slice(1) : 'query';
navigateTo(initialHashPage, { updateHash: !knownPages.has(initialHashPage) });
startHealthPolling();

setInterval(() => {
    if (currentPage === 'metrics') {
        loadMetrics();
    }
}, 5000);

// Accessibility: Keyboard navigation
document.addEventListener('keydown', (e) => {
    const target = e.target;
    const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT';
    
    if (e.key === 'Escape') {
        const help = $('keyboard-help');
        if (!help.classList.contains('hidden')) {
            help.classList.add('hidden');
            $('keyboard-help-close')?.focus();
        }
        return;
    }
    
    if (isInput || e.ctrlKey || e.metaKey || e.altKey) {
        return;
    }
    
    switch (e.key.toLowerCase()) {
        case '/':
            e.preventDefault();
            if (currentPage === 'history') {
                $('history-search')?.focus();
            } else if (currentPage === 'query') {
                $('query-domain')?.focus();
            } else if (currentPage === 'compare') {
                $('compare-domain')?.focus();
            }
            break;
        case 'q':
            e.preventDefault();
            navigateTo('query');
            $('query-domain')?.focus();
            break;
        case 'c':
            if (e.key !== 'P') {
                e.preventDefault();
                navigateTo('cache');
            }
            break;
        case 'm':
            e.preventDefault();
            navigateTo('metrics');
            break;
        case 'h':
            e.preventDefault();
            navigateTo('history');
            $('history-search')?.focus();
            break;
        case 'p':
            e.preventDefault();
            navigateTo('compare');
            $('compare-domain')?.focus();
            break;
        case 's':
            e.preventDefault();
            navigateTo('settings');
            break;
        case '?':
            e.preventDefault();
            $('keyboard-help').classList.remove('hidden');
            $('keyboard-help-close')?.focus();
            break;
        case 'enter':
            if (currentPage === 'query' && target.id !== 'query-domain') {
                resolveQuery();
            } else if (currentPage === 'compare' && target.id !== 'compare-domain' && target.id !== 'compare-servers') {
                compareServers();
            }
            break;
        case 'r':
            e.preventDefault();
            if (currentPage === 'cache') loadCache();
            else if (currentPage === 'history') loadHistory();
            else if (currentPage === 'metrics') loadMetrics();
            break;
    }
});

$('keyboard-help-close')?.addEventListener('click', () => {
    $('keyboard-help').classList.add('hidden');
});

$('keyboard-help')?.addEventListener('click', (e) => {
    if (e.target === $('keyboard-help')) {
        $('keyboard-help').classList.add('hidden');
    }
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
        document.body.classList.add('high-contrast-focus');
    }
});

const navLinks = document.querySelectorAll('.nav-link');
navLinks.forEach(link => {
    link.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            const page = link.dataset.page;
            if (page) navigateTo(page);
        }
    });
});

function announceToScreenReader(message) {
    const announcement = document.createElement('div');
    announcement.setAttribute('role', 'alert');
    announcement.setAttribute('aria-live', 'polite');
    announcement.className = 'sr-only';
    announcement.textContent = message;
    document.body.appendChild(announcement);
    setTimeout(() => announcement.remove(), 1000);
}

window.addEventListener('hashchange', () => {
    const page = window.location.hash.slice(1);
    if (page !== currentPage) {
        navigateTo(page, { updateHash: false });
    }
});
