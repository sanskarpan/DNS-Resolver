const API_BASE = '/api/v1';
const REQUEST_TIMEOUT_MS = 10000;
const CONTROL_PLANE_TOKEN_KEY = 'dnsresolver.controlPlaneToken';

function getControlPlaneToken() {
    try {
        return (localStorage.getItem(CONTROL_PLANE_TOKEN_KEY) || '').trim();
    } catch (_) {
        return '';
    }
}

function setControlPlaneToken(token) {
    try {
        localStorage.setItem(CONTROL_PLANE_TOKEN_KEY, String(token || '').trim());
    } catch (_) {
        // Ignore storage failures and keep the token ephemeral for this session.
    }
}

function clearControlPlaneToken() {
    try {
        localStorage.removeItem(CONTROL_PLANE_TOKEN_KEY);
    } catch (_) {
        // Ignore storage failures.
    }
}

async function request(path, options = {}, expect = 'json') {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const headers = new Headers(options.headers || {});
        const token = getControlPlaneToken();
        if (token && !headers.has('Authorization')) {
            headers.set('Authorization', `Bearer ${token}`);
        }
        const res = await fetch(path, { ...options, headers, signal: controller.signal });
        if (!res.ok) {
            let detail = `HTTP ${res.status}`;
            try {
                const body = await res.json();
                if (body && body.error) detail = body.error;
            } catch (_) {
                // Ignore parse failures and keep the status fallback.
            }
            throw new Error(detail);
        }
        if (expect === 'text') return res.text();
        if (expect === 'response') return res;
        return res.json();
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new Error('Request timed out');
        }
        throw err;
    } finally {
        clearTimeout(timeout);
    }
}

const api = {
    async resolve(domain, type, trace = false) {
        const params = new URLSearchParams({ q: domain, type });
        if (trace) params.append('trace', 'true');
        return request(`${API_BASE}/resolve?${params}`);
    },

    async getCache(page = 1, limit = 50) {
        return request(`${API_BASE}/cache?page=${page}&limit=${limit}`);
    },

    async getCacheStats() {
        return request(`${API_BASE}/cache/stats`);
    },

    async flushCache() {
        return request(`${API_BASE}/cache`, { method: 'DELETE' });
    },

    async evictCacheEntry(key) {
        return request(`${API_BASE}/cache/${encodeURIComponent(key)}`, { method: 'DELETE' });
    },

    async getMetrics() {
        return request(`${API_BASE}/metrics`);
    },

    async getHistory(page = 1, limit = 100) {
        return request(`${API_BASE}/history?page=${page}&limit=${limit}`);
    },

    async getTrace(id) {
        return request(`${API_BASE}/history/${id}`);
    },

    async replayQuery(id) {
        return request(`${API_BASE}/history/${id}/replay`);
    },

    async compare(domain, type, servers) {
        const params = new URLSearchParams({ q: domain, type, servers: servers.join(',') });
        return request(`${API_BASE}/compare?${params}`);
    },

    async getSettings() {
        return request(`${API_BASE}/settings`);
    },

    async updateSettings(settings) {
        return request(`${API_BASE}/settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });
    },

    async getRootServers() {
        return request(`${API_BASE}/rootservers`);
    },

    async getSecurityStats() {
        return request(`${API_BASE}/security/stats`);
    },

    async reverse(ip) {
        return request(`${API_BASE}/reverse?ip=${encodeURIComponent(ip)}`);
    },

    async bulkResolve(queries, type = 'A', format = 'json') {
        const params = new URLSearchParams({ queries: queries.join(','), type, format });
        return request(`${API_BASE}/bulk?${params}`, {}, format === 'csv' ? 'text' : 'json');
    },

    async health() {
        return request(`${API_BASE}/health/ready`);
    },

    getControlPlaneToken,
    setControlPlaneToken,
    clearControlPlaneToken
};

function connectWebSocket(path, onMessage, onOpen, onClose) {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = new URL(`${protocol}//${location.host}${path}`);
    const token = getControlPlaneToken();
    if (token) {
        url.searchParams.set('token', token);
    }
    const ws = new WebSocket(url.toString());
    
    ws.onopen = () => {
        console.log(`WebSocket connected: ${path}`);
        if (onOpen) onOpen();
    };
    
    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            onMessage(data);
        } catch (e) {
            console.error('WebSocket parse error:', e);
        }
    };
    
    ws.onclose = () => {
        console.log(`WebSocket disconnected: ${path}`);
        if (onClose) onClose();
        setTimeout(() => connectWebSocket(path, onMessage, onOpen, onClose), 5000);
    };
    
    ws.onerror = (err) => {
        console.error('WebSocket error:', err);
    };
    
    return ws;
}
