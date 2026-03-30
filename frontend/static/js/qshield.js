// frontend/static/js/qshield.js
// Q-Shield — Shared Frontend Utilities

const qshield = {
    API_BASE: 'http://localhost:8000',

    async api(path, options = {}) {
        const url      = this.API_BASE + path;
        const defaults = {
            credentials: 'include',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': this.getCsrf() }
        };
        const resp = await fetch(url, { ...defaults, ...options });
        if (resp.status === 401 || resp.status === 403) {
            window.location.href = '/pages/login.html'; return null;
        }
        return resp.json();
    },

    getCsrf() {
        const match = document.cookie.match(/csrftoken=([^;]+)/);
        return match ? match[1] : '';
    },

    async init(activePage) {
        await fetch(this.API_BASE + '/api/csrf/', { credentials: 'include' });
        try {
            const me = await this.api('/api/me/');
            if (!me) return;
            this.renderLayout(activePage, me.username, me.role);
        } catch {
            window.location.href = '/pages/login.html';
        }
    },

    renderLayout(activePage, username, role) {
        const pages = [
            { id: 'home',      href: 'index.html',           label: 'Home' },
            { id: 'discovery', href: 'asset_discovery.html', label: 'Asset Discovery' },
            { id: 'cbom',      href: 'cbom.html',            label: 'CBOM' },
            { id: 'posture',   href: 'pqc_posture.html',     label: 'Posture of PQC' },
            { id: 'rating',    href: 'cyber_rating.html',    label: 'Cyber Rating' },
            { id: 'reporting', href: 'reporting.html',       label: 'Reporting' },
        ];

        const navItems = pages.map(p =>
            `<li><a href='${p.href}' class='${p.id === activePage ? "active" : ""}'>${p.label}</a></li>`
        ).join('');

        document.getElementById('app-layout').innerHTML = `
          <div class='d-flex' style='min-height:100vh'>
            <nav class='qshield-sidebar'>
              <div class='sidebar-logo'>
                <div style='color:#D4AC0D;font-weight:900;font-size:20px;padding:20px'>Q-SHIELD</div>
                <div style='color:rgba(255,255,255,0.5);font-size:11px;padding:0 20px 16px'>PQC-Ready | PNB</div>
              </div>
              <ul class='sidebar-nav'>${navItems}</ul>
              <div style='padding:16px;border-top:1px solid rgba(255,255,255,0.1)'>
                <a href='#' onclick='qshield.logout()' style='color:rgba(255,255,255,0.5);font-size:12px;text-decoration:none'>Logout</a>
                <button onclick='qshield.toggleDark()' style='float:right;background:none;border:none;color:rgba(255,255,255,0.5);font-size:14px;cursor:pointer'>Dark</button>
              </div>
            </nav>
            <main class='qshield-main flex-grow-1'>
              <div class='topbar'>
                <div style='font-weight:800;font-size:17px;color:#1B2A4A'>Q-Shield Dashboard</div>
                <div class='d-flex align-items-center gap-3'>
                  <span class='topbar-user'>Welcome: ${username}</span>
                  <span class='badge' style='background:#D4AC0D;color:#1B2A4A;font-weight:700'>${role.toUpperCase()}</span>
                </div>
              </div>
              <div class='page-content' id='page-main'></div>
            </main>
          </div>`;

        const content = document.getElementById('page-content');
        const target  = document.getElementById('page-main');
        if (content && target) target.appendChild(content);
    },

    async logout() {
        await this.api('/api/logout/', { method: 'POST' });
        window.location.href = '/pages/login.html';
    },

    getLabelClass(label) {
        const map = {
            'Fully Quantum Safe': 'badge-quantum-safe',
            'PQC Ready':          'badge-pqc-ready',
            'Quantum Vulnerable': 'badge-vulnerable',
            'Critical':           'badge-critical',
        };
        return map[label] || 'badge-critical';
    },

    getRiskClass(risk) {
        const map = { 'HIGH': 'risk-high', 'MEDIUM': 'risk-medium', 'LOW': 'risk-low' };
        return map[(risk||'').toUpperCase()] || 'risk-low';
    },

    async startScan() {
        const url  = document.getElementById('scanInput')?.value?.trim();
        if (!url) { alert('Please enter a URL or domain.'); return; }

        const prog = document.getElementById('scan-progress');
        const res  = document.getElementById('scan-result');

        prog?.classList.remove('d-none');
        if (res) res.innerHTML = '';

        try {
            const r = await this.api('/api/scan/', { method: 'POST', body: JSON.stringify({ url }) });
            if (!r) return;

            if (r.error) {
                if (res) res.innerHTML = `<div class='alert alert-danger mt-2'>${r.error}</div>`;
                return;
            }

            const labelCls   = this.getLabelClass(r.label?.text);
            const scoreColor = r.score>=90?'#27AE60':r.score>=60?'#F39C12':'#E74C3C';

            if (res) res.innerHTML = `
              <div class='scan-result-card mt-2'>
                <strong>${r.hostname}</strong><br>
                Score: <strong style='color:${scoreColor};font-size:18px'>${r.score}/100</strong>
                &nbsp;<span class='${labelCls}'>${r.label?.text}</span>
                <br><small>HNDL Risk: <strong>${r.hndl?.hndl_risk||'--'}</strong></small>
              </div>`;

            if (typeof loadHome === 'function') loadHome();

        } catch(e) {
            if (res) res.innerHTML = `<div class='alert alert-danger mt-2'>Connection error: ${e.message}</div>`;
        } finally {
            prog?.classList.add('d-none');
        }
    },

    async scanAll() {
        const results  = await this.api('/api/results/');
        if (!results) return;

        const hostnames = results.map(r => r.hostname);
        if (!hostnames.length) {
            alert('No assets in inventory yet.');
            return;
        }

        await this.api('/api/scan/batch/', {
            method: 'POST',
            body: JSON.stringify({ urls: hostnames })
        });

        if (typeof loadHome === 'function') loadHome();
    },

    filterTable(query) {
        const q = query.toLowerCase();
        document.querySelectorAll('#asset-tbody tr').forEach(row => {
            row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
    },

    renderGraph(graphData, containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = "";

        let nodes, edges;

        if (graphData.nodes && graphData.edges) {
            nodes = new vis.DataSet(graphData.nodes);
            edges = new vis.DataSet(graphData.edges);
        }

        else if (graphData.results) {
            const results = graphData.results;

            nodes = new vis.DataSet(results.map(r => {
                const score = r.quantum_score || 0;

                let color = '#27AE60';
                if (r.label === 'PQC Ready') color = '#F39C12';
                if (r.label === 'Quantum Vulnerable') color = '#E74C3C';
                if (r.label === 'Critical') color = '#8B1A1A';

                return {
                    id: r.hostname,
                    label: r.hostname,
                    value: Math.max(12, score),
                    color: {
                        background: color,
                        border: '#ffffff',
                        highlight: { background: color, border: '#FFD700' }
                    },
                    font: { color: '#fff', size: 12 },
                    title: `
<b>${r.hostname}</b><br>
Score: ${score}/100<br>
Label: ${r.label}<br>
TLS: ${r.tls_version || '--'}<br>
Risk: ${r.hndl_risk || '--'}
                    `
                };
            }));

            edges = new vis.DataSet([]);

            results.forEach(r1 => {
                results.forEach(r2 => {
                    if (r1 !== r2) {
                        const base1 = r1.hostname.split('.').slice(-2).join('.');
                        const base2 = r2.hostname.split('.').slice(-2).join('.');

                        if (base1 === base2) {
                            edges.add({
                                from: r1.hostname,
                                to: r2.hostname,
                                dashes: true,
                                color: { color: '#AAAAAA' }
                            });
                        }
                    }
                });
            });

            results.forEach(r => {
                if (r.hostname.includes('pnb') && results.some(x => x.hostname === 'google.com')) {
                    edges.add({
                        from: r.hostname,
                        to: 'google.com',
                        color: { color: '#3498DB' }
                    });
                }
            });

            results.forEach(r => {
                if ((r.hndl_risk || '').toUpperCase() === 'HIGH') {
                    edges.add({
                        from: r.hostname,
                        to: results[0]?.hostname,
                        width: 2,
                        color: { color: '#E74C3C' }
                    });
                }
            });
        }

        if (!nodes || !edges) {
            console.warn("Graph data missing");
            return;
        }

        new vis.Network(container, { nodes, edges }, {
            layout: { randomSeed: 42, improvedLayout: true },
            physics: { enabled: true, stabilization: { iterations: 200 } },
            interaction: { hover: true, zoomView: true, navigationButtons: true },
            nodes: {
                borderWidth: 2,
                shadow: true,
                scaling: { min: 10, max: 30 },
                font: { color: '#fff', size: 11 }
            },
            edges: {
                width: 1.5,
                smooth: { type: 'dynamic' }
            }
        });
    },

    toggleDark() {
        const r = document.getElementById('html-root');
        r.dataset.theme = r.dataset.theme === 'dark' ? 'light' : 'dark';
        document.body.dataset.theme = r.dataset.theme;
    }
};