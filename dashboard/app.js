// Kernel Security Monitor Dashboard — Vanilla JS
// PAUSE mode, Known/Unknown, Paused processes panel, AI Chat, D3 Graph

(function () {
    'use strict';

    // ---- State ----
    const state = {
        mode: 'observe',
        trustScores: {},   // pid -> {comm, ppid, trust, status, tier, paused, killed, technique, action, pvalue}
        decisions: [],
        events: [],
        narrations: [],
        actionLog: [],
        graphData: { nodes: {}, edges: [] },
        stats: { nodes_process: 0, nodes_file: 0, nodes_socket: 0, edges_total: 0 },
        alertCount: 0,
        killCount: 0,
        pausedCount: 0,
        currentFilter: 'all',
        currentTab: 'narration',
        currentView: 'security',
        rateInfo: { processed: 0, dropped: 0 },
        pausedProcesses: [],
        chatHistory: []   // [{role:'user'|'ai', text:'...'}]
    };

    // ---- DOM refs ----
    const $trustContainer = document.getElementById('trust-scores-container');
    const $decisionsContainer = document.getElementById('decisions-container');
    const $eventsContainer = document.getElementById('events-container');
    const $narrationContainer = document.getElementById('narration-container');
    const $actionLogContainer = document.getElementById('action-log-container');
    const $graphContainer = document.getElementById('graph-container');
    const $modeBtn = document.getElementById('mode-toggle-btn');
    const $modeLabel = document.getElementById('mode-label');
    const $chatForm = document.getElementById('chat-form');
    const $chatInput = document.getElementById('chat-input');
    const $chatMessages = document.getElementById('chat-messages-container');
    const $pausedBanner = document.getElementById('paused-banner');
    const $pausedBannerList = document.getElementById('paused-banner-list');
    const $searchInput = document.getElementById('process-search-input');
    const $inspectorModal = document.getElementById('inspector-modal');
    const $inspCloseBtn = document.getElementById('insp-close-btn');
    const $inspOverlay = document.getElementById('insp-overlay');

    let searchTerm = '';
    let htopSearchTerm = '';
    let htopSortBy = 'trust';
    let trustContainerHovered = false;
    let renderPending = false;
    let renderDebounceTimer = null;

    // ---- Init ----
    document.addEventListener('DOMContentLoaded', () => {
        initModeToggle();
        initTabs();
        initChat();
        initFilters();
        initSearch();
        initInspector();
        initTopNav();
        initSSE();
        initGraph();
        fetchInitialData();

        setInterval(fetchTrustScores, 3000);
        setInterval(fetchStats, 2500);
        setInterval(fetchPausedProcesses, 2000);
        setInterval(fetchActionLog, 3000);

        if ($trustContainer) {
            $trustContainer.addEventListener('mouseenter', () => { trustContainerHovered = true; });
            $trustContainer.addEventListener('mouseleave', () => {
                trustContainerHovered = false;
                if (renderPending) {
                    renderPending = false;
                    renderTrustScores();
                    renderHtop();
                }
            });
        }
    });

    // ---- Top Nav ----
    function initTopNav() {
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                state.currentView = btn.dataset.view;
                document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
                document.getElementById(`view-${state.currentView}`).classList.add('active');
            });
        });
    }

    // ---- Mode Toggle (cycles: observe → pause → enforce → observe) ----
    const modeCycle = ['observe', 'pause', 'enforce'];
    function initModeToggle() {
        if (!$modeBtn) return;
        $modeBtn.addEventListener('click', async () => {
            const idx = modeCycle.indexOf(state.mode);
            const newMode = modeCycle[(idx + 1) % modeCycle.length];
            try {
                const resp = await fetch('/api/mode', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mode: newMode })
                });
                if (resp.ok) {
                    const data = await resp.json();
                    setModeUI(data.mode);
                }
            } catch (e) {
                console.warn('Failed to switch mode:', e);
            }
        });
    }

    function setModeUI(mode) {
        state.mode = mode;
        const modeIcon = document.querySelector('#mode-toggle-btn .mode-icon');
        if (mode === 'enforce') {
            $modeBtn.className = 'mode-btn enforce';
            $modeLabel.textContent = 'ENFORCE MODE';
            if (modeIcon) modeIcon.textContent = '⚡';
        } else if (mode === 'pause') {
            $modeBtn.className = 'mode-btn pause';
            $modeLabel.textContent = 'PAUSE MODE';
            if (modeIcon) modeIcon.textContent = '⏸';
        } else {
            $modeBtn.className = 'mode-btn observe';
            $modeLabel.textContent = 'OBSERVE MODE';
            if (modeIcon) modeIcon.textContent = '🛡️';
        }
    }

    // ---- Tabs ----
    function initTabs() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tab = btn.dataset.tab;
                state.currentTab = tab;

                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

                btn.classList.add('active');
                const target = document.getElementById(`tab-${tab}`);
                if (target) target.classList.add('active');
            });
        });
    }

    // ---- Filters ----
    function initFilters() {
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.currentFilter = btn.dataset.filter;
                renderTrustScores();
            });
        });
    }

    // ---- Search ----
    function initSearch() {
        if (!$searchInput) return;
        $searchInput.addEventListener('input', (e) => {
            searchTerm = e.target.value.toLowerCase().trim();
            renderTrustScores();
        });
    }

    // ---- Process Inspector ----
    function initInspector() {
        if ($inspCloseBtn) {
            $inspCloseBtn.addEventListener('click', closeProcessInspector);
        }
        if ($inspOverlay) {
            $inspOverlay.addEventListener('click', closeProcessInspector);
        }
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && $inspectorModal && !$inspectorModal.classList.contains('hidden')) {
                closeProcessInspector();
            }
        });
    }

    function closeProcessInspector() {
        if ($inspectorModal) {
            $inspectorModal.classList.add('hidden');
        }
    }

    function openProcessInspector(entry) {
        if (!entry || !$inspectorModal) return;
        const tier = getTrustTier(entry.trust);
        const status = entry.killed ? 'killed' : (entry.paused ? 'paused' : (entry.status || (entry.trust > 75 ? 'known' : 'unknown')));
        const isPaused = status === 'paused' || entry.paused;
        const isKnown = status === 'known';

        const statusEmoji = { 'known': '🟢', 'unknown': '🟡', 'suspicious': '🔴', 'paused': '⏸', 'killed': '☠️' }[status] || '🟡';

        setText('#insp-comm', entry.comm || 'Unknown');
        setText('#insp-pids', `PID ${entry.pid}${entry.ppid ? ` (Parent PID: ${entry.ppid})` : ''}`);
        setText('#insp-status', `${statusEmoji} ${status.toUpperCase()}`);
        setText('#insp-trust', `${Math.round(entry.trust)}% (${tier})`);
        setText('#insp-first-seen', entry.firstSeen ? new Date(entry.firstSeen).toLocaleTimeString() : 'Unknown');

        // Threat analysis fields
        const tech = entry.technique || entry.techniqueID;
        const techDesc = entry.techniqueDesc || '';
        setText('#insp-technique', tech ? `${tech}${techDesc ? ' — ' + techDesc : ''}` : 'None detected');
        const reasonMap = {
            'observe_critical': 'Anomaly score below threshold — unusual behavior pattern detected',
            'paused_sigstop': 'Suspended by monitor — awaiting user decision',
            'kill': 'Killed — exceeded threat threshold',
            'verified_kill': 'Killed — confirmed malicious behavior',
            'trusted_allow': 'Known/trusted process — whitelisted',
            'observe_log': 'Logged for observation — low anomaly score',
            'observe_alert': 'Alert — moderate anomaly, monitoring closely'
        };
        setText('#insp-reason', reasonMap[entry.action || ''] || (entry.trust < 40 ? 'High anomaly score from ML model' : entry.trust < 70 ? 'Moderate anomaly score — monitoring' : 'No significant threat indicators'));
        setText('#insp-action', entry.action || '-');
        const pval = entry.pvalue !== undefined && entry.pvalue !== null ? Number(entry.pvalue).toFixed(4) : '-';
        setText('#insp-pvalue', pval);

        const bar = document.getElementById('insp-trust-bar');
        if (bar) {
            bar.className = `trust-mini-fill ${tier}`;
            bar.style.width = `${Math.max(5, entry.trust)}%`;
        }

        const actionsContainer = document.getElementById('insp-actions-container');
        if (actionsContainer) {
            actionsContainer.innerHTML = '';

            // Known button
            if (!isKnown) {
                const btn = document.createElement('button');
                btn.className = 'insp-action-btn row-btn known-btn';
                btn.innerHTML = '✅ Mark Known';
                btn.addEventListener('click', async () => {
                    await markAsKnown(entry.comm, entry.pid);
                    await fetchTrustScores();
                    await fetchActionLog();
                    closeProcessInspector();
                });
                actionsContainer.appendChild(btn);
            }

            // Pause / Resume
            if (!isPaused) {
                const btn = document.createElement('button');
                btn.className = 'insp-action-btn row-btn pause-btn';
                btn.innerHTML = '⏸ Suspend (SIGSTOP)';
                btn.addEventListener('click', async () => {
                    await pauseProcess(entry.pid, entry.comm);
                    await fetchPausedProcesses();
                    await fetchActionLog();
                    closeProcessInspector();
                });
                actionsContainer.appendChild(btn);
            } else {
                const btn = document.createElement('button');
                btn.className = 'insp-action-btn row-btn resume-btn';
                btn.innerHTML = '▶ Resume (SIGCONT)';
                btn.addEventListener('click', async () => {
                    await resumeProcess(entry.pid);
                    await fetchPausedProcesses();
                    await fetchActionLog();
                    closeProcessInspector();
                });
                actionsContainer.appendChild(btn);
            }

            // Kill
            const killBtn = document.createElement('button');
            killBtn.className = 'insp-action-btn row-btn kill-btn';
            killBtn.innerHTML = '💀 Kill (SIGKILL)';
            killBtn.addEventListener('click', async () => {
                if (!confirm(`SIGKILL '${entry.comm}' (PID ${entry.pid})?`)) return;
                await killProcess(entry.pid, entry.comm);
                await fetchPausedProcesses();
                await fetchActionLog();
                closeProcessInspector();
            });
            actionsContainer.appendChild(killBtn);

            // Ask AI
            const askBtn = document.createElement('button');
            askBtn.className = 'insp-action-btn row-btn ask-btn';
            askBtn.innerHTML = '🔍 Ask AI Copilot';
            askBtn.addEventListener('click', () => {
                closeProcessInspector();
                const statusCtx = isPaused ? 'PAUSED' : `trust=${Math.round(entry.trust)}`;
                handleChatQuery(`Analyze process '${entry.comm}' (PID ${entry.pid}, ${statusCtx}). Is it safe or malicious? What should I do?`, entry.pid);
            });
            actionsContainer.appendChild(askBtn);
        }

        $inspectorModal.classList.remove('hidden');
    }

    // ---- AI Security Chat ----
    function initChat() {
        if ($chatForm) {
            $chatForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const q = $chatInput.value.trim();
                if (!q) return;
                $chatInput.value = '';
                await handleChatQuery(q);
            });
        }

        document.querySelectorAll('.quick-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const q = chip.dataset.q;
                if (q) handleChatQuery(q);
            });
        });
    }

    async function handleChatQuery(query, pid) {
        // Switch to chat tab
        const chatTabBtn = document.querySelector('.tab-btn[data-tab="chat"]');
        if (chatTabBtn) chatTabBtn.click();

        // Push to history before sending
        state.chatHistory.push({ role: 'user', text: query });
        if (state.chatHistory.length > 20) state.chatHistory = state.chatHistory.slice(-20);

        appendChatMessage('user', query);
        const loadingBubble = appendChatMessage('ai loading', '⏳ Analysing with AI...');

        try {
            const body = { query, history: state.chatHistory.slice(-10) };
            if (pid) body.pid = pid;

            const resp = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            loadingBubble.classList.remove('loading');
            loadingBubble.classList.add('ai');

            if (resp.ok) {
                const data = await resp.json();
                const text = data.response || 'Analysis complete.';
                loadingBubble.innerHTML = `<strong>Kernel Security AI:</strong> ${escapeHtml(text).replace(/\n/g, '<br>')}`;
                // Save AI reply to history
                state.chatHistory.push({ role: 'ai', text });
                if (state.chatHistory.length > 20) state.chatHistory = state.chatHistory.slice(-20);
            } else {
                loadingBubble.innerHTML = '<strong>Kernel Security AI:</strong> ⚠️ Request failed. Check that LLM_API_KEY is set.';
            }
        } catch (err) {
            loadingBubble.classList.remove('loading');
            loadingBubble.classList.add('ai');
            loadingBubble.innerHTML = '<strong>Kernel Security AI:</strong> ⚠️ Could not reach monitor backend.';
        }
        if ($chatMessages) $chatMessages.scrollTop = $chatMessages.scrollHeight;
    }

    function appendChatMessage(type, text) {
        const bubble = document.createElement('div');
        bubble.className = `chat-bubble ${type}`;
        if (type === 'user') {
            bubble.textContent = text;
        } else {
            bubble.innerHTML = `<strong>Kernel Security AI:</strong> ${escapeHtml(text).replace(/\n/g, '<br>')}`;
        }
        $chatMessages.appendChild(bubble);
        $chatMessages.scrollTop = $chatMessages.scrollHeight;
        return bubble;
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // ---- SSE Stream ----
    function initSSE() {
        const source = new EventSource('/api/stream');

        source.addEventListener('event', (e) => {
            const data = JSON.parse(e.data);
            handleEvent(data);
        });

        source.addEventListener('narration', (e) => {
            const data = JSON.parse(e.data);
            handleNarration(data);
        });

        source.onerror = () => {
            const dot = document.querySelector('#sensor-status .status-dot');
            if (dot) dot.classList.remove('pulse');
        };

        source.onopen = () => {
            const dot = document.querySelector('#sensor-status .status-dot');
            if (dot) dot.classList.add('pulse', 'active');
        };
    }

    // ---- Fetch initial data ----
    async function fetchInitialData() {
        try {
            const modeResp = await fetch('/api/mode');
            if (modeResp.ok) {
                const modeData = await modeResp.json();
                setModeUI(modeData.mode);
            }

            const decisionsResp = await fetch('/api/decisions');
            if (decisionsResp.ok) {
                const decisions = await decisionsResp.json();
                if (decisions) decisions.forEach(d => addDecision(d));
            }

            const graphResp = await fetch('/api/graph');
            if (graphResp.ok) {
                const graphData = await graphResp.json();
                if (graphData) updateGraphData(graphData);
            }

            await fetchTrustScores();
            await fetchStats();
            await fetchPausedProcesses();
        } catch (err) {
            console.warn('Initial data fetch:', err);
        }
    }

    async function fetchTrustScores() {
        try {
            const resp = await fetch('/api/trust');
            if (resp.ok) {
                const scores = await resp.json();
                if (scores) {
                    scores.forEach(s => {
                        state.trustScores[s.pid] = s;
                    });
                    renderTrustScores();
                }
            }
        } catch (e) { /* silent */ }
    }

    async function fetchStats() {
        try {
            const resp = await fetch('/api/stats');
            if (resp.ok) {
                const stats = await resp.json();
                if (stats) {
                    state.stats = stats;
                    renderStats();
                }
            }
        } catch (e) { /* silent */ }
    }

    async function fetchPausedProcesses() {
        try {
            const resp = await fetch('/api/paused');
            if (resp.ok) {
                const list = await resp.json();
                state.pausedProcesses = list || [];
                renderPausedBanner();
                setText('#stat-paused .stat-value', state.pausedProcesses.length);

                // Update paused status in trustScores map
                const pausedPIDs = new Set((list || []).map(p => p.pid));
                Object.values(state.trustScores).forEach(entry => {
                    if (pausedPIDs.has(entry.pid)) {
                        entry.paused = true;
                        entry.status = 'paused';
                    } else if (entry.paused && entry.status === 'paused') {
                        entry.paused = false;
                        entry.status = 'unknown';
                    }
                });
                renderTrustScores();
            }
        } catch (e) { /* silent */ }
    }

    async function fetchActionLog() {
        try {
            const resp = await fetch('/api/actionlog');
            if (resp.ok) {
                const log = await resp.json();
                state.actionLog = log || [];
                renderActionLog();
            }
        } catch (e) { /* silent */ }
    }

    function renderActionLog() {
        if (!$actionLogContainer) return;
        if (state.actionLog.length === 0) {
            $actionLogContainer.innerHTML = '<div class="empty-state">No actions yet. Kill/Pause/Trust actions will appear here in real time.</div>';
            return;
        }
        $actionLogContainer.innerHTML = '';
        state.actionLog.forEach(entry => {
            const icons = { kill: '💀', pause: '⏸', resume: '▶', trust: '✅' };
            const icon = icons[entry.action] || '📋';
            const time = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '--:--:--';
            const resultColor = entry.result === 'ok' ? '#10b981' : '#ef4444';

            const el = document.createElement('div');
            el.className = `action-log-entry action-${entry.action}`;
            el.innerHTML = `
                <span class="alog-icon">${icon}</span>
                <div class="alog-body">
                    <span class="alog-action">${entry.action.toUpperCase()}</span>
                    <span class="alog-comm">${escapeHtml(entry.comm || '?')} (PID ${entry.pid})</span>
                    <span class="alog-by">by:${entry.by}</span>
                </div>
                <div class="alog-meta">
                    <span class="alog-result" style="color:${resultColor}">${entry.result}</span>
                    <span class="alog-time">${time}</span>
                </div>
            `;
            $actionLogContainer.appendChild(el);
        });
    }

    // ---- Handle SSE events ----
    function handleEvent(data) {
        const evt = data.event;
        const decision = data.decision;
        const stats = data.graph_stats;
        const rate = data.rate_info;

        if (stats) {
            state.stats = stats;
            renderStats();
        }

        if (rate) {
            state.rateInfo = rate;
            const rateDisplay = document.getElementById('rate-display');
            if (rateDisplay) {
                rateDisplay.textContent = `PROC: ${rate.processed || 0}`;
            }
        }

        if (evt) {
            state.events.unshift(evt);
            if (state.events.length > 100) state.events.pop();
            renderEventEntry(evt);
        }

        if (decision) {
            addDecision(decision);
        }

        if (decision && evt) {
            const existing = state.trustScores[evt.pid] || {};
            if (!existing.killed) { // don't overwrite killed state
                state.trustScores[evt.pid] = {
                    pid: evt.pid,
                    ppid: evt.ppid || 0,
                    comm: evt.comm,
                    trust: decision.trust_score,
                    status: decision.status || 'unknown',
                    tier: getTrustTier(decision.trust_score),
                    paused: decision.status === 'paused',
                    killed: false,
                    technique: decision.technique_id || '',
                    techniqueDesc: decision.technique || '',
                    action: decision.action || '',
                    pvalue: decision.conformal_p_value,
                    firstSeen: existing.firstSeen || new Date().toISOString()
                };
            }
            scheduledRender();
        }
    }

    function addDecision(d) {
        state.decisions.unshift(d);
        if (state.decisions.length > 50) state.decisions.pop();

        if (d.tier === 'medium' || d.tier === 'high') state.alertCount++;
        if (d.action === 'kill' || d.action === 'verified_kill') state.killCount++;

        renderDecisionEntry(d);
        renderAlertStats();
    }

    function handleNarration(data) {
        state.narrations.unshift(data);
        if (state.narrations.length > 10) state.narrations.pop();
        renderNarration(data);
    }

    // ---- Paused Banner ----
    function renderPausedBanner() {
        if (!$pausedBanner || !$pausedBannerList) return;

        if (state.pausedProcesses.length === 0) {
            $pausedBanner.classList.add('hidden');
            return;
        }

        $pausedBanner.classList.remove('hidden');
        $pausedBannerList.innerHTML = '';

        state.pausedProcesses.forEach(p => {
            const card = document.createElement('div');
            card.className = 'paused-card';
            card.innerHTML = `
                <span class="paused-name">⏸ ${p.comm || '?'} (PID ${p.pid})</span>
                <div class="paused-actions">
                    <button class="row-btn known-btn" title="Mark as KNOWN and resume" data-pid="${p.pid}" data-comm="${p.comm}">✅ Trust & Resume</button>
                    <button class="row-btn resume-btn" title="Resume process" data-pid="${p.pid}">▶ Resume</button>
                    <button class="row-btn ask-btn" title="Ask AI about this process" data-pid="${p.pid}" data-comm="${p.comm}">🔍 AI</button>
                </div>
            `;

            card.querySelector('.known-btn').addEventListener('click', async (e) => {
                e.stopPropagation();
                await markAsKnown(p.comm, p.pid);
                await resumeProcess(p.pid);
                await fetchPausedProcesses();
                await fetchTrustScores();
            });

            card.querySelector('.resume-btn').addEventListener('click', async (e) => {
                e.stopPropagation();
                await resumeProcess(p.pid);
                await fetchPausedProcesses();
            });

            card.querySelector('.ask-btn').addEventListener('click', (e) => {
                e.stopPropagation();
                handleChatQuery(`This process ${p.comm} (PID ${p.pid}) is PAUSED by the system monitor. Is it trustworthy? Should I resume it?`, p.pid);
            });

            $pausedBannerList.appendChild(card);
        });
    }

    // ---- Top Navigation ----
    function initTopNav() {
        document.querySelectorAll('.top-nav-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const view = btn.dataset.view;
                state.currentView = view;
                document.querySelectorAll('.top-nav-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                document.querySelectorAll('.main-view').forEach(v => v.classList.remove('active'));
                const target = document.getElementById(`view-${view}`);
                if (target) target.classList.add('active');
                if (view === 'processes') renderHtop();
            });
        });
    }

    // ---- htop Controls ----
    function initHtopControls() {
        const $hs = document.getElementById('htop-search');
        const $sort = document.getElementById('htop-sort');
        if ($hs) $hs.addEventListener('input', e => { htopSearchTerm = e.target.value.toLowerCase().trim(); renderHtop(); });
        if ($sort) $sort.addEventListener('change', e => { htopSortBy = e.target.value; renderHtop(); });
        // Hover lock for htop tbody
        const $tbody = document.getElementById('htop-tbody');
        if ($tbody) {
            $tbody.addEventListener('mouseenter', () => { trustContainerHovered = true; });
            $tbody.addEventListener('mouseleave', () => {
                trustContainerHovered = false;
                if (renderPending) { renderPending = false; renderHtop(); }
            });
        }
    }

    // ---- Scheduled render (debounced + hover-aware) ----
    function scheduledRender() {
        if (trustContainerHovered) {
            renderPending = true;
            return;
        }
        clearTimeout(renderDebounceTimer);
        renderDebounceTimer = setTimeout(() => {
            renderTrustScores();
            if (state.currentView === 'processes') renderHtop();
        }, 800);
    }

    // ---- htop-like Process Monitor ----
    function renderHtop() {
        const $tbody = document.getElementById('htop-tbody');
        const $count = document.getElementById('htop-count');
        if (!$tbody) return;

        let entries = Object.values(state.trustScores).filter(e => !e.killed);
        if ($count) $count.textContent = entries.length;

        // Filter
        if (htopSearchTerm) {
            entries = entries.filter(e =>
                (e.comm && e.comm.toLowerCase().includes(htopSearchTerm)) ||
                String(e.pid).includes(htopSearchTerm)
            );
        }

        // Sort
        entries.sort((a, b) => {
            switch (htopSortBy) {
                case 'trust': return a.trust - b.trust; // most risky first
                case 'trust-desc': return b.trust - a.trust;
                case 'pid': return a.pid - b.pid;
                case 'comm': return (a.comm||'').localeCompare(b.comm||'');
                case 'status': return (a.status||'').localeCompare(b.status||'');
                default: return a.trust - b.trust;
            }
        });

        if (entries.length === 0) {
            $tbody.innerHTML = `<tr><td colspan="7" class="htop-empty">No processes tracked yet. Run the monitor and events will appear.</td></tr>`;
            return;
        }

        $tbody.innerHTML = '';
        entries.forEach(entry => {
            const tier = getTrustTier(entry.trust);
            const status = entry.paused ? 'paused' : (entry.status || 'unknown');
            const isPaused = status === 'paused';
            const isKnown = status === 'known';

            const statusColors = { known: '#10b981', unknown: '#f59e0b', suspicious: '#ef4444', paused: '#6366f1' };
            const sColor = statusColors[status] || '#94a3b8';

            const tr = document.createElement('tr');
            tr.className = `htop-tr${ status === 'suspicious' ? ' htop-row-suspicious' : ''}${isPaused ? ' htop-row-paused' : ''}${isKnown ? ' htop-row-known' : ''}`;
            tr.title = 'Click to open Process Inspector';
            tr.innerHTML = `
                <td class="htop-td htop-td-pid">${entry.pid}</td>
                <td class="htop-td htop-td-ppid">${entry.ppid || '-'}</td>
                <td class="htop-td htop-td-comm" title="${escapeHtml(entry.comm)}">${escapeHtml(entry.comm || '?')}</td>
                <td class="htop-td htop-td-trust ${tier}">${Math.round(entry.trust)}</td>
                <td class="htop-bar-cell">
                    <div class="htop-bar"><div class="htop-bar-fill ${tier}" style="width:${Math.max(3,entry.trust)}%"></div></div>
                </td>
                <td class="htop-td" style="color:${sColor};font-weight:700;font-size:10px">${status.toUpperCase()}</td>
                <td class="htop-actions-td">
                    ${!isKnown ? `<button class="row-btn known-btn htop-act" data-pid="${entry.pid}" data-comm="${escapeHtml(entry.comm)}" title="Trust">✅</button>` : ''}
                    ${!isPaused ? `<button class="row-btn pause-btn htop-act" data-pid="${entry.pid}" data-comm="${escapeHtml(entry.comm)}" title="Suspend">⏸</button>` : ''}
                    ${isPaused ? `<button class="row-btn resume-btn htop-act" data-pid="${entry.pid}" title="Resume">▶</button>` : ''}
                    <button class="row-btn kill-btn htop-act" data-pid="${entry.pid}" data-comm="${escapeHtml(entry.comm)}" title="Kill">💀</button>
                    <button class="row-btn ask-btn htop-act" data-pid="${entry.pid}" data-comm="${escapeHtml(entry.comm)}" title="Ask AI">🔍</button>
                </td>
            `;

            // Row click → inspector (not on action buttons)
            tr.addEventListener('click', e => {
                if (e.target.classList.contains('htop-act')) return;
                openProcessInspector(entry);
            });

            // Wire action buttons
            tr.querySelectorAll('.htop-act').forEach(btn => {
                btn.addEventListener('click', async e => {
                    e.stopPropagation();
                    const pid = parseInt(btn.dataset.pid);
                    const comm = btn.dataset.comm || '';
                    if (btn.classList.contains('known-btn')) {
                        await markAsKnown(comm, pid);
                        await fetchTrustScores(); await fetchActionLog();
                    } else if (btn.classList.contains('pause-btn')) {
                        await pauseProcess(pid, comm);
                        await fetchPausedProcesses(); await fetchActionLog();
                    } else if (btn.classList.contains('resume-btn')) {
                        await resumeProcess(pid);
                        await fetchPausedProcesses();
                    } else if (btn.classList.contains('kill-btn')) {
                        if (!confirm(`SIGKILL '${comm}' (PID ${pid})?`)) return;
                        state.trustScores[pid].killed = true;
                        renderHtop();
                        await killProcess(pid, comm);
                        setTimeout(() => { delete state.trustScores[pid]; renderHtop(); }, 8000);
                        await fetchActionLog();
                    } else if (btn.classList.contains('ask-btn')) {
                        handleChatQuery(`Analyze '${comm}' (PID ${pid}, trust=${Math.round(entry.trust)}). Is it safe or malicious? What should I do?`, pid);
                        // Switch to security view to see chat
                        document.querySelector('[data-view="security"]')?.click();
                        document.querySelector('.tab-btn[data-tab="chat"]')?.click();
                    }
                });
            });

            $tbody.appendChild(tr);
        });
    }

    // ---- Process Table ----
    function renderTrustScores() {
        let entries = Object.values(state.trustScores);

        // Apply filter
        if (state.currentFilter === 'suspicious') {
            entries = entries.filter(e => e.status === 'suspicious' || (e.trust < 65 && e.status !== 'known'));
        } else if (state.currentFilter === 'known') {
            entries = entries.filter(e => e.status === 'known');
        } else if (state.currentFilter === 'paused') {
            entries = entries.filter(e => e.status === 'paused' || e.paused);
        }

        // Apply search query
        if (searchTerm) {
            entries = entries.filter(e =>
                (e.comm && e.comm.toLowerCase().includes(searchTerm)) ||
                (String(e.pid).includes(searchTerm)) ||
                (e.ppid && String(e.ppid).includes(searchTerm))
            );
        }

        // Sort: paused first, then by trust ascending
        entries.sort((a, b) => {
            const aPaused = a.paused || a.status === 'paused' ? 1 : 0;
            const bPaused = b.paused || b.status === 'paused' ? 1 : 0;
            if (bPaused !== aPaused) return bPaused - aPaused;
            return a.trust - b.trust;
        });

        if (entries.length === 0) {
            $trustContainer.innerHTML = '<div class="empty-state">No matching processes found</div>';
            return;
        }

        const visible = entries.slice(0, 60);
        $trustContainer.innerHTML = '';

        visible.forEach(entry => {
            const tier = getTrustTier(entry.trust);
            const isKilled = entry.killed;
            const status = isKilled ? 'killed' : (entry.paused ? 'paused' : (entry.status || (entry.trust > 75 ? 'known' : 'unknown')));
            const isPaused = status === 'paused' || entry.paused;
            const isKnown = status === 'known';

            const statusEmoji = {
                'known': '🟢', 'unknown': '🟡', 'suspicious': '🔴', 'paused': '⏸', 'killed': '☠️'
            }[status] || '🟡';

            const row = document.createElement('div');
            row.className = `process-row ${isPaused ? 'row-paused' : ''} ${status === 'suspicious' ? 'row-suspicious' : ''} ${isKilled ? 'row-killed' : ''}`;
            row.title = isKilled ? 'Process terminated' : 'Click to inspect process details';

            row.innerHTML = `
                <div class="process-info">
                    <span class="process-comm" title="${escapeHtml(entry.comm)}">${escapeHtml(entry.comm || '?')}</span>
                    <span class="process-pid">PID ${entry.pid}${entry.ppid ? ` ← ${entry.ppid}` : ''}</span>
                </div>
                <span class="status-badge ${status}">${statusEmoji} ${status.toUpperCase()}</span>
                <div class="trust-mini-bar" title="Trust: ${Math.round(entry.trust)}%">
                    <div class="trust-mini-fill ${tier}" style="width: ${Math.max(3, entry.trust)}%"></div>
                </div>
                <span class="trust-score-num ${tier}">${Math.round(entry.trust)}</span>
                <div class="process-actions">
                    ${!isKnown ? `<button class="row-btn known-btn" title="Mark as KNOWN — trust 100%, persists across restarts">✅</button>` : '<span class="known-badge">✅ KNOWN</span>'}
                    ${!isPaused ? `<button class="row-btn pause-btn" title="SIGSTOP this process">⏸</button>` : ''}
                    ${isPaused ? `<button class="row-btn resume-btn" title="SIGCONT — resume">▶</button>` : ''}
                    <button class="row-btn kill-btn" title="SIGKILL this process immediately">💀</button>
                    <button class="row-btn ask-btn" title="Ask AI about this process">🔍</button>
                </div>
            `;

            // Clicking the row opens the Process Inspector
            row.addEventListener('click', (e) => {
                if (e.target.closest('.process-actions')) return; // ignore if clicking buttons
                openProcessInspector(entry);
            });

            // Known button
            const knownBtn = row.querySelector('.known-btn');
            if (knownBtn) {
                knownBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    await markAsKnown(entry.comm, entry.pid);
                    await fetchTrustScores();
                    await fetchActionLog();
                    appendChatMessage('ai', `✅ '${escapeHtml(entry.comm)}' (PID ${entry.pid}) is KNOWN — trust=100, saved to disk.`);
                    // Switch to chat tab to show confirmation
                    const chatTab = document.querySelector('.tab-btn[data-tab="chat"]');
                    if (chatTab) chatTab.click();
                });
            }

            // Pause button
            const pauseBtn = row.querySelector('.pause-btn');
            if (pauseBtn) {
                pauseBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    await pauseProcess(entry.pid, entry.comm);
                    await fetchPausedProcesses();
                    await fetchActionLog();
                });
            }

            // Resume button
            const resumeBtn = row.querySelector('.resume-btn');
            if (resumeBtn) {
                resumeBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    await resumeProcess(entry.pid);
                    await fetchPausedProcesses();
                    await fetchActionLog();
                });
            }

            // Kill button
            const killBtn = row.querySelector('.kill-btn');
            if (killBtn) {
                killBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    if (!confirm(`SIGKILL '${entry.comm}' (PID ${entry.pid})?\nThis will immediately terminate the process.`)) return;
                    // Mark as killed immediately so UI shows dead state
                    if (state.trustScores[entry.pid]) {
                        state.trustScores[entry.pid].killed = true;
                        state.trustScores[entry.pid].status = 'killed';
                    }
                    renderTrustScores();
                    const result = await killProcess(entry.pid, entry.comm);
                    // Remove from state after 8s fade animation
                    setTimeout(() => { delete state.trustScores[entry.pid]; renderTrustScores(); }, 8000);
                    await fetchPausedProcesses();
                    await fetchActionLog();
                    appendChatMessage('ai', result ? (result.message || `💀 PID ${entry.pid} killed.`) : `⚠️ Kill failed for PID ${entry.pid}`);
                    const chatTab = document.querySelector('.tab-btn[data-tab="chat"]');
                    if (chatTab) chatTab.click();
                });
            }

            // AI button
            const askBtn = row.querySelector('.ask-btn');
            if (askBtn) {
                askBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const statusCtx = isPaused ? 'PAUSED (SIGSTOP)' : `trust=${Math.round(entry.trust)}`;
                    handleChatQuery(`Analyze '${entry.comm}' (PID ${entry.pid}, ${statusCtx}). Is it safe or malicious? What should I do?`, entry.pid);
                });
            }

            $trustContainer.appendChild(row);
        });
    }

    // ---- API helpers ----
    async function markAsKnown(comm, pid) {
        try {
            const resp = await fetch('/api/process/known', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ comm, pid })
            });
            if (resp.ok) {
                const data = await resp.json();
                if (state.trustScores[pid]) {
                    state.trustScores[pid].trust = 100;
                    state.trustScores[pid].status = 'known';
                    state.trustScores[pid].paused = false;
                } else {
                    // Add a new entry for this newly-trusted process
                    state.trustScores[pid] = { pid, comm, trust: 100, status: 'known', paused: false };
                }
                renderTrustScores();
                return data;
            }
        } catch (e) {
            console.warn('Failed to mark as known:', e);
        }
    }

    async function pauseProcess(pid, comm) {
        try {
            const resp = await fetch('/api/process/pause', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pid, comm })
            });
            if (resp.ok) {
                const data = await resp.json();
                if (state.trustScores[pid]) {
                    state.trustScores[pid].status = 'paused';
                    state.trustScores[pid].paused = true;
                }
                renderTrustScores();
                return data;
            }
        } catch (e) {
            console.warn('Failed to pause process:', e);
        }
    }

    async function resumeProcess(pid) {
        try {
            const resp = await fetch('/api/process/resume', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pid })
            });
            if (resp.ok) {
                if (state.trustScores[pid]) {
                    state.trustScores[pid].paused = false;
                    if (state.trustScores[pid].status === 'paused') {
                        state.trustScores[pid].status = 'unknown';
                    }
                }
                renderTrustScores();
                return await resp.json();
            }
        } catch (e) {
            console.warn('Failed to resume process:', e);
        }
    }

    async function killProcess(pid, comm) {
        try {
            const resp = await fetch('/api/process/kill', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pid, comm })
            });
            if (resp.ok) {
                const data = await resp.json();
                // Remove from trustScores since the process is dead
                delete state.trustScores[pid];
                renderTrustScores();
                return data;
            }
        } catch (e) {
            console.warn('Failed to kill process:', e);
        }
    }

    // ---- Decision Renderer ----
    function renderDecisionEntry(d) {
        const empty = $decisionsContainer.querySelector('.empty-state');
        if (empty) empty.remove();

        const tier = d.tier || 'low';
        const el = document.createElement('div');
        el.className = `decision-entry ${tier}`;

        const time = d.timestamp ? new Date(d.timestamp).toLocaleTimeString() : '--:--:--';

        const actionIcon = {
            'trusted_allow': '🟢',
            'observe_log': '📋',
            'observe_alert': '⚠️',
            'observe_critical': '🚨',
            'paused_sigstop': '⏸',
            'already_paused': '⏸',
            'kill': '💀',
            'verified_kill': '💀',
        }[d.action] || '📋';

        el.innerHTML = `
            <div class="decision-header">
                <span class="decision-tier ${tier}">${actionIcon} ${tier} [${d.status || 'unknown'}]</span>
                <span class="decision-time">${time}</span>
            </div>
            <div class="decision-body">
                <strong>${d.comm || '?'}</strong> (PID ${d.pid}) → ${d.action || 'unknown'}
                ${d.technique_id ? `<br><span class="decision-technique">${d.technique_id}: ${d.technique || ''}</span>` : ''}
                ${d.trust_score !== undefined ? `<br>Trust: ${Math.round(d.trust_score)} | p=${(d.conformal_p_value || 0).toFixed(4)}` : ''}
            </div>
        `;

        $decisionsContainer.insertBefore(el, $decisionsContainer.firstChild);

        while ($decisionsContainer.children.length > 40) {
            $decisionsContainer.removeChild($decisionsContainer.lastChild);
        }
    }

    function renderEventEntry(evt) {
        const empty = $eventsContainer.querySelector('.empty-state');
        if (empty) empty.remove();

        const el = document.createElement('div');
        el.className = 'event-entry';
        el.innerHTML = `
            <span class="event-type ${evt.type_str || ''}">${evt.type_str || '?'}</span>
            <span class="event-pid">[${evt.pid}]</span>
            <span class="event-payload">${evt.comm || ''} ${evt.payload ? '→ ' + truncate(evt.payload, 42) : ''}</span>
            ${evt.dst_ip ? `<span class="event-payload"> → ${evt.dst_ip}:${evt.dst_port}</span>` : ''}
        `;

        $eventsContainer.insertBefore(el, $eventsContainer.firstChild);

        while ($eventsContainer.children.length > 50) {
            $eventsContainer.removeChild($eventsContainer.lastChild);
        }
    }

    function renderNarration(data) {
        const empty = $narrationContainer.querySelector('.empty-state');
        if (empty) empty.remove();

        const el = document.createElement('div');
        el.className = 'narration-entry';

        const techniques = (data.technique_ids || [])
            .map(id => `<span class="technique-chip">${id}</span>`)
            .join('');

        el.innerHTML = `
            <div>${data.narrative || 'No narrative generated.'}</div>
            ${techniques ? `<div class="narration-techniques">${techniques}</div>` : ''}
            <div class="narration-meta">Model: ${data.model || '?'} | Latency: ${data.latency_ms || 0}ms</div>
        `;

        $narrationContainer.insertBefore(el, $narrationContainer.firstChild);

        while ($narrationContainer.children.length > 8) {
            $narrationContainer.removeChild($narrationContainer.lastChild);
        }
    }

    function renderStats() {
        setText('#stat-processes .stat-value', state.stats.nodes_process || 0);
        setText('#stat-files .stat-value', state.stats.nodes_file || 0);
        setText('#stat-sockets .stat-value', state.stats.nodes_socket || 0);
        setText('#stat-edges .stat-value', state.stats.edges_total || 0);
    }

    function renderAlertStats() {
        setText('#stat-alerts .stat-value', state.alertCount);
    }

    // ---- D3 Causal Graph ----
    let simulation, svgSel, linkSel, nodeSel, labelSel, zoomBehavior;
    let graphNodes = [];
    let graphLinks = [];
    const nodeMap = new Map();
    const MAX_GRAPH_NODES = 100;

    function initGraph() {
        const svg = d3.select('#causal-graph');
        const container = document.getElementById('graph-container');
        const width = container.clientWidth || 600;
        const height = container.clientHeight || 400;

        svg.attr('viewBox', `0 0 ${width} ${height}`);

        svg.append('defs').append('marker')
            .attr('id', 'arrowhead')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 18)
            .attr('refY', 0)
            .attr('markerWidth', 5)
            .attr('markerHeight', 5)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', 'rgba(148, 163, 184, 0.25)');

        const g = svg.append('g');

        zoomBehavior = d3.zoom()
            .scaleExtent([0.2, 3])
            .on('zoom', (event) => g.attr('transform', event.transform));

        svg.call(zoomBehavior);

        const resetBtn = document.getElementById('reset-graph-btn');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                svg.transition().duration(500).call(zoomBehavior.transform, d3.zoomIdentity);
            });
        }

        linkSel = g.append('g').attr('class', 'links').selectAll('line');
        nodeSel = g.append('g').attr('class', 'nodes').selectAll('circle');
        labelSel = g.append('g').attr('class', 'labels').selectAll('text');

        simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(60))
            .force('charge', d3.forceManyBody().strength(-100))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide(18))
            .on('tick', ticked);

        svgSel = g;
    }

    function updateGraphData(data) {
        if (!data || !data.nodes) return;

        let hasNew = false;
        Object.values(data.nodes).forEach(n => {
            // Only show process and socket nodes in graph (skip file nodes for clarity)
            if (n.type === 'file') return;
            if (!nodeMap.has(n.id)) {
                const gNode = {
                    id: n.id,
                    label: n.label || n.id,
                    type: n.type,
                    trust: n.trust !== undefined ? n.trust : 80,
                };
                graphNodes.push(gNode);
                nodeMap.set(n.id, gNode);
                hasNew = true;
            } else {
                // Update trust score
                const existing = nodeMap.get(n.id);
                if (n.trust !== undefined) {
                    existing.trust = n.trust;
                }
            }
        });

        if (graphNodes.length > MAX_GRAPH_NODES) {
            const removed = graphNodes.splice(0, graphNodes.length - MAX_GRAPH_NODES);
            removed.forEach(r => nodeMap.delete(r.id));
            hasNew = true;
        }

        if (data.edges) {
            data.edges.forEach(e => {
                // Only show process<->process and process<->socket edges
                const fromNode = nodeMap.get(e.from);
                const toNode = nodeMap.get(e.to);
                if (!fromNode || !toNode) return;
                if (fromNode.type === 'file' || toNode.type === 'file') return;

                if (nodeMap.has(e.from) && nodeMap.has(e.to)) {
                    const exists = graphLinks.some(l =>
                        (l.source.id || l.source) === e.from && (l.target.id || l.target) === e.to
                    );
                    if (!exists) {
                        graphLinks.push({ source: e.from, target: e.to, type: e.type });
                        hasNew = true;
                    }
                }
            });
        }

        if (graphLinks.length > MAX_GRAPH_NODES * 1.5) {
            graphLinks = graphLinks.slice(-Math.floor(MAX_GRAPH_NODES * 1.5));
        }

        if (hasNew) {
            updateGraph();
        }
    }

    function updateGraph() {
        linkSel = svgSel.select('.links').selectAll('line').data(graphLinks);
        linkSel.exit().remove();
        linkSel = linkSel.enter().append('line')
            .attr('stroke', 'rgba(148, 163, 184, 0.15)')
            .attr('stroke-width', 1)
            .attr('marker-end', 'url(#arrowhead)')
            .merge(linkSel);

        nodeSel = svgSel.select('.nodes').selectAll('circle').data(graphNodes, d => d.id);
        nodeSel.exit().remove();
        nodeSel = nodeSel.enter().append('circle')
            .attr('r', d => d.type === 'process' ? 8 : 5)
            .attr('fill', d => getNodeColor(d))
            .attr('stroke', d => getNodeStroke(d))
            .attr('stroke-width', 2)
            .attr('opacity', 0.9)
            .call(d3.drag()
                .on('start', dragStarted)
                .on('drag', dragged)
                .on('end', dragEnded))
            .on('click', (event, d) => {
                if (d.type === 'process') {
                    const commMatch = d.label.match(/(.+?) \[/);
                    const pidMatch = d.id.match(/proc:(\d+)/);
                    const comm = commMatch ? commMatch[1] : d.label;
                    const pid = pidMatch ? parseInt(pidMatch[1]) : 0;
                    const entry = state.trustScores[pid] || {
                        pid, comm, trust: d.trust !== undefined ? d.trust : 80,
                        status: (d.trust < 60 ? 'suspicious' : 'unknown')
                    };
                    openProcessInspector(entry);
                }
            })
            .merge(nodeSel);

        // Update colors for existing nodes (trust may have changed)
        svgSel.select('.nodes').selectAll('circle')
            .attr('fill', d => getNodeColor(d))
            .attr('stroke', d => getNodeStroke(d));

        labelSel = svgSel.select('.labels').selectAll('text').data(graphNodes, d => d.id);
        labelSel.exit().remove();
        labelSel = labelSel.enter().append('text')
            .text(d => truncate(d.label, 14))
            .attr('font-family', "'JetBrains Mono', monospace")
            .attr('font-size', '8px')
            .attr('fill', 'rgba(148, 163, 184, 0.7)')
            .attr('dx', 11)
            .attr('dy', 3)
            .merge(labelSel);

        simulation.nodes(graphNodes);
        simulation.force('link').links(graphLinks);
        simulation.alpha(0.2).restart();
    }

    function ticked() {
        linkSel
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        nodeSel
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        labelSel
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    }

    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.2).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    // ---- Helpers ----
    function getNodeColor(d) {
        if (d.type === 'socket') return '#34d399';
        if (d.type === 'process') {
            if (d.trust < 40) return '#ef4444';
            if (d.trust < 70) return '#f59e0b';
            return '#6366f1';
        }
        return '#94a3b8';
    }

    function getNodeStroke(d) {
        if (d.type === 'process' && d.trust !== undefined) {
            if (d.trust < 40) return '#ef4444';
            if (d.trust < 70) return '#f59e0b';
            return '#10b981';
        }
        return 'rgba(255,255,255,0.15)';
    }

    function getTrustTier(trust) {
        if (trust >= 70) return 'trusted';
        if (trust >= 40) return 'suspicious';
        return 'hostile';
    }

    function truncate(str, max) {
        if (!str) return '';
        return str.length > max ? str.substring(0, max) + '…' : str;
    }

    function setText(selector, value) {
        const el = document.querySelector(selector);
        if (el) el.textContent = value;
    }

    // Periodically fetch graph and paused
    setInterval(async () => {
        try {
            const resp = await fetch('/api/graph');
            if (resp.ok) {
                const data = await resp.json();
                if (data) updateGraphData(data);
            }
        } catch (e) { /* silent */ }
    }, 5000);

})();
