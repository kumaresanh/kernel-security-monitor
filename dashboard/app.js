// Kernel Security Monitor Dashboard — Production SIEM & Threat Intelligence UI
// Multi-view navigation, htop process monitor, Attack Patterns & Provenance Tree, Production Causal Graph

(function () {
    'use strict';

    // ---- State ----
    const state = {
        mode: 'observe',
        trustScores: {},       // pid -> {comm, ppid, trust, status, tier, paused, killed, technique, action, pvalue}
        decisions: [],
        events: [],
        narrations: [],
        actionLog: [],
        attackPatterns: [],
        processTree: [],
        productionGraph: { nodes: [], edges: [], active_threats: 0, total_pids: 0 },
        stats: { nodes_process: 0, nodes_file: 0, nodes_socket: 0, edges_total: 0 },
        alertCount: 0,
        killCount: 0,
        currentFilter: 'all',
        graphFilter: 'all',
        currentTab: 'narration',
        currentView: 'security',
        rateInfo: { processed: 0, dropped: 0 },
        pausedProcesses: [],
        chatHistory: []       // [{role:'user'|'ai', text:'...'}]
    };

    // ---- DOM refs ----
    const $trustContainer = document.getElementById('trust-scores-container');
    const $decisionsContainer = document.getElementById('decisions-container');
    const $eventsContainer = document.getElementById('events-container');
    const $narrationContainer = document.getElementById('narration-container');
    const $actionLogContainer = document.getElementById('action-log-container');
    const $attackPatternsContainer = document.getElementById('attack-patterns-container');
    const $processTreeContainer = document.getElementById('process-tree-container');
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
    let treeSearchTerm = '';
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
        initHtopControls();
        initTreeControls();
        initGraphFilters();
        initSSE();
        initProductionGraph();
        fetchInitialData();

        // Background polls
        setInterval(fetchTrustScores, 3000);
        setInterval(fetchStats, 2500);
        setInterval(fetchPausedProcesses, 2000);
        setInterval(fetchActionLog, 3000);
        setInterval(fetchAttackPatternsAndTree, 4000);

        // Hover lock for process list
        if ($trustContainer) {
            $trustContainer.addEventListener('mouseenter', () => { trustContainerHovered = true; });
            $trustContainer.addEventListener('mouseleave', () => {
                trustContainerHovered = false;
                if (renderPending) {
                    renderPending = false;
                    renderTrustScores();
                    if (state.currentView === 'processes') renderHtop();
                }
            });
        }
    });

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
                if (view === 'patterns') {
                    renderAttackPatterns();
                    renderProcessTree();
                }
                if (view === 'security') {
                    updateProductionGraph();
                }
            });
        });
    }

    // ---- Mode Toggle ----
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

    // ---- Tabs inside right panel ----
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

    // ---- Process classification filters ----
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

    // ---- Search Inputs ----
    function initSearch() {
        if ($searchInput) {
            $searchInput.addEventListener('input', (e) => {
                searchTerm = e.target.value.toLowerCase().trim();
                renderTrustScores();
            });
        }
    }

    function initHtopControls() {
        const $hs = document.getElementById('htop-search');
        const $sort = document.getElementById('htop-sort');
        if ($hs) $hs.addEventListener('input', e => { htopSearchTerm = e.target.value.toLowerCase().trim(); renderHtop(); });
        if ($sort) $sort.addEventListener('change', e => { htopSortBy = e.target.value; renderHtop(); });
    }

    function initTreeControls() {
        const $ts = document.getElementById('tree-search');
        if ($ts) $ts.addEventListener('input', e => { treeSearchTerm = e.target.value.toLowerCase().trim(); renderProcessTree(); });

        const $expandBtn = document.getElementById('tree-expand-btn');
        if ($expandBtn) {
            $expandBtn.addEventListener('click', () => {
                document.querySelectorAll('.tree-children-container').forEach(c => c.style.display = 'block');
                document.querySelectorAll('.tree-toggle-icon').forEach(i => i.textContent = '▼');
            });
        }

        const $collapseBtn = document.getElementById('tree-collapse-btn');
        if ($collapseBtn) {
            $collapseBtn.addEventListener('click', () => {
                document.querySelectorAll('.tree-children-container').forEach(c => c.style.display = 'none');
                document.querySelectorAll('.tree-toggle-icon').forEach(i => i.textContent = '▶');
            });
        }
    }

    function initGraphFilters() {
        document.querySelectorAll('.graph-filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.graph-filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.graphFilter = btn.dataset.graphFilter;
                updateProductionGraph();
            });
        });
    }

    // ---- Process Inspector Modal ----
    function initInspector() {
        if ($inspCloseBtn) $inspCloseBtn.addEventListener('click', closeProcessInspector);
        if ($inspOverlay) $inspOverlay.addEventListener('click', closeProcessInspector);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && $inspectorModal && !$inspectorModal.classList.contains('hidden')) {
                closeProcessInspector();
            }
        });
    }

    function closeProcessInspector() {
        if ($inspectorModal) $inspectorModal.classList.add('hidden');
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
        setText('#insp-first-seen', entry.firstSeen ? new Date(entry.firstSeen).toLocaleTimeString() : 'Active');

        // Threat analysis fields
        const tech = entry.technique || entry.techniqueID;
        const techDesc = entry.techniqueDesc || '';
        setText('#insp-technique', tech ? `${tech}${techDesc ? ' — ' + techDesc : ''}` : 'None detected');
        const reasonMap = {
            'observe_critical': 'High anomaly score — staging or anomalous payload activity',
            'paused_sigstop': 'Suspended by monitor — awaiting operator authorization',
            'kill': 'Terminated — confirmed threat signature',
            'verified_kill': 'Terminated — verified malicious ATT&CK pattern',
            'trusted_allow': 'Whitelisted / known Linux system tool',
            'observe_log': 'Low anomaly score — logged for telemetry',
            'observe_alert': 'Moderate anomaly — closely observed'
        };
        setText('#insp-reason', reasonMap[entry.action || ''] || (entry.trust < 40 ? 'High anomaly score from ML model' : entry.trust < 70 ? 'Moderate anomaly score' : 'Safe telemetry profile'));
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

            // Mark Known
            if (!isKnown) {
                const btn = document.createElement('button');
                btn.className = 'insp-action-btn row-btn known-btn';
                btn.innerHTML = '✅ Mark Known';
                btn.addEventListener('click', async () => {
                    await markAsKnown(entry.comm, entry.pid);
                    await fetchTrustScores(); await fetchActionLog();
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
                    await fetchPausedProcesses(); await fetchActionLog();
                    closeProcessInspector();
                });
                actionsContainer.appendChild(btn);
            } else {
                const btn = document.createElement('button');
                btn.className = 'insp-action-btn row-btn resume-btn';
                btn.innerHTML = '▶ Resume (SIGCONT)';
                btn.addEventListener('click', async () => {
                    await resumeProcess(entry.pid);
                    await fetchPausedProcesses(); await fetchActionLog();
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
                if (state.trustScores[entry.pid]) {
                    state.trustScores[entry.pid].killed = true;
                    state.trustScores[entry.pid].status = 'killed';
                }
                renderTrustScores();
                await killProcess(entry.pid, entry.comm);
                setTimeout(() => { delete state.trustScores[entry.pid]; renderTrustScores(); }, 8000);
                await fetchPausedProcesses(); await fetchActionLog();
                closeProcessInspector();
            });
            actionsContainer.appendChild(killBtn);

            // Ask AI Copilot
            const askBtn = document.createElement('button');
            askBtn.className = 'insp-action-btn row-btn ask-btn';
            askBtn.innerHTML = '🔍 Ask AI Copilot';
            askBtn.addEventListener('click', () => {
                closeProcessInspector();
                document.querySelector('.top-nav-btn[data-view="security"]')?.click();
                handleChatQuery(`Analyze process '${entry.comm}' (PID ${entry.pid}, trust=${Math.round(entry.trust)}). Is it safe or malicious? What files/sockets has it accessed?`, entry.pid);
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
        const chatTabBtn = document.querySelector('.tab-btn[data-tab="chat"]');
        if (chatTabBtn) chatTabBtn.click();

        state.chatHistory.push({ role: 'user', text: query });
        if (state.chatHistory.length > 20) state.chatHistory = state.chatHistory.slice(-20);

        appendChatMessage('user', query);
        const loadingBubble = appendChatMessage('ai loading', '⏳ Analyzing telemetry with AI...');

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

    // ---- Initial Data Fetch ----
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

            await fetchTrustScores();
            await fetchStats();
            await fetchPausedProcesses();
            await fetchAttackPatternsAndTree();
            await fetchProductionGraphData();
        } catch (err) {
            console.warn('Initial data fetch error:', err);
        }
    }

    async function fetchTrustScores() {
        try {
            const resp = await fetch('/api/trust');
            if (resp.ok) {
                const scores = await resp.json();
                if (scores) {
                    scores.forEach(s => {
                        if (!state.trustScores[s.pid] || !state.trustScores[s.pid].killed) {
                            state.trustScores[s.pid] = { ...state.trustScores[s.pid], ...s };
                        }
                    });
                    scheduledRender();
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
                scheduledRender();
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

    async function fetchAttackPatternsAndTree() {
        try {
            const [patResp, treeResp] = await Promise.all([
                fetch('/api/db/attack_patterns'),
                fetch('/api/db/tree')
            ]);
            if (patResp.ok) {
                state.attackPatterns = await patResp.json() || [];
                setText('#pattern-count', state.attackPatterns.length);
                setText('#attack-patterns-live-badge', `${state.attackPatterns.length} DETECTED`);
                if (state.currentView === 'patterns') renderAttackPatterns();
            }
            if (treeResp.ok) {
                state.processTree = await treeResp.json() || [];
                if (state.currentView === 'patterns') renderProcessTree();
            }
        } catch (e) { /* silent */ }
    }

    async function fetchProductionGraphData() {
        try {
            const resp = await fetch('/api/db/graph');
            if (resp.ok) {
                const data = await resp.json();
                if (data) {
                    state.productionGraph = data;
                    updateProductionGraph();
                }
            }
        } catch (e) { /* silent */ }
    }

    // ---- Event handling from SSE ----
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
            if (rateDisplay) rateDisplay.textContent = `PROC: ${rate.processed || 0}`;
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
            if (!existing.killed) {
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

    // ---- Process Table Render (Left Column) ----
    function renderTrustScores() {
        if (!$trustContainer) return;
        let entries = Object.values(state.trustScores);

        // Filter
        if (state.currentFilter === 'suspicious') {
            entries = entries.filter(e => e.status === 'suspicious' || (e.trust < 65 && e.status !== 'known'));
        } else if (state.currentFilter === 'known') {
            entries = entries.filter(e => e.status === 'known');
        } else if (state.currentFilter === 'paused') {
            entries = entries.filter(e => e.status === 'paused' || e.paused);
        }

        // Search
        if (searchTerm) {
            entries = entries.filter(e =>
                (e.comm && e.comm.toLowerCase().includes(searchTerm)) ||
                (String(e.pid).includes(searchTerm)) ||
                (e.ppid && String(e.ppid).includes(searchTerm))
            );
        }

        // Sort: paused/threats first, then trust ascending
        entries.sort((a, b) => {
            const aP = a.paused || a.status === 'paused' ? 1 : 0;
            const bP = b.paused || b.status === 'paused' ? 1 : 0;
            if (bP !== aP) return bP - aP;
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

            const statusEmoji = { 'known': '🟢', 'unknown': '🟡', 'suspicious': '🔴', 'paused': '⏸', 'killed': '☠️' }[status] || '🟡';

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
                    ${!isKnown ? `<button class="row-btn known-btn" title="Mark Known">✅</button>` : '<span class="known-badge">✅ KNOWN</span>'}
                    ${!isPaused ? `<button class="row-btn pause-btn" title="Suspend (SIGSTOP)">⏸</button>` : ''}
                    ${isPaused ? `<button class="row-btn resume-btn" title="Resume (SIGCONT)">▶</button>` : ''}
                    <button class="row-btn kill-btn" title="Kill (SIGKILL)">💀</button>
                    <button class="row-btn ask-btn" title="Ask AI">🔍</button>
                </div>
            `;

            row.addEventListener('click', (e) => {
                if (e.target.closest('.process-actions')) return;
                openProcessInspector(entry);
            });

            // Button listeners
            row.querySelector('.known-btn')?.addEventListener('click', async (e) => {
                e.stopPropagation();
                await markAsKnown(entry.comm, entry.pid);
                await fetchTrustScores(); await fetchActionLog();
            });

            row.querySelector('.pause-btn')?.addEventListener('click', async (e) => {
                e.stopPropagation();
                await pauseProcess(entry.pid, entry.comm);
                await fetchPausedProcesses(); await fetchActionLog();
            });

            row.querySelector('.resume-btn')?.addEventListener('click', async (e) => {
                e.stopPropagation();
                await resumeProcess(entry.pid);
                await fetchPausedProcesses(); await fetchActionLog();
            });

            row.querySelector('.kill-btn')?.addEventListener('click', async (e) => {
                e.stopPropagation();
                if (!confirm(`SIGKILL '${entry.comm}' (PID ${entry.pid})?`)) return;
                if (state.trustScores[entry.pid]) {
                    state.trustScores[entry.pid].killed = true;
                    state.trustScores[entry.pid].status = 'killed';
                }
                renderTrustScores();
                await killProcess(entry.pid, entry.comm);
                setTimeout(() => { delete state.trustScores[entry.pid]; renderTrustScores(); }, 8000);
                await fetchPausedProcesses(); await fetchActionLog();
            });

            row.querySelector('.ask-btn')?.addEventListener('click', (e) => {
                e.stopPropagation();
                document.querySelector('.top-nav-btn[data-view="security"]')?.click();
                handleChatQuery(`Analyze process '${entry.comm}' (PID ${entry.pid}, trust=${Math.round(entry.trust)}). Is it safe or malicious?`, entry.pid);
            });

            $trustContainer.appendChild(row);
        });
    }

    // ---- htop-like Process Monitor (View 2) ----
    function renderHtop() {
        const $tbody = document.getElementById('htop-tbody');
        const $count = document.getElementById('htop-count');
        if (!$tbody) return;

        let entries = Object.values(state.trustScores).filter(e => !e.killed);
        if ($count) $count.textContent = entries.length;

        if (htopSearchTerm) {
            entries = entries.filter(e =>
                (e.comm && e.comm.toLowerCase().includes(htopSearchTerm)) ||
                String(e.pid).includes(htopSearchTerm)
            );
        }

        entries.sort((a, b) => {
            switch (htopSortBy) {
                case 'trust': return a.trust - b.trust;
                case 'trust-desc': return b.trust - a.trust;
                case 'pid': return a.pid - b.pid;
                case 'comm': return (a.comm||'').localeCompare(b.comm||'');
                case 'status': return (a.status||'').localeCompare(b.status||'');
                default: return a.trust - b.trust;
            }
        });

        if (entries.length === 0) {
            $tbody.innerHTML = `<tr><td colspan="7" class="htop-empty">No processes tracked yet. Events are streaming live.</td></tr>`;
            return;
        }

        $tbody.innerHTML = '';
        entries.forEach(entry => {
            const tier = getTrustTier(entry.trust);
            const status = entry.paused ? 'paused' : (entry.status || 'unknown');
            const isPaused = status === 'paused';
            const isKnown = status === 'known';
            const sColors = { known: '#10b981', unknown: '#f59e0b', suspicious: '#ef4444', paused: '#6366f1' };

            const tr = document.createElement('tr');
            tr.className = `htop-tr${ status === 'suspicious' ? ' htop-row-suspicious' : ''}${isPaused ? ' htop-row-paused' : ''}${isKnown ? ' htop-row-known' : ''}`;
            tr.innerHTML = `
                <td class="htop-td htop-td-pid">${entry.pid}</td>
                <td class="htop-td htop-td-ppid">${entry.ppid || '-'}</td>
                <td class="htop-td htop-td-comm" title="${escapeHtml(entry.comm)}">${escapeHtml(entry.comm || '?')}</td>
                <td class="htop-td htop-td-trust ${tier}">${Math.round(entry.trust)}</td>
                <td class="htop-bar-cell">
                    <div class="htop-bar"><div class="htop-bar-fill ${tier}" style="width:${Math.max(3,entry.trust)}%"></div></div>
                </td>
                <td class="htop-td" style="color:${sColors[status]||'#94a3b8'};font-weight:700;font-size:10px">${status.toUpperCase()}</td>
                <td class="htop-actions-td">
                    ${!isKnown ? `<button class="row-btn known-btn htop-act" data-pid="${entry.pid}" data-comm="${escapeHtml(entry.comm)}" title="Trust">✅</button>` : ''}
                    ${!isPaused ? `<button class="row-btn pause-btn htop-act" data-pid="${entry.pid}" data-comm="${escapeHtml(entry.comm)}" title="Suspend">⏸</button>` : ''}
                    ${isPaused ? `<button class="row-btn resume-btn htop-act" data-pid="${entry.pid}" title="Resume">▶</button>` : ''}
                    <button class="row-btn kill-btn htop-act" data-pid="${entry.pid}" data-comm="${escapeHtml(entry.comm)}" title="Kill">💀</button>
                    <button class="row-btn ask-btn htop-act" data-pid="${entry.pid}" data-comm="${escapeHtml(entry.comm)}" title="Ask AI">🔍</button>
                </td>
            `;

            tr.addEventListener('click', e => {
                if (e.target.classList.contains('htop-act')) return;
                openProcessInspector(entry);
            });

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
                        document.querySelector('.top-nav-btn[data-view="security"]')?.click();
                        handleChatQuery(`Analyze '${comm}' (PID ${pid}, trust=${Math.round(entry.trust)}). Is it safe or malicious?`, pid);
                    }
                });
            });

            $tbody.appendChild(tr);
        });
    }

    // ---- Attack Patterns & Hierarchical Tree (View 3) ----
    function renderAttackPatterns() {
        if (!$attackPatternsContainer) return;
        if (state.attackPatterns.length === 0) {
            $attackPatternsContainer.innerHTML = '<div class="empty-state">No attack patterns identified yet. Running system is clean.</div>';
            return;
        }

        $attackPatternsContainer.innerHTML = '';
        state.attackPatterns.forEach(pat => {
            const card = document.createElement('div');
            card.className = 'attack-pattern-card';
            const time = pat.timestamp ? new Date(pat.timestamp).toLocaleTimeString() : '--:--:--';

            const evidenceChips = (pat.evidence || []).map(ev => `<span class="evidence-chip">${escapeHtml(ev)}</span>`).join('');

            card.innerHTML = `
                <div class="pattern-header">
                    <span class="pattern-tech-badge">${escapeHtml(pat.technique_id || 'ATT&CK')} [${pat.severity}]</span>
                    <span class="pattern-time">${time}</span>
                </div>
                <div class="pattern-title">${escapeHtml(pat.comm)} (PID ${pat.pid}) — ${escapeHtml(pat.technique || pat.pattern_type)}</div>
                <div class="pattern-desc">${escapeHtml(pat.description)}</div>
                ${evidenceChips ? `<div class="pattern-evidence">${evidenceChips}</div>` : ''}
                <div class="pattern-actions">
                    <button class="row-btn kill-btn" data-pid="${pat.pid}" data-comm="${escapeHtml(pat.comm)}">💀 Kill PID ${pat.pid}</button>
                    <button class="row-btn pause-btn" data-pid="${pat.pid}" data-comm="${escapeHtml(pat.comm)}">⏸ Suspend</button>
                    <button class="row-btn known-btn" data-pid="${pat.pid}" data-comm="${escapeHtml(pat.comm)}">✅ Trust</button>
                    <button class="row-btn ask-btn" data-pid="${pat.pid}">🔍 Ask AI</button>
                </div>
            `;

            card.querySelector('.kill-btn')?.addEventListener('click', async () => {
                if (!confirm(`SIGKILL PID ${pat.pid}?`)) return;
                await killProcess(pat.pid, pat.comm);
                await fetchAttackPatternsAndTree();
            });

            card.querySelector('.pause-btn')?.addEventListener('click', async () => {
                await pauseProcess(pat.pid, pat.comm);
                await fetchAttackPatternsAndTree();
            });

            card.querySelector('.known-btn')?.addEventListener('click', async () => {
                await markAsKnown(pat.comm, pat.pid);
                await fetchAttackPatternsAndTree();
            });

            card.querySelector('.ask-btn')?.addEventListener('click', () => {
                document.querySelector('.top-nav-btn[data-view="security"]')?.click();
                handleChatQuery(`Why was PID ${pat.pid} (${pat.comm}) flagged with attack pattern ${pat.technique_id}? Explain full threat evidence.`, pat.pid);
            });

            $attackPatternsContainer.appendChild(card);
        });
    }

    function renderProcessTree() {
        if (!$processTreeContainer) return;
        let roots = state.processTree || [];

        if (treeSearchTerm) {
            roots = roots.filter(r =>
                r.comm.toLowerCase().includes(treeSearchTerm) ||
                String(r.pid).includes(treeSearchTerm) ||
                (r.children && r.children.some(c => c.comm.toLowerCase().includes(treeSearchTerm) || String(c.pid).includes(treeSearchTerm)))
            );
        }

        if (roots.length === 0) {
            $processTreeContainer.innerHTML = '<div class="empty-state">No process trees recorded yet. Telemetry will build tree automatically.</div>';
            return;
        }

        $processTreeContainer.innerHTML = '';
        roots.forEach(root => {
            $processTreeContainer.appendChild(buildTreeNodeDOM(root, true));
        });
    }

    function buildTreeNodeDOM(node, isRoot) {
        const card = document.createElement('div');
        card.className = isRoot ? `tree-root-card ${node.attack_patterns && node.attack_patterns.length > 0 ? 'has-threats' : ''}` : 'tree-node';

        const tier = getTrustTier(node.trust_score);
        const hasChildren = node.children && node.children.length > 0;
        const filesCount = node.files_count || 0;
        const socksCount = node.sockets_count || 0;

        let fileTags = (node.recent_files || []).slice(0, 3).map(f => `<span class="tree-access-tag">📄 ${truncate(f, 32)}</span>`).join('');
        let sockTags = (node.recent_sockets || []).slice(0, 2).map(s => `<span class="tree-access-tag tree-sock-tag">🌐 ${s}</span>`).join('');

        card.innerHTML = `
            <div class="tree-node-row">
                <div class="tree-node-left">
                    <span class="tree-toggle-icon">${hasChildren ? '▼' : '•'}</span>
                    <span class="tree-comm">${escapeHtml(node.comm)}</span>
                    <span class="tree-pid-badge">PID ${node.pid}</span>
                    <span class="status-badge ${node.status}">${node.status}</span>
                    <span class="trust-score-num ${tier}">${Math.round(node.trust_score)}%</span>
                </div>
                <div class="process-actions">
                    <button class="row-btn ask-btn" title="Inspect">🔍</button>
                    <button class="row-btn pause-btn" title="Suspend">⏸</button>
                    <button class="row-btn kill-btn" title="Kill">💀</button>
                </div>
            </div>
            ${(filesCount > 0 || socksCount > 0) ? `<div class="tree-access-section">${fileTags} ${sockTags}</div>` : ''}
        `;

        card.querySelector('.ask-btn')?.addEventListener('click', (e) => {
            e.stopPropagation();
            openProcessInspector({
                pid: node.pid, ppid: node.ppid, comm: node.comm,
                trust: node.trust_score, status: node.status,
                action: node.attack_patterns && node.attack_patterns[0] ? node.attack_patterns[0].pattern_type : ''
            });
        });

        card.querySelector('.pause-btn')?.addEventListener('click', async (e) => {
            e.stopPropagation();
            await pauseProcess(node.pid, node.comm);
            await fetchAttackPatternsAndTree();
        });

        card.querySelector('.kill-btn')?.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!confirm(`SIGKILL PID ${node.pid}?`)) return;
            await killProcess(node.pid, node.comm);
            await fetchAttackPatternsAndTree();
        });

        if (hasChildren) {
            const childContainer = document.createElement('div');
            childContainer.className = 'tree-children-container';
            node.children.forEach(child => {
                childContainer.appendChild(buildTreeNodeDOM(child, false));
            });

            const toggle = card.querySelector('.tree-toggle-icon');
            toggle.addEventListener('click', () => {
                if (childContainer.style.display === 'none') {
                    childContainer.style.display = 'block';
                    toggle.textContent = '▼';
                } else {
                    childContainer.style.display = 'none';
                    toggle.textContent = '▶';
                }
            });

            card.appendChild(childContainer);
        }

        return card;
    }

    // ---- Production-Grade Causal Provenance Graph (Hairball-Filtered) ----
    let prodSim, prodSvg, prodG, prodLinkSel, prodNodeSel, prodLabelSel, prodZoom;
    let currentGraphNodes = [];
    let currentGraphLinks = [];

    function initProductionGraph() {
        const svg = d3.select('#causal-graph');
        const container = document.getElementById('graph-container');
        if (!container || svg.empty()) return;

        const width = container.clientWidth || 900;
        const height = container.clientHeight || 520;

        svg.attr('viewBox', `0 0 ${width} ${height}`);

        svg.append('defs').append('marker')
            .attr('id', 'prod-arrowhead')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 18)
            .attr('refY', 0)
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#06b6d4');

        prodG = svg.append('g');

        prodZoom = d3.zoom()
            .scaleExtent([0.2, 3.5])
            .on('zoom', (event) => prodG.attr('transform', event.transform));

        svg.call(prodZoom);

        document.getElementById('reset-graph-btn')?.addEventListener('click', () => {
            svg.transition().duration(500).call(prodZoom.transform, d3.zoomIdentity);
        });

        prodLinkSel = prodG.append('g').attr('class', 'links').selectAll('line');
        prodNodeSel = prodG.append('g').attr('class', 'nodes').selectAll('circle');
        prodLabelSel = prodG.append('g').attr('class', 'labels').selectAll('text');

        prodSim = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(80))
            .force('charge', d3.forceManyBody().strength(-140))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide(24))
            .on('tick', prodTicked);
    }

    function updateProductionGraph() {
        if (!prodG || !state.productionGraph) return;

        const rawNodes = state.productionGraph.nodes || [];
        const rawEdges = state.productionGraph.edges || [];

        // Apply Graph Filtering to prevent the "Hairball Problem"
        let filteredNodes = rawNodes;
        if (state.graphFilter === 'threats') {
            filteredNodes = rawNodes.filter(n => n.type === 'threat' || n.type === 'socket' || n.trust < 60);
        } else if (state.graphFilter === 'hierarchy') {
            filteredNodes = rawNodes.filter(n => n.type === 'parent_process' || n.type === 'process' || n.type === 'threat');
        }

        const allowedIDs = new Set(filteredNodes.map(n => n.id));
        let filteredEdges = rawEdges.filter(e => {
            const src = typeof e.source === 'object' ? e.source.id : e.source;
            const tgt = typeof e.target === 'object' ? e.target.id : e.target;
            return allowedIDs.has(src) && allowedIDs.has(tgt);
        });

        // Update stats overlay
        setText('#g-node-count', filteredNodes.length);
        setText('#g-edge-count', filteredEdges.length);
        setText('#g-threat-count', state.productionGraph.active_threats || 0);

        // Map nodes for d3 force simulation
        const nodeMap = new Map();
        currentGraphNodes.forEach(n => nodeMap.set(n.id, n));

        const newGraphNodes = filteredNodes.map(n => {
            const existing = nodeMap.get(n.id);
            if (existing) {
                existing.trust = n.trust;
                existing.type = n.type;
                return existing;
            }
            return { ...n };
        });

        currentGraphNodes = newGraphNodes;
        currentGraphLinks = filteredEdges.map(e => ({
            source: typeof e.source === 'object' ? e.source.id : e.source,
            target: typeof e.target === 'object' ? e.target.id : e.target,
            severity: e.severity,
            label: e.label
        }));

        // Render Links
        prodLinkSel = prodG.select('.links').selectAll('line').data(currentGraphLinks);
        prodLinkSel.exit().remove();
        prodLinkSel = prodLinkSel.enter().append('line')
            .attr('stroke', d => d.severity === 'critical' ? '#ef4444' : 'rgba(6, 182, 212, 0.4)')
            .attr('stroke-width', d => d.severity === 'critical' ? 2 : 1)
            .attr('marker-end', 'url(#prod-arrowhead)')
            .merge(prodLinkSel);

        // Render Nodes
        prodNodeSel = prodG.select('.nodes').selectAll('circle').data(currentGraphNodes, d => d.id);
        prodNodeSel.exit().remove();
        prodNodeSel = prodNodeSel.enter().append('circle')
            .attr('r', d => d.type === 'parent_process' ? 12 : d.type === 'threat' ? 10 : d.type === 'socket' ? 7 : 8)
            .attr('fill', d => getProdNodeColor(d))
            .attr('stroke', d => d.type === 'threat' ? '#ef4444' : 'rgba(255,255,255,0.25)')
            .attr('stroke-width', d => d.type === 'threat' ? 3 : 1.5)
            .call(d3.drag()
                .on('start', prodDragStarted)
                .on('drag', prodDragged)
                .on('end', prodDragEnded))
            .on('click', (event, d) => {
                if (d.pid) {
                    const entry = state.trustScores[d.pid] || {
                        pid: d.pid, ppid: d.ppid, comm: d.comm,
                        trust: d.trust || 80, status: d.status || 'unknown'
                    };
                    openProcessInspector(entry);
                }
            })
            .merge(prodNodeSel);

        // Node Labels
        prodLabelSel = prodG.select('.labels').selectAll('text').data(currentGraphNodes, d => d.id);
        prodLabelSel.exit().remove();
        prodLabelSel = prodLabelSel.enter().append('text')
            .text(d => truncate(d.label, 18))
            .attr('font-family', "'JetBrains Mono', monospace")
            .attr('font-size', '9px')
            .attr('fill', 'rgba(226, 232, 240, 0.85)')
            .attr('dx', 13)
            .attr('dy', 4)
            .merge(prodLabelSel);

        prodSim.nodes(currentGraphNodes);
        prodSim.force('link').links(currentGraphLinks);
        prodSim.alpha(0.25).restart();
    }

    function prodTicked() {
        prodLinkSel
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        prodNodeSel
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        prodLabelSel
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    }

    function prodDragStarted(event, d) {
        if (!event.active) prodSim.alphaTarget(0.2).restart();
        d.fx = d.x; d.fy = d.y;
    }

    function prodDragged(event, d) {
        d.fx = event.x; d.fy = event.y;
    }

    function prodDragEnded(event, d) {
        if (!event.active) prodSim.alphaTarget(0);
        d.fx = null; d.fy = null;
    }

    function getProdNodeColor(d) {
        if (d.type === 'threat') return '#ef4444';
        if (d.type === 'parent_process') return '#8b5cf6';
        if (d.type === 'socket') return '#06b6d4';
        if (d.trust < 50) return '#ef4444';
        if (d.trust < 75) return '#f59e0b';
        return '#6366f1';
    }

    // ---- Decision & Action Logs ----
    function renderDecisionEntry(d) {
        if (!$decisionsContainer) return;
        const empty = $decisionsContainer.querySelector('.empty-state');
        if (empty) empty.remove();

        const tier = d.tier || 'low';
        const el = document.createElement('div');
        el.className = `decision-entry ${tier}`;
        const time = d.timestamp ? new Date(d.timestamp).toLocaleTimeString() : '--:--:--';
        const icons = { 'trusted_allow': '🟢', 'observe_log': '📋', 'observe_alert': '⚠️', 'observe_critical': '🚨', 'paused_sigstop': '⏸', 'kill': '💀' };

        el.innerHTML = `
            <div class="decision-header">
                <span class="decision-tier ${tier}">${icons[d.action]||'📋'} ${tier} [${d.status || 'unknown'}]</span>
                <span class="decision-time">${time}</span>
            </div>
            <div class="decision-body">
                <strong>${escapeHtml(d.comm || '?')}</strong> (PID ${d.pid}) → ${d.action || 'unknown'}
                ${d.technique_id ? `<br><span class="decision-technique">${d.technique_id}: ${d.technique || ''}</span>` : ''}
                ${d.trust_score !== undefined ? `<br>Trust: ${Math.round(d.trust_score)} | p=${(d.conformal_p_value || 0).toFixed(4)}` : ''}
            </div>
        `;
        $decisionsContainer.insertBefore(el, $decisionsContainer.firstChild);
        while ($decisionsContainer.children.length > 40) $decisionsContainer.removeChild($decisionsContainer.lastChild);
    }

    function renderEventEntry(evt) {
        if (!$eventsContainer) return;
        const empty = $eventsContainer.querySelector('.empty-state');
        if (empty) empty.remove();

        const el = document.createElement('div');
        el.className = 'event-entry';
        el.innerHTML = `
            <span class="event-type ${evt.type_str || ''}">${evt.type_str || '?'}</span>
            <span class="event-pid">[${evt.pid}]</span>
            <span class="event-payload">${escapeHtml(evt.comm || '')} ${evt.payload ? '→ ' + truncate(evt.payload, 36) : ''}</span>
            ${evt.dst_ip ? `<span class="event-payload"> → ${evt.dst_ip}:${evt.dst_port}</span>` : ''}
        `;
        $eventsContainer.insertBefore(el, $eventsContainer.firstChild);
        while ($eventsContainer.children.length > 50) $eventsContainer.removeChild($eventsContainer.lastChild);
    }

    function renderNarration(data) {
        if (!$narrationContainer) return;
        const empty = $narrationContainer.querySelector('.empty-state');
        if (empty) empty.remove();

        const el = document.createElement('div');
        el.className = 'narration-entry';
        const techniques = (data.technique_ids || []).map(id => `<span class="technique-chip">${id}</span>`).join('');

        el.innerHTML = `
            <div>${data.narrative || 'No narrative generated.'}</div>
            ${techniques ? `<div class="narration-techniques">${techniques}</div>` : ''}
            <div class="narration-meta">Model: ${data.model || '?'} | Latency: ${data.latency_ms || 0}ms</div>
        `;
        $narrationContainer.insertBefore(el, $narrationContainer.firstChild);
        while ($narrationContainer.children.length > 8) $narrationContainer.removeChild($narrationContainer.lastChild);
    }

    function renderActionLog() {
        if (!$actionLogContainer) return;
        if (state.actionLog.length === 0) {
            $actionLogContainer.innerHTML = '<div class="empty-state">No actions yet. Kill/Pause/Trust actions appear here.</div>';
            return;
        }
        $actionLogContainer.innerHTML = '';
        state.actionLog.forEach(entry => {
            const icons = { kill: '💀', pause: '⏸', resume: '▶', trust: '✅' };
            const time = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '--:--:--';
            const el = document.createElement('div');
            el.className = `action-log-entry action-${entry.action}`;
            el.innerHTML = `
                <span class="alog-icon">${icons[entry.action] || '📋'}</span>
                <div class="alog-body">
                    <span class="alog-action">${entry.action.toUpperCase()}</span>
                    <span class="alog-comm">${escapeHtml(entry.comm || '?')} (PID ${entry.pid})</span>
                    <span class="alog-by">by:${entry.by}</span>
                </div>
                <div class="alog-meta">
                    <span class="alog-result" style="color:${entry.result === 'ok' ? '#10b981' : '#ef4444'}">${entry.result}</span>
                    <span class="alog-time">${time}</span>
                </div>
            `;
            $actionLogContainer.appendChild(el);
        });
    }

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
                <span class="paused-name">⏸ ${escapeHtml(p.comm || '?')} (PID ${p.pid})</span>
                <div class="paused-actions">
                    <button class="row-btn known-btn" data-pid="${p.pid}" data-comm="${escapeHtml(p.comm)}">✅ Trust &amp; Resume</button>
                    <button class="row-btn resume-btn" data-pid="${p.pid}">▶ Resume</button>
                    <button class="row-btn ask-btn" data-pid="${p.pid}" data-comm="${escapeHtml(p.comm)}">🔍 Ask AI</button>
                </div>
            `;
            card.querySelector('.known-btn').addEventListener('click', async () => {
                await markAsKnown(p.comm, p.pid);
                await resumeProcess(p.pid);
                await fetchPausedProcesses(); await fetchTrustScores();
            });
            card.querySelector('.resume-btn').addEventListener('click', async () => {
                await resumeProcess(p.pid);
                await fetchPausedProcesses();
            });
            card.querySelector('.ask-btn').addEventListener('click', () => {
                document.querySelector('.top-nav-btn[data-view="security"]')?.click();
                handleChatQuery(`Process ${p.comm} (PID ${p.pid}) is SUSPENDED. Is it safe to resume?`, p.pid);
            });
            $pausedBannerList.appendChild(card);
        });
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

    // ---- API Actions ----
    async function markAsKnown(comm, pid) {
        try {
            const resp = await fetch('/api/process/known', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ comm, pid })
            });
            if (resp.ok) {
                if (state.trustScores[pid]) {
                    state.trustScores[pid].trust = 100;
                    state.trustScores[pid].status = 'known';
                    state.trustScores[pid].paused = false;
                }
                scheduledRender();
                return await resp.json();
            }
        } catch (e) { console.warn('Failed to mark as known:', e); }
    }

    async function pauseProcess(pid, comm) {
        try {
            const resp = await fetch('/api/process/pause', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pid, comm })
            });
            if (resp.ok) {
                if (state.trustScores[pid]) {
                    state.trustScores[pid].status = 'paused';
                    state.trustScores[pid].paused = true;
                }
                scheduledRender();
                return await resp.json();
            }
        } catch (e) { console.warn('Failed to pause process:', e); }
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
                    if (state.trustScores[pid].status === 'paused') state.trustScores[pid].status = 'unknown';
                }
                scheduledRender();
                return await resp.json();
            }
        } catch (e) { console.warn('Failed to resume process:', e); }
    }

    async function killProcess(pid, comm) {
        try {
            const resp = await fetch('/api/process/kill', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pid, comm })
            });
            if (resp.ok) {
                return await resp.json();
            }
        } catch (e) { console.warn('Failed to kill process:', e); }
    }

    // ---- Helpers ----
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

    function escapeHtml(s) {
        return String(s || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

})();
