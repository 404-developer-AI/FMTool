/**
 * NAT rules migration page JavaScript — sync, dry-run, execute, progress.
 */
(function() {
    'use strict';

    const selectAll = document.getElementById('select-all');
    const searchInput = document.getElementById('search-input');
    const interfaceFilter = document.getElementById('interface-filter');
    const statusFilter = document.getElementById('status-filter');
    const disabledFilter = document.getElementById('disabled-filter');
    const visibleCount = document.getElementById('visible-count');
    const btnDryrun = document.getElementById('btn-dryrun');
    const btnMigrate = document.getElementById('btn-migrate');
    const btnSkip = document.getElementById('btn-skip');
    const btnReset = document.getElementById('btn-reset');
    const dryrunPanel = document.getElementById('dryrun-panel');
    const dryrunResults = document.getElementById('dryrun-results');
    const btnDryrunExecute = document.getElementById('btn-dryrun-execute');
    const btnDryrunClose = document.getElementById('btn-dryrun-close');
    const progressPanel = document.getElementById('progress-panel');
    const progressBar = document.getElementById('progress-bar');
    const progressInfo = document.getElementById('progress-info');
    const modal = document.getElementById('migrate-modal');
    const modalCount = document.getElementById('modal-count');
    const modalCancel = document.getElementById('modal-cancel');
    const modalConfirm = document.getElementById('modal-confirm');
    const origDestSelect = document.getElementById('orig-dest-select');
    const btnFetchInterfaces = document.getElementById('btn-fetch-interfaces');

    // --- Fetch Sophos interfaces for Original Destination dropdown ---
    let sophosInterfaces = [];

    if (btnFetchInterfaces) {
        btnFetchInterfaces.addEventListener('click', async function() {
            btnFetchInterfaces.disabled = true;
            btnFetchInterfaces.textContent = 'Fetching...';

            try {
                const resp = await fetch('/migrate/nat-rules/sophos-interfaces', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                });
                const data = await resp.json();
                if (data.success) {
                    sophosInterfaces = data.interfaces;
                    populateOrigDestDropdown();
                    showToast(`Loaded ${sophosInterfaces.length} interfaces from Sophos`, 'success');
                } else {
                    showToast(data.message || 'Failed to fetch interfaces', 'error');
                }
            } catch (e) {
                showToast('Network error fetching from Sophos', 'error');
            }

            btnFetchInterfaces.disabled = false;
            btnFetchInterfaces.textContent = 'Fetch from Sophos';
        });
    }

    function populateOrigDestDropdown() {
        if (!origDestSelect) return;
        const currentVal = origDestSelect.value;
        origDestSelect.innerHTML = '<option value="">(per rule)</option>';

        for (const iface of sophosInterfaces) {
            const zoneSuffix = iface.zone ? ` (${iface.zone})` : '';
            if (iface.ip) {
                const opt = document.createElement('option');
                opt.value = '#' + iface.name;
                opt.textContent = `#${iface.name} - ${iface.ip}${zoneSuffix}`;
                origDestSelect.appendChild(opt);
            }
            for (const alias of (iface.alias_ips || [])) {
                const opt = document.createElement('option');
                opt.value = '#' + alias.name;
                opt.textContent = `#${alias.name} - ${alias.ip}${zoneSuffix}`;
                origDestSelect.appendChild(opt);
            }
        }

        if (currentVal) origDestSelect.value = currentVal;
    }

    function getSelectedOrigDest() {
        return origDestSelect ? origDestSelect.value : '';
    }

    // --- Table filters & search ---
    if (!selectAll) return;

    const rows = document.querySelectorAll('.migrate-row');
    let lastDryrunIds = [];

    function populateFilters() {
        const interfaces = new Set();
        const statuses = new Set();
        rows.forEach(row => {
            const i = row.dataset.interface;
            const s = row.dataset.status;
            if (i) interfaces.add(i);
            if (s) statuses.add(s);
        });
        interfaces.forEach(i => {
            const opt = document.createElement('option');
            opt.value = i;
            opt.textContent = i;
            interfaceFilter.appendChild(opt);
        });
        statuses.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s;
            opt.textContent = s;
            statusFilter.appendChild(opt);
        });
    }
    populateFilters();

    function applyFilters() {
        const search = searchInput.value.toLowerCase();
        const ifVal = interfaceFilter.value;
        const statusVal = statusFilter.value;
        const disVal = disabledFilter.value;
        let count = 0;

        rows.forEach(row => {
            const matchSearch = !search || row.dataset.search.toLowerCase().includes(search);
            const matchIf = !ifVal || row.dataset.interface === ifVal;
            const matchStatus = !statusVal || row.dataset.status === statusVal;
            let matchDisabled = true;
            if (disVal === 'enabled') matchDisabled = row.dataset.disabled === '0';
            else if (disVal === 'disabled') matchDisabled = row.dataset.disabled !== '0';
            const visible = matchSearch && matchIf && matchStatus && matchDisabled;
            row.style.display = visible ? '' : 'none';
            if (visible) count++;
        });
        visibleCount.textContent = count;
        updateSelectAllState();
    }

    searchInput.addEventListener('input', applyFilters);
    interfaceFilter.addEventListener('change', applyFilters);
    statusFilter.addEventListener('change', applyFilters);
    disabledFilter.addEventListener('change', applyFilters);

    // --- Checkbox management with shift+click range selection ---
    let lastCheckedIndex = null;

    selectAll.addEventListener('change', function() {
        const checked = this.checked;
        rows.forEach(row => {
            if (row.style.display !== 'none') {
                row.querySelector('.rule-checkbox').checked = checked;
            }
        });
        lastCheckedIndex = null;
    });

    const tableBody = document.querySelector('#nat-rules-table tbody');
    if (tableBody) {
        tableBody.addEventListener('click', function(e) {
            if (!e.target.classList.contains('rule-checkbox')) return;

            const allCheckboxes = Array.from(document.querySelectorAll('.rule-checkbox'));
            const currentIndex = allCheckboxes.indexOf(e.target);

            if (e.shiftKey && lastCheckedIndex !== null && currentIndex !== lastCheckedIndex) {
                const start = Math.min(lastCheckedIndex, currentIndex);
                const end = Math.max(lastCheckedIndex, currentIndex);
                const checked = e.target.checked;
                for (let i = start; i <= end; i++) {
                    const row = allCheckboxes[i].closest('.migrate-row');
                    if (row && row.style.display !== 'none') {
                        allCheckboxes[i].checked = checked;
                    }
                }
            }

            lastCheckedIndex = currentIndex;
            updateSelectAllState();
        });
    }

    function updateSelectAllState() {
        const visible = getVisibleCheckboxes();
        const checked = visible.filter(cb => cb.checked);
        selectAll.checked = visible.length > 0 && checked.length === visible.length;
        selectAll.indeterminate = checked.length > 0 && checked.length < visible.length;
    }

    function getVisibleCheckboxes() {
        return Array.from(rows)
            .filter(r => r.style.display !== 'none')
            .map(r => r.querySelector('.rule-checkbox'));
    }

    function getSelectedIds() {
        return Array.from(document.querySelectorAll('.rule-checkbox:checked'))
            .map(cb => parseInt(cb.value));
    }

    // --- Sorting ---
    document.querySelectorAll('.sortable').forEach(th => {
        th.addEventListener('click', function() {
            const col = this.dataset.col;
            const tbody = document.querySelector('#nat-rules-table tbody');
            const rowsArr = Array.from(rows);
            const asc = !this.classList.contains('sort-asc');

            document.querySelectorAll('.sortable').forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
            });
            this.classList.add(asc ? 'sort-asc' : 'sort-desc');

            rowsArr.sort((a, b) => {
                let va, vb;
                if (col === 'status') {
                    va = a.dataset.status;
                    vb = b.dataset.status;
                } else {
                    const colIdx = getColIndex(col);
                    va = a.children[colIdx]?.textContent?.trim() || '';
                    vb = b.children[colIdx]?.textContent?.trim() || '';
                }
                const cmp = va.localeCompare(vb, undefined, {numeric: true});
                return asc ? cmp : -cmp;
            });

            rowsArr.forEach(row => tbody.appendChild(row));
        });
    });

    function getColIndex(col) {
        const headers = document.querySelectorAll('#nat-rules-table thead th');
        for (let i = 0; i < headers.length; i++) {
            if (headers[i].dataset.col === col) return i;
        }
        return 1;
    }

    // --- Dry Run ---
    btnDryrun.addEventListener('click', async function() {
        const ids = getSelectedIds();
        if (ids.length === 0) {
            showToast('Select at least one rule', 'warning');
            return;
        }
        btnDryrun.disabled = true;
        btnDryrun.textContent = 'Planning...';
        dryrunPanel.style.display = 'none';

        try {
            const resp = await fetch('/migrate/nat-rules/plan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({rule_ids: ids, orig_dest: getSelectedOrigDest()}),
            });
            const data = await resp.json();
            if (data.success) {
                lastDryrunIds = ids;
                renderDryrunResults(data.plans);
                dryrunPanel.style.display = 'block';
                showToast('Dry run complete', 'success');
            } else {
                showToast(data.message || 'Dry run failed', 'error');
            }
        } catch (e) {
            showToast('Network error during dry run', 'error');
        }

        btnDryrun.disabled = false;
        btnDryrun.textContent = 'Dry Run';
    });

    // Collect all missing services and hosts across plans for bulk create
    let allMissingServices = [];
    let allMissingHosts = [];

    function renderDryrunResults(plans) {
        allMissingServices = [];
        allMissingHosts = [];
        let html = '';

        // Collect unique missing services and hosts across all plans
        const seenServices = new Set();
        const seenHosts = new Set();
        for (const plan of plans) {
            const msList = plan.rule_params?._missing_services || [];
            for (const ms of msList) {
                if (ms.proposed) {
                    for (const svc of ms.proposed) {
                        if (!seenServices.has(svc.name)) {
                            seenServices.add(svc.name);
                            allMissingServices.push(svc);
                        }
                    }
                }
            }
            const mhList = plan.rule_params?._missing_hosts || [];
            for (const mh of mhList) {
                if (mh.name && !seenHosts.has(mh.name)) {
                    seenHosts.add(mh.name);
                    allMissingHosts.push(mh);
                }
            }
        }

        // Bulk create buttons
        if (allMissingServices.length > 0 || allMissingHosts.length > 0) {
            html += `<div class="dryrun-bulk-actions">`;
            if (allMissingServices.length > 0) {
                html += `<button class="btn btn-small btn-warning" id="btn-create-all-services">Create All Missing Services (${allMissingServices.length})</button> `;
            }
            if (allMissingHosts.length > 0) {
                html += `<button class="btn btn-small btn-warning" id="btn-create-all-hosts">Create All Missing Hosts (${allMissingHosts.length})</button>`;
            }
            html += `</div>`;
        }

        for (const plan of plans) {
            const actionClass = plan.action === 'create' ? 'dryrun-create' :
                                plan.action === 'exists' ? 'dryrun-exists' : 'dryrun-skip';

            const levels = new Set();
            if (plan.warnings && plan.warnings.length > 0) {
                for (const w of plan.warnings) {
                    const level = (typeof w === 'object' && w.level) ? w.level : 'orange';
                    levels.add(level);
                }
            }
            const severityAttr = levels.size > 0 ? [...levels].join(' ') : 'none';

            html += `<div class="dryrun-item ${actionClass}" data-severity="${severityAttr}">`;
            html += `<div class="dryrun-item-header">`;
            html += `<strong>${escapeHtml(plan.rule_name || plan.pf_description || '(unnamed)')}</strong>`;
            html += `<span class="dryrun-action">${escapeHtml(plan.action)}</span>`;
            html += `</div>`;
            html += `<div class="dryrun-reason">${escapeHtml(plan.reason)}</div>`;

            if (plan.rule_params && plan.action === 'create') {
                const p = plan.rule_params;
                html += '<div class="planned-objects">';
                html += `<div class="planned-object"><span class="object-type">Status</span><span class="object-name">${escapeHtml(p.status || '')}</span></div>`;
                html += `<div class="planned-object"><span class="object-type">Original Dest</span><span class="object-name">${escapeHtml(p.original_destination || '')}</span></div>`;
                html += `<div class="planned-object"><span class="object-type">Translated Dest</span><span class="object-name">${escapeHtml(p.translated_destination || '')}</span></div>`;

                // Original service
                const msList = p._missing_services || [];
                const origMs = msList.find(m => m.type === 'original_service');
                if (origMs) {
                    const proposed = origMs.proposed || [];
                    const names = proposed.map(s => s.name).join(', ');
                    const dataAttr = escapeHtml(JSON.stringify(proposed));
                    html += `<div class="planned-object dryrun-missing-service">`;
                    html += `<span class="object-type">Original Svc</span>`;
                    html += `<span class="object-name">Missing: ${escapeHtml(origMs.protocol)}/${escapeHtml(origMs.port)} -> will create: ${escapeHtml(names)}</span>`;
                    html += ` <button class="btn btn-small btn-warning btn-create-service" data-services='${dataAttr}'>Create</button>`;
                    html += `</div>`;
                } else {
                    html += `<div class="planned-object"><span class="object-type">Original Svc</span><span class="object-name">${escapeHtml(p.original_service || '(none)')}</span></div>`;
                }

                // Translated service
                const transMs = msList.find(m => m.type === 'translated_service');
                if (transMs) {
                    const proposed = transMs.proposed || [];
                    const names = proposed.map(s => s.name).join(', ');
                    const dataAttr = escapeHtml(JSON.stringify(proposed));
                    html += `<div class="planned-object dryrun-missing-service">`;
                    html += `<span class="object-type">Translated Svc</span>`;
                    html += `<span class="object-name">Missing: ${escapeHtml(transMs.protocol)}/${escapeHtml(transMs.port)} -> will create: ${escapeHtml(names)}</span>`;
                    html += ` <button class="btn btn-small btn-warning btn-create-service" data-services='${dataAttr}'>Create</button>`;
                    html += `</div>`;
                } else {
                    html += `<div class="planned-object"><span class="object-type">Translated Svc</span><span class="object-name">${escapeHtml(p.translated_service || 'Original')}</span></div>`;
                }

                // Missing hosts
                const mhList = p._missing_hosts || [];
                for (const mh of mhList) {
                    const dataAttr = escapeHtml(JSON.stringify([mh]));
                    html += `<div class="planned-object dryrun-missing-service">`;
                    html += `<span class="object-type">Missing Host</span>`;
                    html += `<span class="object-name">${escapeHtml(mh.name)} (${escapeHtml(mh.ip)})</span>`;
                    html += ` <button class="btn btn-small btn-warning btn-create-host" data-hosts='${dataAttr}'>Create</button>`;
                    html += `</div>`;
                }

                if (p.position) {
                    let posText = p.position;
                    if (p.after_rule_name) posText += ': ' + p.after_rule_name;
                    html += `<div class="planned-object"><span class="object-type">Position</span><span class="object-name">${escapeHtml(posText)}</span></div>`;
                }
                html += '</div>';
            }

            if (plan.warnings && plan.warnings.length > 0) {
                html += '<div class="dryrun-warnings">';
                for (const w of plan.warnings) {
                    const level = (typeof w === 'object' && w.level) ? w.level : 'orange';
                    const text = (typeof w === 'object' && w.text) ? w.text : w;
                    html += `<div class="dryrun-warning dryrun-warning-${level}">${escapeHtml(text)}</div>`;
                }
                html += '</div>';
            }

            html += '</div>';
        }
        dryrunResults.innerHTML = html;

        // Update warning severity counts
        const items = dryrunResults.querySelectorAll('.dryrun-item');
        const counts = {red: 0, orange: 0, green: 0, none: 0};
        items.forEach(item => {
            const sevs = (item.dataset.severity || 'none').split(' ');
            for (const s of sevs) {
                if (counts[s] !== undefined) counts[s]++;
            }
        });
        const countRed = document.getElementById('dryrun-count-red');
        const countOrange = document.getElementById('dryrun-count-orange');
        const countGreen = document.getElementById('dryrun-count-green');
        if (countRed) countRed.textContent = counts.red;
        if (countOrange) countOrange.textContent = counts.orange;
        if (countGreen) countGreen.textContent = counts.green;

        // Attach bulk create handlers
        const btnCreateAllSvc = document.getElementById('btn-create-all-services');
        if (btnCreateAllSvc) {
            btnCreateAllSvc.addEventListener('click', function() {
                createServicesOnSophos(allMissingServices, this);
            });
        }
        const btnCreateAllHosts = document.getElementById('btn-create-all-hosts');
        if (btnCreateAllHosts) {
            btnCreateAllHosts.addEventListener('click', function() {
                createHostsOnSophos(allMissingHosts, this);
            });
        }
    }

    // --- Dry-run warning severity filter ---
    const dryrunFilterBtns = document.querySelectorAll('.dryrun-filter-btn');
    dryrunFilterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const filter = this.dataset.filter;
            if (filter === 'all') {
                dryrunFilterBtns.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
            } else {
                dryrunFilterBtns.forEach(b => { if (b.dataset.filter === 'all') b.classList.remove('active'); });
                this.classList.toggle('active');
                const anyActive = [...dryrunFilterBtns].some(b => b.classList.contains('active'));
                if (!anyActive) {
                    dryrunFilterBtns.forEach(b => { if (b.dataset.filter === 'all') b.classList.add('active'); });
                }
            }
            applyDryrunFilter();
        });
    });

    function applyDryrunFilter() {
        const activeFilters = [...dryrunFilterBtns]
            .filter(b => b.classList.contains('active'))
            .map(b => b.dataset.filter);
        const showAll = activeFilters.includes('all');
        const items = dryrunResults.querySelectorAll('.dryrun-item');
        items.forEach(item => {
            if (showAll) {
                item.style.display = '';
            } else {
                const sevs = (item.dataset.severity || 'none').split(' ');
                const match = activeFilters.some(f => sevs.includes(f));
                item.style.display = match ? '' : 'none';
            }
        });
    }

    // --- Create missing services on Sophos ---
    async function createServicesOnSophos(services, btn) {
        if (!services || services.length === 0) return;
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Creating...';

        try {
            const resp = await fetch('/migrate/nat-rules/create-services', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({services: services}),
            });

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const {done, value} = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, {stream: true});
                const lines = buffer.split('\n');
                buffer = lines.pop();
                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    const event = JSON.parse(line.slice(6));
                    if (event.type === 'progress' && event.success !== undefined) {
                        btn.textContent = `Creating ${event.index + 1}/${event.total}...`;
                    } else if (event.type === 'done') {
                        showToast(`Created ${event.created} service(s)${event.failed > 0 ? `, ${event.failed} failed` : ''}`, event.failed > 0 ? 'warning' : 'success');
                        btn.textContent = '\u2713 Created';
                        btn.classList.remove('btn-warning');
                        btn.classList.add('btn-secondary');
                        if (lastDryrunIds.length > 0) {
                            showToast('Re-running dry run to update results...', 'info');
                            btnDryrun.click();
                        }
                    }
                }
            }
        } catch (e) {
            showToast('Network error creating services', 'error');
            btn.disabled = false;
            btn.textContent = origText;
        }
    }

    // --- Create missing hosts on Sophos ---
    async function createHostsOnSophos(hosts, btn) {
        if (!hosts || hosts.length === 0) return;
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Creating...';

        try {
            const resp = await fetch('/migrate/nat-rules/create-hosts', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({hosts: hosts}),
            });

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const {done, value} = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, {stream: true});
                const lines = buffer.split('\n');
                buffer = lines.pop();
                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    const event = JSON.parse(line.slice(6));
                    if (event.type === 'progress' && event.success !== undefined) {
                        btn.textContent = `Creating ${event.index + 1}/${event.total}...`;
                    } else if (event.type === 'done') {
                        showToast(`Created ${event.created} host(s)${event.failed > 0 ? `, ${event.failed} failed` : ''}`, event.failed > 0 ? 'warning' : 'success');
                        btn.textContent = '\u2713 Created';
                        btn.classList.remove('btn-warning');
                        btn.classList.add('btn-secondary');
                        if (lastDryrunIds.length > 0) {
                            showToast('Re-running dry run to update results...', 'info');
                            btnDryrun.click();
                        }
                    }
                }
            }
        } catch (e) {
            showToast('Network error creating hosts', 'error');
            btn.disabled = false;
            btn.textContent = origText;
        }
    }

    // Delegated click handler for per-rule create buttons
    dryrunResults.addEventListener('click', function(e) {
        const svcBtn = e.target.closest('.btn-create-service');
        if (svcBtn) {
            try {
                const services = JSON.parse(svcBtn.dataset.services);
                createServicesOnSophos(services, svcBtn);
            } catch (err) {
                showToast('Invalid service data', 'error');
            }
            return;
        }
        const hostBtn = e.target.closest('.btn-create-host');
        if (hostBtn) {
            try {
                const hosts = JSON.parse(hostBtn.dataset.hosts);
                createHostsOnSophos(hosts, hostBtn);
            } catch (err) {
                showToast('Invalid host data', 'error');
            }
        }
    });

    btnDryrunClose.addEventListener('click', function() {
        dryrunPanel.style.display = 'none';
        lastDryrunIds = [];
        allMissingServices = [];
        allMissingHosts = [];
    });

    btnDryrunExecute.addEventListener('click', function() {
        if (lastDryrunIds.length > 0) {
            executeMigration(lastDryrunIds);
        }
    });

    // --- Migrate ---
    btnMigrate.addEventListener('click', function() {
        const ids = getSelectedIds();
        if (ids.length === 0) {
            showToast('Select at least one rule', 'warning');
            return;
        }
        modalCount.textContent = `${ids.length} NAT rule(s) will be migrated to Sophos.`;
        modal.style.display = 'flex';
    });

    modalCancel.addEventListener('click', function() {
        modal.style.display = 'none';
    });

    modalConfirm.addEventListener('click', function() {
        modal.style.display = 'none';
        const ids = getSelectedIds();
        executeMigration(ids);
    });

    async function executeMigration(ids) {
        btnMigrate.disabled = true;
        btnDryrun.disabled = true;
        btnSkip.disabled = true;
        progressPanel.style.display = 'block';
        dryrunPanel.style.display = 'none';
        progressBar.style.width = '0%';
        progressInfo.textContent = 'Fetching Sophos data...';

        try {
            const resp = await fetch('/migrate/nat-rules/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({rule_ids: ids, orig_dest: getSelectedOrigDest()}),
            });

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const {done, value} = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, {stream: true});
                const lines = buffer.split('\n');
                buffer = lines.pop();
                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    const event = JSON.parse(line.slice(6));
                    if (event.type === 'phase') {
                        progressInfo.textContent = event.message;
                    } else if (event.type === 'progress' && event.success !== undefined) {
                        const pct = ((event.index + 1) / event.total) * 100;
                        progressBar.style.width = pct + '%';
                        progressInfo.textContent = `Migrating ${event.index + 1} of ${event.total}...`;
                        updateRowStatus(event.item_id, event.status);
                    } else if (event.type === 'done') {
                        progressBar.style.width = '100%';
                        progressInfo.textContent = `Done: ${event.migrated} migrated, ${event.failed} failed`;
                        if (event.failed > 0) {
                            showToast(`Migration completed with ${event.failed} error(s)`, 'warning');
                        } else {
                            showToast(`Successfully migrated ${event.migrated} NAT rule(s)`, 'success');
                        }
                    } else if (event.type === 'error') {
                        showToast(event.message || 'Migration failed', 'error');
                        progressInfo.textContent = 'Migration failed';
                    }
                }
            }
        } catch (e) {
            showToast('Network error during migration', 'error');
            progressInfo.textContent = 'Network error';
        }

        btnMigrate.disabled = false;
        btnDryrun.disabled = false;
        btnSkip.disabled = false;
    }

    // --- Skip ---
    btnSkip.addEventListener('click', async function() {
        const ids = getSelectedIds();
        if (ids.length === 0) {
            showToast('Select at least one rule', 'warning');
            return;
        }
        if (!confirm(`Mark ${ids.length} NAT rule(s) as skipped?`)) return;

        btnSkip.disabled = true;
        btnSkip.textContent = 'Updating...';

        try {
            const resp = await fetch('/migrate/nat-rules/skip', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({rule_ids: ids}),
            });
            const data = await resp.json();
            if (data.success) {
                ids.forEach(id => updateRowStatus(id, 'skipped'));
                showToast(`${data.updated} rule(s) marked as skipped`, 'success');
            } else {
                showToast(data.message || 'Failed to skip', 'error');
            }
        } catch (e) {
            showToast('Network error', 'error');
        }

        btnSkip.disabled = false;
        btnSkip.textContent = 'Skip Selected';
    });

    // --- Reset to Pending ---
    btnReset.addEventListener('click', async function() {
        const ids = getSelectedIds();
        if (ids.length === 0) {
            showToast('Select at least one rule', 'warning');
            return;
        }
        if (!confirm(`Reset ${ids.length} NAT rule(s) to pending? This does NOT remove the rule from Sophos.`)) return;

        btnReset.disabled = true;
        btnReset.textContent = 'Updating...';

        try {
            const resp = await fetch('/migrate/nat-rules/reset', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({rule_ids: ids}),
            });
            const data = await resp.json();
            if (data.success) {
                ids.forEach(id => updateRowStatus(id, 'pending'));
                showToast(`${data.updated} rule(s) reset to pending`, 'success');
            } else {
                showToast(data.message || 'Failed to reset', 'error');
            }
        } catch (e) {
            showToast('Network error', 'error');
        }

        btnReset.disabled = false;
        btnReset.textContent = 'Reset to Pending';
    });

    // --- Helpers ---
    function updateRowStatus(ruleId, status) {
        const row = document.querySelector(`.migrate-row[data-id="${ruleId}"]`);
        if (!row) return;
        row.dataset.status = status;
        const badge = row.querySelector('.status-badge');
        if (badge) {
            badge.className = `status-badge ${status}`;
            badge.textContent = status;
        }
        const searchParts = row.dataset.search.split(' ');
        searchParts[0] = status;
        row.dataset.search = searchParts.join(' ');
        const cb = row.querySelector('.rule-checkbox');
        if (cb) cb.checked = false;
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Sophos sync: duplicate check with caching ---
    const SYNC_CACHE_KEY = 'fmtool_sophos_natrule_sync';
    const SYNC_MAX_AGE_MS = 60 * 60 * 1000;

    const syncIcon = document.getElementById('sync-icon');
    const syncText = document.getElementById('sync-text');
    const syncTimestamp = document.getElementById('sync-timestamp');
    const btnSyncRefresh = document.getElementById('btn-sync-refresh');

    function setSyncState(state, message, timestamp) {
        if (!syncIcon) return;
        syncIcon.className = 'sync-icon sync-' + state;
        syncText.textContent = message;
        if (timestamp) {
            const date = new Date(timestamp);
            syncTimestamp.textContent = 'Last sync: ' + date.toLocaleString();
        } else {
            syncTimestamp.textContent = '';
        }
    }

    function getCachedSync() {
        try {
            const raw = localStorage.getItem(SYNC_CACHE_KEY);
            if (!raw) return null;
            return JSON.parse(raw);
        } catch (e) {
            return null;
        }
    }

    function saveSyncCache(duplicates) {
        const data = {
            timestamp: Date.now(),
            duplicates: duplicates,
        };
        localStorage.setItem(SYNC_CACHE_KEY, JSON.stringify(data));
        return data;
    }

    function applyCachedDuplicates(duplicates) {
        if (!duplicates || duplicates.length === 0) return;
        duplicates.forEach(dup => {
            updateRowStatus(dup.rule_id, 'migrated');
        });
    }

    async function runSync(force) {
        if (!window.SOPHOS_CONFIGURED) return;

        if (!force) {
            const cached = getCachedSync();
            if (cached && (Date.now() - cached.timestamp) < SYNC_MAX_AGE_MS) {
                applyCachedDuplicates(cached.duplicates);
                const count = cached.duplicates.length;
                setSyncState('done',
                    count > 0 ? `Synced \u2014 ${count} NAT rule(s) already on Sophos` : 'Synced \u2014 no duplicates found',
                    cached.timestamp);
                return;
            }
        }

        setSyncState('checking', 'Checking Sophos for existing NAT rules...', null);
        if (btnSyncRefresh) btnSyncRefresh.disabled = true;

        try {
            const resp = await fetch('/migrate/nat-rules/check-duplicates', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
            });
            const data = await resp.json();

            if (data.success) {
                const cache = saveSyncCache(data.duplicates);
                applyCachedDuplicates(data.duplicates);
                const count = data.duplicates.length;
                setSyncState('done',
                    count > 0 ? `Synced \u2014 ${count} NAT rule(s) already on Sophos` : 'Synced \u2014 no duplicates found',
                    cache.timestamp);
                if (count > 0) {
                    showToast(`${count} NAT rule(s) already exist on Sophos`, 'info');
                }
            } else {
                setSyncState('failed', `Sync failed: ${data.message || 'Unknown error'}`, null);
                showToast('Sophos sync failed', 'error');
            }
        } catch (e) {
            setSyncState('failed', 'Sync failed: could not reach server', null);
        }

        if (btnSyncRefresh) btnSyncRefresh.disabled = false;
    }

    if (btnSyncRefresh) {
        btnSyncRefresh.addEventListener('click', function() {
            runSync(true);
        });
    }

    // Auto-sync on page load
    runSync(false);
})();
