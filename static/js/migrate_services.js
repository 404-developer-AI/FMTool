/**
 * Services migration page JavaScript — analyze, create, rollback.
 */
(function() {
    'use strict';

    const btnAnalyze = document.getElementById('btn-analyze');
    const btnCreate = document.getElementById('btn-create');
    const btnRollback = document.getElementById('btn-rollback');
    const searchInput = document.getElementById('search-input');
    const statusFilter = document.getElementById('status-filter');
    const visibleCount = document.getElementById('visible-count');
    const totalCount = document.getElementById('total-count');
    const selectAll = document.getElementById('select-all');
    const headerSelectAll = document.getElementById('header-select-all');
    const servicesTable = document.getElementById('services-table');
    const servicesTbody = document.getElementById('services-tbody');
    const emptyState = document.getElementById('empty-state');
    const progressPanel = document.getElementById('progress-panel');
    const progressBar = document.getElementById('progress-bar');
    const progressInfo = document.getElementById('progress-info');
    const rollbackModal = document.getElementById('rollback-modal');
    const rollbackPreview = document.getElementById('rollback-preview');
    const rollbackCancel = document.getElementById('rollback-cancel');
    const rollbackConfirm = document.getElementById('rollback-confirm');

    let allServices = [];

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Analyze ---
    btnAnalyze.addEventListener('click', async function() {
        btnAnalyze.disabled = true;
        btnAnalyze.textContent = 'Analyzing...';

        try {
            const resp = await fetch('/migrate/services/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: '{}',
            });
            const data = await resp.json();

            if (data.success) {
                allServices = data.services;
                renderTable();
                showToast(`Found ${allServices.length} service(s)`, 'success');
            } else {
                showToast(data.message || 'Analysis failed', 'error');
            }
        } catch (e) {
            showToast('Network error during analysis', 'error');
        }

        btnAnalyze.disabled = false;
        btnAnalyze.textContent = 'Analyze Rules';
    });

    // --- Render table ---
    function renderTable() {
        if (allServices.length === 0) {
            servicesTable.style.display = 'none';
            emptyState.style.display = 'block';
            emptyState.innerHTML = '<p>No services found. All rules use existing Sophos services.</p>';
            totalCount.textContent = '0';
            visibleCount.textContent = '0';
            return;
        }

        emptyState.style.display = 'none';
        servicesTable.style.display = 'table';
        totalCount.textContent = allServices.length;

        servicesTbody.innerHTML = '';
        for (const svc of allServices) {
            const tr = document.createElement('tr');
            tr.className = 'migrate-row';
            tr.dataset.status = svc.status;
            tr.dataset.name = svc.name;
            tr.dataset.search = `${svc.status} ${svc.name} ${svc.protocol} ${svc.port}`.toLowerCase();

            const usedByStr = (svc.used_by || [])
                .map(u => `${u.type === 'fw' ? 'FW' : 'NAT'}: ${escapeHtml(u.descr)}`)
                .slice(0, 3)
                .join(', ') + (svc.used_by && svc.used_by.length > 3 ? ` +${svc.used_by.length - 3} more` : '');

            const canSelect = svc.status === 'pending' || svc.status === 'migrated';

            tr.innerHTML = `
                <td class="col-checkbox">
                    <input type="checkbox" class="svc-checkbox"
                        data-name="${escapeHtml(svc.name)}"
                        data-status="${svc.status}"
                        data-protocol="${escapeHtml(svc.protocol)}"
                        data-port="${escapeHtml(svc.port)}"
                        data-ports='${svc.ports ? JSON.stringify(svc.ports) : ""}'
                        ${canSelect ? '' : 'disabled'}>
                </td>
                <td><span class="status-badge ${svc.status}">${svc.status}</span></td>
                <td>${escapeHtml(svc.name)}</td>
                <td>${escapeHtml(svc.protocol)}</td>
                <td>${escapeHtml(svc.port)}</td>
                <td class="used-by-cell" title="${escapeHtml(usedByStr)}">${usedByStr}</td>
            `;
            servicesTbody.appendChild(tr);
        }

        selectAll.disabled = false;
        headerSelectAll.disabled = false;
        applyFilters();
        updateButtons();
    }

    // --- Filters ---
    function applyFilters() {
        const search = searchInput.value.toLowerCase();
        const statusVal = statusFilter.value;
        let visible = 0;

        document.querySelectorAll('#services-tbody .migrate-row').forEach(row => {
            const matchSearch = !search || row.dataset.search.includes(search);
            const matchStatus = !statusVal || row.dataset.status === statusVal;
            const show = matchSearch && matchStatus;
            row.style.display = show ? '' : 'none';
            if (show) visible++;
        });

        visibleCount.textContent = visible;
    }

    searchInput.addEventListener('input', applyFilters);
    statusFilter.addEventListener('change', applyFilters);

    // --- Checkboxes ---
    function updateButtons() {
        const checked = document.querySelectorAll('.svc-checkbox:checked');
        let hasPending = false;
        let hasMigrated = false;
        checked.forEach(cb => {
            if (cb.dataset.status === 'pending') hasPending = true;
            if (cb.dataset.status === 'migrated') hasMigrated = true;
        });
        btnCreate.disabled = !hasPending;
        btnRollback.disabled = !hasMigrated;
    }

    document.addEventListener('change', function(e) {
        if (e.target.classList.contains('svc-checkbox')) {
            updateButtons();
        }
    });

    selectAll.addEventListener('change', function() {
        document.querySelectorAll('.svc-checkbox').forEach(cb => {
            const row = cb.closest('.migrate-row');
            if (row && row.style.display !== 'none' && !cb.disabled) {
                cb.checked = selectAll.checked;
            }
        });
        updateButtons();
    });

    headerSelectAll.addEventListener('change', function() {
        selectAll.checked = headerSelectAll.checked;
        selectAll.dispatchEvent(new Event('change'));
    });

    // --- Create services ---
    btnCreate.addEventListener('click', async function() {
        const selected = Array.from(document.querySelectorAll('.svc-checkbox:checked'))
            .filter(cb => cb.dataset.status === 'pending')
            .map(cb => ({
                name: cb.dataset.name,
                protocol: cb.dataset.protocol,
                port: cb.dataset.port,
                ports: cb.dataset.ports ? JSON.parse(cb.dataset.ports) : null,
            }));

        if (selected.length === 0) {
            showToast('Select at least one pending service', 'warning');
            return;
        }

        if (!confirm(`Create ${selected.length} service(s) on Sophos?`)) return;

        btnCreate.disabled = true;
        btnRollback.disabled = true;
        btnAnalyze.disabled = true;
        progressPanel.style.display = 'block';
        progressBar.style.width = '0%';
        progressInfo.textContent = 'Creating services...';

        try {
            const resp = await fetch('/migrate/services/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({services: selected}),
            });
            await processSSE(resp, 'create');
        } catch (e) {
            showToast('Network error', 'error');
            progressInfo.textContent = 'Network error';
        }

        btnAnalyze.disabled = false;
    });

    // --- Rollback services ---
    btnRollback.addEventListener('click', function() {
        const selected = Array.from(document.querySelectorAll('.svc-checkbox:checked'))
            .filter(cb => cb.dataset.status === 'migrated')
            .map(cb => cb.dataset.name);

        if (selected.length === 0) {
            showToast('Select at least one migrated service', 'warning');
            return;
        }

        rollbackPreview.innerHTML = '<ul>' +
            selected.map(n => `<li>${escapeHtml(n)} <span class="rollback-type">(Service)</span></li>`).join('') +
            '</ul>';
        rollbackModal.style.display = 'flex';
    });

    rollbackCancel.addEventListener('click', function() {
        rollbackModal.style.display = 'none';
    });

    rollbackConfirm.addEventListener('click', async function() {
        rollbackModal.style.display = 'none';

        const selected = Array.from(document.querySelectorAll('.svc-checkbox:checked'))
            .filter(cb => cb.dataset.status === 'migrated')
            .map(cb => cb.dataset.name);

        btnCreate.disabled = true;
        btnRollback.disabled = true;
        btnAnalyze.disabled = true;
        progressPanel.style.display = 'block';
        progressBar.style.width = '0%';
        progressInfo.textContent = 'Rolling back services...';

        try {
            const resp = await fetch('/migrate/services/rollback', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({service_names: selected}),
            });
            await processSSE(resp, 'rollback');
        } catch (e) {
            showToast('Network error', 'error');
            progressInfo.textContent = 'Network error';
        }

        btnAnalyze.disabled = false;
    });

    // --- SSE processing ---
    async function processSSE(resp, mode) {
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
                    const verb = mode === 'create' ? 'Creating' : 'Rolling back';
                    progressInfo.textContent = `${verb} ${event.index + 1} of ${event.total}...`;

                    // Update row status
                    if (event.success) {
                        updateServiceStatus(event.item_name, mode === 'create' ? 'migrated' : 'pending');
                    }
                } else if (event.type === 'done') {
                    progressBar.style.width = '100%';
                    const count = mode === 'create' ? event.created : event.deleted;
                    const verb = mode === 'create' ? 'created' : 'rolled back';
                    progressInfo.textContent = `Done: ${count} ${verb}, ${event.failed} failed`;
                    if (event.failed > 0) {
                        showToast(`Completed with ${event.failed} error(s)`, 'warning');
                    } else {
                        showToast(`Successfully ${verb} ${count} service(s)`, 'success');
                    }
                } else if (event.type === 'error') {
                    showToast(event.message || 'Operation failed', 'error');
                    progressInfo.textContent = 'Operation failed';
                }
            }
        }
    }

    function updateServiceStatus(name, newStatus) {
        // Update in allServices array
        const svc = allServices.find(s => s.name === name);
        if (svc) svc.status = newStatus;

        // Update in DOM
        const rows = document.querySelectorAll('#services-tbody .migrate-row');
        for (const row of rows) {
            if (row.dataset.name === name) {
                row.dataset.status = newStatus;
                row.dataset.search = row.dataset.search.replace(/^\S+/, newStatus);
                const badge = row.querySelector('.status-badge');
                if (badge) {
                    badge.className = `status-badge ${newStatus}`;
                    badge.textContent = newStatus;
                }
                const cb = row.querySelector('.svc-checkbox');
                if (cb) {
                    cb.dataset.status = newStatus;
                    cb.checked = false;
                    cb.disabled = newStatus === 'exists';
                }
                break;
            }
        }
        updateButtons();
    }

})();
