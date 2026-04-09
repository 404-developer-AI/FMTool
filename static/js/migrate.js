/**
 * Migration page JavaScript — checkboxes, dry-run, execute, progress.
 */
(function() {
    'use strict';

    const selectAll = document.getElementById('select-all');
    const searchInput = document.getElementById('search-input');
    const typeFilter = document.getElementById('type-filter');
    const statusFilter = document.getElementById('status-filter');
    const visibleCount = document.getElementById('visible-count');
    const btnDryrun = document.getElementById('btn-dryrun');
    const btnMigrate = document.getElementById('btn-migrate');
    const btnSkip = document.getElementById('btn-skip');
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

    if (!selectAll) return;

    const rows = document.querySelectorAll('.migrate-row');
    let lastDryrunIds = [];

    // --- Populate filter dropdowns ---
    function populateFilters() {
        const types = new Set();
        const statuses = new Set();
        rows.forEach(row => {
            const t = row.dataset.type;
            const s = row.dataset.status;
            if (t) types.add(t);
            if (s) statuses.add(s);
        });
        types.forEach(t => {
            const opt = document.createElement('option');
            opt.value = t;
            opt.textContent = t;
            typeFilter.appendChild(opt);
        });
        statuses.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s;
            opt.textContent = s;
            statusFilter.appendChild(opt);
        });
    }
    populateFilters();

    // --- Filter & search ---
    function applyFilters() {
        const search = searchInput.value.toLowerCase();
        const typeVal = typeFilter.value;
        const statusVal = statusFilter.value;
        let count = 0;

        rows.forEach(row => {
            const matchSearch = !search || row.dataset.search.toLowerCase().includes(search);
            const matchType = !typeVal || row.dataset.type === typeVal;
            const matchStatus = !statusVal || row.dataset.status === statusVal;
            const visible = matchSearch && matchType && matchStatus;
            row.style.display = visible ? '' : 'none';
            if (visible) count++;
        });
        visibleCount.textContent = count;
        updateSelectAllState();
    }

    searchInput.addEventListener('input', applyFilters);
    typeFilter.addEventListener('change', applyFilters);
    statusFilter.addEventListener('change', applyFilters);

    // --- Checkbox management ---
    selectAll.addEventListener('change', function() {
        const checked = this.checked;
        rows.forEach(row => {
            if (row.style.display !== 'none') {
                row.querySelector('.alias-checkbox').checked = checked;
            }
        });
    });

    document.querySelector('.migrate-table tbody').addEventListener('change', function(e) {
        if (e.target.classList.contains('alias-checkbox')) {
            updateSelectAllState();
        }
    });

    function updateSelectAllState() {
        const visible = getVisibleCheckboxes();
        const checked = visible.filter(cb => cb.checked);
        selectAll.checked = visible.length > 0 && checked.length === visible.length;
        selectAll.indeterminate = checked.length > 0 && checked.length < visible.length;
    }

    function getVisibleCheckboxes() {
        return Array.from(rows)
            .filter(r => r.style.display !== 'none')
            .map(r => r.querySelector('.alias-checkbox'));
    }

    function getSelectedIds() {
        return Array.from(document.querySelectorAll('.alias-checkbox:checked'))
            .map(cb => parseInt(cb.value));
    }

    function getFqdnOverrides() {
        const overrides = {};
        document.querySelectorAll('.fqdn-input').forEach(input => {
            const val = input.value.trim();
            if (val) {
                overrides[input.dataset.alias] = val;
            }
        });
        return overrides;
    }

    // --- Sorting ---
    document.querySelectorAll('.sortable').forEach(th => {
        th.addEventListener('click', function() {
            const col = this.dataset.col;
            const tbody = document.querySelector('.migrate-table tbody');
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
        const headers = document.querySelectorAll('.migrate-table thead th');
        for (let i = 0; i < headers.length; i++) {
            if (headers[i].dataset.col === col) return i;
        }
        return 1;
    }

    // --- Dry Run ---
    btnDryrun.addEventListener('click', async function() {
        const ids = getSelectedIds();
        if (ids.length === 0) {
            showToast('Select at least one alias', 'warning');
            return;
        }
        btnDryrun.disabled = true;
        btnDryrun.textContent = 'Planning...';
        dryrunPanel.style.display = 'none';

        try {
            const resp = await fetch('/migrate/aliases/plan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({alias_ids: ids, fqdn_overrides: getFqdnOverrides()}),
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

    function renderDryrunResults(plans) {
        let html = '';
        for (const plan of plans) {
            const actionClass = plan.action === 'create' ? 'dryrun-create' :
                                plan.action === 'exists' ? 'dryrun-exists' :
                                plan.action === 'skip' ? 'dryrun-skip' : 'dryrun-manual';

            html += `<div class="dryrun-item ${actionClass}">`;
            html += `<div class="dryrun-item-header">`;
            html += `<strong>${escapeHtml(plan.alias_name)}</strong>`;
            html += `<span class="dryrun-type">${escapeHtml(plan.alias_type)}</span>`;
            html += `<span class="dryrun-action">${escapeHtml(plan.action)}</span>`;
            html += `</div>`;
            html += `<div class="dryrun-reason">${escapeHtml(plan.reason)}</div>`;

            if (plan.objects.length > 0) {
                html += '<div class="planned-objects">';
                for (const obj of plan.objects) {
                    const memberTag = obj.is_member ? ' <span class="member-tag">member</span>' : '';
                    html += `<div class="planned-object">`;
                    html += `<span class="object-type">${escapeHtml(obj.sophos_type)}</span>`;
                    html += `<span class="object-name">${escapeHtml(obj.sophos_name)}</span>`;
                    html += memberTag;
                    html += `</div>`;
                }
                html += '</div>';
            }

            if (plan.warnings.length > 0) {
                html += '<div class="dryrun-warnings">';
                for (const w of plan.warnings) {
                    html += `<div class="dryrun-warning">${escapeHtml(w)}</div>`;
                }
                html += '</div>';
            }

            html += '</div>';
        }
        dryrunResults.innerHTML = html;
    }

    btnDryrunClose.addEventListener('click', function() {
        dryrunPanel.style.display = 'none';
        lastDryrunIds = [];
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
            showToast('Select at least one alias', 'warning');
            return;
        }
        modalCount.textContent = `${ids.length} alias(es) will be migrated to Sophos.`;
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
            const resp = await fetch('/migrate/aliases/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({alias_ids: ids, fqdn_overrides: getFqdnOverrides()}),
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
                            showToast(`Successfully migrated ${event.migrated} alias(es)`, 'success');
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
            showToast('Select at least one alias', 'warning');
            return;
        }
        if (!confirm(`Mark ${ids.length} alias(es) as skipped?`)) return;

        btnSkip.disabled = true;
        btnSkip.textContent = 'Updating...';

        try {
            const resp = await fetch('/migrate/aliases/skip', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({alias_ids: ids}),
            });
            const data = await resp.json();
            if (data.success) {
                ids.forEach(id => updateRowStatus(id, 'skipped'));
                showToast(`${data.updated} alias(es) marked as skipped`, 'success');
            } else {
                showToast(data.message || 'Failed to skip', 'error');
            }
        } catch (e) {
            showToast('Network error', 'error');
        }

        btnSkip.disabled = false;
        btnSkip.textContent = 'Skip Selected';
    });

    // --- Helpers ---
    function updateRowStatus(aliasId, status) {
        const row = document.querySelector(`.migrate-row[data-id="${aliasId}"]`);
        if (!row) return;
        row.dataset.status = status;
        const badge = row.querySelector('.status-badge');
        if (badge) {
            badge.className = `status-badge ${status}`;
            badge.textContent = status;
        }
        // Update search data
        const searchParts = row.dataset.search.split(' ');
        searchParts[0] = status;
        row.dataset.search = searchParts.join(' ');
        // Uncheck after migration
        const cb = row.querySelector('.alias-checkbox');
        if (cb) cb.checked = false;
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Rollback ---
    const btnRollback = document.getElementById('btn-rollback');
    const rollbackModal = document.getElementById('rollback-modal');
    const rollbackPreview = document.getElementById('rollback-preview');
    const rollbackCascade = document.getElementById('rollback-cascade');
    const rollbackCancel = document.getElementById('rollback-cancel');
    const rollbackConfirm = document.getElementById('rollback-confirm');
    let rollbackItemIds = [];

    function getSelectedMigratedIds() {
        return Array.from(document.querySelectorAll('.alias-checkbox:checked'))
            .filter(cb => {
                const row = cb.closest('.migrate-row');
                return row && row.dataset.status === 'migrated';
            })
            .map(cb => parseInt(cb.value));
    }

    async function fetchRollbackPlan(ids, cascade) {
        const resp = await fetch('/migrate/aliases/rollback/plan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({item_ids: ids, cascade: cascade}),
        });
        return await resp.json();
    }

    function renderRollbackPreview(plans) {
        let html = '';
        for (const plan of plans) {
            html += `<div class="rollback-item">`;
            html += `<strong>${escapeHtml(plan.item_name)}</strong>`;
            if (plan.primary_objects.length === 0 && plan.member_objects.length === 0) {
                html += `<div class="rollback-warning">No tracked objects</div>`;
            } else {
                html += '<ul>';
                for (const obj of plan.primary_objects) {
                    html += `<li>${escapeHtml(obj.sophos_name)} <span class="rollback-type">(${obj.sophos_type})</span></li>`;
                }
                for (const obj of plan.member_objects) {
                    html += `<li class="rollback-member">${escapeHtml(obj.sophos_name)} <span class="rollback-type">(${obj.sophos_type})</span></li>`;
                }
                html += '</ul>';
            }
            for (const w of plan.warnings) {
                html += `<div class="rollback-warning">${escapeHtml(w)}</div>`;
            }
            html += '</div>';
        }
        rollbackPreview.innerHTML = html;
    }

    if (btnRollback) {
        btnRollback.addEventListener('click', async function() {
            rollbackItemIds = getSelectedMigratedIds();
            if (rollbackItemIds.length === 0) {
                showToast('Select at least one migrated alias', 'warning');
                return;
            }
            rollbackCascade.checked = false;
            rollbackPreview.innerHTML = '<p>Loading preview...</p>';
            rollbackModal.style.display = 'flex';

            try {
                const data = await fetchRollbackPlan(rollbackItemIds, false);
                if (data.success) {
                    renderRollbackPreview(data.plans);
                } else {
                    rollbackPreview.innerHTML = `<p class="error">${escapeHtml(data.message)}</p>`;
                }
            } catch (e) {
                rollbackPreview.innerHTML = '<p class="error">Failed to load preview</p>';
            }
        });

        rollbackCascade.addEventListener('change', async function() {
            rollbackPreview.innerHTML = '<p>Loading preview...</p>';
            try {
                const data = await fetchRollbackPlan(rollbackItemIds, rollbackCascade.checked);
                if (data.success) renderRollbackPreview(data.plans);
            } catch (e) {
                rollbackPreview.innerHTML = '<p class="error">Failed to load preview</p>';
            }
        });

        rollbackCancel.addEventListener('click', function() {
            rollbackModal.style.display = 'none';
        });

        rollbackConfirm.addEventListener('click', async function() {
            rollbackModal.style.display = 'none';
            await executeRollback(rollbackItemIds, rollbackCascade.checked);
        });
    }

    async function executeRollback(ids, cascade) {
        btnRollback.disabled = true;
        btnMigrate.disabled = true;
        btnDryrun.disabled = true;
        progressPanel.style.display = 'block';
        dryrunPanel.style.display = 'none';
        progressBar.style.width = '0%';
        progressInfo.textContent = 'Preparing rollback...';

        try {
            const resp = await fetch('/migrate/aliases/rollback/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({item_ids: ids, cascade: cascade}),
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
                        progressInfo.textContent = `Rolling back ${event.index + 1} of ${event.total}...`;
                        if (event.success) {
                            updateRowStatus(event.item_id, 'pending');
                        }
                    } else if (event.type === 'done') {
                        progressBar.style.width = '100%';
                        progressInfo.textContent = `Done: ${event.deleted} rolled back, ${event.failed} failed`;
                        if (event.failed > 0) {
                            showToast(`Rollback completed with ${event.failed} error(s)`, 'warning');
                        } else {
                            showToast(`Successfully rolled back ${event.deleted} item(s)`, 'success');
                        }
                    } else if (event.type === 'error') {
                        showToast(event.message || 'Rollback failed', 'error');
                        progressInfo.textContent = 'Rollback failed';
                    }
                }
            }
        } catch (e) {
            showToast('Network error during rollback', 'error');
            progressInfo.textContent = 'Network error';
        }

        btnRollback.disabled = false;
        btnMigrate.disabled = false;
        btnDryrun.disabled = false;
    }

    // --- NAT Host rollback ---
    const btnRollbackNatHosts = document.getElementById('btn-rollback-nat-hosts');
    const natHostSelectAll = document.getElementById('nat-host-select-all');

    if (natHostSelectAll) {
        natHostSelectAll.addEventListener('change', function() {
            document.querySelectorAll('.nat-host-checkbox').forEach(cb => {
                cb.checked = natHostSelectAll.checked;
            });
        });
    }

    if (btnRollbackNatHosts) {
        btnRollbackNatHosts.addEventListener('click', async function() {
            const selected = Array.from(document.querySelectorAll('.nat-host-checkbox:checked'))
                .map(cb => cb.value);

            if (selected.length === 0) {
                showToast('Select at least one host', 'warning');
                return;
            }

            if (!confirm(`Delete ${selected.length} host(s) from Sophos?`)) return;

            btnRollbackNatHosts.disabled = true;
            progressPanel.style.display = 'block';
            progressBar.style.width = '0%';
            progressInfo.textContent = 'Rolling back NAT hosts...';

            try {
                const resp = await fetch('/migrate/hosts/rollback', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({host_names: selected}),
                });

                const reader = resp.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';
                let deletedCount = 0;

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
                            const pct = ((event.index + 1) / event.total) * 100;
                            progressBar.style.width = pct + '%';
                            progressInfo.textContent = `Rolling back ${event.index + 1} of ${event.total}...`;
                            if (event.success) {
                                deletedCount++;
                                // Remove row from DOM
                                const row = document.querySelector(`.nat-host-row[data-name="${event.item_name}"]`);
                                if (row) row.remove();
                            }
                        } else if (event.type === 'done') {
                            progressBar.style.width = '100%';
                            progressInfo.textContent = `Done: ${event.deleted} rolled back, ${event.failed} failed`;
                            if (event.failed > 0) {
                                showToast(`Rollback completed with ${event.failed} error(s)`, 'warning');
                            } else {
                                showToast(`Successfully rolled back ${event.deleted} host(s)`, 'success');
                            }
                        } else if (event.type === 'error') {
                            showToast(event.message || 'Rollback failed', 'error');
                        }
                    }
                }
            } catch (e) {
                showToast('Network error', 'error');
            }

            btnRollbackNatHosts.disabled = false;
        });
    }

    // --- Sophos sync: duplicate check with caching ---
    const SYNC_CACHE_KEY = 'fmtool_sophos_sync';
    const SYNC_MAX_AGE_MS = 60 * 60 * 1000; // 1 hour

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
            updateRowStatus(dup.alias_id, 'migrated');
        });
    }

    async function runSync(force) {
        if (!window.SOPHOS_CONFIGURED) return;

        // Check cache unless forced
        if (!force) {
            const cached = getCachedSync();
            if (cached && (Date.now() - cached.timestamp) < SYNC_MAX_AGE_MS) {
                applyCachedDuplicates(cached.duplicates);
                const count = cached.duplicates.length;
                setSyncState('done',
                    count > 0 ? `Synced — ${count} alias(es) already on Sophos` : 'Synced — no duplicates found',
                    cached.timestamp);
                return;
            }
        }

        setSyncState('checking', 'Checking Sophos for existing objects...', null);
        if (btnSyncRefresh) btnSyncRefresh.disabled = true;

        try {
            const resp = await fetch('/migrate/aliases/check-duplicates', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
            });
            const data = await resp.json();

            if (data.success) {
                const cache = saveSyncCache(data.duplicates);
                applyCachedDuplicates(data.duplicates);
                const count = data.duplicates.length;
                setSyncState('done',
                    count > 0 ? `Synced — ${count} alias(es) already on Sophos` : 'Synced — no duplicates found',
                    cache.timestamp);
                if (count > 0) {
                    showToast(`${count} alias(es) already exist on Sophos`, 'info');
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
