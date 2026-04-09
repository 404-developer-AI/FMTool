/**
 * Activity Log page JavaScript — filtering, sorting, pagination, expandable rows.
 */
(function() {
    'use strict';

    const body = document.getElementById('activity-body');
    const filterCategory = document.getElementById('filter-category');
    const filterAction = document.getElementById('filter-action');
    const filterResult = document.getElementById('filter-result');
    const filterSearch = document.getElementById('filter-search');
    const filterDateFrom = document.getElementById('filter-date-from');
    const filterDateTo = document.getElementById('filter-date-to');
    const btnRefresh = document.getElementById('btn-refresh');
    const btnPrev = document.getElementById('btn-prev');
    const btnNext = document.getElementById('btn-next');
    const pageInfo = document.getElementById('page-info');

    let currentPage = 1;
    let currentSort = 'timestamp';
    let currentDir = 'desc';
    let totalPages = 1;
    let searchTimeout = null;

    const ACTION_LABELS = {
        migrate: 'Migrate',
        dry_run: 'Dry Run',
        skip: 'Skip',
        reset: 'Reset',
        create_service: 'Create Service',
        create_host: 'Create Host',
        check_duplicates: 'Check Duplicates',
        import: 'Import',
        cleanup: 'Cleanup',
        rollback: 'Rollback',
    };

    const CATEGORY_LABELS = {
        aliases: 'Aliases',
        firewall_rules: 'Firewall Rules',
        nat_rules: 'NAT Rules',
        services: 'Services',
        hosts: 'Hosts',
        system: 'System',
    };

    function buildParams() {
        const params = new URLSearchParams();
        if (filterCategory.value) params.set('category', filterCategory.value);
        if (filterAction.value) params.set('action_type', filterAction.value);
        if (filterResult.value) params.set('result', filterResult.value);
        if (filterSearch.value.trim()) params.set('search', filterSearch.value.trim());
        if (filterDateFrom.value) params.set('date_from', filterDateFrom.value + 'T00:00:00');
        if (filterDateTo.value) params.set('date_to', filterDateTo.value + 'T23:59:59');
        params.set('page', currentPage);
        params.set('per_page', 50);
        params.set('sort', currentSort);
        params.set('dir', currentDir);
        return params;
    }

    async function loadData() {
        body.innerHTML = '<tr><td colspan="6" class="text-muted">Loading...</td></tr>';
        try {
            const resp = await fetch('/activity-log/data?' + buildParams());
            const data = await resp.json();
            renderTable(data.entries);
            const total = data.total;
            totalPages = Math.max(1, Math.ceil(total / data.per_page));
            pageInfo.textContent = `Page ${data.page} of ${totalPages} (${total} entries)`;
            btnPrev.disabled = data.page <= 1;
            btnNext.disabled = data.page >= totalPages;
        } catch (e) {
            body.innerHTML = '<tr><td colspan="6" class="text-muted">Failed to load activity log.</td></tr>';
        }
    }

    function renderTable(entries) {
        if (!entries || entries.length === 0) {
            body.innerHTML = '<tr><td colspan="6" class="text-muted">No log entries found.</td></tr>';
            return;
        }
        let html = '';
        for (const e of entries) {
            const ts = formatTimestamp(e.timestamp);
            const actionLabel = ACTION_LABELS[e.action_type] || e.action_type;
            const categoryLabel = CATEGORY_LABELS[e.category] || e.category;
            const resultClass = e.result === 'success' ? 'result-success' :
                                e.result === 'fail' ? 'result-fail' : 'result-error';
            const summary = buildSummary(e);
            const hasDetails = e.details || e.error_message;

            html += `<tr class="log-row${hasDetails ? ' log-expandable' : ''}" data-id="${e.id}">`;
            html += `<td class="log-ts">${escapeHtml(ts)}</td>`;
            html += `<td><span class="log-action log-action-${e.action_type}">${escapeHtml(actionLabel)}</span></td>`;
            html += `<td><span class="log-category">${escapeHtml(categoryLabel)}</span></td>`;
            html += `<td class="log-item">${escapeHtml(e.item_name || '-')}</td>`;
            html += `<td><span class="log-result ${resultClass}">${escapeHtml(e.result)}</span></td>`;
            html += `<td class="log-summary">${escapeHtml(summary)}${hasDetails ? ' <span class="log-expand-hint">&#9654;</span>' : ''}</td>`;
            html += `</tr>`;

            if (hasDetails) {
                html += `<tr class="log-detail-row" data-parent="${e.id}" style="display:none">`;
                html += `<td colspan="6"><div class="log-detail-content">`;
                if (e.error_message) {
                    html += `<div class="log-detail-error"><strong>Error:</strong> ${escapeHtml(e.error_message)}</div>`;
                }
                if (e.details) {
                    html += formatDetails(e.details);
                }
                html += `</div></td></tr>`;
            }
        }
        body.innerHTML = html;
    }

    function buildSummary(entry) {
        if (entry.error_message && entry.result !== 'success') {
            return truncate(entry.error_message, 80);
        }
        if (!entry.details) return '';
        try {
            const d = JSON.parse(entry.details);
            // Migration: show object count
            if (d.objects_created && Array.isArray(d.objects_created)) {
                return `${d.objects_created.length} object(s) created`;
            }
            if (d.rule_name) return `Rule: ${d.rule_name}`;
            if (d.sophos_name) return d.sophos_name;
            if (d.matched) return `${d.matched} duplicate(s) found`;
            if (d.duplicates_found !== undefined) return `${d.duplicates_found} duplicate(s) found`;
            if (d.objects_deleted !== undefined) return `${d.objects_deleted} object(s) deleted`;
            if (d.tables_count !== undefined) return `${d.tables_count} tables, ${d.total_items || 0} items`;
            // Fallback: first meaningful key
            const keys = Object.keys(d);
            if (keys.length <= 3) {
                return keys.map(k => `${k}: ${truncate(String(d[k]), 30)}`).join(', ');
            }
            return `${keys.length} fields`;
        } catch {
            return truncate(entry.details, 80);
        }
    }

    function formatDetails(detailsStr) {
        try {
            const d = JSON.parse(detailsStr);
            return formatObject(d);
        } catch {
            return `<div class="log-detail-text">${escapeHtml(detailsStr)}</div>`;
        }
    }

    function formatObject(obj) {
        if (Array.isArray(obj)) {
            if (obj.length === 0) return '<span class="text-muted">(empty)</span>';
            // Array of simple values
            if (typeof obj[0] !== 'object') {
                return `<div class="log-detail-list">${obj.map(v => `<span class="log-detail-tag">${escapeHtml(String(v))}</span>`).join(' ')}</div>`;
            }
            // Array of objects — render as mini-cards
            let html = '<div class="log-detail-array">';
            for (const item of obj) {
                html += '<div class="log-detail-card">';
                if (typeof item === 'object' && item !== null) {
                    for (const [k, v] of Object.entries(item)) {
                        html += `<div class="log-detail-field"><span class="log-detail-key">${escapeHtml(k)}:</span> <span class="log-detail-value">${escapeHtml(String(v))}</span></div>`;
                    }
                } else {
                    html += escapeHtml(String(item));
                }
                html += '</div>';
            }
            html += '</div>';
            return html;
        }

        if (typeof obj === 'object' && obj !== null) {
            let html = '<div class="log-detail-fields">';
            for (const [k, v] of Object.entries(obj)) {
                html += `<div class="log-detail-field">`;
                html += `<span class="log-detail-key">${escapeHtml(k)}:</span> `;
                if (Array.isArray(v)) {
                    html += formatObject(v);
                } else if (typeof v === 'object' && v !== null) {
                    html += formatObject(v);
                } else {
                    html += `<span class="log-detail-value">${escapeHtml(String(v))}</span>`;
                }
                html += `</div>`;
            }
            html += '</div>';
            return html;
        }

        return `<span class="log-detail-value">${escapeHtml(String(obj))}</span>`;
    }

    function formatTimestamp(ts) {
        if (!ts) return '';
        try {
            const d = new Date(ts);
            const date = d.toLocaleDateString('nl-NL', { day: '2-digit', month: '2-digit', year: 'numeric' });
            const time = d.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            return `${date} ${time}`;
        } catch {
            return ts;
        }
    }

    function truncate(str, max) {
        if (!str) return '';
        return str.length > max ? str.substring(0, max) + '...' : str;
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Expand/collapse rows
    body.addEventListener('click', function(e) {
        const row = e.target.closest('.log-expandable');
        if (!row) return;
        const id = row.dataset.id;
        const detailRow = body.querySelector(`.log-detail-row[data-parent="${id}"]`);
        if (!detailRow) return;
        const isOpen = detailRow.style.display !== 'none';
        detailRow.style.display = isOpen ? 'none' : '';
        row.classList.toggle('log-expanded', !isOpen);
    });

    // Sort headers
    document.querySelectorAll('.sortable').forEach(th => {
        th.addEventListener('click', function() {
            const col = this.dataset.col;
            if (currentSort === col) {
                currentDir = currentDir === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort = col;
                currentDir = 'desc';
            }
            document.querySelectorAll('.sortable').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
            this.classList.add(currentDir === 'asc' ? 'sort-asc' : 'sort-desc');
            currentPage = 1;
            loadData();
        });
    });

    // Filters
    [filterCategory, filterAction, filterResult].forEach(el => {
        el.addEventListener('change', function() {
            currentPage = 1;
            loadData();
        });
    });

    [filterDateFrom, filterDateTo].forEach(el => {
        el.addEventListener('change', function() {
            currentPage = 1;
            loadData();
        });
    });

    filterSearch.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            currentPage = 1;
            loadData();
        }, 300);
    });

    btnRefresh.addEventListener('click', loadData);

    btnPrev.addEventListener('click', function() {
        if (currentPage > 1) {
            currentPage--;
            loadData();
        }
    });

    btnNext.addEventListener('click', function() {
        if (currentPage < totalPages) {
            currentPage++;
            loadData();
        }
    });

    // Initial load
    loadData();
})();
