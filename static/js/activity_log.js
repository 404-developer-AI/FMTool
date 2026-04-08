/**
 * Activity Log page JavaScript — filtering, sorting, pagination.
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
        body.innerHTML = '<tr><td colspan="7" class="text-muted">Loading...</td></tr>';
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
            body.innerHTML = '<tr><td colspan="7" class="text-muted">Failed to load activity log.</td></tr>';
        }
    }

    function renderTable(entries) {
        if (!entries || entries.length === 0) {
            body.innerHTML = '<tr><td colspan="7" class="text-muted">No log entries found.</td></tr>';
            return;
        }
        body.innerHTML = entries.map(e => {
            const ts = formatTimestamp(e.timestamp);
            const resultClass = e.result === 'success' ? 'status-migrated' :
                                e.result === 'fail' ? 'status-failed' : 'status-pending';
            const details = e.details ? truncate(e.details, 80) : '';
            const error = e.error_message ? truncate(e.error_message, 60) : '';
            return `<tr>
                <td class="text-muted">${ts}</td>
                <td>${escapeHtml(e.action_type)}</td>
                <td>${escapeHtml(e.category)}</td>
                <td>${escapeHtml(e.item_name || '-')}</td>
                <td class="text-muted" title="${escapeHtml(e.details || '')}">${escapeHtml(details)}</td>
                <td><span class="status-badge ${resultClass}">${e.result}</span></td>
                <td class="text-muted" title="${escapeHtml(e.error_message || '')}">${escapeHtml(error)}</td>
            </tr>`;
        }).join('');
    }

    function formatTimestamp(ts) {
        if (!ts) return '';
        try {
            const d = new Date(ts);
            return d.toLocaleString();
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
