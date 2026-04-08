// FMTool - Global JavaScript

/**
 * Show a toast notification.
 * @param {string} message - The message to display
 * @param {string} type - One of: success, error, warning, info
 * @param {number} duration - Auto-dismiss in milliseconds (default 4000)
 */
function showToast(message, type = "info", duration = 4000) {
    let container = document.querySelector(".toast-container");
    if (!container) {
        container = document.createElement("div");
        container.className = "toast-container";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.3s";
        setTimeout(() => toast.remove(), 300);
    }, duration);
}


/**
 * Per-item log modal handler.
 * Listens for clicks on .btn-log buttons, fetches log entries, and shows them in #log-modal.
 */
(function() {
    'use strict';

    document.addEventListener('click', async function(e) {
        const btn = e.target.closest('.btn-log');
        if (!btn) return;

        const id = btn.dataset.id;
        const name = btn.dataset.name;
        const category = btn.dataset.category;

        const modal = document.getElementById('log-modal');
        const modalName = document.getElementById('log-modal-name');
        const modalBody = document.getElementById('log-modal-body');
        const modalClose = document.getElementById('log-modal-close');
        const modalFullLink = document.getElementById('log-modal-fulllink');

        if (!modal) return;

        modalName.textContent = name || 'Item';
        modalBody.innerHTML = '<p class="text-muted">Loading...</p>';
        modal.style.display = 'flex';

        // Set full activity log link with search pre-filled
        if (modalFullLink) {
            modalFullLink.href = '/activity-log';
        }

        try {
            const resp = await fetch(`/activity-log/item/${encodeURIComponent(category)}/${id}?name=${encodeURIComponent(name || '')}`);
            const data = await resp.json();

            if (!data.entries || data.entries.length === 0) {
                modalBody.innerHTML = '<p class="text-muted">No log entries found for this item.</p>';
                return;
            }

            let html = '<table class="data-table"><thead><tr><th>Time</th><th>Action</th><th>Category</th><th>Result</th><th>Error</th></tr></thead><tbody>';
            for (const entry of data.entries) {
                const ts = new Date(entry.timestamp).toLocaleString();
                const resultClass = entry.result === 'success' ? 'status-migrated' :
                                    entry.result === 'fail' ? 'status-failed' : 'status-pending';
                html += `<tr>
                    <td class="text-muted">${escapeHtml(ts)}</td>
                    <td>${escapeHtml(entry.action_type)}</td>
                    <td>${escapeHtml(entry.category)}</td>
                    <td><span class="status-badge ${resultClass}">${entry.result}</span></td>
                    <td class="text-muted">${escapeHtml(entry.error_message || '')}</td>
                </tr>`;
            }
            html += '</tbody></table>';
            modalBody.innerHTML = html;
        } catch (err) {
            modalBody.innerHTML = '<p class="text-muted">Failed to load log entries.</p>';
        }

        if (modalClose) {
            modalClose.onclick = function() { modal.style.display = 'none'; };
        }
    });

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
})();
