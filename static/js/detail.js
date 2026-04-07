document.addEventListener("DOMContentLoaded", function () {
    const table = document.querySelector(".detail-table");
    if (!table) return;

    const tbody = table.querySelector("tbody");
    const searchInput = document.querySelector(".search-input");
    const statusFilter = document.querySelector('.filter-select[data-filter="status"]');
    const visibleCount = document.getElementById("visible-count");

    // --- Expand / Collapse XML ---

    tbody.addEventListener("click", function (e) {
        const row = e.target.closest(".expandable-row");
        if (!row) return;

        const xmlRow = row.nextElementSibling;
        if (!xmlRow || !xmlRow.classList.contains("xml-row")) return;

        const isExpanded = row.classList.toggle("expanded");
        xmlRow.style.display = isExpanded ? "table-row" : "none";
    });

    // --- Populate status filter dynamically ---

    if (statusFilter) {
        const statuses = new Set();
        tbody.querySelectorAll(".expandable-row").forEach(function (row) {
            const s = row.dataset.status;
            if (s) statuses.add(s);
        });
        Array.from(statuses).sort().forEach(function (s) {
            const opt = document.createElement("option");
            opt.value = s;
            opt.textContent = s.charAt(0).toUpperCase() + s.slice(1);
            statusFilter.appendChild(opt);
        });
    }

    // --- Filter logic ---

    function applyFilters() {
        const searchTerm = (searchInput.value || "").toLowerCase();
        const statusValue = statusFilter ? statusFilter.value : "";
        let shown = 0;

        const rows = tbody.querySelectorAll(".expandable-row");
        rows.forEach(function (row) {
            const xmlRow = row.nextElementSibling;
            const searchData = (row.dataset.search || "").toLowerCase();
            const rowStatus = row.dataset.status || "";

            const matchesSearch = !searchTerm || searchData.indexOf(searchTerm) !== -1;
            const matchesStatus = !statusValue || rowStatus === statusValue;
            const visible = matchesSearch && matchesStatus;

            row.style.display = visible ? "" : "none";
            if (xmlRow && xmlRow.classList.contains("xml-row")) {
                if (!visible) {
                    xmlRow.style.display = "none";
                    row.classList.remove("expanded");
                }
            }
            if (visible) shown++;
        });

        if (visibleCount) visibleCount.textContent = shown;
    }

    if (searchInput) searchInput.addEventListener("input", applyFilters);
    if (statusFilter) statusFilter.addEventListener("change", applyFilters);

    // --- Sort logic ---

    let currentSortCol = null;
    let sortAsc = true;

    table.querySelectorAll("th.sortable").forEach(function (th) {
        th.addEventListener("click", function () {
            const col = th.dataset.col;
            if (currentSortCol === col) {
                sortAsc = !sortAsc;
            } else {
                currentSortCol = col;
                sortAsc = true;
            }

            // Update sort indicators
            table.querySelectorAll("th.sortable").forEach(function (h) {
                h.classList.remove("sort-asc", "sort-desc");
            });
            th.classList.add(sortAsc ? "sort-asc" : "sort-desc");

            // Get column index
            const headers = Array.from(th.parentElement.children);
            const colIndex = headers.indexOf(th);

            // Collect row pairs (data row + xml row)
            var pairs = [];
            var dataRows = tbody.querySelectorAll(".expandable-row");
            dataRows.forEach(function (row) {
                var xmlRow = row.nextElementSibling;
                var sortVal = "";
                if (col === "status") {
                    sortVal = row.dataset.status || "";
                } else {
                    var cell = row.children[colIndex];
                    sortVal = cell ? cell.textContent.trim() : "";
                }
                pairs.push({ dataRow: row, xmlRow: xmlRow, sortVal: sortVal });
            });

            // Sort pairs
            pairs.sort(function (a, b) {
                var va = a.sortVal;
                var vb = b.sortVal;

                // Try numeric comparison
                var na = parseFloat(va);
                var nb = parseFloat(vb);
                if (!isNaN(na) && !isNaN(nb)) {
                    return sortAsc ? na - nb : nb - na;
                }

                // String comparison
                va = va.toLowerCase();
                vb = vb.toLowerCase();
                if (va < vb) return sortAsc ? -1 : 1;
                if (va > vb) return sortAsc ? 1 : -1;
                return 0;
            });

            // Reorder DOM
            pairs.forEach(function (pair) {
                tbody.appendChild(pair.dataRow);
                if (pair.xmlRow && pair.xmlRow.classList.contains("xml-row")) {
                    tbody.appendChild(pair.xmlRow);
                }
            });
        });
    });
});
