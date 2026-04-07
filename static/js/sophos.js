/**
 * Sophos connection page — AJAX handlers for test and fetch.
 */

(function () {
    "use strict";

    // Test Connection
    const testBtn = document.getElementById("test-connection-btn");
    if (testBtn) {
        testBtn.addEventListener("click", async function () {
            const resultDiv = document.getElementById("connection-result");
            testBtn.disabled = true;
            testBtn.textContent = "Testing...";
            resultDiv.style.display = "none";
            resultDiv.innerHTML = "";

            try {
                const resp = await fetch("/sophos/test", { method: "POST" });
                const data = await resp.json();

                resultDiv.style.display = "block";

                if (data.success) {
                    showToast("Connection successful!", "success");
                    let html = '<div class="result-success"><strong>Connected</strong>';
                    if (data.firmware_version) {
                        html += "<br>Firmware: " + escapeHtml(data.firmware_version);
                    }
                    if (data.model) {
                        html += "<br>Model: " + escapeHtml(data.model);
                    }
                    if (data.serial_number) {
                        html += "<br>Serial: " + escapeHtml(data.serial_number);
                    }
                    html += "</div>";
                    resultDiv.innerHTML = html;
                } else {
                    showToast(data.message, "error");
                    resultDiv.innerHTML =
                        '<div class="result-error">' + escapeHtml(data.message) + "</div>";
                }
            } catch (err) {
                showToast("Request failed: " + err.message, "error");
                resultDiv.style.display = "block";
                resultDiv.innerHTML =
                    '<div class="result-error">Request failed: ' +
                    escapeHtml(err.message) +
                    "</div>";
            } finally {
                testBtn.disabled = false;
                testBtn.textContent = "Test Connection";
            }
        });
    }

    // Fetch Objects
    const fetchBtn = document.getElementById("fetch-objects-btn");
    if (fetchBtn) {
        fetchBtn.addEventListener("click", async function () {
            const grid = document.getElementById("objects-grid");
            fetchBtn.disabled = true;
            fetchBtn.textContent = "Fetching...";
            grid.style.display = "none";
            grid.innerHTML = "";

            try {
                const resp = await fetch("/sophos/objects", { method: "POST" });
                const data = await resp.json();

                if (data.success) {
                    showToast("Configuration fetched!", "success");
                    grid.style.display = "grid";
                    const labels = {
                        ip_hosts: "IP Hosts",
                        ip_host_groups: "IP Host Groups",
                        fqdn_hosts: "FQDN Hosts",
                        services: "Services",
                        service_groups: "Service Groups",
                        fw_rules: "Firewall Rules",
                        zones: "Zones",
                        interfaces: "Interfaces",
                        vlans: "VLANs",
                    };
                    for (const [key, label] of Object.entries(labels)) {
                        const count = data.objects[key];
                        const card = document.createElement("div");
                        card.className = "object-card";
                        const countText =
                            count === null
                                ? '<span class="count-error">Error</span>'
                                : '<span class="count-value">' + count + "</span>";
                        card.innerHTML =
                            '<span class="object-label">' +
                            escapeHtml(label) +
                            "</span>" +
                            countText;
                        grid.appendChild(card);
                    }
                } else {
                    showToast(data.message, "error");
                }
            } catch (err) {
                showToast("Request failed: " + err.message, "error");
            } finally {
                fetchBtn.disabled = false;
                fetchBtn.textContent = "Fetch Configuration";
            }
        });
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }
})();
