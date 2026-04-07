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
