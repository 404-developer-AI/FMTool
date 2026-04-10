(function () {
    const deleteBtn = document.getElementById("delete-logo-btn");
    const deleteForm = document.getElementById("delete-logo-form");
    if (deleteBtn && deleteForm) {
        deleteBtn.addEventListener("click", function () {
            if (confirm("Remove the current logo?")) {
                deleteForm.submit();
            }
        });
    }
})();
