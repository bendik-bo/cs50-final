document.addEventListener("DOMContentLoaded", function () {
    const savedCategory = sessionStorage.getItem("selectedCategory");
    if (savedCategory) {
        document.getElementById("category").value = savedCategory;
    }
});

function saveSelected() {
    const selected = document.getElementById("category").value;

    sessionStorage.setItem("selectedCategory", selected);
}