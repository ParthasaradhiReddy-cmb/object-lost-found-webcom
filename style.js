document.addEventListener("DOMContentLoaded", function () {

    const form = document.querySelector("form");

    form.addEventListener("submit", function (event) {

        const itemName = document
            .getElementById("item_name").value.trim();

        const description = document
            .getElementById("description").value.trim();

        const location = document
            .getElementById("location").value.trim();

        const status = document
            .getElementById("status").value;

        if (!itemName || !description || !location || !status) {
            event.preventDefault();
            alert("Please fill in all the fields!");
            return;
        }

        const confirmed = confirm(
            "Are you sure you want to submit this report?"
        );

        if (!confirmed) {
            event.preventDefault();
        }
    });

});