function validateForm() {
    var newPassword = document.getElementById("new_password").value;
    var confirmPassword = document.getElementById("confirm_password").value;

    if (newPassword !== confirmPassword) {
        alert("Passwords do not match");
        return false;
    }
    return true;
}
