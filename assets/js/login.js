function galleryLogin() {
    sessionStorage.setItem("galleryAuthenticator", document.getElementById("defaultForm-pass").value);
    window.location.replace("/gallery");
}