// Example: JavaScript-based login validation using Ajax
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', function (event) {
        event.preventDefault();
        const formData = new FormData(this);
        fetch('/login', {
            method: 'POST',
            body: formData
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = data.redirectUrl;
                } else {
                    displayErrorMessage(data.errorMessage);
                }
            })
            .catch(error => console.error('Error:', error));
    });
}


