document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const loginView = document.getElementById('login-view');
    const signupView = document.getElementById('signup-view');
    const showSignup = document.getElementById('show-signup');
    const showLogin = document.getElementById('show-login');
    const notification = document.getElementById('notification');

    // Switch to Signup
    showSignup.addEventListener('click', (e) => {
        e.preventDefault();
        loginView.classList.add('hidden');
        signupView.classList.remove('hidden');
    });

    // Switch to Login
    showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        signupView.classList.add('hidden');
        loginView.classList.remove('hidden');
    });

    // Simple notification helper
    function showNotification(message) {
        notification.textContent = message;
        notification.classList.add('show');
        setTimeout(() => {
            notification.classList.remove('show');
        }, 3000);
    }

    // Signup Logic
    signupForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const username = signupForm.username.value;
        const password = signupForm.password.value;
        const confirm = signupForm.confirm_password.value;

        if (password !== confirm) {
            alert('Passwords do not match!');
            return;
        }

        const users = JSON.parse(localStorage.getItem('soc_analysts') || '[]');
        if (users.find(u => u.username === username)) {
            alert('Username already exists!');
            return;
        }

        // Add user
        users.push({ username, password }); // In a real app, hash password!
        localStorage.setItem('soc_analysts', JSON.stringify(users));

        showNotification('Your sign up is successful');
        
        // Redirect to login after a small delay
        setTimeout(() => {
            signupView.classList.add('hidden');
            loginView.classList.remove('hidden');
            signupForm.reset();
        }, 1500);
    });

    // Login Logic
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const username = loginForm.username.value;
        const password = loginForm.password.value;

        const users = JSON.parse(localStorage.getItem('soc_analysts') || '[]');
        const user = users.find(u => u.username === username && u.password === password);

        if (user) {
            localStorage.setItem('soc_session', JSON.stringify({
                username,
                expire: Date.now() + (1000 * 60 * 60 * 24) // 24 hour session
            }));
            window.location.href = '/';
        } else {
            alert('Invalid credentials!');
        }
    });
});
