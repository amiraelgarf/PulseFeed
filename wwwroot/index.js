const login = document.querySelector('#login');
let passFlag = false;
let emailFlag = false;
let passConfirmFlag = false;

document.addEventListener('DOMContentLoaded', function () {
document.body.addEventListener('htmx:afterRequest', function (event) {
    console.log("hello")
    console.log(event);
    email = document.querySelector('#email');
    password = document.querySelector('#password');
    const requestPath = event.detail.requestConfig.path;
    const requestVerb = event.detail.requestConfig.verb;
    
    function addBlurListenersForLogin() {
        if (email) email.addEventListener('blur', () => validateLoginForm(email, password));
        if (password) password.addEventListener('blur', () => validateLoginForm(email, password));
    }

    function addBlurListenersForRegister() {
        const passwordConf = document.querySelector('#confirmPassword');
        if (email) email.addEventListener('blur', () => validateRegisterForm(email, password, passwordConf));
        if (password) password.addEventListener('blur', () => validateRegisterForm(email, password, passwordConf));
        if (passwordConf) passwordConf.addEventListener('blur', () => validateRegisterForm(email, password, passwordConf));
    }

    function toggleLoginLogoutButtons(showLoginButton) {
        document.querySelector('.loginButton').classList.toggle('d-none', !showLoginButton);
        document.querySelector('.logoutNav').classList.toggle('d-none', showLoginButton);
    }

    if (requestVerb === 'get') {
        console.log("GET request to:", requestPath);

        if (requestPath === '/login-form' || requestPath === '/feed') {
            console.log('Login page or home loaded');
            addBlurListenersForLogin();

            const shareBtn = document.querySelector('#shareBtn');
            if (shareBtn) shareBtn.addEventListener('click', shareFeed);

            const loginForm = document.querySelector('#login');
            if (loginForm) {
                console.log('Login form present');
            } else {
                toggleLoginLogoutButtons(false);
            }
        } else if (requestPath === '/register-form') {
            console.log('Register page loaded');
            addBlurListenersForRegister();
        } else if (requestPath === '/logout') {
            console.log('Logout request');
            htmx.ajax('GET', '/login-form', { target: '.replace' });
            toggleLoginLogoutButtons(true);
        }
    }

    if (requestVerb === 'post') {
        console.log("POST request to:", requestPath);

        if (requestPath === '/login' && document.querySelector('.loginMessage').innerHTML === 'Login Successful') {
            localStorage.setItem('email', email.value);
            htmx.ajax('GET', '/feed', { target: '.replace' });
            toggleLoginLogoutButtons(false);
        } else if (requestPath === '/register' && document.querySelector('.registerMsg').innerHTML === 'User Created Successfully.') {
            htmx.ajax('GET', '/login-form', { target: '.replace' });
        } else if (requestPath === '/addFeed' && document.querySelector('.addFeedMsg').innerHTML === 'Feed Added Successfully.') {
            htmx.ajax('GET', '/feed', { target: '.replace' });
        }
    }

    if (requestVerb === 'delete') {
        console.log("DELETE request to:", requestPath);

        if (document.querySelector('.removeFeedMsg').innerHTML === 'Feed Removed Successfully.') {
            htmx.ajax('GET', '/feed', { target: '.replace' });
        }
    }

});
});

function isEmailValid(email) {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

function setError(element, message) {
    const inputControl = element.parentElement;
    const errorDisplay = inputControl.querySelector('.error');

    errorDisplay.textContent = message;
    inputControl.classList.add('error');
    inputControl.classList.remove('success');
}

function setSuccess(element) {
    const inputControl = element.parentElement;
    const errorDisplay = inputControl.querySelector('.error');

    errorDisplay.textContent = '';
    inputControl.classList.add('success');
    inputControl.classList.remove('error');
}

function validateLoginForm() {
    const email = document.querySelector('#login #email');
    const password = document.querySelector('#login #password');
    let emailFlag = false;
    let passFlag = false;

    // Validate email
    const emailValue = email.value.trim();
    if (emailValue === '') {
        setError(email, 'Email is required.');
    } else if (!isEmailValid(emailValue)) {
        setError(email, 'Please enter a valid email.');
    } else {
        setSuccess(email);
        emailFlag = true;
    }

    // Validate password
    const passwordValue = password.value.trim();
    if (passwordValue === '') {
        setError(password, 'Password is required.');
    } else if (passwordValue.length < 8) {
        setError(password, 'Password must be at least 8 characters.');
    } else {
        setSuccess(password);
        passFlag = true;
    }

    // Enable or disable login button
    document.querySelector("#loginBtn").disabled = !(emailFlag && passFlag);
}

function validateRegisterForm() {
    const email = document.querySelector('#register #email');
    const password = document.querySelector('#register #password');
    const confirmPassword = document.querySelector('#register #confirmPassword');
    let emailFlag = false;
    let passFlag = false;
    let passConfirmFlag = false;
    console.log('Email:', email.value);
    console.log('Password:', password.value);
    console.log('Confirm Password:', confirmPassword.value);


    // Validate email
    const emailValue = email.value.trim();
    if (emailValue === '') {
        setError(email, 'Email is required.');
    } else if (!isEmailValid(emailValue)) {
        setError(email, 'Please enter a valid email.');
    } else {
        setSuccess(email);
        emailFlag = true;
    }

    // Validate password
    const passwordValue = password.value.trim();
    if (passwordValue === '') {
        setError(password, 'Password is required.');
    } else if (passwordValue.length < 8) {
        setError(password, 'Password must be at least 8 characters.');
    } else {
        setSuccess(password);
        passFlag = true;
    }

    // Validate password confirmation
    const passwordConfValue = confirmPassword.value.trim();
    if (passwordConfValue !== passwordValue || passwordConfValue === '') {
        setError(confirmPassword, 'Please confirm your password.');
    } else {
        setSuccess(confirmPassword);
        passConfirmFlag = true;
    }

    // Enable or disable register button
    document.querySelector("#registerBtn").disabled = !(emailFlag && passFlag && passConfirmFlag);
}
function shareFeed() {
    const userEmail = localStorage.getItem('email');
    if (userEmail) {
        const shareLink = `${window.location.origin}/?feed=${encodeURIComponent(userEmail)}`;
        navigator.clipboard.writeText(shareLink).then(() => {
            alert(`Share link copied to clipboard: ${shareLink}`);
        }).catch(err => {
            console.error('Failed to copy share link: ', err);
        });
    } else {
        alert('No email found in local storage.');
    }
}


