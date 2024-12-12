async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

document.getElementById('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorElement = document.getElementById('error');

    if (!username || !password) {
        errorElement.textContent = 'Please fill in all fields.';
        return;
    }

    const hashedPassword = await hashPassword(password);

    // Check based on SQL database in future
    if (username === 'testuser' && hashedPassword === 'dummyhashvalue') {
        alert('Login successful!');
    } else {
        errorElement.textContent = 'Invalid username or password.';
    }
});
