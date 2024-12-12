async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

document.getElementById('registerForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorElement = document.getElementById('error');

    if (!username || !email || !password) {
        errorElement.textContent = 'Please fill in all fields.';
        return;
    }

    const hashedPassword = await hashPassword(password);

    // Convert to SQL database in future
    alert(`Registration successful!\nUsername: ${username}\nEmail: ${email}\nHashed Password: ${hashedPassword}`);
});