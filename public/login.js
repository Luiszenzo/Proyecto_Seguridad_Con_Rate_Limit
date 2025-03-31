document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const mfaContainer = document.getElementById('mfaContainer');
    const verifyMfaBtn = document.getElementById('verifyMfaBtn');
    const messageDiv = document.getElementById('message');
    
    let authToken = '';
    let mfaSecret = '';
    
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        try {
            const response = await fetch('http://localhost:3001/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store token and MFA secret
                authToken = data.token;
                mfaSecret = data.mfaSecret;
                
                // Show MFA verification form
                loginForm.classList.add('hidden');
                mfaContainer.classList.remove('hidden');
                
                // If we have a direct code or preview URL (for development)
                if (data.mfaCode || data.emailPreviewUrl) {
                    const infoDiv = document.createElement('div');
                    infoDiv.className = 'mfa-code';
                    
                    if (data.mfaCode) {
                        infoDiv.innerHTML += `
                            <h3>Código de verificación (solo para pruebas):</h3>
                            <div class="code">${data.mfaCode}</div>
                        `;
                    }
                    
                    if (data.emailPreviewUrl) {
                        infoDiv.innerHTML += `
                            <p>Ver el correo en: <a href="${data.emailPreviewUrl}" target="_blank">Ethereal Email</a></p>
                        `;
                    }
                    
                    // Insert before the input field
                    const mfaInput = document.getElementById('mfaCode');
                    mfaInput.parentNode.insertBefore(infoDiv, mfaInput);
                    
                    // Auto-fill for testing
                    if (data.mfaCode) {
                        document.getElementById('mfaCode').value = data.mfaCode;
                    }
                }
                
                showMessage(data.message, 'success');
            } else {
                showMessage(data.error, 'error');
            }
        } catch (error) {
            showMessage('An error occurred. Please try again.', 'error');
            console.error('Login error:', error);
        }
    });
    
    verifyMfaBtn.addEventListener('click', async function() {
        const mfaCode = document.getElementById('mfaCode').value;
        
        if (!mfaCode) {
            showMessage('Please enter the verification code', 'error');
            return;
        }
        
        try {
            const response = await fetch('http://localhost:3001/verify-mfa', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-auth-token': authToken,
                    'x-mfa-code': mfaCode
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showMessage('Login successful! Redirecting...', 'success');
                // Store token in localStorage for future authenticated requests
                localStorage.setItem('authToken', authToken);
                
                // Redirect to dashboard or home page after successful login
                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 1500);
            } else {
                showMessage(data.error, 'error');
            }
        } catch (error) {
            showMessage('An error occurred during MFA verification.', 'error');
            console.error('MFA verification error:', error);
        }
    });
    
    function showMessage(message, type) {
        messageDiv.textContent = message;
        messageDiv.className = 'message';
        messageDiv.classList.add(type);
    }
});