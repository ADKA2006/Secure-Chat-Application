class SecureChatClient {
    constructor() {
        this.socket = null;
        this.username = null;
        this.currentRoom = null;
        this.currentTransferId = null;
        this.typingTimeout = null;
        this.isTyping = false;
        this.private_key = new TextEncoder().encode('this_is_the_key_for_ICN_project=');

        this.initialiseElements();
        this.attachEventListeners();
        this.connectSocket();
    }
    // getRandomVlaues
    // Import Key
    // encrypt
    // decrypt
    async Encrypt(message) {
        try {
            const nonce = crypto.getRandomValues(new Uint8Array(16));
            const key = await crypto.subtle.importKey(
                'raw', this.private_key, { name: 'AES-GCM' }, false, ['encrypt']);
            
            const messageData = new TextEncoder().encode(message);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce, tagLength: 128 },
                key,
                messageData
            );
            
            const encryptedArray = new Uint8Array(encrypted);
            const tag = encryptedArray.slice(-16);
            const encryptedData = encryptedArray.slice(0, -16);
            
            const combined = new Uint8Array(16 + 16 + encryptedData.length);
            combined.set(nonce, 0);
            combined.set(tag, 16);
            combined.set(encryptedData, 32);
            
            return btoa(String.fromCharCode(...combined));
        } catch (error) {
            console.log('Encryption failed');
            return message;
        }
    }

    async Decrypt(encryptedMessage) {
        try {
            const data = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
            const nonce = data.slice(0, 16);
            const tag = data.slice(16, 32);
            const encryptedData = data.slice(32);
            const key = await crypto.subtle.importKey(
                'raw', this.private_key, { name: 'AES-GCM' }, false, ['decrypt']);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce, tagLength: 128 },key,
                new Uint8Array([...encryptedData, ...tag])
            );
            
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.log('Decryption failed');
            return encryptedMessage; 
        }
    }

    // Initialise all the elements - Starting
    initialiseElements() {
        this.loginScreen = document.getElementById('loginScreen');
        this.mainScreen = document.getElementById('mainScreen');
        this.loginTab = document.getElementById('loginTab');
        this.registerTab = document.getElementById('registerTab');
        this.loginForm = document.getElementById('loginForm');
        this.registerForm = document.getElementById('registerForm');
        this.loginUsername = document.getElementById('loginUsername');
        this.loginPassword = document.getElementById('loginPassword');
        this.loginBtn = document.getElementById('loginBtn');
        this.loginStatus = document.getElementById('loginStatus');
        this.registerUsername = document.getElementById('registerUsername');
        this.registerPassword = document.getElementById('registerPassword');
        this.confirmPassword = document.getElementById('confirmPassword');
        this.registerBtn = document.getElementById('registerBtn');
        this.registerStatus = document.getElementById('registerStatus');
        this.currentUser = document.getElementById('currentUser');
        this.disconnectBtn = document.getElementById('disconnectBtn');
        this.roomInput = document.getElementById('roomInput');
        this.joinRoomBtn = document.getElementById('joinRoomBtn');
        this.roomStatus = document.getElementById('roomStatus');
        this.roomUsers = document.getElementById('roomUsers');
        this.usersList = document.getElementById('usersList');
        this.usersTyping = document.getElementById('usersTyping');
        this.typingUsersList = document.getElementById('typingUsersList');
        this.messages = document.getElementById('messages');
        this.messageInput = document.getElementById('messageInput');
        this.sendBtn = document.getElementById('sendBtn');
        this.fileInput = document.getElementById('fileInput');
        this.fileModal = document.getElementById('fileModal');
        this.progressFill = document.getElementById('progressFill');
        this.progressText = document.getElementById('progressText');
        this.fileStatus = document.getElementById('fileStatus');
        this.closeModalBtn = document.getElementById('closeModalBtn');
        this.toastContainer = document.getElementById('toastContainer');
    }
    // Initialise all the elements - End

    // Event listeners we are adding here - Starting
    attachEventListeners() {
        // Tab switching
        this.loginTab.addEventListener('click', () => this.showLoginForm());
        this.registerTab.addEventListener('click', () => this.showRegisterForm());
        this.loginBtn.addEventListener('click', () => this.handleLogin());
        this.loginUsername.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleLogin();
        });
        this.loginPassword.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleLogin();
        });
        this.registerBtn.addEventListener('click', () => this.handleRegister());
        this.registerUsername.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleRegister();
        });
        this.registerPassword.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleRegister();
        });
        this.confirmPassword.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleRegister();
        });
        this.joinRoomBtn.addEventListener('click', () => this.joinRoom());
        this.roomInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.joinRoom();
        });
        this.messageInput.addEventListener('input', () => this.userTyping());
        this.sendBtn.addEventListener('click', () => this.sendMessage());
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        this.closeModalBtn.addEventListener('click', () => this.hideModal());
        this.disconnectBtn.addEventListener('click', () => this.disconnect());
    }
    // Event listeners - End

    // Authentication functions
    showLoginForm() {
        this.loginTab.classList.add('active');
        this.registerTab.classList.remove('active');
        this.loginForm.classList.add('active');
        this.registerForm.classList.remove('active');
    }
    
    showRegisterForm() {
        this.registerTab.classList.add('active');
        this.loginTab.classList.remove('active');
        this.registerForm.classList.add('active');
        this.loginForm.classList.remove('active');
    }
    
    handleLogin() {
        const username = this.loginUsername.value.trim();
        const password = this.loginPassword.value.trim();

        if (username == "" || password == "") {
            this.showStatus(this.loginStatus, 'Please enter both username and password', 'error');
            return;
        }
        
        this.showStatus(this.loginStatus, 'Logging in', 'info');
        this.socket.emit('login_user', { username, password });
    }
    
    handleRegister() {
        const username = this.registerUsername.value.trim();
        const password = this.registerPassword.value.trim();
        const confirmPassword = this.confirmPassword.value.trim();
        
        // Validation
        if (!username || !password || !confirmPassword) {
            this.showStatus(this.registerStatus, 'Please fill in all fields', 'error');
            return;
        }
        
        if (username.length < 3) {
            this.showStatus(this.registerStatus, 'Username must be at least 3 characters long', 'error');
            return;
        }
        
        if (password.length < 6) {
            this.showStatus(this.registerStatus, 'Password must be at least 6 characters long', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            this.showStatus(this.registerStatus, 'Passwords do not match', 'error');
            return;
        }
        
        this.showStatus(this.registerStatus, 'Creating account...', 'info');
        this.socket.emit('register_user', { username, password });
    }

    joinRoom() {
        const roomId = this.roomInput.value.trim();
        if (roomId == "") {
            this.showStatus(this.roomStatus, 'Please enter a room name', 'error');
            return;
        }
        this.showStatus(this.roomStatus, 'Joining the room', 'info');
        this.socket.emit('join_room', {room_id:roomId});
        this.roomInput.value = '';
    }

    userTyping() {
        if (!this.isTyping) {
            this.socket.emit('user_start_typing');
            this.isTyping = true;
        }
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        this.typingTimeout = setTimeout(() => {
            this.socket.emit('user_stop_typing');
            this.isTyping = false;
        }, 3000);
    }

    async sendMessage() {
        const message = this.messageInput.value.trim();
        if (!message) return;
        
        if (this.isTyping) {
            this.socket.emit('user_stop_typing');
            this.isTyping = false;
            if (this.typingTimeout) {
                clearTimeout(this.typingTimeout);
                this.typingTimeout = null;
            }
        }
        
        const encryptedMessage = await this.Encrypt(message);
        this.socket.emit('send_message', { message: encryptedMessage });
        this.messageInput.value = '';
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return; 
        if (file.size > 10 * 1024 * 1024) {
            this.showToast('File too large. Maximum is 10 MB', 'error');
            return;
        }
        this.uploadFile(file);
        event.target.value = ''; 
    }

    async uploadFile(file) {
        const chunkSize = 64 * 1024;
        const totalChunks = Math.ceil(file.size / chunkSize);

        this.showModal();
        this.fileStatus.textContent = `Uploading: ${file.name}`;
        this.updateProgress(0);
        this.socket.emit('start_file_transfer', {
            filename: file.name,
            file_size: file.size,
            total_chunks: totalChunks
        });

        while (!this.currentTransferId) {
            await new Promise(resolve => setTimeout(resolve, 50));
        }

        for (let i = 0; i < totalChunks; i++) {
            const start = i * chunkSize;
            const end = Math.min(start + chunkSize, file.size);
            const chunk = file.slice(start, end);
            
            const arrayBuffer = await chunk.arrayBuffer();
            const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
            
            this.socket.emit('file_chunk', {
                transfer_id: this.currentTransferId,
                chunk_index: i,
                chunk_data: base64
            });

            await new Promise(resolve => setTimeout(resolve, 10));
        }

        this.currentTransferId = null;
    }

    addMessage(username, message, timestamp) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${username === this.username ? 'user' : 'other'}`;
        
        if (username !== this.username) {
            const header = document.createElement('div');
            header.className = 'message-header';
            header.textContent = username;
            messageDiv.appendChild(header);
        }
        
        const content = document.createElement('div');
        content.textContent = message;
        messageDiv.appendChild(content);
        
        const time = document.createElement('div');
        time.className = 'message-time';
        time.textContent = timestamp;
        messageDiv.appendChild(time);
        
        this.messages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addSystemMessage(message) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message system';
        messageDiv.textContent = message;
        
        this.messages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addFileMessage(filename, fileData, sender) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message file-message';
        messageDiv.innerHTML = `
            <div class="message-header"> ${sender}</div>
            <div>File: ${filename}</div>
            <div class="message-time">Click to download</div>
        `;
        
        messageDiv.addEventListener('click', () => {
            this.downloadFile(filename, fileData);
        });
        
        this.messages.appendChild(messageDiv);
        this.scrollToBottom();
        
        this.showToast(`File received: ${filename}`, 'success');
    }

    downloadFile(filename, base64Data) {
        try {
            if (!base64Data || base64Data.length === 0) {
                throw new Error('Empty or invalid base64 data');
            }

            const cleanBase64 = base64Data.replace(/\s/g, '');
            const byteCharacters = atob(cleanBase64);
            const byteNumbers = new Array(byteCharacters.length);
            for (let i = 0; i < byteCharacters.length; i++) {
                byteNumbers[i] = byteCharacters.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            const blob = new Blob([byteArray]);
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            this.showToast(`Downloaded: ${filename}`, 'success');
        } catch (error) {
            console.error('Download error:', error);
            this.showToast(`Failed to download file: ${error.message}`, 'error');
        }
    }

    clearMessages() {
        this.messages.innerHTML = '';
    }

    scrollToBottom() {
        this.messages.scrollTop = this.messages.scrollHeight;
    }

    showMainScreen() {
        this.loginScreen.classList.add('hidden');
        this.mainScreen.classList.remove('hidden');
    }

    clearAuthForms() {
        this.loginUsername.value = '';
        this.loginPassword.value = '';
        this.loginStatus.textContent = '';
        
        this.registerUsername.value = '';
        this.registerPassword.value = '';
        this.confirmPassword.value = '';
        this.registerStatus.textContent = '';
    }

    showModal() {
        this.fileModal.classList.remove('hidden');
    }

    hideModal() {
        this.fileModal.classList.add('hidden');
        this.updateProgress(0);
        this.fileStatus.textContent = '';
    }

    updateProgress(progress) {
        this.progressFill.style.width = `${progress}%`;
        this.progressText.textContent = `${Math.round(progress)}%`;
        
        if (progress >= 100) {
            this.fileStatus.textContent = 'Upload complete!';
            setTimeout(() => this.hideModal(), 2000);
        }
    }

    showStatus(element, message, type) {
        element.textContent = message;
        element.className = `status ${type}`;
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        this.toastContainer.appendChild(toast);
        
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 3000);
    }

    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
        }
        location.reload();
    }

    connectSocket() {
        console.log('Attempting to connect to Socket.IO server');
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Successfully connected to server');
        });

        this.socket.on('connect_error', (error) => {
            console.error('Connection failed:', error);
            this.showToast('Connection failed to server', 'error');
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.showToast('Connection lost', 'error');
        });

        // Authentication event handlers
        this.socket.on('login_success', (data) => {
            this.username = data.user.username;
            this.currentUser.textContent = `Username: ${this.username}`;
            this.showMainScreen();
            this.showToast('Login successful!', 'success');
            this.clearAuthForms();
        });

        this.socket.on('login_error', (data) => {
            this.showStatus(this.loginStatus, data.message, 'error');
        });

        this.socket.on('register_success', (data) => {
            this.showStatus(this.registerStatus, data.message, 'success');
            this.showToast('Account created successfully! Please login', 'success');
            this.showLoginForm();
            this.clearAuthForms();
        });

        this.socket.on('register_error', (data) => {
            this.showStatus(this.registerStatus, data.message, 'error');
        });

        this.socket.on('room_joined', (data) => {
            this.currentRoom = data.room_id;
            this.roomStatus.textContent = `Room-Name: ${data.room_id}`;
            this.roomStatus.className = 'status success';
            this.usersList.textContent = data.users.join(', ');
            this.roomUsers.classList.remove('hidden');
            this.usersTyping.classList.add('hidden');
            this.typingUsersList.textContent = '';
            if (this.isTyping) {
                this.isTyping = false;
                if (this.typingTimeout) {
                    clearTimeout(this.typingTimeout);
                    this.typingTimeout = null;
                }
            }
            
            this.messageInput.disabled = false;
            this.messageInput.placeholder = 'Type your message';
            this.sendBtn.disabled = false;
            this.fileInput.disabled = false;
            
            this.clearMessages();
            this.addSystemMessage(`Joined room: ${data.room_id}`);
        });

        this.socket.on('user_joined', (data) => {
            this.addSystemMessage(data.message);
        });

        this.socket.on('user_left', (data) => {
            this.addSystemMessage(data.message);
            this.usersList.textContent = data.users.join(', ');
        });
        
        this.socket.on('users_typing', (data) => {
            const typingUsers = data.users || [];
            this.typingUsersList.textContent = typingUsers.join(', ');
            if (typingUsers.length > 0) {
                this.usersTyping.classList.remove('hidden');
            } else {
                this.usersTyping.classList.add('hidden');
            }
        });
        
        this.socket.on('new_message', async (data) => {
            const decryptedMessage = await this.Decrypt(data.message);
            this.addMessage(data.username, decryptedMessage, data.timestamp);
        });

        this.socket.on('transfer_ready', (data) => {
            this.currentTransferId = data.transfer_id;
        });

        this.socket.on('transfer_progress', (data) => {
            this.updateProgress(data.progress);
        });

        this.socket.on('file_incoming', (data) => {
            this.showToast(`${data.sender} is sending: ${data.filename}`, 'info');
        });

        this.socket.on('file_ready', (data) => {
            this.addFileMessage(data.filename, data.file_data, data.sender);
        });

        this.socket.on('error', (data) => {
            this.showToast(data.message, 'error');
        });
    }
}

// Initialize the chat client when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new SecureChatClient();
});
