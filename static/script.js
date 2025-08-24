class SecureChatClient {
    constructor() {
        this.socket = null;
        this.username = null;
        this.currentRoom = null;
        this.currentTransferId = null;
        
        this.initialiseElements();
        this.attachEventListeners();
        this.connectSocket();
    }

    // Pending is for video.
    // Initialise all the elements - Starting
    initialiseElements() {
        this.loginScreen = document.getElementById('loginScreen');
        this.mainScreen = document.getElementById('mainScreen');
        this.usernameInput = document.getElementById('username');
        this.joinBtn = document.getElementById('joinBtn');
        this.loginStatus = document.getElementById('loginStatus');
        this.currentUser = document.getElementById('currentUser');
        this.disconnectBtn = document.getElementById('disconnectBtn');
        this.roomInput = document.getElementById('roomInput');
        this.joinRoomBtn = document.getElementById('joinRoomBtn');
        this.roomStatus = document.getElementById('roomStatus');
        this.roomUsers = document.getElementById('roomUsers');
        this.usersList = document.getElementById('usersList');
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

    // Both btn press and enter key is the standard ie the user can use both click or enter to the things
    attachEventListeners() {
        // Login (Password thing is pending)
        this.joinBtn.addEventListener('click', () => this.joinChat());
        this.usernameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.joinChat();
        });
        this.joinRoomBtn.addEventListener('click', () => this.joinRoom());
        this.roomInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.joinRoom();
        });
        this.sendBtn.addEventListener('click', () => this.sendMessage());
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });
        this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        this.closeModalBtn.addEventListener('click', () => this.hideModal());
        this.disconnectBtn.addEventListener('click', () => this.disconnect());
    }
    // Event listeners - End

    // Defining the functions for different things -  Start
    // Here the logic will be like when any of these functions is invoked, **emit** will be there which will relay the information to the server asking it to do the corresponding event
    joinChat() {
        const username = this.usernameInput.value.trim();
        if (username == "") {
            this.showStatus(this.loginStatus, 'Please enter a username', 'error');
            return;
        }
        this.showStatus(this.loginStatus, 'Joining chat server', 'info');
        this.socket.emit('join_chat', {username});
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

    sendMessage() {
        const message = this.messageInput.value.trim();
        if (!message) return;
        this.socket.emit('send_message', { message });
        this.messageInput.value = '';
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return; 
         // 1 kb = 1024 bytes and 1 MB = 1024 * 1024 bytes. After seeing the performance we can increase the limit.
        if (file.size > 10 * 1024 * 1024) {
            this.showToast('File too large. Maximum is 10 MB', 'error');
            return;
        }

        this.uploadFile(file);
        event.target.value = ''; 
    }

    async uploadFile(file) {
        const chunkSize = 64 * 1024; // 64KB chunks  
        const totalChunks = Math.ceil(file.size / chunkSize);

        // Show progress modal
        this.showModal();
        this.fileStatus.textContent = `Uploading: ${file.name}`;
        this.updateProgress(0);
        this.socket.emit('start_file_transfer', {
            filename: file.name,
            file_size: file.size,
            total_chunks: totalChunks
        });

        while (!this.currentTransferId) {
            await new Promise(resolve => setTimeout(resolve, 50));  // delay
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
    //Just like the upload thing for chunks
    downloadFile(filename, base64Data) {
        try {
            console.log('Attempting to download file:', filename);
            console.log('Base64 data length:', base64Data.length);
            console.log('Base64 data preview:', base64Data.substring(0, 100) + '...');
            
            if (!base64Data || base64Data.length === 0) {   // validatong base64
                throw new Error('Empty or invalid base64 data');
            }

            const cleanBase64 = base64Data.replace(/\s/g, '');  //Was showing error without this remember in future
            
            const byteCharacters = atob(cleanBase64);
            const byteNumbers = new Array(byteCharacters.length);
            for (let i = 0; i < byteCharacters.length; i++) {
                byteNumbers[i] = byteCharacters.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            const blob = new Blob([byteArray]);
            
            console.log('Blob created successfully, size:', blob.size);
            
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
            console.error('Download error details:', error);
            console.error('Error name:', error.name);
            console.error('Error message:', error.message);
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
        
        // Auto remove after 3 seconds
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

        this.socket.on('join_success', (data) => {
            this.username = data.username;
            this.currentUser.textContent = `Username: ${this.username}`;
            this.showMainScreen();
            this.showToast('Welcome to Secure Chat Application', 'success');
        });

        this.socket.on('room_joined', (data) => {
            this.currentRoom = data.room_id;
            this.roomStatus.textContent = `Room-Name: ${data.room_id}`;
            this.roomStatus.className = 'status success';
            this.usersList.textContent = data.users.join(', ');
            this.roomUsers.classList.remove('hidden');
            
            // Enable chat
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
        
        /*
        this.socket.on('users_typing', (data) => {
            this.typingUsersList.textContent = data.users.join(', ');
            this.usersTyping.classList.remove('hidden');
        });
        */

        // Message events
        this.socket.on('new_message', (data) => {
            this.addMessage(data.username, data.message, data.timestamp);
        });

        // File transfer events
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

        // Universal Error events -  If the server sends an error let this catch
        this.socket.on('error', (data) => {
            this.showToast(data.message, 'error');
        });
    }
}

// Initialize the chat client when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new SecureChatClient();
});
