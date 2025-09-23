class SecureChatClient {
    constructor() {
        this.socket = null;
        this.username = null;
        this.currentRoom = null;
        this.currentTransferId = null;
        this.typingTimeout = null;
        this.isTyping = false;
        this.private_key = new TextEncoder().encode('this_is_the_key_for_ICN_project=');
        
        // Group video call properties
        this.localStream = null;
        this.peerConnections = new Map(); // Map of username -> RTCPeerConnection
        this.remoteStreams = new Map(); // Map of username -> MediaStream
        this.isInCall = false;
        this.participants = new Set();

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
        this.videoCallBtn = document.getElementById('videoCallBtn');
        this.videoModal = document.getElementById('videoModal');
        this.videoCallTitle = document.getElementById('videoCallTitle');
        this.videoGrid = document.getElementById('videoGrid');
        this.participantCount = document.getElementById('participantCount');
        this.muteToggleBtn = document.getElementById('muteToggleBtn');
        this.videoToggleBtn = document.getElementById('videoToggleBtn');
        this.endCallBtn = document.getElementById('endCallBtn');
        this.closeVideoBtn = document.getElementById('closeVideoBtn');
        this.videoStatus = document.getElementById('videoStatus');
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
        
        this.videoCallBtn.addEventListener('click', () => this.joinVideoCall());
        this.muteToggleBtn.addEventListener('click', () => this.toggleMute());
        this.videoToggleBtn.addEventListener('click', () => this.toggleVideo());
        this.endCallBtn.addEventListener('click', () => this.leaveVideoCall());
        this.closeVideoBtn.addEventListener('click', () => this.leaveVideoCall());
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

    // Diagnostic function to check WebRTC state
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

    // Group Video Call Methods
    async joinVideoCall() {
        if (this.isInCall) {
            this.showToast('You are already in a video call', 'error');
            return;
        }
        
        if (!this.currentRoom) {
            this.showToast('You must be in a room to start a video call', 'error');
            return;
        }
        
        try {
            await this.setupLocalStream();
            this.socket.emit('join_video_call');
            this.isInCall = true;
            this.showVideoModal();
            this.showVideoStatus('Joining video call', 'info');
        } catch (error) {
            console.error('Error joining video call:', error);
            this.showToast('Failed to join video call', 'error');
        }
    }

    async setupLocalStream() {
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({  // mediadevices API
                video: true,
                audio: true
            });
            this.addLocalVideoToGrid();
            return true;
        } catch (error) {
            console.error('Error accessing media devices:', error);
            this.showToast('Could not access camera/microphone', 'error');
            throw error;
        }
    }

    addLocalVideoToGrid() {
        const existingLocal = document.querySelector('.video-participant.local');
        if (existingLocal) {
            existingLocal.remove();
        }

        const videoContainer = document.createElement('div');
        videoContainer.className = 'video-participant local';
        videoContainer.id = `participant-${this.username}`;

        const video = document.createElement('video');
        video.autoplay = true;
        video.muted = true;
        video.playsInline = true;
        video.srcObject = this.localStream;

        const participantInfo = document.createElement('div');
        participantInfo.className = 'participant-info';
        participantInfo.textContent = `${this.username} (You)`;

        videoContainer.appendChild(video);
        videoContainer.appendChild(participantInfo);
        this.videoGrid.appendChild(videoContainer);

        this.participants.add(this.username);
        this.updateGridLayout();
    }

    async createPeerConnection(username) {
        const configuration = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };

        const peerConnection = new RTCPeerConnection(configuration);
        
        // Add local stream tracks to peer connection
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => {
                peerConnection.addTrack(track, this.localStream);
            });
        }
        
        // Handle incoming remote streams
        peerConnection.ontrack = (event) => {
            const remoteStream = event.streams[0];
            this.remoteStreams.set(username, remoteStream);
            this.addRemoteVideoToGrid(username, remoteStream);
            
            
            setTimeout(() => {
               
                const videoElement = document.querySelector(`#participant-${username} video`);
                if (videoElement) {
                    videoElement.muted = false; 
                    if (videoElement.paused) {
                        videoElement.play().catch(e => 
                            console.error(`Error playing video for ${username}:`, e)
                        );
                    }
                }
            }, 500);
        };
        
        // Handle ICE candidates
        peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.socket.emit('webrtc_ice_candidate', {
                    candidate: event.candidate,
                    target_user: username
                });
            }
        };

        // Monitor connection state
        peerConnection.onconnectionstatechange = () => {
            if (peerConnection.connectionState === 'connected') {
                this.showVideoStatus(`Connected to ${username}`, 'success');
            } else if (peerConnection.connectionState === 'disconnected' || 
                       peerConnection.connectionState === 'failed') {
                this.handlePeerDisconnection(username);
            }
        };

        this.peerConnections.set(username, peerConnection);
        return peerConnection;
    }

    addRemoteVideoToGrid(username, stream) {
        const existingVideo = document.getElementById(`participant-${username}`);
        if (existingVideo) {
            existingVideo.remove();
        }

        const videoContainer = document.createElement('div');
        videoContainer.className = 'video-participant remote';
        videoContainer.id = `participant-${username}`;

        const video = document.createElement('video');
        video.autoplay = true;
        video.playsInline = true;
        video.muted = false; // Start unmuted for remote videos
        video.controls = false;
        
        // Basic event handlers
        video.onloadedmetadata = () => {
            video.play().then(() => {
                // Success
            }).catch(e => {
                // Try muted play if autoplay fails
                video.muted = true;
                return video.play();
            }).then(() => {
                // Try to unmute after successful play
                setTimeout(() => {
                    if (video.muted) {
                        video.muted = false;
                    }
                }, 1000);
            }).catch(finalError => {
                console.error(`Video play failed for ${username}:`, finalError);
            });
        };
        
        video.oncanplay = () => {
            if (video.paused) {
                video.play().catch(e => console.error(`Error playing video for ${username}:`, e));
            }
        };
        
        video.onerror = (e) => {
            console.error(`Video error for ${username}:`, e);
        };
        
        // Set the stream
        video.srcObject = stream;
        
        // Check if video track has actual content
        const videoTracks = stream.getVideoTracks();
        if (videoTracks.length > 0) {
            const videoTrack = videoTracks[0];
            
            // Listen for track events
            videoTrack.onended = () => {
                console.log(`Video track ended for ${username}`);
            };
            
            videoTrack.onmute = () => {
                console.log(`Video track muted for ${username}`);
            };
            
            videoTrack.onunmute = () => {
                // Force video to play when track becomes unmuted
                setTimeout(() => {
                    const videoElement = document.querySelector(`#participant-${username} video`);
                    if (videoElement) {
                        videoElement.muted = false; // Ensure video element is not muted
                        videoElement.play().then(() => {
                            // Success
                        }).catch(e => {
                            console.error(`Error playing video after unmute for ${username}:`, e);
                            // Try with muted playback as fallback
                            videoElement.muted = true;
                            videoElement.play().catch(err => 
                                console.error(`Final play attempt failed for ${username}:`, err)
                            );
                        });
                    }
                }, 100);
            };
        }

        const participantInfo = document.createElement('div');
        participantInfo.className = 'participant-info';
        participantInfo.textContent = username;

        videoContainer.appendChild(video);
        videoContainer.appendChild(participantInfo);
        this.videoGrid.appendChild(videoContainer);

        this.participants.add(username);
        this.updateGridLayout();
        
        // Force video to play after a short delay
        setTimeout(() => {
            if (video.paused) {
                video.play().catch(e => console.error(`Error force playing video for ${username}:`, e));
            }
        }, 100);
    }

    updateGridLayout() {
        const participantCount = this.participants.size;
        this.participantCount.textContent = `${participantCount} participant${participantCount !== 1 ? 's' : ''}`;
        this.videoGrid.className = 'video-grid';
        if (participantCount <= 1) {
            this.videoGrid.classList.add('participants-1');
        } else if (participantCount === 2) {
            this.videoGrid.classList.add('participants-2');
        } else if (participantCount <= 4) {
            this.videoGrid.classList.add('participants-4');
        } else if (participantCount <= 6) {
            this.videoGrid.classList.add('participants-6');
        } else if (participantCount <= 9) {
            this.videoGrid.classList.add('participants-9');
        } else {
            this.videoGrid.classList.add('participants-many');
        }
    }

    async handleNewParticipant(username) {
        if (username === this.username) return;

        const peerConnection = await this.createPeerConnection(username);
        
        // Use polite/impolite peer pattern to avoid glare
        const isPolite = this.username < username; // Lexicographically smaller username is polite
        
        if (isPolite) {
            try {
                const offer = await peerConnection.createOffer({
                    offerToReceiveAudio: true,
                    offerToReceiveVideo: true
                });
                await peerConnection.setLocalDescription(offer);
                
                this.socket.emit('webrtc_offer', {
                    offer: offer,
                    target_user: username
                });
            } catch (error) {
                console.error('Error creating offer for', username, ':', error);
            }
        }
    }

    async handleOffer(offer, fromUser) {
        if (fromUser === this.username) return;

        let peerConnection = this.peerConnections.get(fromUser);
        
        if (!peerConnection) {
            peerConnection = await this.createPeerConnection(fromUser);
        }
        
        try {
            await peerConnection.setRemoteDescription(offer);
            
            const answer = await peerConnection.createAnswer({
                offerToReceiveAudio: true,
                offerToReceiveVideo: true
            });
            await peerConnection.setLocalDescription(answer);
            
            this.socket.emit('webrtc_answer', {
                answer: answer,
                target_user: fromUser
            });
        } catch (error) {
            console.error('Error handling offer from', fromUser, ':', error);
        }
    }

    async handleAnswer(answer, fromUser) {
        if (fromUser === this.username) return;

        const peerConnection = this.peerConnections.get(fromUser);
        
        if (peerConnection) {
            try {
                // Check signaling state before setting remote description
                if (peerConnection.signalingState === 'have-local-offer') {
                    await peerConnection.setRemoteDescription(answer);
                }
            } catch (error) {
                console.error('Error handling answer from', fromUser, ':', error);
            }
        } else {
            console.error('No peer connection found for answer from:', fromUser);
        }
    }

    async handleIceCandidate(candidate, fromUser) {
        if (fromUser === this.username) return;

        const peerConnection = this.peerConnections.get(fromUser);
        
        if (peerConnection) {
            try {
                await peerConnection.addIceCandidate(candidate);
            } catch (error) {
                console.error('Error adding ICE candidate from', fromUser, ':', error);
            }
        } else {
            console.error('No peer connection found for ICE candidate from:', fromUser);
        }
    }

    handlePeerDisconnection(username) {
        console.log('Peer disconnected:', username);
        const peerConnection = this.peerConnections.get(username);
        if (peerConnection) {
            peerConnection.close();
            this.peerConnections.delete(username);
        }
        this.remoteStreams.delete(username);
        const videoElement = document.getElementById(`participant-${username}`);
        if (videoElement) {
            videoElement.remove();
        }
        
        this.participants.delete(username);
        this.updateGridLayout();
    }

    toggleMute() {
        if (!this.localStream) return;
        
        const audioTrack = this.localStream.getAudioTracks()[0];
        if (audioTrack) {
            audioTrack.enabled = !audioTrack.enabled;
            this.muteToggleBtn.textContent = audioTrack.enabled ? 'Mute' : 'Unmute';
            this.muteToggleBtn.className = audioTrack.enabled ? 'btn secondary' : 'btn secondary muted';
            
            const localContainer = document.getElementById(`participant-${this.username}`);
            if (localContainer) {
                let mutedIndicator = localContainer.querySelector('.participant-muted');
                if (!audioTrack.enabled) {
                    if (!mutedIndicator) {
                        mutedIndicator = document.createElement('div');
                        mutedIndicator.className = 'participant-muted';
                        mutedIndicator.textContent = 'Muted';
                        localContainer.appendChild(mutedIndicator);
                    }
                } else if (mutedIndicator) {
                    mutedIndicator.remove();
                }
            }
        }
    }

    toggleVideo() {
        if (!this.localStream) return;
        
        const videoTrack = this.localStream.getVideoTracks()[0];
        if (videoTrack) {
            videoTrack.enabled = !videoTrack.enabled;
            this.videoToggleBtn.textContent = videoTrack.enabled ? 'Video' : 'Video Off';
            this.videoToggleBtn.className = videoTrack.enabled ? 'btn secondary' : 'btn secondary video-off';
        }
    }

    leaveVideoCall() {
        this.socket.emit('leave_video_call');
        this.cleanupVideoCall();
    }

    cleanupVideoCall() {
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }
 
        this.peerConnections.forEach((peerConnection, username) => {
            peerConnection.close();
        });
        this.peerConnections.clear();
        this.remoteStreams.clear();
        this.participants.clear();
        this.videoGrid.innerHTML = '';
        this.isInCall = false;
        this.muteToggleBtn.textContent = 'Mute';
        this.muteToggleBtn.className = 'btn secondary';
        this.videoToggleBtn.textContent = 'Video';
        this.videoToggleBtn.className = 'btn secondary';
        this.hideVideoModal();
    }

    showVideoModal() {
        this.videoModal.classList.remove('hidden');
    }

    hideVideoModal() {
        this.videoModal.classList.add('hidden');
    }

    showVideoStatus(message, type) {
        this.videoStatus.textContent = message;
        this.videoStatus.className = `status ${type}`;
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
            this.videoCallBtn.disabled = false;
            
            // Only clear messages if switching rooms, not when first joining
            if (this.currentRoom && this.currentRoom !== data.room_id) {
                this.clearMessages();
            }
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

        this.socket.on('message_history', async (data) => {
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

        // Group video call event handlers
        this.socket.on('user_joined_video_call', (data) => {
            console.log('User joined video call:', data.username);
            if (data.username !== this.username) {
                this.handleNewParticipant(data.username);
            }
            this.showToast(`${data.username} joined the video call`, 'info');
        });

        this.socket.on('user_left_video_call', (data) => {
            console.log('User left video call:', data.username);
            this.handlePeerDisconnection(data.username);
            this.showToast(`${data.username} left the video call`, 'info');
        });

        this.socket.on('video_call_participants', (data) => {
            console.log('Current video call participants:', data.participants);
            data.participants.forEach(username => {
                if (username !== this.username) {
                    this.handleNewParticipant(username);
                }
            });
        });

        // WebRTC signaling events for group calls
        this.socket.on('webrtc_offer', (data) => {
            if (data.target_user === this.username) {
                this.handleOffer(data.offer, data.from_user);
            }
        });

        this.socket.on('webrtc_answer', (data) => {
            if (data.target_user === this.username) {
                this.handleAnswer(data.answer, data.from_user);
            }
        });

        this.socket.on('webrtc_ice_candidate', (data) => {
            if (data.target_user === this.username) {
                this.handleIceCandidate(data.candidate, data.from_user);
            }
        });
    }
}

// Initialize the chat client when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new SecureChatClient();
});
