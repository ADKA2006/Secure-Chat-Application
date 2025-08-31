from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, join_room, leave_room, emit
import mysql.connector
from mysql.connector import Error
import uuid
import ssl
import base64
import bcrypt
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'sem3icnproject'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False

# Database configuration - MariaDB
DB_CONFIG = {
    'user': 'admin',
    'password': '12345',
    'host': 'localhost',
    'port': 3306,
    'database': 'secure_chat_db'
}

def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print(f"Error connecting to MySQL/MariaDB: {e}")
        return None

socketio = SocketIO(app, logger=True, cors_allowed_origins="*")

# Authentication functions are defined from here
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  # Hashing the pwd

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

# Registration thing
def create_user(username, password):
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return False, "Username already exists"
        
        password_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash)
        )
        conn.commit()
        return True, "User created successfully"
        
    except Error as e:
        print(f"Database error: {e}")
        return False, f"Database error: {e}"
    finally:
        cursor.close()
        conn.close()

# Login thing
def authenticate_user(username, password):
    conn = get_db_connection()
    if not conn:
        return False, None, "Database connection failed"
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if not user:
            return False, None, "Invalid username or password"
        
        user_id, db_username, password_hash = user
        if verify_password(password, password_hash):
            return True, {
                'id': user_id,
                'username': db_username
            }, "Authentication successful"
        else:
            return False, None, "Invalid username or password"
        
    except Error as e:
        print(f"Database error: {e}")
        return False, None, f"Database error: {e}"
    finally:
        cursor.close()
        conn.close()
# Authentication is over here

connected_users = {} # {client_id: {user_id: ..., username: ..., room: ..., joined_at: ...}}
active_rooms = {} # {room_id: {users: [...], created_at: ...}}
file_transfers = {} # {transfer_id: {file_name: ..., file_size: ..., total_chunks: ...,chunks:{...} sender: ..., room/receiver:.... , time: ...}}
users_typing = {} # {room_id: set([usernames])}


@app.route('/')   #Get only
def index():
    return render_template('index.html')

# Defining the connect and disconnect events
@socketio.on('connect')
def handle_connect():
    client_id = request.sid
    print(f"Client with id {client_id} connected")
    
@socketio.on('disconnect')
def handle_disconnect():
    client_id = request.sid
    if client_id in connected_users:
        user = connected_users[client_id]  #Key value pair - Key is CID and value is the username we are providing when we are entering
        print(f"Client with id {client_id} and username {user['username']} disconnected")
        # Informing others in the room (or cleaning up)
        temp = user.get('room')
        if temp:
            leave_room(temp)
            if temp in active_rooms and user['username'] in active_rooms[temp]['users']:
                active_rooms[temp]['users'].remove(user['username'])
            
            # Clean up typing users
            if temp in users_typing and user['username'] in users_typing[temp]:
                users_typing[temp].discard(user['username'])
                if not users_typing[temp]:
                    del users_typing[temp]
                # Emit updated typing status
                emit('users_typing', {'users': list(users_typing.get(temp, []))}, room=temp)
            
            emit('user_left', {
                'username': user['username'],
                'message': f"{user['username']} left the room"
            }, room=temp, include_self=False)

            emit('room_joined', {
                'room_id': temp,
                'users': active_rooms[temp]['users'] if temp in active_rooms else []  # If everyone leave then reqruired this condition other wise showing error
            }, room=temp)
        del connected_users[client_id]


#Chat thing,room thing,.....
@socketio.on('register_user')
def handle_register(data):
    client_id = request.sid
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if username == "" or password == "":
        emit('register_error', {'message': 'All fields are required'})
        return
    
    if len(username) < 3:
        emit('register_error', {'message': 'Username must be at least 3 characters long'})
        return
    
    if len(password) < 6:
        emit('register_error', {'message': 'Password must be at least 6 characters long'})
        return

    success, message = create_user(username, password)

    if success:
        emit('register_success', {
            'message': message,
            'username': username
        })
    else:
        emit('register_error', {'message': message})

@socketio.on('login_user')
def handle_login(data):
    client_id = request.sid
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if username == "" or password == "":
        emit('login_error', {'message': 'Username and password are required'})
        return
    
    success, user_data, message = authenticate_user(username, password)
    
    if success:
        session['user_id'] = user_data['id']
        session['username'] = user_data['username']
        connected_users[client_id] = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'room': None,
            'joined_at': datetime.now().isoformat()
        }
        
        emit('login_success', {
            'user': user_data,
            'message': 'Login successful'
        })
    else:
        emit('login_error', {'message': message})

@socketio.on('join_room')
def handle_join_room(data):
    client_id = request.sid
    if client_id not in connected_users:
        emit('error', {'message': 'The given client id is not part of the connected users'})
        return
    
    room_id = data.get('room_id', '').strip()
    if room_id == "":
        emit('error', {'message': 'Room ID is required. Please enter the room id'})
        return
    
    user = connected_users[client_id]
    temp = user.get('room')  # What we did in disconnect
    if temp:
        leave_room(temp)
        if temp in active_rooms and user['username'] in active_rooms[temp]['users']:
            active_rooms[temp]['users'].remove(user['username'])

        if temp in users_typing and user['username'] in users_typing[temp]:
            users_typing[temp].discard(user['username'])
            if not users_typing[temp]:
                del users_typing[temp]
            emit('users_typing', {'users': list(users_typing.get(temp, []))}, room=temp)
        
        emit('user_left', {
            'username': user['username'],
            'message': f"{user['username']} left the room"
        }, room=temp, include_self=False)

        emit('room_joined', {
            'room_id': temp,
            'users': active_rooms[temp]['users'] if temp in active_rooms else []  # If everyone leave then reqruired the empty list
        }, room=temp)  # For the old room updation

    join_room(room_id)
    user['room'] = room_id
    
    if room_id not in active_rooms:
        active_rooms[room_id] = {
            'users': [],
            'created_at': datetime.now().isoformat()
        }
    if user['username'] not in active_rooms[room_id]['users']:
        active_rooms[room_id]['users'].append(user['username'])
    
    print(f"{user['username']} joined room: {room_id}")

    emit('room_joined', {
        'room_id': room_id,
        'users': active_rooms[room_id]['users']
    }, room=room_id)  # For the new room updation

    emit('user_joined', {           
        'username': user['username'],
        'message': f"{user['username']} joined the room"
    }, room=room_id, include_self=False)

@socketio.on('send_message')
def handle_message(data):
    client_id = request.sid
    if client_id not in connected_users:
        emit('error', {'message': 'The given client id is not part of the connected users'})
        return
    
    user = connected_users[client_id]
    if not user.get('room'):
        emit('error', {'message': 'You are not in any room'})
        return
    
    message = data.get('message', '').strip()
    if message == "":
        return
    
    message_data = {
        'username': user['username'],
        'message': message,
        'timestamp': datetime.now().strftime('%H:%M')
    }
    
    print(f"{user['username']} in {user['room']} send: {message}")
    emit('new_message', message_data, room=user['room'])

# User typing thing
@socketio.on('user_start_typing')
def handle_start_typing():
    client_id = request.sid
    if client_id not in connected_users:
        emit('error', {'message': 'The given client id is not part of the connected users'})
        return
    
    user = connected_users[client_id]
    if not user.get('room'):
        emit('error', {'message': 'You are not in any room'})
        return

    room_id = user['room']
    username = user['username']
    if room_id not in users_typing:
        users_typing[room_id] = set()
    users_typing[room_id].add(username)
    emit('users_typing', {'users': list(users_typing[room_id])}, room=room_id, include_self=False)

@socketio.on('user_stop_typing')
def handle_stop_typing():
    client_id = request.sid
    if client_id not in connected_users:
        emit('error', {'message': 'The given client id is not part of the connected users'})
        return
    
    user = connected_users[client_id]
    if not user.get('room'):
        emit('error', {'message': 'You are not in any room'})
        return
    
    room_id = user['room']
    username = user['username']
    
    if room_id in users_typing and username in users_typing[room_id]:
        users_typing[room_id].discard(username)
        if not users_typing[room_id]:
            del users_typing[room_id]
        emit('users_typing', {'users': list(users_typing.get(room_id, []))}, room=room_id, include_self=False)

@socketio.on('start_file_transfer')
def handle_file_transfer_start(data):
    client_id = request.sid
    if client_id not in connected_users:
        emit('error', {'message': 'The given client id is not part of the connected users'})
        return
    
    user = connected_users[client_id]
    if not user.get('room'):
        emit('error', {'message': 'You are not in any room'})
        return
    

    #Check the structure and do accordingly in js or change here don't forget......
    filename = data.get('filename')
    file_size = data.get('file_size')
    total_chunks = data.get('total_chunks')
    transfer_id = str(uuid.uuid4()) # 128 bits
    file_transfers[transfer_id] = {
        'filename': filename,
        'file_size': file_size,
        'total_chunks': total_chunks,
        'chunks': {},
        'sender': user['username'],
        'room': user['room'],
        'created_at': datetime.now().isoformat()
    }

    print(f"File-{filename} of size {file_size} bytes transfer started")
    emit('transfer_ready', {'transfer_id': transfer_id})
    emit('file_incoming', {
        'filename': filename,
        'file_size': file_size,
        'sender': user['username']
    }, room=user['room'], include_self=False)

@socketio.on('file_chunk')
def handle_file_chunk(data):
    client_id = request.sid
    transfer_id = data.get('transfer_id')
    chunk_index = data.get('chunk_index')
    chunk_data = data.get('chunk_data')
    
    if transfer_id not in file_transfers:
        emit('error', {'message': 'Invalid transfer ID'})
        return
    
    transfer = file_transfers[transfer_id]
    transfer['chunks'][chunk_index] = chunk_data 
    progress = (len(transfer['chunks']) / transfer['total_chunks']) * 100
    print(f"Chunk {chunk_index + 1}/{transfer['total_chunks']} received ({progress:.1f}%)")
    emit('transfer_progress', {'progress': progress})  # For progress indication bar if required or just printing
    if len(transfer['chunks']) == transfer['total_chunks']:
        try:
            binary_data = b''
            for i in range(transfer['total_chunks']):
                if i not in transfer['chunks']:
                    emit('error', {'message': f'Missing file chunk {i+1}/{transfer["total_chunks"]}. File transfer failed.'})
                    del file_transfers[transfer_id]
                    return
                chunk_binary = base64.b64decode(transfer['chunks'][i])
                binary_data += chunk_binary
            file_data = base64.b64encode(binary_data).decode('utf-8')
            
            print(f"File transfer complete: {transfer['filename']}")
            emit('file_ready', {
                'filename': transfer['filename'],
                'file_data': file_data,
                'sender': transfer['sender']
            }, room=transfer['room'])
            del file_transfers[transfer_id]
        except Exception as e:
            print(f"Error reconstructing file: {e}")
            emit('error', {'message': 'File reconstruction failed'})
            del file_transfers[transfer_id]

if __name__ == '__main__':
    print("Starting Secure Chat Server")

    # SSL context creation from here
    context = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('cert.pem', 'key.pem')
        print("SSL context loaded. Running with HTTPS.")
    except Exception as e:
        print(f"Could not load SSL context. Running without SSL ie HTTP")
        context = None

    print("Server is ready")

    socketio.run(
        app,
        host='0.0.0.0',
        port=4000,
        debug=True,
        ssl_context=context
    )
