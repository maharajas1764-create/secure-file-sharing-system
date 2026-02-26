import os
import uuid
import hashlib
from datetime import datetime, timedelta  # Make sure timedelta is imported
from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from datetime import datetime
import pytz # type: ignore
from pytz import timezone # type: ignore
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import inspect
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_fileshare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, nullable=True)  # Added missing field
    files = db.relationship('File', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    share_id = db.Column(db.String(50), unique=True, nullable=False)
    encryption_key_hash = db.Column(db.String(255), nullable=False)
    iv = db.Column(db.Text, nullable=False)  # Initialization Vector for AES
    failed_attempts = db.Column(db.Integer, default=0)
    expiry_date = db.Column(db.DateTime, nullable=True)  # New column for expiry

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions for Encryption
def generate_key_from_password(password, salt=None):
    """Generate encryption key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    # Use PBKDF2 to derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(file_path, password):
    """Encrypt file using AES encryption"""
    # Generate key from password
    key, salt = generate_key_from_password(password)
    
    # Initialize Fernet with the key
    fernet = Fernet(key)
    
    # Read file
    with open(file_path, 'rb') as file:
        original_data = file.read()
    
    # Encrypt file
    encrypted_data = fernet.encrypt(original_data)
    
    # Save encrypted file
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        # Store salt first (16 bytes), then encrypted data
        encrypted_file.write(salt + encrypted_data)
    
    return encrypted_file_path, key, salt

def decrypt_file(encrypted_file_path, password):
    """Decrypt file using password"""
    try:
        # Read encrypted file
        with open(encrypted_file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()
        
        # Extract salt (first 16 bytes) and encrypted data
        salt = data[:16]
        encrypted_data = data[16:]
        
        # Generate key from password and salt
        key, _ = generate_key_from_password(password, salt)
        
        # Initialize Fernet with the key
        fernet = Fernet(key)
        
        # Decrypt data
        decrypted_data = fernet.decrypt(encrypted_data)
        
        return decrypted_data
    except Exception as e:
        return None

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simple admin check (you can enhance this)
        if username == 'admin' and password == 'admin123':
            # Create a temporary admin session
            session['admin_logged_in'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials!', 'danger')
    
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if admin is logged in
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    # Get current time for file status comparison
    now = datetime.now()
    
    # Get all users and files
    users = User.query.all()
    files = File.query.all()
    
    # Calculate dashboard stats
    total_users = User.query.count()
    total_files = File.query.count()
    total_storage = db.session.query(db.func.sum(File.file_size)).scalar() or 0
    
    # File status counts
    active_files = File.query.filter(File.expiry_date > now).count()
    no_expiry_files = File.query.filter(File.expiry_date == None).count()
    expired_files = File.query.filter(File.expiry_date < now).count()
    
    return render_template('admin_dashboard.html',
                         users=users,
                         files=files,
                         total_users=total_users,
                         total_files=total_files,
                         total_storage=total_storage,
                         active_files=active_files,
                         no_expiry_files=no_expiry_files,
                         expired_files=expired_files,
                         now=now)  # Important: pass now to template

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/view_details')
@login_required
def view_details():
    # Get user information
    user = current_user
    
    # Get user's file statistics
    total_files = File.query.filter_by(user_id=current_user.id).count()
    total_size = db.session.query(db.func.sum(File.file_size)).filter_by(user_id=current_user.id).scalar() or 0
    recent_files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_date.desc()).limit(5).all()
    
    return render_template('view_details.html', 
                          user=user, 
                          total_files=total_files,
                          total_size=total_size,
                          recent_files=recent_files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            user.last_login = datetime.now()
            db.session.commit()
            
            login_user(user)
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    total_size = sum(file.file_size for file in files)
    current_time = datetime.now()
    return render_template('dashboard.html', files=files, total_size=total_size, current_time=current_time)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'danger')
            return redirect(url_for('upload'))
        
        file = request.files['file']
        password = request.form['password']
        expiry_value = request.form.get('expiry_value')
        expiry_unit = request.form.get('expiry_unit')
        
        if file.filename == '':
            flash('No file selected!', 'danger')
            return redirect(url_for('upload'))
        
        if not password:
            flash('Encryption password is required!', 'danger')
            return redirect(url_for('upload'))
        
        # Save original file temporarily
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            # Encrypt the file
            encrypted_file_path, key, salt = encrypt_file(file_path, password)
            
            # Generate unique share ID
            share_id = str(uuid.uuid4())
            
            # Hash the encryption key for storage (not the actual key)
            key_hash = hashlib.sha256(key).hexdigest()
            
            # Calculate expiry date if provided
            expiry_date = None
            if expiry_value and expiry_unit and int(expiry_value) > 0:
                expiry_value = int(expiry_value)
                now = datetime.now()
                
                if expiry_unit == 'minutes':
                    expiry_date = now + timedelta(minutes=expiry_value)
                elif expiry_unit == 'hours':
                    expiry_date = now + timedelta(hours=expiry_value)
                elif expiry_unit == 'days':
                    expiry_date = now + timedelta(days=expiry_value)
                elif expiry_unit == 'months':
                    expiry_date = now + timedelta(days=expiry_value * 30)  # Approximate months
            
            # Save file info to database
            new_file = File(
                filename=filename,
                encrypted_filename=os.path.basename(encrypted_file_path),
                file_size=os.path.getsize(encrypted_file_path),
                user_id=current_user.id,
                share_id=share_id,
                encryption_key_hash=key_hash,
                iv=base64.b64encode(salt).decode('utf-8'),
                expiry_date=expiry_date
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            # Remove original unencrypted file
            os.remove(file_path)
            
            # Format success message with expiry info
            if expiry_date:
                expiry_formatted = expiry_date.strftime('%d-%m-%Y %I:%M:%S %p')
                flash(f'File "{filename}" uploaded and encrypted successfully! It will expire on {expiry_formatted}', 'success')
            else:
                flash(f'File "{filename}" uploaded and encrypted successfully! (No expiry)', 'success')
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error during encryption: {str(e)}', 'danger')
            if os.path.exists(file_path):
                os.remove(file_path)
            return redirect(url_for('upload'))
    
    return render_template('upload.html')

@app.route('/share/<share_id>')
@login_required
def share_file(share_id):
    file = File.query.filter_by(share_id=share_id, user_id=current_user.id).first()
    
    if not file:
        flash('File not found!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if file is expired
    now = datetime.now()
    is_expired = file.expiry_date and file.expiry_date < now
    
    share_url = f"{request.host_url}download/{share_id}"
    return render_template('share.html', file=file, share_url=share_url, now=now, is_expired=is_expired)

@app.route('/download/<share_id>', methods=['GET', 'POST'])
def download_file(share_id):
    file = File.query.filter_by(share_id=share_id).first()

    if not file:
        flash('File not found!', 'danger')
        return redirect(url_for('index'))

    # Check if file has expired
    now = datetime.now()
    if file.expiry_date and file.expiry_date < now:
        flash('This file has expired and is no longer available for download!', 'danger')
        return redirect(url_for('index'))

    # If already exceeded attempts
    if file.failed_attempts >= 3:
        flash('This file has been permanently corrupted due to multiple failed attempts!', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        password = request.form['password']

        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.encrypted_filename)

        if not os.path.exists(encrypted_file_path):
            flash('File no longer exists on server!', 'danger')
            return redirect(url_for('index'))

        decrypted_data = decrypt_file(encrypted_file_path, password)

        # WRONG PASSWORD
        if decrypted_data is None:
            file.failed_attempts += 1
            db.session.commit()

            remaining = 3 - file.failed_attempts

            if file.failed_attempts >= 3:
                # CORRUPT FILE (DELETE)
                if os.path.exists(encrypted_file_path):
                    os.remove(encrypted_file_path)

                db.session.delete(file)
                db.session.commit()

                flash('Maximum attempts reached! File permanently corrupted.', 'danger')
                return redirect(url_for('index'))

            flash(f'Invalid password! {remaining} attempts remaining.', 'danger')
            return redirect(url_for('download_file', share_id=share_id))

        # CORRECT PASSWORD
        file.failed_attempts = 0
        db.session.commit()

        from io import BytesIO
        return send_file(
            BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file.filename
        )

    return render_template('download.html', file=file, now=now)

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.user_id != current_user.id:
        flash('Unauthorized action!', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete encrypted file from filesystem
        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.encrypted_filename)
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
        
        # Delete from database
        db.session.delete(file)
        db.session.commit()
        
        flash('File deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match!', 'danger')
            return redirect(url_for('change_password'))
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return redirect(url_for('change_password'))
        
        # Verify current password
        user = User.query.get(current_user.id)
        if not check_password_hash(user.password_hash, current_password):
            flash('Current password is incorrect!', 'danger')
            return redirect(url_for('change_password'))
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/files')
@login_required
def files():
    files = File.query.filter_by(user_id=current_user.id).all()
    current_time_utc = datetime.now() 
    return render_template('files.html', 
                         files=files,
                         current_user=current_user,
                         current_time=current_time_utc) 

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # Delete user's files first
    for file in user.files:
        # Delete physical file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(file)
    
    db.session.delete(user)
    db.session.commit()
    flash('User and all associated files deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))



