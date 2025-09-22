from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import sqlite3
import hashlib
import os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config.from_object('config')

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            account_type TEXT NOT NULL CHECK(account_type IN ('admin', 'viewer'))
        )
    ''')
    
    # Create patients table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            age INTEGER NOT NULL,
            diagnosis TEXT NOT NULL,
            entry_date DATE NOT NULL,
            status TEXT NOT NULL,
            doctor_name TEXT NOT NULL,
            is_in_surgery_section BOOLEAN NOT NULL DEFAULT 0,
            is_prepared BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            table_name TEXT NOT NULL,
            record_id INTEGER,
            old_values TEXT,
            new_values TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create images table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image_type TEXT NOT NULL CHECK(image_type IN ('duty_schedule', 'upcoming_operations')),
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users (id)
        )
    ''')
    
    # Check if admin user exists, if not create it
    cursor.execute("SELECT * FROM users WHERE username = 'mounir'")
    if not cursor.fetchone():
        # Hash the password
        hashed_password = hashlib.sha256('3mmk'.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password, account_type) VALUES (?, ?, ?)",
                      ('mounir', hashed_password, 'admin'))
    
    conn.commit()
    conn.close()

# Hash password function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Verify password function
def verify_password(password, hashed):
    return hash_password(password) == hashed

# Check if user is logged in
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Check if user is admin
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('account_type') != 'admin':
            flash('Admin access required!', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Logging function
def log_action(action, table_name, record_id=None, old_values=None, new_values=None):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (user_id, action, table_name, record_id, old_values, new_values)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session['user_id'], action, table_name, record_id, old_values, new_values))
    conn.commit()
    conn.close()

# Doctor color assignment function
def get_doctor_color(doctor_name, variant='light'):
    import hashlib
    
    # Predefined color palette
    colors = [
        '#E3F2FD', '#F3E5F5', '#E8F5E8', '#FFF3E0', '#FCE4EC',
        '#E0F2F1', '#F1F8E9', '#FFF8E1', '#E8EAF6', '#F9FBE7',
        '#E0F7FA', '#F3E5F5', '#E8F5E8', '#FFF3E0', '#FCE4EC'
    ]
    
    dark_colors = [
        '#1976D2', '#7B1FA2', '#388E3C', '#F57C00', '#C2185B',
        '#00695C', '#689F38', '#F9A825', '#3F51B5', '#827717',
        '#0097A7', '#7B1FA2', '#388E3C', '#F57C00', '#C2185B'
    ]
    
    # Generate consistent color based on doctor name hash
    hash_value = int(hashlib.md5(doctor_name.encode()).hexdigest(), 16)
    color_index = hash_value % len(colors)
    
    return dark_colors[color_index] if variant == 'dark' else colors[color_index]

# Register the function for use in templates
app.jinja_env.globals.update(get_doctor_color=get_doctor_color)

# File upload helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_latest_image(image_type):
    """Get the latest uploaded image of a specific type"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT filename, original_filename, uploaded_at 
        FROM images 
        WHERE image_type = ? 
        ORDER BY uploaded_at DESC 
        LIMIT 1
    """, (image_type,))
    result = cursor.fetchone()
    conn.close()
    return result

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, account_type FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        # Get filter parameters
        doctor_filter = request.args.get('doctor', '')
        
        # Build query with optional doctor filter
        if doctor_filter:
            cursor.execute("""
                SELECT id, full_name, age, diagnosis, entry_date, status, doctor_name, 
                       is_in_surgery_section, is_prepared, created_at, updated_at
                FROM patients 
                WHERE doctor_name LIKE ?
                ORDER BY created_at DESC
            """, (f'%{doctor_filter}%',))
        else:
            cursor.execute("""
                SELECT id, full_name, age, diagnosis, entry_date, status, doctor_name, 
                       is_in_surgery_section, is_prepared, created_at, updated_at
                FROM patients ORDER BY created_at DESC
            """)
        patients = cursor.fetchall()
        
        # Get unique doctors for filter dropdown
        cursor.execute("SELECT DISTINCT doctor_name FROM patients ORDER BY doctor_name")
        doctors = [row[0] for row in cursor.fetchall()]
        
        # Get recent logs
        cursor.execute("""
            SELECT l.action, l.table_name, l.record_id, l.timestamp, u.username
            FROM logs l
            JOIN users u ON l.user_id = u.id
            ORDER BY l.timestamp DESC
            LIMIT 10
        """)
        logs = cursor.fetchall()
        
        conn.close()
        
        # Get latest images
        duty_schedule_image = get_latest_image('duty_schedule')
        upcoming_operations_image = get_latest_image('upcoming_operations')
        
        if user:
            return render_template('index.html', 
                                 username=user[0], 
                                 account_type=user[1],
                                 patients=patients,
                                 logs=logs,
                                 doctors=doctors,
                                 selected_doctor=doctor_filter,
                                 duty_schedule_image=duty_schedule_image,
                                 upcoming_operations_image=upcoming_operations_image)
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, account_type FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and verify_password(password, user[1]):
            session['user_id'] = user[0]
            session['username'] = username
            session['account_type'] = user[2]
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@login_required
@admin_required
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate input
        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register.html')
        
        # Hash password and insert user (only viewer accounts allowed)
        hashed_password = hash_password(password)
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO users (username, password, account_type) VALUES (?, ?, ?)",
                          (username, hashed_password, 'viewer'))
            conn.commit()
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

# Patient management routes (admin only)
@app.route('/add_patient', methods=['POST'])
@login_required
@admin_required
def add_patient():
    try:
        full_name = request.form['full_name']
        age = int(request.form['age'])
        diagnosis = request.form['diagnosis']
        entry_date = request.form['entry_date']
        status = request.form['status']
        doctor_name = request.form['doctor_name']
        is_in_surgery_section = 'is_in_surgery_section' in request.form
        is_prepared = 'is_prepared' in request.form
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO patients (full_name, age, diagnosis, entry_date, status, doctor_name, 
                                is_in_surgery_section, is_prepared)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (full_name, age, diagnosis, entry_date, status, doctor_name, 
              is_in_surgery_section, is_prepared))
        
        patient_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Log the action
        log_action('CREATE', 'patients', patient_id, None, 
                  f"Name: {full_name}, Age: {age}, Diagnosis: {diagnosis}")
        
        flash('Patient added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding patient: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/edit_patient/<int:patient_id>', methods=['POST'])
@login_required
@admin_required
def edit_patient(patient_id):
    try:
        # Get old values for logging
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
        old_patient = cursor.fetchone()
        
        if not old_patient:
            flash('Patient not found!', 'error')
            return redirect(url_for('index'))
        
        # Get new values
        full_name = request.form['full_name']
        age = int(request.form['age'])
        diagnosis = request.form['diagnosis']
        entry_date = request.form['entry_date']
        status = request.form['status']
        doctor_name = request.form['doctor_name']
        is_in_surgery_section = 'is_in_surgery_section' in request.form
        is_prepared = 'is_prepared' in request.form
        
        # Update patient
        cursor.execute("""
            UPDATE patients SET full_name=?, age=?, diagnosis=?, entry_date=?, status=?, 
                              doctor_name=?, is_in_surgery_section=?, is_prepared=?, 
                              updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (full_name, age, diagnosis, entry_date, status, doctor_name, 
              is_in_surgery_section, is_prepared, patient_id))
        
        conn.commit()
        conn.close()
        
        # Log the action
        old_values = f"Name: {old_patient[1]}, Age: {old_patient[2]}, Diagnosis: {old_patient[3]}"
        new_values = f"Name: {full_name}, Age: {age}, Diagnosis: {diagnosis}"
        log_action('UPDATE', 'patients', patient_id, old_values, new_values)
        
        flash('Patient updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating patient: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/delete_patient/<int:patient_id>')
@login_required
@admin_required
def delete_patient(patient_id):
    try:
        # Get patient info for logging
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT full_name, age, diagnosis FROM patients WHERE id = ?", (patient_id,))
        patient = cursor.fetchone()
        
        if not patient:
            flash('Patient not found!', 'error')
            return redirect(url_for('index'))
        
        # Delete patient
        cursor.execute("DELETE FROM patients WHERE id = ?", (patient_id,))
        conn.commit()
        conn.close()
        
        # Log the action
        log_action('DELETE', 'patients', patient_id, 
                  f"Name: {patient[0]}, Age: {patient[1]}, Diagnosis: {patient[2]}", None)
        
        flash('Patient deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting patient: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/toggle_prepared/<int:patient_id>')
@login_required
@admin_required
def toggle_prepared(patient_id):
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Get current patient info
        cursor.execute("SELECT full_name, is_prepared FROM patients WHERE id = ?", (patient_id,))
        patient = cursor.fetchone()
        
        if not patient:
            flash('Patient not found!', 'error')
            return redirect(url_for('index'))
        
        # Toggle prepared status
        new_prepared_status = not patient[1]
        cursor.execute("UPDATE patients SET is_prepared = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", 
                      (new_prepared_status, patient_id))
        conn.commit()
        conn.close()
        
        # Log the action
        action = "Marked as prepared" if new_prepared_status else "Marked as not prepared"
        log_action('UPDATE', 'patients', patient_id, 
                  f"Prepared: {not new_prepared_status}", f"Prepared: {new_prepared_status}")
        
        status_msg = "marked as prepared" if new_prepared_status else "marked as not prepared"
        flash(f'Patient {patient[0]} has been {status_msg}!', 'success')
    except Exception as e:
        flash(f'Error updating patient: {str(e)}', 'error')
    
    return redirect(url_for('index'))

# Image management routes (admin only)
@app.route('/upload_image', methods=['POST'])
@login_required
@admin_required
def upload_image():
    try:
        if 'image' not in request.files:
            flash('لم يتم اختيار ملف!', 'error')
            return redirect(url_for('index'))
        
        file = request.files['image']
        image_type = request.form.get('image_type')
        
        if file.filename == '':
            flash('لم يتم اختيار ملف!', 'error')
            return redirect(url_for('index'))
        
        if not image_type or image_type not in ['duty_schedule', 'upcoming_operations']:
            flash('نوع الصورة غير صحيح!', 'error')
            return redirect(url_for('index'))
        
        if file and allowed_file(file.filename):
            # Generate unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            unique_filename = f"{image_type}_{timestamp}{ext}"
            
            # Save file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Save to database
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO images (image_type, filename, original_filename, uploaded_by)
                VALUES (?, ?, ?, ?)
            """, (image_type, unique_filename, filename, session['user_id']))
            conn.commit()
            conn.close()
            
            # Log the action
            log_action('CREATE', 'images', None, None, f"Image type: {image_type}, File: {filename}")
            
            flash('تم رفع الصورة بنجاح!', 'success')
        else:
            flash('نوع الملف غير مدعوم!', 'error')
    except Exception as e:
        flash(f'خطأ في رفع الصورة: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
