# app.py
from flask import Flask, request, redirect, url_for, flash, send_from_directory, session, g, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import qrcode
import io
import base64
import jinja2
from datetime import datetime # Import datetime for date handling

# --- Flask App Configuration ---
app = Flask(__name__)
app.secret_key = 'your_very_strong_and_random_secret_key_here_for_security' # !!! هام: قم بتغيير هذا إلى مفتاح سري قوي !!!

# --- Database Setup ---
DATABASE = 'documents.db'

def get_db():
    """يتصل بقاعدة البيانات SQLite ويعيد كائن اتصال.
    يستخدم g لضمان وجود اتصال واحد لكل طلب.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # يسمح بالوصول إلى الأعمدة بالاسم
    return g.db

def close_db(e=None):
    """يغلق اتصال قاعدة البيانات في نهاية الطلب."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Register the close_db function to run after each request
app.teardown_appcontext(close_db)

def init_db():
    """يهيئ جداول قاعدة البيانات إذا لم تكن موجودة."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                document_type TEXT NOT NULL,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                filename_back TEXT,
                original_filename_back TEXT,
                description TEXT,
                issue_date TEXT,               -- New: Issue Date
                expiry_date TEXT,              -- New: Expiry Date
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        db.commit()
        print("Database initialized.")

# Ensure the upload folder exists
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 Megabytes limit

ALLOWED_EXTENSIONS_IMAGES = {'png', 'jpg', 'jpeg'}
ALLOWED_EXTENSIONS_DOCS = {'pdf'}

# Document types that require expiry date
DOCUMENT_TYPES_WITH_EXPIRY = ['جواز سفر', 'فيزا', 'رقم وطني / بطاقة هوية', 'رخصة قيادة']

# Document types that *might* have a back side
DOCUMENT_TYPES_WITH_BACK_SIDE = ['رقم وطني / بطاقة هوية', 'رخصة قيادة']


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMAGES.union(ALLOWED_EXTENSIONS_DOCS)

def is_image(filename):
    """Checks if the file is an image."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMAGES

# --- User Authentication Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    """صفحة تسجيل حساب جديد."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            flash('تم التسجيل بنجاح! يرجى تسجيل الدخول.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('اسم المستخدم موجود بالفعل. يرجى اختيار اسم آخر.', 'danger')
    
    # Pass the variables to the template even on GET request for rendering
    return render_template('register.html',
                           document_types_with_expiry=DOCUMENT_TYPES_WITH_EXPIRY,
                           document_types_with_back_side=DOCUMENT_TYPES_WITH_BACK_SIDE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """صفحة تسجيل الدخول."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('تم تسجيل الدخول بنجاح!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'danger')
    
    # Pass the variables to the template even on GET request for rendering
    return render_template('login.html',
                           document_types_with_expiry=DOCUMENT_TYPES_WITH_EXPIRY,
                           document_types_with_back_side=DOCUMENT_TYPES_WITH_BACK_SIDE)

@app.route('/logout')
def logout():
    """تسجيل الخروج من الحساب."""
    session.pop('user_id', None)
    session.pop('username', None)
    flash('تم تسجيل خروجك بنجاح.', 'info')
    return redirect(url_for('login'))

# --- Dashboard ---
@app.route('/')
@app.route('/dashboard')
def dashboard():
    """لوحة التحكم الرئيسية للمستخدم."""
    if 'user_id' not in session:
        flash('يرجى تسجيل الدخول للوصول إلى لوحة التحكم.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    documents = db.execute("SELECT * FROM documents WHERE user_id = ? ORDER BY upload_date DESC", (user_id,)).fetchall()
    return render_template('dashboard.html', 
                           documents=documents,
                           document_types_with_expiry=DOCUMENT_TYPES_WITH_EXPIRY, # These are needed for base.html JS
                           document_types_with_back_side=DOCUMENT_TYPES_WITH_BACK_SIDE) # These are needed for base.html JS


# --- Document Management Routes ---
@app.route('/add_document', methods=['GET', 'POST'])
def add_document():
    """إضافة مستند جديد."""
    if 'user_id' not in session:
        flash('يرجى تسجيل الدخول لإضافة المستندات.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        document_type = request.form['document_type']
        description = request.form['description']
        issue_date = request.form.get('issue_date') if request.form.get('issue_date') else None
        expiry_date = request.form.get('expiry_date') if request.form.get('expiry_date') else None
        
        file_front = request.files.get('document_file_front')
        file_back = request.files.get('document_file_back') # Optional back file

        if not name or not document_type:
            flash('اسم المستند ونوع المستند مطلوبان.', 'danger')
            return redirect(request.url)

        if not file_front or file_front.filename == '':
            flash('يرجى رفع ملف للمستند (الوجه الأمامي).', 'danger')
            return redirect(request.url)

        # Handle front file
        if file_front and allowed_file(file_front.filename):
            original_filename_front = secure_filename(file_front.filename)
            unique_filename_front = f"{os.urandom(8).hex()}_{original_filename_front}"
            filepath_front = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename_front)
            file_front.save(filepath_front)
        else:
            flash('نوع ملف الوجه الأمامي غير مسموح به. الأنواع المدعومة: صور (png, jpg, jpeg) أو pdf.', 'danger')
            return redirect(request.url)

        # Handle back file if provided and document type allows it
        unique_filename_back = None
        original_filename_back = None
        if document_type in DOCUMENT_TYPES_WITH_BACK_SIDE and file_back and file_back.filename != '':
            if allowed_file(file_back.filename):
                original_filename_back = secure_filename(file_back.filename)
                unique_filename_back = f"{os.urandom(8).hex()}_{original_filename_back}"
                filepath_back = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename_back)
                file_back.save(filepath_back)
            else:
                flash('نوع ملف الوجه الخلفي غير مسموح به. الأنواع المدعومة: صور (png, jpg, jpeg) أو pdf.', 'danger')
                # Clean up the front file if back file is invalid
                if os.path.exists(filepath_front):
                    os.remove(filepath_front)
                return redirect(request.url)
        
        db = get_db()
        user_id = session['user_id']
        try:
            db.execute("INSERT INTO documents (user_id, name, document_type, filename, original_filename, filename_back, original_filename_back, description, issue_date, expiry_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (user_id, name, document_type, unique_filename_front, original_filename_front, unique_filename_back, original_filename_back, description, issue_date, expiry_date))
            db.commit()
            flash('تمت إضافة المستند بنجاح!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'حدث خطأ أثناء حفظ المستند: {e}', 'danger')
            # Clean up uploaded files if database insertion fails
            if os.path.exists(filepath_front):
                os.remove(filepath_front)
            if unique_filename_back and os.path.exists(filepath_back):
                os.remove(filepath_back)
            return redirect(request.url)

    document_types = ['جواز سفر', 'فيزا', 'رقم وطني / بطاقة هوية', 'شهادة ميلاد', 'رخصة قيادة', 'عقد إيجار', 'فاتورة كهرباء', 'فاتورة مياه', 'بيان بنكي', 'شهادة دراسية', 'أخرى']
    return render_template('add_document.html', 
                           document_types=document_types,
                           document_types_with_expiry=DOCUMENT_TYPES_WITH_EXPIRY,
                           document_types_with_back_side=DOCUMENT_TYPES_WITH_BACK_SIDE)

@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    """عرض تفاصيل مستند معين مع رمز QR ومعاينة الصور."""
    if 'user_id' not in session:
        flash('يرجى تسجيل الدخول لعرض المستندات.', 'warning')
        return redirect(url_for('login'))

    db = get_db()
    document = db.execute("SELECT * FROM documents WHERE id = ? AND user_id = ?",
                          (doc_id, session['user_id'])).fetchone()

    if not document:
        flash('المستند غير موجود أو ليس لديك إذن لعرضه.', 'danger')
        return redirect(url_for('dashboard'))

    # Generate QR Code
    qr_data = f"Document Name: {document['name']}, Type: {document['document_type']}, ID: {document['id']}"
    qr_img = qrcode.make(qr_data)
    buffered = io.BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

    # Check if files are images for preview
    is_front_image = is_image(document['filename'])
    is_back_image = document['filename_back'] and is_image(document['filename_back'])

    # Determine if back side should be shown
    show_back_side = document['document_type'] in DOCUMENT_TYPES_WITH_BACK_SIDE and document['filename_back']

    return render_template('view_document.html', 
                           document=document, 
                           qr_img_str=qr_img_str,
                           is_front_image=is_front_image,
                           is_back_image=is_back_image,
                           show_back_side=show_back_side,
                           document_types_with_expiry=DOCUMENT_TYPES_WITH_EXPIRY, # These are needed for base.html JS
                           document_types_with_back_side=DOCUMENT_TYPES_WITH_BACK_SIDE) # These are needed for base.html JS

@app.route('/edit_document/<int:doc_id>', methods=['GET', 'POST'])
def edit_document(doc_id):
    """تعديل معلومات المستند."""
    if 'user_id' not in session:
        flash('يرجى تسجيل الدخول لتعديل المستندات.', 'warning')
        return redirect(url_for('login'))

    db = get_db()
    document = db.execute("SELECT * FROM documents WHERE id = ? AND user_id = ?",
                          (doc_id, session['user_id'])).fetchone()

    if not document:
        flash('المستند غير موجود أو ليس لديك إذن لتعديله.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        document_type = request.form['document_type']
        description = request.form['description']
        issue_date = request.form.get('issue_date') if request.form.get('issue_date') else None
        expiry_date = request.form.get('expiry_date') if request.form.get('expiry_date') else None
        
        file_front = request.files.get('document_file_front')
        file_back = request.files.get('document_file_back')

        # Variables to hold new filenames, default to existing ones
        unique_filename_front = document['filename']
        original_filename_front = document['original_filename']
        unique_filename_back = document['filename_back']
        original_filename_back = document['original_filename_back']

        # Handle new front file upload
        if file_front and file_front.filename != '':
            if allowed_file(file_front.filename):
                # Delete old front file
                old_filepath_front = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
                if os.path.exists(old_filepath_front):
                    os.remove(old_filepath_front)
                
                original_filename_front = secure_filename(file_front.filename)
                unique_filename_front = f"{os.urandom(8).hex()}_{original_filename_front}"
                filepath_front = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename_front)
                file_front.save(filepath_front)
            else:
                flash('نوع ملف الوجه الأمامي الجديد غير مسموح به. الأنواع المدعومة: صور (png, jpg, jpeg) أو pdf.', 'danger')
                return redirect(request.url)

        # Handle new back file upload or clear it
        if document_type in DOCUMENT_TYPES_WITH_BACK_SIDE:
            if file_back and file_back.filename != '':
                if allowed_file(file_back.filename):
                    # Delete old back file if exists
                    if document['filename_back']:
                        old_filepath_back = os.path.join(app.config['UPLOAD_FOLDER'], document['filename_back'])
                        if os.path.exists(old_filepath_back):
                            os.remove(old_filepath_back)
                    
                    original_filename_back = secure_filename(file_back.filename)
                    unique_filename_back = f"{os.urandom(8).hex()}_{original_filename_back}"
                    filepath_back = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename_back)
                    file_back.save(filepath_back)
                else:
                    flash('نوع ملف الوجه الخلفي الجديد غير مسموح به. الأنواع المدعومة: صور (png, jpg, jpeg) أو pdf.', 'danger')
                    return redirect(request.url)
            elif 'clear_back_file' in request.form: # Option to clear back file
                if document['filename_back']:
                    old_filepath_back = os.path.join(app.config['UPLOAD_FOLDER'], document['filename_back'])
                    if os.path.exists(old_filepath_back):
                        os.remove(old_filepath_back)
                    unique_filename_back = None
                    original_filename_back = None
        else: # If document type no longer supports back side, clear it
            if document['filename_back']:
                old_filepath_back = os.path.join(app.config['UPLOAD_FOLDER'], document['filename_back'])
                if os.path.exists(old_filepath_back):
                    os.remove(old_filepath_back)
                unique_filename_back = None
                original_filename_back = None

        try:
            db.execute("UPDATE documents SET name = ?, document_type = ?, description = ?, filename = ?, original_filename = ?, filename_back = ?, original_filename_back = ?, issue_date = ?, expiry_date = ? WHERE id = ?",
                       (name, document_type, description, unique_filename_front, original_filename_front, unique_filename_back, original_filename_back, issue_date, expiry_date, doc_id))
            db.commit()
            flash('تم تحديث المستند بنجاح!', 'success')
            return redirect(url_for('view_document', doc_id=doc_id))
        except Exception as e:
            flash(f'حدث خطأ أثناء تحديث المستند: {e}', 'danger')
            return redirect(request.url)

    document_types = ['جواز سفر', 'فيزا', 'رقم وطني / بطاقة هوية', 'شهادة ميلاد', 'رخصة قيادة', 'عقد إيجار', 'فاتورة كهرباء', 'فاتورة مياه', 'بيان بنكي', 'شهادة دراسية', 'أخرى']
    return render_template('edit_document.html', 
                           document=document, 
                           document_types=document_types,
                           document_types_with_expiry=DOCUMENT_TYPES_WITH_EXPIRY,
                           document_types_with_back_side=DOCUMENT_TYPES_WITH_BACK_SIDE)

@app.route('/delete_document/<int:doc_id>', methods=['POST'])
def delete_document(doc_id):
    """حذف مستند."""
    if 'user_id' not in session:
        flash('يرجى تسجيل الدخول لحذف المستندات.', 'warning')
        return redirect(url_for('login'))

    db = get_db()
    document = db.execute("SELECT * FROM documents WHERE id = ? AND user_id = ?",
                          (doc_id, session['user_id'])).fetchone()

    if not document:
        flash('المستند غير موجود أو ليس لديك إذن لحذفه.', 'danger')
        return redirect(url_for('dashboard'))

    # Delete the physical files
    if document['filename']:
        filepath_front = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        if os.path.exists(filepath_front):
            os.remove(filepath_front)
    
    if document['filename_back']:
        filepath_back = os.path.join(app.config['UPLOAD_FOLDER'], document['filename_back'])
        if os.path.exists(filepath_back):
            os.remove(filepath_back)
    
    db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    db.commit()
    flash('تم حذف المستند بنجاح!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    """تنزيل ملف مستند."""
    if 'user_id' not in session:
        flash('يرجى تسجيل الدخول لتنزيل المستندات.', 'warning')
        return redirect(url_for('login'))
    
    db = get_db()
    # Check if filename is the front or back file for the user
    document_front = db.execute("SELECT * FROM documents WHERE filename = ? AND user_id = ?",
                                (filename, session['user_id'])).fetchone()
    document_back = db.execute("SELECT * FROM documents WHERE filename_back = ? AND user_id = ?",
                               (filename, session['user_id'])).fetchone()

    if not document_front and not document_back:
        flash('الملف غير موجود أو ليس لديك إذن لتنزيله.', 'danger')
        return redirect(url_for('dashboard'))

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# Static files (for displaying images in browser)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """يعرض الملفات المرفوعة مباشرة في المتصفح."""
    # This route is for displaying, not downloading directly.
    # It still needs a security check to ensure only owned files are shown.
    if 'user_id' not in session:
        return "Unauthorized", 401 # Or redirect to login

    db = get_db()
    # Check if filename is the front or back file for the user
    document_front = db.execute("SELECT * FROM documents WHERE filename = ? AND user_id = ?",
                                (filename, session['user_id'])).fetchone()
    document_back = db.execute("SELECT * FROM documents WHERE filename_back = ? AND user_id = ?",
                               (filename, session['user_id'])).fetchone()

    if not document_front and not document_back:
        return "File not found or unauthorized", 404

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- User Profile ---
@app.route('/profile')
def profile():
    """صفحة الملف الشخصي للمستخدم."""
    if 'user_id' not in session:
        flash('يرجى تسجيل الدخول لعرض ملفك الشخصي.', 'warning')
        return redirect(url_for('login'))
    
    username = session['username']
    return render_template('profile.html', 
                           username=username,
                           document_types_with_expiry=DOCUMENT_TYPES_WITH_EXPIRY, # These are needed for base.html JS
                           document_types_with_back_side=DOCUMENT_TYPES_WITH_BACK_SIDE) # These are needed for base.html JS

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    """معالج الخطأ لصفحة 404 غير موجودة."""
    return render_template('404.html',
                           document_types_with_expiry=DOCUMENT_TYPES_WITH_EXPIRY, # These are needed for base.html JS
                           document_types_with_back_side=DOCUMENT_TYPES_WITH_BACK_SIDE), 404 # These are needed for base.html JS

@app.errorhandler(413) # Payload Too Large
def too_large(e):
    flash('حجم الملف كبير جدًا. الحد الأقصى المسموح به هو 5 ميجابايت.', 'danger')
    return redirect(request.url)


# --- HTML Templates (Embedded) ---
TEMPLATES = {
    'base.html': '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نظام إدارة المستندات - {% block title %}{% endblock %}</title>
    <style>
/* General Styles */
:root {
    --primary-color: #007bff;
    --secondary-color: #6c757d;
    --success-color: #28a745;
    --danger-color: #dc3545;
    --info-color: #17a2b8;
    --warning-color: #ffc107;
    --light-bg: #f8f9fa;
    --dark-bg: #343a40;
    --text-color: #212529;
    --border-color: #dee2e6;
    --card-bg: #ffffff;
    --hover-color: #0056b3;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: var(--light-bg);
    direction: rtl; /* Right-to-left for Arabic */
    text-align: right; /* Align text to the right for Arabic */
}

a {
    color: var(--primary-color);
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

/* Header and Navigation */
header {
    background-color: var(--dark-bg);
    color: #fff;
    padding: 1rem 0;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
}

nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
    flex-wrap: wrap; /* Allow navigation items to wrap on smaller screens */
}

.logo a {
    color: #fff;
    font-size: 1.8rem;
    font-weight: bold;
    text-decoration: none;
}

nav ul {
    list-style: none;
    display: flex;
    margin: 0;
    padding: 0;
    flex-wrap: wrap;
    justify-content: center; /* Center items when wrapped */
}

nav ul li {
    margin-left: 20px; /* Adjust for RTL */
}

nav ul li a {
    color: #fff;
    font-weight: 500;
    padding: 5px 10px;
    border-radius: 5px;
    transition: background-color 0.3s ease;
}

nav ul li a:hover {
    background-color: var(--primary-color);
    text-decoration: none;
}

/* Main Content Area */
main {
    max-width: 1200px;
    margin: 20px auto;
    padding: 20px;
    background-color: var(--card-bg);
    border-radius: 8px;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.05);
}

/* Flash Messages */
.flash-messages {
    margin-bottom: 20px;
}

.alert {
    padding: 10px 15px;
    border-radius: 5px;
    margin-bottom: 10px;
    font-weight: 500;
}

.alert-success {
    background-color: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

.alert-danger {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

.alert-info {
    background-color: #d1ecf1;
    color: #0c5460;
    border: 1px solid #bee5eb;
}

.alert-warning {
    background-color: #fff3cd;
    color: #856404;
    border: 1px solid #ffeeba;
}

/* Forms */
.auth-container, .form-container, .profile-container, .dashboard-container, .document-detail-container, .error-container {
    padding: 30px;
    border-radius: 8px;
    background-color: var(--card-bg);
    box-shadow: 0 0 15px rgba(0, 0, 0, 0.08);
    margin-bottom: 20px;
}

h2, h3 {
    color: var(--dark-bg);
    margin-bottom: 20px;
    text-align: center; /* Center headings within their containers */
}

.form-group {
    margin-bottom: 15px;
}

.form-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
    color: var(--text-color);
}

.form-group input[type="text"],
.form-group input[type="password"],
.form-group input[type="file"],
.form-group input[type="date"], /* Added date input */
.form-group select, /* Added select */
.form-group textarea {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--border-color);
    border-radius: 5px;
    font-size: 1rem;
    color: var(--text-color);
    background-color: #fff;
    transition: border-color 0.3s ease, box-shadow 0.3s ease;
}

.form-group input[type="text"]:focus,
.form-group input[type="password"]:focus,
.form-group input[type="file"]:focus,
.form-group input[type="date"]:focus, /* Added date input */
.form-group select:focus, /* Added select */
.form-group textarea:focus {
    border-color: var(--primary-color);
    box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25);
    outline: none;
}

.form-group textarea {
    min-height: 100px;
    resize: vertical;
}

/* Buttons */
.btn {
    display: inline-block;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 1rem;
    font-weight: 600;
    text-align: center;
    transition: background-color 0.3s ease, color 0.3s ease;
    border: none;
    text-decoration: none;
    margin-top: 10px; /* Add some space above buttons */
}

.btn-primary {
    background-color: var(--primary-color);
    color: #fff;
}

.btn-primary:hover {
    background-color: var(--hover-color);
    text-decoration: none;
}

.btn-secondary {
    background-color: var(--secondary-color);
    color: #fff;
}

.btn-secondary:hover {
    background-color: #5a6268;
    text-decoration: none;
}

.btn-success {
    background-color: var(--success-color);
    color: #fff;
}

.btn-success:hover {
    background-color: #218838;
    text-decoration: none;
}

.btn-danger {
    background-color: var(--danger-color);
    color: #fff;
}

.btn-danger:hover {
    background-color: #c82333;
    text-decoration: none;
}

.btn-info {
    background-color: var(--info-color);
    color: #fff;
}

.btn-info:hover {
    background-color: #138496;
    text-decoration: none;
}

.btn-download {
    background-color: #20c997; /* A pleasant green for download */
    color: #fff;
}

.btn-download:hover {
    background-color: #17a67f;
    text-decoration: none;
}

/* Dashboard Document List */
.document-list {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 20px;
    margin-top: 30px;
}

.document-item {
    background-color: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}

.document-item h4 {
    margin-bottom: 10px;
    color: var(--primary-color);
}

.document-item h4 a {
    text-decoration: none;
    color: var(--primary-color);
}

.document-item h4 a:hover {
    text-decoration: underline;
}

.document-actions {
    margin-top: 15px;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}

.document-actions .btn, .document-actions form button {
    margin: 0; /* Remove default button margin */
}

/* Document Detail Page */
.document-detail-container {
    padding: 30px;
    border-radius: 8px;
    background-color: var(--card-bg);
    box-shadow: 0 0 15px rgba(0, 0, 0, 0.08);
}

.document-detail-container h2 {
    margin-bottom: 25px;
    text-align: center;
    color: var(--dark-bg);
}

.document-detail-container p {
    margin-bottom: 10px;
    font-size: 1.1rem;
    color: #555;
}

.qr-code-display {
    text-align: center;
    margin: 30px 0;
    padding: 20px;
    background-color: var(--light-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px;
}

.qr-code-display img {
    max-width: 200px;
    height: auto;
    border: 5px solid #fff;
    box-shadow: 0 0 15px rgba(0, 0, 0, 0.1);
    border-radius: 5px;
}

.document-images {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 20px;
    margin-top: 20px;
    margin-bottom: 30px;
}

.document-image-wrapper {
    text-align: center;
    border: 1px solid var(--border-color);
    padding: 10px;
    border-radius: 8px;
    background-color: var(--light-bg);
}

.document-image-wrapper img {
    max-width: 250px; /* Adjust as needed */
    height: auto;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    cursor: pointer; /* Indicate clickable for lightbox */
}

.document-image-wrapper p {
    margin-top: 10px;
    font-weight: bold;
    color: var(--primary-color);
}


/* Lightbox Styles */
.lightbox {
    display: none; /* Hidden by default */
    position: fixed; /* Stay in place */
    z-index: 1000; /* Sit on top */
    padding-top: 60px; /* Location of the box */
    left: 0;
    top: 0;
    width: 100%; /* Full width */
    height: 100%; /* Full height */
    overflow: auto; /* Enable scroll if needed */
    background-color: rgba(0,0,0,0.9); /* Black w/ opacity */
}

.lightbox-content {
    margin: auto;
    display: block;
    max-width: 90%;
    max-height: 90%;
    object-fit: contain; /* Ensure image fits while maintaining aspect ratio */
}

.lightbox-caption {
    margin: auto;
    display: block;
    width: 80%;
    max-width: 700px;
    text-align: center;
    color: #ccc;
    padding: 10px 0;
    height: 150px;
}

.lightbox-close {
    position: absolute;
    top: 15px;
    right: 35px;
    color: #f1f1f1;
    font-size: 40px;
    font-weight: bold;
    transition: 0.3s;
    cursor: pointer;
}

.lightbox-close:hover,
.lightbox-close:focus {
    color: #bbb;
    text-decoration: none;
    cursor: pointer;
}


.document-actions-bottom {
    margin-top: 30px;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    justify-content: center; /* Center buttons at the bottom */
}

/* Footer */
footer {
    text-align: center;
    padding: 20px;
    margin-top: 40px;
    background-color: var(--dark-bg);
    color: #fff;
    font-size: 0.9rem;
    border-top: 1px solid rgba(0, 0, 0, 0.1);
}

/* Responsive Design */
@media (max-width: 768px) {
    nav {
        flex-direction: column;
        align-items: center;
    }

    nav ul {
        margin-top: 15px;
        flex-direction: column;
        align-items: center;
    }

    nav ul li {
        margin: 5px 0;
    }

    main {
        margin: 10px auto;
        padding: 15px;
    }

    .auth-container, .form-container, .profile-container, .dashboard-container, .document-detail-container, .error-container {
        padding: 20px;
    }

    .document-list {
        grid-template-columns: 1fr; /* Stack documents vertically on small screens */
    }

    .document-actions {
        flex-direction: column;
        align-items: flex-end; /* Align actions to the right */
    }
    
    .document-actions .btn, .document-actions form button {
        width: 100%; /* Make buttons full width */
    }

    .document-actions-bottom {
        flex-direction: column;
    }
    
    .document-actions-bottom .btn, .document-actions-bottom form button {
        width: 100%;
    }

    .document-images {
        flex-direction: column;
        align-items: center;
    }

    .document-image-wrapper img {
        max-width: 90%; /* Smaller on mobile */
    }
}
</style>
</head>
<body>
    <header>
        <nav>
            <div class="logo">
                <a href="{{ url_for('dashboard') }}">نظام إدارة المستندات</a>
            </div>
            <ul>
                {% if 'user_id' in session %}
                <li><a href="{{ url_for('dashboard') }}">الرئيسية</a></li>
                <li><a href="{{ url_for('add_document') }}">إضافة مستند</a></li>
                <li><a href="{{ url_for('profile') }}">الملف الشخصي</a></li>
                <li><a href="{{ url_for('logout') }}">تسجيل الخروج</a></li>
                {% else %}
                <li><a href="{{ url_for('login') }}">تسجيل الدخول</a></li>
                <li><a href="{{ url_for('register') }}">إنشاء حساب</a></li>
                {% endif %}
            </ul>
        </nav>
    </header>
    <main>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flash-messages">
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </main>
    <footer>
        <p>&copy; 2025 نظام إدارة المستندات. جميع الحقوق محفوظة.</p>
    </footer>

    <div id="myLightbox" class="lightbox">
        <span class="lightbox-close">&times;</span>
        <img class="lightbox-content" id="img01">
        <div id="caption" class="lightbox-caption"></div>
    </div>

    <script>
document.addEventListener('DOMContentLoaded', () => {
    const flashMessages = document.querySelectorAll('.flash-messages .alert');
    if (flashMessages.length > 0) {
        flashMessages.forEach(msg => {
            setTimeout(() => {
                msg.style.transition = 'opacity 1s ease-out';
                msg.style.opacity = '0';
                msg.addEventListener('transitionend', () => msg.remove());
            }, 5000);
        });
    }

    // Lightbox functionality
    const lightbox = document.getElementById("myLightbox");
    const lightboxImg = document.getElementById("img01");
    const captionText = document.getElementById("caption");
    const closeBtn = document.querySelector(".lightbox-close");

    document.querySelectorAll(".document-image-wrapper img").forEach(img => {
        img.addEventListener("click", function() {
            lightbox.style.display = "block";
            lightboxImg.src = this.src;
            captionText.innerHTML = this.alt;
        });
    });

    closeBtn.addEventListener("click", function() {
        lightbox.style.display = "none";
    });

    lightbox.addEventListener("click", function(event) {
        if (event.target === lightbox) {
            lightbox.style.display = "none";
        }
    });

    // Dynamic fields for add_document and edit_document pages
    const documentTypeSelect = document.getElementById('document_type');
    const expiryDateGroup = document.getElementById('expiry_date_group');
    const issueDateGroup = document.getElementById('issue_date_group');
    const documentFileBackGroup = document.getElementById('document_file_back_group');

    // Make sure these are properly passed from Flask to Jinja as JSON strings
    // and then parsed back into JavaScript arrays.
    const documentTypesWithExpiry = JSON.parse('{{ document_types_with_expiry | tojson }}');
    const documentTypesWithBackSide = JSON.parse('{{ document_types_with_back_side | tojson }}');

    function toggleFields() {
        const selectedType = documentTypeSelect.value;

        // Toggle expiry date fields
        if (issueDateGroup) {
            if (documentTypesWithExpiry.includes(selectedType)) {
                issueDateGroup.style.display = 'block';
            } else {
                issueDateGroup.style.display = 'none';
            }
        }
        
        if (expiryDateGroup) {
            if (documentTypesWithExpiry.includes(selectedType)) {
                expiryDateGroup.style.display = 'block';
            } else {
                expiryDateGroup.style.display = 'none';
            }
        }

        // Toggle back file field
        if (documentFileBackGroup) {
            if (documentTypesWithBackSide.includes(selectedType)) {
                documentFileBackGroup.style.display = 'block';
            } else {
                documentFileBackGroup.style.display = 'none';
            }
        }
    }

    if (documentTypeSelect) {
        documentTypeSelect.addEventListener('change', toggleFields);
        // Initial call to set correct state on page load
        toggleFields();
    }
});
</script>
</body>
</html>
'''
,
    'login.html': '''
{% extends 'base.html' %}
{% block title %}تسجيل الدخول{% endblock %}
{% block content %}
<div class="auth-container">
    <h2>تسجيل الدخول</h2>
    <form method="POST">
        <div class="form-group">
            <label for="username">اسم المستخدم:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">كلمة المرور:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary">تسجيل الدخول</button>
    </form>
    <p>ليس لديك حساب؟ <a href="{{ url_for('register') }}">أنشئ حساباً الآن</a></p>
</div>
{% endblock %}
'''
,
    'register.html': '''
{% extends 'base.html' %}
{% block title %}إنشاء حساب{% endblock %}
{% block content %}
<div class="auth-container">
    <h2>إنشاء حساب</h2>
    <form method="POST">
        <div class="form-group">
            <label for="username">اسم المستخدم:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">كلمة المرور:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary">إنشاء حساب</button>
    </form>
    <p>لديك حساب بالفعل؟ <a href="{{ url_for('login') }}">سجل الدخول</a></p>
</div>
{% endblock %}
'''
,
    'dashboard.html': '''
{% extends 'base.html' %}
{% block title %}لوحة التحكم{% endblock %}
{% block content %}
<div class="dashboard-container">
    <h2>أهلاً بك، {{ session['username'] }}!</h2>
    <h3>مستنداتي</h3>
    {% if documents %}
    <div class="document-list">
        {% for doc in documents %}
        <div class="document-item">
            <h4><a href="{{ url_for('view_document', doc_id=doc.id) }}">{{ doc.name }}</a></h4>
            <p><strong>النوع:</strong> {{ doc.document_type }}</p>
            {% if doc.issue_date %}
            <p><strong>تاريخ الإصدار:</strong> {{ doc.issue_date }}</p>
            {% endif %}
            {% if doc.expiry_date %}
            <p><strong>تاريخ الانتهاء:</strong> {{ doc.expiry_date }}</p>
            {% endif %}
            <p><strong>تاريخ الرفع:</strong> {{ doc.upload_date }}</p>
            <div class="document-actions">
                <a href="{{ url_for('view_document', doc_id=doc.id) }}" class="btn btn-secondary">عرض</a>
                <a href="{{ url_for('edit_document', doc_id=doc.id) }}" class="btn btn-info">تعديل</a>
                <a href="{{ url_for('download_file', filename=doc.filename) }}" class="btn btn-download">تحميل الأمامي</a>
                {% if doc.filename_back %}
                <a href="{{ url_for('download_file', filename=doc.filename_back) }}" class="btn btn-download">تحميل الخلفي</a>
                {% endif %}
                <form action="{{ url_for('delete_document', doc_id=doc.id) }}" method="POST" style="display:inline;">
                    <button type="submit" class="btn btn-danger" onclick="return confirm('هل أنت متأكد من حذف هذا المستند؟')">حذف</button>
                </form>
            </div>
        </div>
        {% endfor %}
    </div>
    {% else %}
    <p>لا توجد مستندات بعد. <a href="{{ url_for('add_document') }}">أضف مستنداً جديداً</a>.</p>
    {% endif %}
</div>
{% endblock %}
'''
,
    'add_document.html': '''
{% extends 'base.html' %}
{% block title %}إضافة مستند جديد{% endblock %}
{% block content %}
<div class="form-container">
    <h2>إضافة مستند جديد</h2>
    <form method="POST" enctype="multipart/form-data">
        <div class="form-group">
            <label for="name">اسم المستند:</label>
            <input type="text" id="name" name="name" required>
        </div>
        <div class="form-group">
            <label for="document_type">نوع المستند:</label>
            <select id="document_type" name="document_type" required>
                <option value="">اختر نوع المستند</option>
                {% for type in document_types %}
                <option value="{{ type }}">{{ type }}</option>
                {% endfor %}
            </select>
        </div>
        
        <div class="form-group" id="issue_date_group" style="display: none;">
            <label for="issue_date">تاريخ الإصدار:</label>
            <input type="date" id="issue_date" name="issue_date">
        </div>
        
        <div class="form-group" id="expiry_date_group" style="display: none;">
            <label for="expiry_date">تاريخ الانتهاء:</label>
            <input type="date" id="expiry_date" name="expiry_date">
        </div>

        <div class="form-group">
            <label for="document_file_front">ملف المستند (الوجه الأمامي):</label>
            <input type="file" id="document_file_front" name="document_file_front" accept="image/*,.pdf" required>
            <small>الأنواع المدعومة: صور (JPG, PNG) و PDF. الحد الأقصى: 5 ميجابايت.</small>
        </div>
        
        <div class="form-group" id="document_file_back_group" style="display: none;">
            <label for="document_file_back">ملف المستند (الوجه الخلفي - اختياري):</label>
            <input type="file" id="document_file_back" name="document_file_back" accept="image/*,.pdf">
            <small>يستخدم للبطاقات القومية وما شابه. الأنواع المدعومة: صور (JPG, PNG) و PDF. الحد الأقصى: 5 ميجابايت.</small>
        </div>
        
        <div class="form-group">
            <label for="description">الوصف (اختياري):</label>
            <textarea id="description" name="description"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">إضافة المستند</button>
    </form>
</div>
{% endblock %}
'''
,
    'view_document.html': '''
{% extends 'base.html' %}
{% block title %}عرض المستند{% endblock %}
{% block content %}
<div class="document-detail-container">
    <h2>تفاصيل المستند: {{ document.name }}</h2>
    <p><strong>النوع:</strong> {{ document.document_type }}</p>
    <p><strong>الوصف:</strong> {{ document.description if document.description else 'لا يوجد وصف' }}</p>
    <p><strong>تاريخ الرفع:</strong> {{ document.upload_date }}</p>
    {% if document.issue_date %}
    <p><strong>تاريخ الإصدار:</strong> {{ document.issue_date }}</p>
    {% endif %}
    {% if document.expiry_date %}
    <p><strong>تاريخ الانتهاء:</strong> {{ document.expiry_date }}</p>
    {% endif %}

    <h3>الملفات المرفوعة</h3>
    <div class="document-images">
        {% if is_front_image %}
        <div class="document-image-wrapper">
            <img src="{{ url_for('uploaded_file', filename=document.filename) }}" alt="الوجه الأمامي: {{ document.original_filename }}">
            <p>الوجه الأمامي</p>
            <a href="{{ url_for('download_file', filename=document.filename) }}" class="btn btn-download">تحميل</a>
        </div>
        {% else %}
        <div class="document-image-wrapper">
            <p><strong>الوجه الأمامي:</strong> {{ document.original_filename }}</p>
            <a href="{{ url_for('download_file', filename=document.filename) }}" class="btn btn-download">تحميل ملف</a>
        </div>
        {% endif %}

        {% if show_back_side %} {# Only show back side if document type supports it and file exists #}
            {% if is_back_image %}
            <div class="document-image-wrapper">
                <img src="{{ url_for('uploaded_file', filename=document.filename_back) }}" alt="الوجه الخلفي: {{ document.original_filename_back }}">
                <p>الوجه الخلفي</p>
                <a href="{{ url_for('download_file', filename=document.filename_back) }}" class="btn btn-download">تحميل</a>
            </div>
            {% else %}
            <div class="document-image-wrapper">
                <p><strong>الوجه الخلفي:</strong> {{ document.original_filename_back }}</p>
                <a href="{{ url_for('download_file', filename=document.filename_back) }}" class="btn btn-download">تحميل ملف</a>
            </div>
            {% endif %}
        {% endif %}
    </div>

    <h3>رمز الاستجابة السريعة (QR Code)</h3>
    <div class="qr-code-display">
        <img src="data:image/png;base64,{{ qr_img_str }}" alt="QR Code for {{ document.name }}">
    </div>

    <div class="document-actions-bottom">
        <a href="{{ url_for('edit_document', doc_id=document.id) }}" class="btn btn-info">تعديل المستند</a>
        <form action="{{ url_for('delete_document', doc_id=document.id) }}" method="POST" style="display:inline;">
            <button type="submit" class="btn btn-danger" onclick="return confirm('هل أنت متأكد من حذف هذا المستند؟')">حذف المستند</button>
        </form>
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">العودة إلى لوحة التحكم</a>
    </div>
</div>
{% endblock %}
'''
,
    'edit_document.html': '''
{% extends 'base.html' %}
{% block title %}تعديل المستند{% endblock %}
{% block content %}
<div class="form-container">
    <h2>تعديل المستند: {{ document.name }}</h2>
    <form method="POST" enctype="multipart/form-data">
        <div class="form-group">
            <label for="name">اسم المستند:</label>
            <input type="text" id="name" name="name" value="{{ document.name }}" required>
        </div>
        <div class="form-group">
            <label for="document_type">نوع المستند:</label>
            <select id="document_type" name="document_type" required>
                {% for type in document_types %}
                <option value="{{ type }}" {% if document.document_type == type %}selected{% endif %}>{{ type }}</option>
                {% endfor %}
            </select>
        </div>
        
        <div class="form-group" id="issue_date_group" style="display: none;">
            <label for="issue_date">تاريخ الإصدار:</label>
            <input type="date" id="issue_date" name="issue_date" value="{{ document.issue_date }}">
        </div>
        
        <div class="form-group" id="expiry_date_group" style="display: none;">
            <label for="expiry_date">تاريخ الانتهاء:</label>
            <input type="date" id="expiry_date" name="expiry_date" value="{{ document.expiry_date }}">
        </div>

        <div class="form-group">
            <label for="document_file_front">تعديل ملف المستند (الوجه الأمامي):</label>
            <input type="file" id="document_file_front" name="document_file_front" accept="image/*,.pdf">
            <small>الملف الحالي: {{ document.original_filename }}</small><br>
            <small>الأنواع المدعومة: صور (JPG, PNG) و PDF. الحد الأقصى: 5 ميجابايت.</small>
        </div>
        
        <div class="form-group" id="document_file_back_group" style="display: none;">
            <label for="document_file_back">تعديل ملف المستند (الوجه الخلفي - اختياري):</label>
            <input type="file" id="document_file_back" name="document_file_back" accept="image/*,.pdf">
            {% if document.original_filename_back %}
            <small>الملف الحالي: {{ document.original_filename_back }}</small><br>
            <input type="checkbox" id="clear_back_file" name="clear_back_file"> <label for="clear_back_file">مسح ملف الوجه الخلفي</label>
            {% else %}
            <small>لا يوجد ملف وجه خلفي حالياً.</small>
            {% endif %}
            <br><small>يستخدم للبطاقات القومية وما شابه. الأنواع المدعومة: صور (JPG, PNG) و PDF. الحد الأقصى: 5 ميجابايت.</small>
        </div>
        
        <div class="form-group">
            <label for="description">الوصف:</label>
            <textarea id="description" name="description">{{ document.description }}</textarea>
        </div>
        <button type="submit" class="btn btn-primary">حفظ التعديلات</button>
        <a href="{{ url_for('view_document', doc_id=document.id) }}" class="btn btn-secondary">إلغاء</a>
    </form>
</div>
{% endblock %}
'''
,
    'profile.html': '''
{% extends 'base.html' %}
{% block title %}الملف الشخصي{% endblock %}
{% block content %}
<div class="profile-container">
    <h2>ملفك الشخصي</h2>
    <p><strong>اسم المستخدم:</strong> {{ username }}</p>
    <p>هنا يمكنك عرض أو تعديل معلومات ملفك الشخصي.</p>
    <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">العودة إلى لوحة التحكم</a>
</div>
{% endblock %}
'''
,
    '404.html': '''
{% extends 'base.html' %}
{% block title %}الصفحة غير موجودة{% endblock %}
{% block content %}
<div class="error-container">
    <h1>404 - الصفحة غير موجودة</h1>
    <p>عذرًا، الصفحة التي تبحث عنها غير موجودة.</p>
    <a href="{{ url_for('dashboard') }}">العودة إلى لوحة التحكم</a>
</div>
{% endblock %}
'''
}

# Configure Flask's Jinja environment to use the DictLoader
app.jinja_env.loader = jinja2.DictLoader(TEMPLATES)
app.template_folder = None # Explicitly set to None

# --- Run the application ---
if __name__ == '__main__':
    init_db()  # Initialize database when the app starts
    app.run(debug=True)
