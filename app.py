from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong, random secret key

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '202130'  # Replace with your actual MySQL password
app.config['MYSQL_DB'] = 'eyecare_ai'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_email_password'   # Replace with your password or app password

mysql = MySQL(app)
mail = Mail(app)

# Home Page
@app.route('/')
def home():
    unread_count = 0
    if session.get('loggedin'):
        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT COUNT(*) AS c FROM notifications WHERE user_id=%s AND is_read=0', (session['id'],))
            row = cursor.fetchone()
            unread_count = (row['c'] if row else 0) or 0
            cursor.close()
        except Exception:
            unread_count = 0
    flash('Welcome to Vision DX!','success')
    return render_template('main.html', unread_count=unread_count)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['id'] = user['id']
            session['email'] = user['email']
            flash('Welcome to Vision DX!','success')
            return redirect(url_for('landing'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()

        if account:
            flash('Account already exists with this email!', 'warning')
        elif not name or not email or not password:
            flash('Please fill out all fields.', 'warning')
        else:
            hashed_pw = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO users (name, email, password) VALUES (%s, %s, %s)',
                (name, email, hashed_pw)
            )
            mysql.connection.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('registration.html')



@app.route('/send-otp', methods=['POST'])
def send_otp():
    email = request.json.get('email')
    if not email:
        return {'success': False, 'message': 'Email is required.'}, 400

    otp = str(random.randint(100000, 999999))
    session['registration_otp'] = otp
    session['registration_email'] = email

    # Send OTP email
    msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP code is: {otp}'
    try:
        mail.send(msg)
        return {'success': True, 'message': 'OTP sent to your email.'}
    except Exception as e:
        return {'success': False, 'message': f'Failed to send OTP: {str(e)}'}, 500


@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():


    error = None
    if request.method == 'POST':
        identifier = request.form.get('username')
        password = request.form.get('password')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM admin WHERE username = %s OR email = %s", (identifier, identifier))
        admin = cursor.fetchone()
        cursor.close()

        if admin and check_password_hash(admin['password_hash'], password):
            session['admin_loggedin'] = True
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            session['admin_role'] = admin['role']
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin'))
        else:
            error = 'Invalid username/email or password'

    return render_template('admin_login.html', error=error)

# Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_loggedin'):
        flash('Admin access only. Please log in as admin.', 'warning')
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("SELECT * FROM appointments ORDER BY id DESC")
    appointments = cursor.fetchall()
    cursor.execute("SELECT id, name, email FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    cursor.execute("SELECT * FROM feedback ORDER BY id DESC")
    feedbacks = cursor.fetchall()
    try:
        cursor.execute("SELECT * FROM contact ORDER BY id DESC")
        contacts = cursor.fetchall()
    except Exception:
        contacts = []

    # Also compute counts for compatibility
    cursor.execute("SELECT COUNT(*) as count FROM appointments WHERE status = 'completed'")
    completed = cursor.fetchone()['count'] if cursor.rowcount != -1 else 0
    cursor.execute("SELECT COUNT(*) as count FROM appointments WHERE status = 'pending'")
    pending = cursor.fetchone()['count'] if cursor.rowcount != -1 else 0

    cursor.close()
    return render_template('admin.html', appointments=appointments, users=users, feedbacks=feedbacks, contacts=contacts, completed=completed, pending=pending)

# Admin Logout
@app.route('/admin-logout')
def admin_logout():
    session.pop('admin_loggedin', None)
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    flash('Admin has been logged out.', 'info')
    return redirect(url_for('admin_login'))



# Dashboard/Main Page
@app.route('/landing')
def landing():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT name FROM users WHERE id = %s', (session['id'],))
        user = cursor.fetchone()
        client_name = user['name'] if user else ''
        cursor.close()
        return render_template('landing.html', client_name=client_name)
    flash('Please log in first.', 'warning')
    return redirect(url_for('login'))

@app.route('/appointment', methods=['GET', 'POST'])
def appointment():
    if 'loggedin' not in session:
        flash('Please log in to book an appointment.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        city = request.form.get('city')
        date = request.form.get('date')
        time = request.form.get('time')
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        email = request.form.get('email')
        message = request.form.get('message')

        cursor = mysql.connection.cursor()
        cursor.execute(
            '''
            INSERT INTO appointments (user_id, city, appointment_date, appointment_time, name, mobile, email, message)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''',
            (session['id'], city, date, time, name, mobile, email, message)
        )
        mysql.connection.commit()
        cursor.close()

        flash('Your appointment has been booked successfully!', 'success')
        return redirect(url_for('landing'))

    return render_template('appointment.html')




# Contact Form
@app.route('/contact', methods=['POST'])
def contact():
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')

    # Optionally save to DB or send an email
    print(f'Contact received from {name} ({email}): {message}')
    flash('Message sent successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/update-status', methods=['POST'])
def update_status():
    if not session.get('admin_loggedin'):
        flash('Admin access only. Please log in as admin.', 'warning')
        return redirect(url_for('admin_login'))

    appointment_id = request.form.get('appointment_id')
    new_status = (request.form.get('status') or '').strip().lower()

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Fetch appointment for context
    cursor.execute('SELECT id, user_id, name, email, appointment_date, appointment_time FROM appointments WHERE id=%s', (appointment_id,))
    appt = cursor.fetchone()

    cursor.execute("UPDATE appointments SET status = %s WHERE id = %s", (new_status, appointment_id))
    mysql.connection.commit()

    # Send email on approved/declined
    if appt and new_status in ('approved', 'declined'):
        user_email = appt.get('email')
        if user_email:
            try:
                subj = 'Your appointment has been approved' if new_status == 'approved' else 'Your appointment has been declined'
                body = f"Hello {appt.get('name','User')},\n\nYour appointment on {appt.get('appointment_date')} at {appt.get('appointment_time')} has been {new_status}.\n\nRegards, Vision DX"
                msg = Message(subj, sender=app.config['MAIL_USERNAME'], recipients=[user_email])
                msg.body = body
                mail.send(msg)
            except Exception:
                pass
        # Insert notification if table exists
        try:
            cursor.execute(
                'INSERT INTO notifications (user_id, title, body) VALUES (%s, %s, %s)',
                (appt.get('user_id'), f'Appointment {new_status.title()}', f"Your appointment on {appt.get('appointment_date')} was {new_status}.")
            )
            mysql.connection.commit()
        except Exception:
            mysql.connection.rollback()
            pass
    cursor.close()

    flash("Appointment status updated!", "success")
    return redirect(url_for('admin_dashboard'))

# Notifications page for users
@app.route('/notifications')
def notifications():
    if not session.get('loggedin'):
        return redirect(url_for('login'))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    rows = []
    try:
        cursor.execute('SELECT id, title, body, created_at, is_read FROM notifications WHERE user_id=%s ORDER BY created_at DESC', (session['id'],))
        rows = cursor.fetchall()
        # Mark as read
        cursor.execute('UPDATE notifications SET is_read=1 WHERE user_id=%s AND is_read=0', (session['id'],))
        mysql.connection.commit()
    except Exception:
        rows = []
    cursor.close()
    return render_template('notifications.html', notifications=rows)


# Feedback Form
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        experience = request.form.get('experience')
        comments = request.form.get('comments')

        cursor = mysql.connection.cursor()
        cursor.execute(
            'INSERT INTO feedback (name, email, experience, comments) VALUES (%s, %s, %s, %s)',
            (name, email, experience, comments)
        )
        mysql.connection.commit()
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('feedback'))

    return render_template('feedback.html')

# Static Pages
@app.route('/consultation')
def consultation():
    return render_template('consultation.html')

@app.route('/assistant')
def assistant():
    return render_template('assistant.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/upload')
def upload():
    if not session.get('admin_loggedin'):
        flash('Admin access only. Please log in as admin.', 'warning')
        return redirect(url_for('admin_login'))
    return render_template('upload.html')

@app.route('/history')
def history():
    if not session.get('admin_loggedin'):
        flash('Admin access only. Please log in as admin.', 'warning')
        return redirect(url_for('admin_login'))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT 
            name,
            appointment_date,
            appointment_time,
            COALESCE(message, '') AS diagnosis,
            COALESCE(status, 'pending') AS status
        FROM appointments
        ORDER BY appointment_date DESC, appointment_time DESC
    """)
    visits = cursor.fetchall()
    cursor.close()
    return render_template('history.html', visits=visits)

@app.route('/report')
def report():
    if 'loggedin' not in session:
        flash('Please log in to view reports.', 'warning')
        return redirect(url_for('login'))
    return render_template('report.html')

@app.route('/admin-forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        # Here, you would verify the username/email and send a reset link or OTP
        flash('If the username and email match our records, a password reset link has been sent.', 'info')
        return redirect(url_for('admin_forgot_password'))
    return render_template('admin_forgot_password.html')


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# Admin Registration
@app.route('/admin-register', methods=['GET', 'POST'])
def admin_register():
    error = None
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password')

        if not username or not email or not password:
            error = 'All fields are required.'
        else:
            try:
                password_hash = generate_password_hash(password)
                cursor = mysql.connection.cursor()
                cursor.execute(
                    "INSERT INTO admin (username, email, password_hash) VALUES (%s, %s, %s)",
                    (username, email, password_hash)
                )
                mysql.connection.commit()
                cursor.close()
                flash('Admin created successfully. Please log in.', 'success')
                return redirect(url_for('admin_login'))
            except Exception:
                mysql.connection.rollback()
                error = 'Username or Email already exists.'

    return render_template('admin_register.html', error=error)

# Admin Users - list only users data
@app.route('/admin-users')
def admin_users():
    if not session.get('admin_loggedin'):
        flash('Admin access only. Please log in as admin.', 'warning')
        return redirect(url_for('admin_login'))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT id, name, email FROM users ORDER BY id DESC')
    users = cursor.fetchall()
    cursor.close()
    return render_template('admin_users.html', users=users)


# Run the app
if __name__ == '__main__':
    app.run(debug=True)
