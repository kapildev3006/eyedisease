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
app.config['MAIL_USERNAME'] = 'kdev202130@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_email_password'   # Replace with your password or app password

mysql = MySQL(app)
mail = Mail(app)

# Home Page
@app.route('/')
def home():
    return redirect(url_for('landing'))

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_mobile = request.form.get('email_or_mobile')
        password = request.form.get('password')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s OR mobile = %s', (email_or_mobile, email_or_mobile))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['id'] = user['id']
            session['email'] = user['email']
            session['mobile'] = user['mobile']
            flash('Login successful!', 'success')
            return redirect(url_for('landing'))
        else:
            flash('Invalid email/mobile or password.', 'danger')

    return render_template('login.html')

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        password = request.form.get('password')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s OR mobile = %s', (email, mobile))
        account = cursor.fetchone()

        if account:
            flash('Account already exists with this email or mobile!', 'warning')
        elif not name or not email or not mobile or not password:
            flash('Please fill out all fields.', 'warning')
        else:
            hashed_pw = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO users (name, email, mobile, password) VALUES (%s, %s, %s, %s)',
                (name, email, mobile, hashed_pw)
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
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM admin WHERE username = %s", (username,))
        admin = cursor.fetchone()
        cursor.close()

        if admin and check_password_hash(admin['password'], password):  # Use hashed password comparison
            session['admin_loggedin'] = True
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Invalid username or password'

    return render_template('admin_login.html', error=error)

# Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_loggedin'):
        flash('Admin access only. Please log in as admin.', 'warning')
        return redirect(url_for('admin_login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get completed and pending appointment counts
    cursor.execute("SELECT COUNT(*) as count FROM appointments WHERE status = 'completed'")
    completed = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) as count FROM appointments WHERE status = 'pending'")
    pending = cursor.fetchone()['count']

    cursor.close()
    return render_template('admin_dashboard.html', completed=completed, pending=pending)

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
    client_name = ''
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT name FROM users WHERE id = %s', (session['id'],))
        user = cursor.fetchone()
        client_name = user['name'] if user else ''
        cursor.close()
    return render_template('landing.html', client_name=client_name)

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
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    appointment_id = request.form.get('appointment_id')
    new_status = request.form.get('status')

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE appointments SET status = %s WHERE id = %s", (new_status, appointment_id))
    mysql.connection.commit()
    flash("Appointment status updated!", "success")
    return redirect(url_for('admin_dashboard'))


# Feedback Form
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'loggedin' not in session:
        flash('Please loging.', 'warning')
        return redirect(url_for('login'))
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
    if 'loggedin' not in session:
        flash('Please log in for consultation', 'warning')
        return redirect(url_for('login'))
    return render_template('consultation.html')

@app.route('/assistant')
def assistant():
    if 'loggedin' not in session:
        flash('Please logging', 'warning')
        return redirect(url_for('login'))
    return render_template('assistant.html')

@app.route('/about')
def about():
    if 'loggedin' not in session:
        flash('Please logging', 'warning')
        return redirect(url_for('login'))
    return render_template('about.html')

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

# User Forgot Password
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email_or_mobile = request.form.get('email_or_mobile')
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Step 1: Send OTP
        if not otp and not new_password:
            # Find user by email or mobile
            cursor.execute('SELECT * FROM users WHERE email = %s OR mobile = %s', (email_or_mobile, email_or_mobile))
            user = cursor.fetchone()
            if not user:
                flash('No account found with this email or mobile.', 'danger')
                return render_template('forgot_password.html')
            # Send OTP to email (for now)
            otp_code = str(random.randint(100000, 999999))
            session['forgot_otp'] = otp_code
            session['forgot_user_id'] = user['id']
            session['forgot_email'] = user['email']
            msg = Message('Your Password Reset OTP', sender=app.config['MAIL_USERNAME'], recipients=[user['email']])
            msg.body = f'Your OTP code for password reset is: {otp_code}'
            try:
                mail.send(msg)
                flash('OTP sent to your registered email.', 'info')
            except Exception as e:
                flash(f'Failed to send OTP: {str(e)}', 'danger')
            return render_template('forgot_password.html')

        # Step 2: Verify OTP and set new password
        elif otp and new_password:
            if otp == session.get('forgot_otp'):
                user_id = session.get('forgot_user_id')
                hashed_pw = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password = %s WHERE id = %s', (hashed_pw, user_id))
                mysql.connection.commit()
                session.pop('forgot_otp', None)
                session.pop('forgot_user_id', None)
                session.pop('forgot_email', None)
                flash('Password reset successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('forgot_password.html')

    return render_template('forgot_password.html')


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))




# Run the app
if __name__ == '__main__':
    app.run(debug=True)
