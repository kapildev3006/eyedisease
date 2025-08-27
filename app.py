import os
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import random
import firebase_admin
from firebase_admin import credentials, firestore







app = Flask(__name__)

app.secret_key = os.environ.get(
    'SECRET_KEY',
    '81341f7075cc06a217a3ff65200329ed1066feed0873fa8aac08da37e6a87ed5'
)

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'kdev7830@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'kmwzakuuchugabaf')

db = None
firebase_initialized = False

try:
    # Step 1: Check environment variable
    firebase_creds_env = os.environ.get("FIREBASE_CREDENTIALS")

    if firebase_creds_env:
        # Parse JSON string into a Python dict
        cred_dict = json.loads(firebase_creds_env)
        cred = credentials.Certificate(cred_dict)
        print("Using Firebase credentials from environment variable.")
    else:
        # Fallback: use local JSON file
        local_path = "firebase-credentials.json"
        if os.path.exists(local_path):
            cred = credentials.Certificate(local_path)
            print("FIREBASE_CREDENTIALS not found, using local file.")
        else:
            raise FileNotFoundError(
                "Firebase credentials not found in env or local file!"
            )

    # Step 2: Initialize Firebase app
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    firebase_initialized = True
    print("Firebase initialized successfully.")

except Exception as e:
    print(f"Error initializing Firebase: {e}")

# Initialize Flask-Mail
mail = Mail(app)
@app.route('/')
def home():
    return redirect(url_for('landing'))

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_mobile = request.form.get('email_or_mobile')
        password = request.form.get('password')

        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email_or_mobile).limit(1)
        results = list(query.stream())

        if not results:
            query = users_ref.where('mobile', '==', email_or_mobile).limit(1)
            results = list(query.stream())

        if results:
            user_doc = results[0]
            user_data = user_doc.to_dict()

            if check_password_hash(user_data['password'], password):
                session['loggedin'] = True
                session['id'] = user_doc.id  # Use Firestore document ID
                session['email'] = user_data['email']
                session['mobile'] = user_data['mobile']
                flash('Login successful!', 'success')
                return redirect(url_for('landing'))

        flash('Invalid email/mobile or password.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        password = request.form.get('password')

        if not name or not email or not mobile or not password:
            flash('Please fill out all fields.', 'warning')
            return render_template('registration.html')

        users_ref = db.collection('users')
        
        email_exists = users_ref.where('email', '==', email).limit(1).get()
        mobile_exists = users_ref.where('mobile', '==', mobile).limit(1).get()

        if len(list(email_exists)) > 0:
            flash('Account already exists with this email!', 'warning')
        elif len(list(mobile_exists)) > 0:
            flash('Account already exists with this mobile!', 'warning')
        else:
            hashed_pw = generate_password_hash(password)
            
            user_data = {
                'name': name,
                'email': email,
                'mobile': mobile,
                'password': hashed_pw
            }
            db.collection('users').add(user_data)
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

        admins_ref = db.collection('admins')
        query = admins_ref.where('username', '==', username).limit(1)
        results = list(query.stream())

        if results:
            admin_doc = results[0]
            admin_data = admin_doc.to_dict()
            if check_password_hash(admin_data['password'], password):
                session['admin_loggedin'] = True
                session['admin_id'] = admin_doc.id
                session['admin_username'] = admin_data['username']
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))

        error = 'Invalid username or password'

    return render_template('admin_login.html', error=error)

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_loggedin'):
        flash('Admin access only. Please log in as admin.', 'warning')
        return redirect(url_for('admin_login'))

    appointments_ref = db.collection('appointments')
    
    completed_query = appointments_ref.where('status', '==', 'completed').stream()
    pending_query = appointments_ref.where('status', '==', 'pending').stream()

    completed_count = len(list(completed_query))
    pending_count = len(list(pending_query))

    return render_template('admin_dashboard.html', completed=completed_count, pending=pending_count)

@app.route('/admin-logout')
def admin_logout():
    session.pop('admin_loggedin', None)
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    flash('Admin has been logged out.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/add_admin')
def add_admin():
    return render_template('add_admin.html')

@app.route('/admin_appoinment')
def admin_appoinment():
    if not session.get('admin_loggedin'):
        return redirect(url_for('admin_login'))
    appointments_ref = db.collection('appointments').stream()
    appointments = [doc.to_dict() for doc in appointments_ref]
    return render_template('admin_appoinment.html', appointments=appointments)

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash('Please fill out all fields.', 'warning')
            return render_template('admin_register.html')

        admins_ref = db.collection('admins')
        
        username_exists = admins_ref.where('username', '==', username).limit(1).get()
        email_exists = admins_ref.where('email', '==', email).limit(1).get()

        if len(list(username_exists)) > 0:
            flash('Username already exists!', 'warning')
        elif len(list(email_exists)) > 0:
            flash('Email already exists!', 'warning')
        else:
            hashed_pw = generate_password_hash(password)
            
            admin_data = {
                'username': username,
                'email': email,
                'password': hashed_pw
            }
            db.collection('admins').add(admin_data)
            flash('Admin registration successful!', 'success')
            return redirect(url_for('admin_dashboard'))

    return render_template('admin_register.html')

@app.route('/admin_users')
def admin_users():
    if not session.get('admin_loggedin'):
        return redirect(url_for('admin_login'))
    users_ref = db.collection('users').stream()
    users = [doc.to_dict() for doc in users_ref]
    return render_template('admin_users.html', users=users)


@app.route('/landing')
def landing():
    client_name = ''
    if 'loggedin' in session:
        user_ref = db.collection('users').document(session['id'])
        user_doc = user_ref.get()
        if user_doc.exists:
            client_name = user_doc.to_dict().get('name', '')
    return render_template('landing.html', client_name=client_name)

# Appointment Booking
@app.route('/appointment', methods=['GET', 'POST'])
def appointment():
    if 'loggedin' not in session:
        flash('Please log in to book an appointment.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        appointment_data = {
            'user_id': session['id'],
            'city': request.form.get('city'),
            'appointment_date': request.form.get('date'),
            'appointment_time': request.form.get('time'),
            'name': request.form.get('name'),
            'mobile': request.form.get('mobile'),
            'email': request.form.get('email'),
            'message': request.form.get('message'),
            'status': 'pending'  # Default status
        }
        db.collection('appointments').add(appointment_data)
        flash('Your appointment has been booked successfully!', 'success')
        return redirect(url_for('landing'))

    return render_template('appointment.html')

#
@app.route('/update-status', methods=['POST'])
def update_status():
    if 'admin_loggedin' not in session: # Should be admin
        return redirect(url_for('admin_login'))

    appointment_id = request.form.get('appointment_id')
    new_status = request.form.get('status')

    if appointment_id and new_status:
        try:
            appointment_ref = db.collection('appointments').document(appointment_id)
            appointment_ref.update({'status': new_status})
            flash("Appointment status updated!", "success")
        except Exception as e:
            flash(f"Error updating status: {e}", "danger")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'loggedin' not in session:
        flash('Please log in to give feedback.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        feedback_data = {
            'user_id': session.get('id'), 
            'name': request.form.get('name'),
            'email': request.form.get('email'),
            'experience': request.form.get('experience'),
            'comments': request.form.get('comments')
        }
        db.collection('feedback').add(feedback_data)
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('feedback'))

    return render_template('feedback.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email_or_mobile = request.form.get('email_or_mobile')
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')

        users_ref = db.collection('users')

        # Step 1: Send OTP
        if 'send_otp_btn' in request.form:
            query = users_ref.where('email', '==', email_or_mobile).limit(1)
            results = list(query.stream())
            if not results:
                query = users_ref.where('mobile', '==', email_or_mobile).limit(1)
                results = list(query.stream())

            if not results:
                flash('No account found with this email or mobile.', 'danger')
                return render_template('forgot_password.html')

            user_doc = results[0]
            user_data = user_doc.to_dict()
            
            otp_code = str(random.randint(100000, 999999))
            session['forgot_otp'] = otp_code
            session['forgot_user_id'] = user_doc.id
            
            msg = Message('Your Password Reset OTP', sender=app.config['MAIL_USERNAME'], recipients=[user_data['email']])
            msg.body = f'Your OTP code for password reset is: {otp_code}'
            try:
                mail.send(msg)
                flash('OTP sent to your registered email.', 'info')
            except Exception as e:
                flash(f'Failed to send OTP: {str(e)}', 'danger')
            return render_template('forgot_password.html', email_or_mobile=email_or_mobile)

        # Step 2: Verify OTP and set new password
        elif 'reset_password_btn' in request.form:
            if otp == session.get('forgot_otp'):
                user_id = session.get('forgot_user_id')
                hashed_pw = generate_password_hash(new_password)
                db.collection('users').document(user_id).update({'password': hashed_pw})
                
                session.pop('forgot_otp', None)
                session.pop('forgot_user_id', None)
                
                flash('Password reset successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('forgot_password.html', email_or_mobile=email_or_mobile)

    return render_template('forgot_password.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/consultation')
def consultation():
    if 'loggedin' not in session:
        flash('Please log in for consultation', 'warning')
        return redirect(url_for('login'))
    return render_template('consultation.html')

@app.route('/assistant')
def assistant():
    if 'loggedin' not in session:
        flash('Please log in', 'warning')
        return redirect(url_for('login'))
    return render_template('assistant.html')

@app.route('/about')
def about():
    if 'loggedin' not in session:
        flash('Please log in', 'warning')
        return redirect(url_for('login'))
    return render_template('about.html')

@app.route('/report')
def report():
    if 'loggedin' not in session:
        flash('Please log in to view reports.', 'warning')
        return redirect(url_for('login'))
    return render_template('report.html')

@app.route('/history')
def history():
    if 'loggedin' not in session:
        flash('Please log in to view history.', 'warning')
        return redirect(url_for('login'))
    return render_template('history.html')

@app.route('/admin-forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')

        admins_ref = db.collection('admins')
        query = admins_ref.where('username', '==', username).where('email', '==', email).limit(1)
        results = list(query.stream())

        if results:
            admin_doc = results[0]
            
            # Generate a new random password
            new_password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=10))
            hashed_pw = generate_password_hash(new_password)
            
            # Update the password in Firestore
            db.collection('admins').document(admin_doc.id).update({'password': hashed_pw})
            
            # Send the new password to the admin's email
            msg = Message('Your New Admin Password', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Your new password is: {new_password}'
            try:
                mail.send(msg)
                flash('A new password has been sent to your email.', 'success')
            except Exception as e:
                flash(f'Failed to send email: {str(e)}', 'danger')
        else:
            flash('Invalid username or email.', 'danger')

        return redirect(url_for('admin_forgot_password'))

    return render_template('admin_forgot_password.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')

# Run the app
@app.route('/admin')
def admin():
    if not session.get('admin_loggedin'):
        return redirect(url_for('admin_login'))

    # Appointments
    appointments_docs = db.collection('appointments').stream()
    appointments = []
    for doc in appointments_docs:
        appointment = doc.to_dict()
        appointment['id'] = doc.id
        appointments.append(appointment)

    # Users
    users_docs = db.collection('users').stream()
    users = []
    for doc in users_docs:
        user = doc.to_dict()
        user['id'] = doc.id
        users.append(user)

    # Feedbacks
    feedbacks_docs = db.collection('feedback').stream()
    feedbacks = []
    for doc in feedbacks_docs:
        feedback_item = doc.to_dict()
        feedback_item['id'] = doc.id
        feedbacks.append(feedback_item)

    # Contacts
    contacts_docs = db.collection('contacts').stream()
    contacts = []
    for doc in contacts_docs:
        contact = doc.to_dict()
        contact['id'] = doc.id
        contacts.append(contact)

    return render_template('admin.html', appointments=appointments, users=users, feedbacks=feedbacks, contacts=contacts)

if __name__ == '__main__':
    # Use PORT from environment for Render, fallback to 5000 locally
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)  # debug=True only for local testing
