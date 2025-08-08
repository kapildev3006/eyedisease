from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong, random secret key

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '202130'  # Replace with your actual MySQL password
app.config['MYSQL_DB'] = 'eyecare_ai'

mysql = MySQL(app)

# Home Page
@app.route('/')
def home():
    return render_template('main.html')

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
            flash('Login successful!', 'success')
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
    if 'loggedin' in session:
        return render_template('landing.html')
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

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))




# Run the app
if __name__ == '__main__':
    app.run(debug=True)
