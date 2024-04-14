from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
import os
import re
from datetime import datetime, timedelta
import random
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
import string
import secrets
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
project_folder = os.path.dirname(os.path.abspath(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SUPABASE_URI')

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'  # Use your email provider's SMTP server
app.config['MAIL_PORT'] = 587  # Use the appropriate port for your email provider
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your email address
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your email password
app.config['MAIL_USE_TLS'] = True  # Use TLS for security
app.config['MAIL_USE_SSL'] = False

db = SQLAlchemy(app)
mail = Mail(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime, default=None)
    is_admin = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), default=None)  # Add OTP field to the USER model
    otp_sent = db.Column(db.Boolean, default=False)  # Add an is_admin field
    token_pchange = db.Column(db.String(32), default=None)
    otp_last_sent = db.Column(db.DateTime, default=None)

class USER(db.Model, UserMixin):
    __tablename__ = 'USER'  # Set the table name explicitly

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime, default=None)
    is_admin = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), default=None)
    otp_sent = db.Column(db.Boolean, default=False)
    token_pchange = db.Column(db.String(32), default=None)
    otp_last_sent = db.Column(db.DateTime, default=None)

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_random_token(token_length=32):
    # Define the characters to use for the token (you can customize this)
    characters = string.ascii_letters + string.digits  # You can add more characters if needed

    # Generate a random token of the specified length
    random_token = ''.join(secrets.choice(characters) for _ in range(token_length))
    
    return random_token

@login_manager.user_loader
def load_user(user_id):
    return USER.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = USER.query.filter_by(username=username).first()
        # print(user.id,user.password,bcrypt.check_password_hash(user.password, password))

        if user and bcrypt.check_password_hash(user.password, password):
            # Reset login attempts on successful login
            user.login_attempts = 0
            user.last_login_attempt = None
            db.session.commit()

            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Check if the user account should be temporarily locked
            if user and user.login_attempts is not None and user.login_attempts >= 3:
                if user.last_login_attempt and datetime.now() - user.last_login_attempt < timedelta(minutes=5):
                    flash('Account temporarily locked. Please try again later.', 'danger')
                    return render_template('login.html', show_request_otp_button=True)  # Show the "Request an OTP" button
                else:
                    # Reset login attempts and last login attempt time if more than 5 minutes have passed
                    user.login_attempts = 0
                    user.last_login_attempt = None
                    db.session.commit()

            if user:
                user.login_attempts = user.login_attempts + 1 if user.login_attempts is not None else 1
                user.last_login_attempt = datetime.now()
                try:
                    # Your code that leads to db.session.commit()
                    db.session.commit()
                    flash('Data saved successfully', 'success')
                    return redirect(url_for('some_route'))
                except Exception as e:
                    flash('An error occurred while saving data. Check the server logs for more information.', 'danger')
                    print(e)
            

            flash('Login failed. Please check your credentials.', 'danger')

    return render_template('login.html', show_request_otp_button=False)  # Don't show the "Request an OTP" button by default

def send_otp_email(user_email, otp):
    msg = Message('OTP Verification', sender='noreply@demo.com', recipients=[user_email])
    msg.body = f'Your OTP for verification is: {otp}'
    mail.send(msg)

@app.route('/otp_verification', methods=['POST'])
def otp_verification():
    if request.method == 'POST':
        # Handle OTP verification
        user_entered_otp = request.form.get('otp')
        if user_entered_otp == session.get('otp') and session['token_pchange'] == USER.query.filter_by(username=session['username']).first().token_pchange and datetime.now() - USER.query.filter_by(username=session['username']).first().otp_last_sent < timedelta(minutes=2):
            # Reset login attempts, last login attempt time, and OTP
            user = USER.query.filter_by(username=session.get('username')).first()
            if user:
                user.otp = None
            flash('OTP verification successful.', 'success')
            return render_template('password_change.html')
        elif user_entered_otp != session.get('otp') and session['token_pchange'] == USER.query.filter_by(username=session['username']).first().token_pchange and datetime.now() - USER.query.filter_by(username=session['username']).first().otp_last_sent < timedelta(minutes=2):
            flash('OTP verification failed. Please try again.', 'danger')
            return render_template('otp_verification.html')
        else:
            flash('OTP expired', 'danger')
            return render_template('request_OTP.html')
    
    # Handle initial request to request OTP
    return render_template('otp_verification.html')

@app.route('/password_change', methods=['POST'])
def password_change():
    if request.method == 'POST':
        new_password = request.form['newPassword']
        confirm_password = request.form['confirmPassword']

        if bcrypt.check_password_hash(USER.query.filter_by(username=session.get('username')).first().password, new_password):
            flash("Old Password Cant be set again!")
            return render_template("password_change.html")

        # Hash the new password (you should use bcrypt or another secure method)
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Update the user's password in the database (you should identify the user by their ID)
        # For example, you can retrieve the user from the database by their ID
        user = USER.query.filter_by(username=session.get('username')).first()  # Replace with the appropriate user ID or session-based user
        user.password = hashed_password
        user.token_pchange = ""
        db.session.commit()
        session.clear()
        
        flash('Password changed successfully. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))

    # Handle the password change form (replace this with your actual route for the password change form)
    return render_template('request_OTP')


@app.route("/user-checking", methods=['POST'])
def user_checking():
    return render_template("request_OTP.html")

@app.route('/request_otp', methods=['POST'])
def request_otp():
    if request.method == 'POST':
        username = request.form.get('username')
        user = USER.query.filter_by(username=username).first()
        
        if user:
            # Generate a new OTP and store it in the session
            otp = generate_otp()
            session['otp'] = otp
            session['username'] = username
            session['token_pchange'] = generate_random_token()
            user.token_pchange = session['token_pchange']
            user.otp_last_sent = datetime.now()
            db.session.commit()

            # Send OTP to the user's email
            msg = Message('OTP Verification', sender='noreply@demo.com', recipients=[user.email])
            msg.body = f'Your OTP for verification is: {otp}'
            mail.send(msg)

            return render_template("otp_verification.html")
        else:
            flash('Invalid username. Please enter a valid username.', 'danger')
            return render_template('request_OTP.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/user_list')
@login_required
def user_list():
    # Check if the current user is an admin
    if not current_user.is_admin:
        abort(403)  # Return a 403 Forbidden error if the user is not an admin
    users = USER.query.all()
    return render_template('user_list.html', users=users)

@app.route('/remove_user/<int:user_id>', methods=['POST'])
@login_required
def remove_user(user_id):
    try:
        # Check if the current user is an admin
        if not current_user.is_admin:
            abort(403, "Permission Denied: You must be an admin to remove a user.")

        user_to_remove = db.session.query(USER).get(user_id)  # Use Session.get() here

        if user_to_remove:
            db.session.delete(user_to_remove)
            db.session.commit()
            flash('USER removed successfully!', 'success')
            return redirect(url_for('user_list'))
        else:
            flash(f'USER with ID {user_id} not found.', 'danger')
            return redirect(url_for('user_list'))

    except Exception as e:
        flash(f'An error occurred while removing the user: {str(e)}', 'danger')
        return redirect(url_for('user_list'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()  # Get the email input
        password = request.form.get('password')


        # Check if a user with the same email already exists
        existing_email = USER.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists. Please use a different email address.', 'danger')
            return render_template('signup.html')

        try:
            existing_user = USER.query.filter_by(username=username).first()
        except Exception as error:
            print(error)

        # Define a regular expression pattern for a strong password
        password_pattern = re.compile(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+{}|:"<>?~]).{8,}$')

        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
        elif not password_pattern.match(password):
            flash('Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character.', 'danger')
        else:
            # Manually set is_admin to True for the admin user
            is_admin = 1 if username.lower() == "admin" else 0
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = USER(username=username, email=email, password=hashed_password, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')


if __name__ == '__main__':
    app.run(debug=True)
