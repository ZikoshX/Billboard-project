import pathlib
from flask import Flask, render_template, request, flash, url_for, session, redirect, abort, session
import re
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests
from flask_mail import Mail, Message
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import AdminIndexView, expose, BaseView
from wtforms import PasswordField
from flask_admin.model import typefmt
from flask_admin.form import SecureForm
app=Flask(__name__)


@app.route('/add/<int:num1>/<int:num2>')
def add(num1, num2):
    return str(num1 + num2)

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'mashrapzere44@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'cdha zmdd hhlh tjvq')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'mashrapzere44@gmail.com')

# Initialize Flask-Mail
mail = Mail(app)

# Generate a random secret key for Flask session
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

# Google OAuth configuration using environment variables
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '187314309127-bo52fulqluaqls64aefmcm453k3mrg5p.apps.googleusercontent.com')
client_secrets_file = os.environ.get('CLIENT_SECRETS_FILE', os.path.join(pathlib.Path(__file__).parent, "client_secret.json"))
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/google-login"
)

DB_HOST='localhost'
DB_NAME='sampledb'
DB_USER='postgres'
DB_PASS='13579'

#conn=psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)
#postgres://user:d2hGA3GAmNDa4kfvJsT1F70iOrk3STXb@dpg-co2sf1f109ks738oqb30-a/sampledb_55ts
DB_URI = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",DB_URI)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
class Manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))  
    email = db.Column(db.String(100), unique=True)
    phone_number = db.Column(db.String(20))
    posts = db.relationship('Posts', backref='manager', lazy='dynamic')

    def __repr__(self):
        return f'<Manager {self.username}>'

    
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text)
    manager_id = db.Column(db.Integer, db.ForeignKey('manager.id'), nullable=False)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


    def __repr__(self):
        return f'<Post {self.title}>'
    

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    lastname = db.Column(db.String(128))
    username = db.Column(db.String(128), unique=True)
    password = db.Column(db.String(255))
    email = db.Column(db.String(512), unique=True)
    phone_number = db.Column(db.String(128))
    posts = db.relationship('Posts', backref='users', lazy='dynamic')
   

    def __repr__(self):
        return f'<User {self.username}>'
    
    def __init__(self, name, lastname, username, password, email, phone_number):
        # Validate email length
        if len(email) > 255:
            abort(400, "Email address is too long")

        self.name = name
        self.lastname = lastname
        self.username = username
        self.password = password
        self.email = email
        self.phone_number = phone_number

class ManagerAdminView(ModelView):
    form_base_class = SecureForm
    column_exclude_list = ('password',)
    form_excluded_columns = ('password',)
    form_extra_fields = {
        'password': PasswordField('Password')
    }
    def on_model_change(self, form, model, is_created):
        if 'password' in form:
            model.password = generate_password_hash(form.password.data)
    def on_model_change(self, form, model, is_created):
        # Generate a unique token
        token = str(uuid.uuid4())
        # Assign the token to the manager
        model.token = token
        # Optionally, you can also hash the token before saving it to the database
        # model.token = generate_password_hash(token)
        super().on_model_change(form, model, is_created)        

class UsersAdminView(ModelView):
    form_base_class = SecureForm
    column_exclude_list = ('password',)
    form_excluded_columns = ('password',)
    form_extra_fields = {
        'password': PasswordField('Password')
    }
    
    def on_model_change(self, form, model, is_created):
        if 'password' in form:
            model.password = generate_password_hash(form.password.data)
    def on_model_change(self, form, model, is_created):
        # Generate a unique token
        token = str(uuid.uuid4())
        # Assign the token to the manager
        model.token = token
        # Optionally, you can also hash the token before saving it to the database
        # model.token = generate_password_hash(token)
        super().on_model_change(form, model, is_created) 

admin = Admin(app)
admin.add_view(ManagerAdminView(Manager, db.session))
admin.add_view(ModelView(Posts, db.session))
admin.add_view(UsersAdminView(Users, db.session))


@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/manager')
def manager():
    # Your logic for the manager's dashboard goes here
    return render_template('manager.html')

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper
@app.route('/google-login')
def google_login():
    # Generate the URL for the Google login callback
    google_login_url = url_for('google_callback', _external=True)
    return render_template('home.html', google_login_url=google_login_url)
@app.route('/callback')
def callback():
    # Fetch the authorization response from Google
    authorization_response = request.url

    # Fetch the token
    flow.fetch_token(authorization_response=authorization_response)

    # Get user info from Google
    google_id_token = flow.credentials.id_token
    google_user_info = id_token.verify_oauth2_token(google_id_token, requests.Request(), GOOGLE_CLIENT_ID)

    # Check if the user already exists in your database
    user = Users.query.filter_by(email=google_user_info['email']).first()

    if user:
        # User exists, log them in
        session['loggedin'] = True
        session['id'] = user.id
        session['username'] = user.username
        return redirect(url_for('profile'))
    else:
        # User doesn't exist, you may need to register them
        flash('User does not exist. You may need to register.')
        return redirect(url_for('home'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        lastname = request.form['lastname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone_number = request.form['phone_number']
        hashed_password = generate_password_hash(password)

        user = Users.query.filter_by(username=username).first()
        if user:
            flash('Account already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not re.match(r'^(?=.*[a-z])(?=.*\d).{8,}$', password):
            flash('Password must be at least 8 characters long and contain at least one number and one lowercase letter!')     
        elif not username or not password or not email:
            flash('Please fill out the form!')
        elif not phone_number.isdigit():  
            flash('Phone number must contain only digits!')    
        else:
            # Create a new user instance
            new_user = Users(name=name, lastname=lastname, username=username, password=hashed_password, email=email, phone_number=phone_number)
            # Add the new user to the database
            db.session.add(new_user)
            # Commit changes to the database
            db.session.commit()
            flash('You have successfully registered!')

    return render_template('signup.html') 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        # Attempt to authenticate as a user
        user = Users.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Authentication successful, set session variables for user
            session['loggedin'] = True
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash('User login successful!', 'success')
            return redirect(url_for('profile'))  # Redirect to user profile route
        else:
            flash('Users does not exist', 'danger')

        # Attempt to authenticate as a manager
        manager = Manager.query.filter_by(username=username).first()
        if manager:
            if check_password_hash(manager.password, password):
                # Password is correct, proceed with login
                session['loggedin'] = True
                session['manager_id'] = manager.id
                session['manager_name'] = manager.name
                flash('Login successful!')
                return redirect(url_for('manager'))
            else:
                flash('Incorrect password', 'danger')
        else:
            flash('Manager does not exist', 'danger')

        

    elif request.method == 'GET':
        # Display login form with Google login link
        google_login_url, _ = flow.authorization_url()
        return render_template('login.html', google_login_url=google_login_url)

    return render_template('login.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'login' in session:
        return redirect('/')
    
    if request.method == 'POST':
        email = request.form['email']
        token = str(uuid.uuid4())
        
        # Check if the email exists in the Manager table
        manager_account = Manager.query.filter_by(email=email).first()
        if manager_account:
            # Update password for manager
            new_password = request.form['new_password']
            manager_account.password = generate_password_hash(new_password)
            manager_account.token = token
            db.session.commit()
            flash("Password updated successfully", 'success')
            return redirect(url_for('login'))
        
        # Check if the email exists in the User table
        user_account = Users.query.filter_by(email=email).first()
        if user_account:
            # Update password for user
            new_password = request.form['new_password']
            user_account.password = generate_password_hash(new_password)
            user_account.token = token
            db.session.commit()
            flash("Password updated successfully", 'success')
            return redirect(url_for('login'))
        
        flash("Email does not match", 'danger')

    return render_template('change_password.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if 'login' in session:
        return redirect('/')
    if request.method == 'POST':
        email = request.form['email']
        token = str(uuid.uuid4())
        
        # Check if the email exists in the Manager table
        manager_account = Manager.query.filter_by(email=email).first()
        if manager_account:
            msg = Message(subject="Forgot password request", sender="mashrapzere44@gmail.com", recipients=[email])
            msg.body = render_template('sent.html', token=token, account=manager_account)
            mail.send(msg)
            manager_account.token = token
            db.session.commit()
            flash("Email already sent to your email", 'success')
            return redirect(url_for('forgot_password'))
        
        # Check if the email exists in the User table
        user_account = Users.query.filter_by(email=email).first()
        if user_account:
            msg = Message(subject="Forgot password request", sender="mashrapzere44@gmail.com", recipients=[email])
            msg.body = render_template('sent.html', token=token, account=user_account)
            mail.send(msg)
            user_account.token = token
            db.session.commit()
            flash("Email already sent to your email", 'success')
            return redirect(url_for('forgot_password'))
        
        flash("Email does not match", 'danger')

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'login' in session:
        return redirect('/')
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        new_token = str(uuid.uuid4())
        
        if password != confirm_password:
            flash("Passwords do not match", 'danger')
            return redirect(url_for('reset_password', token=token))
        
        hashed_password = generate_password_hash(confirm_password)
        
        # Check if the token exists in the Manager table
        manager_account = Manager.query.filter_by(token=token).first()
        if manager_account:
            manager_account.token = new_token
            manager_account.password = hashed_password
            db.session.commit()
            flash("Your password has been successfully updated", 'success')
            return redirect(url_for('login'))
        
        # Check if the token exists in the User table
        user_account = Users.query.filter_by(token=token).first()
        if user_account:
            user_account.token = new_token
            user_account.password = hashed_password
            db.session.commit()
            flash("Your password has been successfully updated", 'success')
            return redirect(url_for('login'))
        
        flash("Invalid token", 'danger')

    return render_template('reset_password.html')


if __name__=='__main__':
   app.run(debug=True, port=5001)
