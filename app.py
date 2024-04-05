import pathlib
from flask import Flask, render_template, request, flash, url_for, session, redirect, abort, session
import re
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
import psycopg2
import psycopg2.extras
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
from sqlalchemy import URL, create_engine
from sqlalchemy import text

def create_app():
    # Create Flask application instance
  app = Flask(__name__)

    # Configure app here if needed

    # Define routes and other app configurations here
  return app
app = create_app()

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

connection_string = URL.create(
    'postgresql',
    username='koyeb-adm',
    password='eI8CgU4ODGrn',
    host='ep-damp-term-a29esurz.eu-central-1.pg.koyeb.app',
    database='jtfd',
)

engine = create_engine(connection_string)
conn = psycopg2.connect(
    dbname=connection_string.database,
    user=connection_string.username,
    password=connection_string.password,
    host=connection_string.host
)

#conn=psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)
#postgres://koyeb-adm:eI8CgU4ODGrn@ep-damp-term-a29esurz.eu-central-1.pg.koyeb.app/koyebdb
#DB_URI = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"
app.config['SQLALCHEMY_DATABASE_URI'] = connection_string
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

        token = str(uuid.uuid4())
        model.token = token
        super().on_model_change(form, model, is_created)        



admin = Admin(app)
admin.add_view(ManagerAdminView(Manager, db.session))
admin.add_view(ModelView(Posts, db.session))
admin.add_view(ModelView(Users, db.session))


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
@app.route('/submit_order', methods=['POST'])
def submit_order():
    return redirect(url_for('next_order'))

@app.route('/next_order')
def next_order():
    return render_template('next_order.html')

@app.route('/manager')
def manager():
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
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM users WHERE email=%s', (google_user_info['email'],))
    account = cursor.fetchone()

    if account:
        # User exists, log them in
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        return redirect(url_for('profile'))
    else:
        # User doesn't exist, you can register them if needed
        flash('User does not exist. You may need to register.')
        return redirect(url_for('home'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        name = request.form['name']
        lastname = request.form['lastname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone_number = request.form['phone_number']
        print(name)
        print(username)
        print(password)
        print(email)

        hashed_password = generate_password_hash(password)

        # Check if the username already exists
        query = text("SELECT * FROM users WHERE username=:username")
        existing_account = engine.execute(query, username=username).fetchone()

        if existing_account:
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
            # Insert new account into users table
            query = text("INSERT INTO users (name,lastname, username, password, email, phone_number) VALUES (:name, :lastname, :username, :password, :email, :phone_number)")
            engine.execute(query, name=name, lastname=lastname, username=username, password=hashed_password, email=email, phone_number=phone_number)
            flash('You have successfully registered!')
    elif request.method == 'POST':
        flash('Please fill out the form!')
    return render_template('signup.html') 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        # Check if the user is a manager
        query = text("SELECT * FROM manager WHERE username=:username")
        manager = engine.execute(query, username=username).fetchone()
        
        if manager and check_password_hash(manager['password'], password):
            # Authentication successful, set session variables for manager
            session['loggedin'] = True
            session['manager_id'] = manager['id']
            session['manager_name'] = manager['name']
            flash('Manager login successful!', 'success')
            return redirect(url_for('manager'))  # Redirect to manager profile route

        # Check if the user is a regular user
        query = text("SELECT * FROM users WHERE username=:username")
        user = engine.execute(query, username=username).fetchone()

        if user and check_password_hash(user['password'], password):
            # Authentication successful, set session variables for user
            session['loggedin'] = True
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            flash('User login successful!', 'success')
            return redirect(url_for('profile'))
        
        # If authentication fails for both manager and user
        flash('Incorrect username or password', 'danger')

    elif request.method == 'GET':
        # Display login form with Google login link
        google_login_url, _ = flow.authorization_url()
        return render_template('login.html', google_login_url=google_login_url)

    return render_template('login.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        # Retrieve username from session or form data
        if 'username' in session:
            username = session['username']
        else:
            username = request.form.get('username')

        # Process the password change request
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('change_password'))

        # Update the password in the database for the specified user
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password=%s WHERE username=%s", (hashed_password, username))
        conn.commit()

        # Clear session to invalidate existing login
        session.clear()

        flash('Your password has been changed successfully. Please log in again.')
        return redirect(url_for('login'))  # Redirect to login page after changing password
    else:
        # Render the change password form
        return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if 'loggedin' in session:
        return redirect('/')
    if request.method == 'POST':
        email = request.form['email']
        # Check if the email exists in the database
        user = Users.query.filter_by(email=email).first()
        if user:
            token = str(uuid.uuid4())
            # Update the user's token in the database
            user.token = token
            db.session.commit()

            # Send the reset password email
            msg = Message(subject="Forgot password request", sender="mashrapzere44@gmail.com", recipients=[email])
            msg.body = render_template('sent.html', token=token, account=user)
            mail.send(msg)

            flash("Email sent to your email address.", 'success')
            return redirect(url_for('forgot_password'))
        else:
            flash("Email address not found.", 'danger')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'loggedin' in session:
        return redirect('/')
    # Find the user with the given token
    user = Users.query.filter_by(token=token).first()
    if not user:
        flash("Invalid token.", 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", 'danger')
            return redirect(url_for('reset_password', token=token))

        # Update the user's password and clear the token
        user.password = generate_password_hash(password)
        user.token = None
        db.session.commit()

        flash("Your password has been successfully updated.", 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')



if __name__=='__main__':
   app.run(debug=True, port='8000')
