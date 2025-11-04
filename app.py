from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import os, re, hmac, secrets
from datetime import timedelta

app = Flask(__name__)
# Use a strong random key in production (store outside code). For the lab we generate one if not set.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_urlsafe(32)

# Security-related session settings
app.config['SESSION_COOKIE_SECURE'] = False  # Set True when serving over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, 'instance', 'firstapp.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB
db = SQLAlchemy(app)

# Simple models
class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

# Create tables if not exist
with app.app_context():
    os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
    db.create_all()

# --- CSRF helpers (manual token) ---
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(16)
    return session['_csrf_token']

def validate_csrf(token):
    stored = session.get('_csrf_token', None)
    if not stored:
        return False
    # Use hmac.compare_digest for timing-attack resistant compare
    return hmac.compare_digest(stored, token)

@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf_token())

# --- Input validation helpers ---
EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
NAME_RE = re.compile(r"^[A-Za-z \-']{1,80}$")

def valid_email(s):
    return bool(EMAIL_RE.match(s)) and len(s) <= 120

def valid_name(s):
    return bool(NAME_RE.match(s)) and len(s) <= 80

# Simple login required decorator
from functools import wraps
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password or len(password) < 8:
            flash('Username and password required (min 8 chars).', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))

        pw_hash = generate_password_hash(password)  # uses PBKDF2 by default (Werkzeug)
        user = User(username=username, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        # Generic error messages to avoid user enumeration
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))
        session.clear()
        session['user_id'] = user.id
        flash('Logged in.', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    people = Person.query.order_by(Person.created_at.desc()).all()
    return render_template('index.html', people=people)

@app.route('/add', methods=['POST'])
@login_required
def add_person():
    # CSRF token validation
    token = request.form.get('csrf_token','')
    if not validate_csrf(token):
        abort(400, description="Missing or invalid CSRF token.")

    # Input sanitization & validation
    first = request.form.get('first_name','').strip()
    last = request.form.get('last_name','').strip()
    email = request.form.get('email','').strip().lower()

    if not (valid_name(first) and valid_name(last)):
        flash('Invalid name format.', 'danger')
        return redirect(url_for('index'))

    if not valid_email(email):
        flash('Invalid email.', 'danger')
        return redirect(url_for('index'))

    # Avoid duplicates using parameterized ORM queries (SQLAlchemy protects against SQLi)
    if Person.query.filter_by(email=email).first():
        flash('Email already exists.', 'warning')
        return redirect(url_for('index'))

    person = Person(first_name=escape(first), last_name=escape(last), email=escape(email))
    db.session.add(person)
    db.session.commit()
    flash('Person added.', 'success')
    return redirect(url_for('index'))

@app.route('/delete/<int:person_id>', methods=['POST'])
@login_required
def delete_person(person_id):
    token = request.form.get('csrf_token','')
    if not validate_csrf(token):
        abort(400, description="Missing or invalid CSRF token.")
    person = Person.query.get_or_404(person_id)
    db.session.delete(person)
    db.session.commit()
    flash('Record deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/update/<int:person_id>', methods=['GET','POST'])
@login_required
def update_person(person_id):
    person = Person.query.get_or_404(person_id)
    if request.method == 'POST':
        token = request.form.get('csrf_token','')
        if not validate_csrf(token):
            abort(400, description="Missing or invalid CSRF token.")

        first = request.form.get('first_name','').strip()
        last = request.form.get('last_name','').strip()
        email = request.form.get('email','').strip().lower()

        if not (valid_name(first) and valid_name(last)):
            flash('Invalid name format.', 'danger')
            return redirect(url_for('update_person', person_id=person.id))

        if not valid_email(email):
            flash('Invalid email.', 'danger')
            return redirect(url_for('update_person', person_id=person.id))

        if email != person.email and Person.query.filter_by(email=email).first():
            flash('Email already used by another record.', 'warning')
            return redirect(url_for('update_person', person_id=person.id))

        person.first_name = escape(first)
        person.last_name = escape(last)
        person.email = escape(email)
        db.session.commit()
        flash('Person updated successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('update.html', person=person)

# Custom error handlers to avoid info leak
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    # Log the error in real application rather than showing details to user
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Debug should be False for production; for lab keep easy to run locally
    app.run(debug=True)
