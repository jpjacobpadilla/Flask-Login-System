import re
import sqlite3
import contextlib
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)

from create_database import setup_database
from utils import login_required, set_session


app = Flask(__name__)

app.config['SECRET_KEY'] = 'EXAMPLE_xpSm7p5bgJY8rNoBjGWiz5yjxMNlW6231IBI62OkLc='
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=15)

setup_database(name='users.db')


@app.route('/')
@login_required
def index():
    print(f'User data: {session}')
    return render_template('index.html', username=session.get('username'))


@app.route('/logout')
def logout():
    session.clear()
    session.permanent = False
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Set data to variables
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Attempt to query associated user data
    query = 'select username, password, email from users where username = :username;'

    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: 
        return render_template('login.html', error='Username does not exist')

    # Verify password
    try:
        ph = PasswordHasher()
        ph.verify(account[1], password)
    except VerifyMismatchError:
        return render_template('login.html', error='Incorrect password')

    # Check if password hash needs to be updated
    if ph.check_needs_rehash(account[1]):
        query = 'update set password = :password where username = :username;'
        params = {'password': ph.hash(password), 'username': account[0]}

        with contextlib.closing(sqlite3.connect('users.db')) as conn:
            with conn:
                conn.execute(query, params)

    # Set cookie for user session
    set_session(
        username=account[0], 
        remember_me='remember-me' in request.form
    )
    
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Store data to variables 
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    username = request.form.get('username')
    email = request.form.get('email')

    # Verify data
    if len(password) < 8:
        return render_template('register.html', error='Your password must be 8 or more characters')
    if password != confirm_password:
        return render_template('register.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register.html', error='Username must only be letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register.html', error='Username must be between 4 and 25 characters')

    query = 'select username from users where username = :username;'
    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register.html', error='Username already exists')

    # Create password hash
    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    query = 'insert into users(username, password, email) values (:username, :password, :email);'
    params = {
        'username': username,
        'password': hashed_password,
        'email': email
    }

    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            result = conn.execute(query, params)

    # We can log the user in right away since no email verification
    set_session(username=username)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
