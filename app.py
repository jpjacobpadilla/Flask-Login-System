import sqlite3
import contextlib
import re

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)

from create_database import setup_database
from utils import login_required, set_session


app = Flask(__name__)
app.secret_key = 'xpSm7p5bgJY8rNoBjGWiz5yjxM-NEBlW6SIBI62OkLc='

database = "users.db"
setup_database(name=database)


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
    username = request.form['username']
    password = request.form['password']
    
    # Attempt to query associated user data
    query = 'select id, username, password, email from users where username = :username'

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: 
        return render_template('login.html', error_msg='Username does not exist')

    # Verify password
    try:
        ph = PasswordHasher()
        ph.verify(account[2], password)
    except VerifyMismatchError:
        return render_template('login.html', error_msg='Incorrect password')

    # Check if password hash needs to be updated
    hashed_password = ph.hash(password)
    if ph.check_needs_rehash(hashed_password):
        query = 'update set password = :password where id = :id'
        params = {'password': hashed_password, 'id': account[0]}

        with contextlib.closing(sqlite3.connect(database)) as conn:
            with conn:
                conn.execute(query, params)

    # Set cookie for user session
    set_session(
        id=account[0], 
        username=account[1], 
        email=account[3], 
        remember_me='remember-me' in request.form
    )
    
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Store data to variables 
    password = request.form['password']
    confirm_password = request.form['confirm-password']
    username = request.form['username']
    email = request.form['email']

    # Verify data
    if password != confirm_password:
        return render_template('register.html', error_msg='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register.html', error_msg='Username must only be letters and numbers')
    if len(username) < 3:
        return render_template('register.html', error_msg='Username must be 3 or more characters')
    if len(username) > 25:
        return render_template('register.html', error_msg='Username must be 25 or less characters')

    query = 'select id from users where username = :username;'
    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register.html', error_msg='Username already exists')

    # Create password hash
    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    query = 'insert into users(username, password, email) values (:username, :password, :email);'
    params = {
        'username': username,
        'password': hashed_password,
        'email': email
    }

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, params)

    # We can log in the user right away since no email verification
    set_session(
        id=result.lastrowid, 
        username=username, 
        email=email
    )

    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
