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
from login_required import login_required


app = Flask(__name__)
app.secret_key = 'xpSm7p5bgJY8rNoBjGWiz5yjxM-NEBlW6SIBI62OkLc='

database = "users.db"
setup_database(name=database)


@app.route('/login')
def login():
    print(session)
    return render_template('login.html')


@app.route('/verify-user', methods=['POST'])
def verify_user():
    username = request.form['username']
    password = request.form['password']
    
    query = 'select id, username, password, email from users where username = :username'

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: return render_template('login.html', error_msg='Username does not exist')

    try:
        ph = PasswordHasher()
        ph.verify(account[2], password)

    except VerifyMismatchError:
        return render_template('login.html', error_msg='Incorrect password')

    hashed_password = ph.hash(password)
    if ph.check_needs_rehash(hashed_password):
        query = 'update set password = :password where id = :id'
        params = {'password': hashed_password, 'id': account[0]}

        with contextlib.closing(sqlite3.connect(database)) as conn:
            with conn:
                conn.execute(query, params)

    session['logged_in'] = True
    session['id'] = account[0]
    session['username'] = account[1]
    session['email'] = account[3]

    if 'remember-me' in request.form:
        session.permanent = True 
    
    return redirect('/')


@app.route('/register-user', methods=['POST'])
def register_user():
    password = request.form['password']
    confirm_password = request.form['confirm-password']
    username = request.form['username']
    email = request.form['email']

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

    session['logged_in'] = True
    session['id'] = result.lastrowid
    session['username'] = username
    session['email'] = email

    if 'remember-me' in request.form:
        session.permanent = True 

    return redirect('/')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    session.permanent = False
    return redirect('/login')


@app.route('/')
@login_required
def index():
    print(f'User data: {session}')
    return render_template('index.html', username=session.get('username'))


if __name__ == '__main__':
    app.run(debug=True)
