from flask import Flask, render_template, request, session, url_for, redirect
from functools import wraps 
import sqlite3
import contextlib
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from create_database import setup_database

def login_required(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        # Check if user is logged in
        if 'logged_in' not in session:
            return redirect(url_for('login')) # User is not logged in; redirect to login page
            
        return func(*args, **kwargs)
    
    return decorator

app = Flask(__name__)

database = "users.db"
setup_database(name=database)
# A secret key that will be used for securely signing the session cookie and 
# can be used for any other security related needs by extensions or your application.
# https://flask.palletsprojects.com/en/2.3.x/config/#SECRET_KEY
app.secret_key = 'dawqwertysujgmhjkytreiwuysgxcvbfrnewkslaiwuebfmxwqvhgzj'


@app.route('/login')
def login():
    print(session)
    return render_template('login.html')


@app.route('/verify-user', methods=['POST'])
def verify_user():
    # Check if "username" and "password" POST requests exist (user submitted form)
    if 'username' not in request.form or 'password' not in request.form:
        return render_template('login.html', error_msg='Please fill out the form.')
    
    # Create variables for easy access
    username = request.form['username']
    password = request.form['password']
    
    query = 'select id, username, password, email from users where username = :username'

    # Will automatically close connection
    with contextlib.closing(sqlite3.connect(database)) as conn:
        # Starts transaction that will auto commit at the end if no errors.
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: return render_template('login.html', error_msg='Wrong username')

    try:
        ph = PasswordHasher()
        ph.verify(account[2], password)

    except VerifyMismatchError:
        return render_template('login.html', error_msg='Incorrect password')

    else:
        hashed_password = ph.hash(password)
        if ph.check_needs_rehash(hashed_password):
            query = 'insert into users(username, password, email) values (:username, :password, :email);'

            params = {
                'username': request.form['username'],
                'password': hashed_password,
                'email': request.form['email']
            }

            # Will automatically close connection
            with contextlib.closing(sqlite3.connect(database)) as conn:
                # Starts transaction that will auto commit at the end if no errors.
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
    pw = PasswordHasher()
    hashed_password = pw.hash(request.form['password'])

    query = 'insert into users(username, password, email) values (:username, :password, :email);'

    params = {
        'username': request.form['username'],
        'password': hashed_password,
        'email': request.form['email']
    }

    # Will automatically close connection
    with contextlib.closing(sqlite3.connect(database)) as conn:
        # Starts transaction that will auto commit at the end if no errors.
        with conn:
            conn.execute(query, params)

    session['logged_in'] = True
    session['id'] = 'test'
    session['username'] = request.form['username']
    session['email'] = request.form['email']

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
    return render_template('index.html', username=session.get('username'))


if __name__ == '__main__':
    app.run(debug=True)
