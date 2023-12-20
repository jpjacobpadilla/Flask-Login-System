import sqlite3
import contextlib

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
    keys = {'username', 'password'}
    if len(keys - request.form.keys()) > 0: 
        return render_template('login.html', error_msg='Please fill out the entire form')
    
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
            query = 'update set password = :password where id = :id'
            params = {'password': hashed_password, 'id': account[1]}

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
    keys = {'username', 'password', 'email', 'confirm-password'}
    if len(keys - request.form.keys()) > 0: 
        return render_template('register.html', error_msg='Please fill out the entire form')

    query = 'select id from users where username = :username;'
    # Will automatically close connection
    with contextlib.closing(sqlite3.connect(database)) as conn:
        # Starts transaction that will auto commit at the end if no errors.
        with conn:
            conn.execute(query, {'username': request.form['username']}) 


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
