from datetime import datetime, timezone, timedelta
from functools import wraps
import contextlib
import sqlite3

from flask import redirect, url_for, session


ACCESS_TOKEN_LIFETIME = timedelta(minutes=30)
DEFAULT_EXPIRATION_TIME = timedelta(days=1)
REMEMBER_ME_EXPIRATION_TIME = timedelta(days=15)


def login_required(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        try:
            expiration_time = datetime.fromisoformat(session.get('exp'))
        except (TypeError, ValueError):
            return redirect(url_for('login')) # Something wrong with Expiration value
        
        if expiration_time < datetime.now(timezone.utc):
            return redirect(url_for('login'))

        try:
            issued_at = datetime.fromisoformat(session.get('iat'))
        except (TypeError, ValueError):
            return redirect(url_for('login')) # Something wrong with Issued At value

        if issued_at + ACCESS_TOKEN_LIFETIME < datetime.now(timezone.utc):
            query = 'select username from users where username = :username;'
            with contextlib.closing(sqlite3.connect('users.db')) as conn:
                with conn:
                    result = conn.execute(query, {'username': session.get('username', '')}).fetchone()
                
            if not result:
                return redirect(url_for('login'))  # No user with that username in the db anymore
            
            session['iat'] = datetime.now(timezone.utc).isoformat()  # Reset the Issued At parameter
            
        return func(*args, **kwargs)
    
    return decorator


def set_session(username: str, remember_me: bool = False) -> None:
    session['username'] = username
    session['iat'] = datetime.now(timezone.utc).isoformat()
    exp_time_offset = REMEMBER_ME_EXPIRATION_TIME if remember_me else DEFAULT_EXPIRATION_TIME
    session['exp'] = (datetime.now(timezone.utc) + exp_time_offset).isoformat()
    session.permanent = remember_me